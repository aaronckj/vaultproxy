//! Upstream HTTP/2 forwarder. Tries TLS+ALPN h2 against `target`; on
//! success runs a single h2 request and returns the parsed response.
//! When the upstream picks http/1.1 (or h2 negotiation fails for a
//! transport reason), returns `Ok(None)` so the caller can fall back
//! to the existing http/1.1 forwarder.
//!
//! Per-request: no connection pool yet. Each agent stream that lands
//! in `h2_mitm` opens its own h2 connection to the upstream. A pool
//! keyed by `(host, port)` is the natural v1.9 follow-up — drop a
//! `DashMap<(String, u16), SendRequest<Bytes>>` here and have the
//! upstream-side accept loop reuse the same `SendRequest` handle.
//!
//! Test affordance: when `VP_TRANSPARENT_TEST_FORCE_H2=1` is set,
//! skip TLS and run h2-with-prior-knowledge over plain TCP so the
//! integration tests can spin up an h2c upstream without a TLS dance.

#![allow(dead_code)]

use anyhow::{Context, Result};
use bytes::Bytes;
use std::sync::Arc;

use crate::proxy::transparent::connect::ConnectTarget;
use crate::proxy::transparent::mitm::HttpRequest;

/// Parsed h2 response shape: (status, headers, body).
pub type ParsedH2Response = (u16, Vec<(String, String)>, Bytes);

/// Attempt to send `req` over h2 to `target`. Returns:
///   * `Ok(Some(parsed))` if the upstream negotiated h2 and responded.
///   * `Ok(None)` if the upstream picked http/1.1 on ALPN (caller
///     should fall back).
///   * `Err(e)` for network/TLS/protocol errors.
pub async fn try_h2(target: &ConnectTarget, req: HttpRequest) -> Result<Option<ParsedH2Response>> {
    let force_h2c = std::env::var("VP_TRANSPARENT_TEST_FORCE_H2")
        .ok()
        .as_deref()
        == Some("1");
    if force_h2c {
        return Ok(Some(send_h2_plain(target, req).await?));
    }
    // Test affordance: VP_TRANSPARENT_TEST_HTTP=1 routes through a
    // plain-HTTP upstream (wiremock by default speaks no TLS). The
    // TLS+ALPN h2 attempt would always fail in that mode, so skip
    // straight to the http/1.1 fallback by returning Ok(None).
    if std::env::var("VP_TRANSPARENT_TEST_HTTP").ok().as_deref() == Some("1") {
        return Ok(None);
    }
    send_h2_tls(target, req).await
}

async fn send_h2_tls(target: &ConnectTarget, req: HttpRequest) -> Result<Option<ParsedH2Response>> {
    use rustls::{ClientConfig, RootCertStore};
    use tokio_rustls::TlsConnector;

    let mut roots = RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    let mut cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    // Offer h2 first; rustls picks the first server-overlap.
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(cfg));
    let server_name = target
        .host
        .clone()
        .try_into()
        .map_err(|e| anyhow::anyhow!("invalid server name '{}': {e}", target.host))?;
    let tcp = tokio::net::TcpStream::connect((target.host.as_str(), target.port)).await?;
    let tls = connector.connect(server_name, tcp).await?;

    let alpn = tls.get_ref().1.alpn_protocol().map(|b| b.to_vec());
    if alpn.as_deref() != Some(b"h2") {
        // Upstream picked http/1.1 (or didn't negotiate ALPN). Drop
        // this connection and let the caller use the http/1.1 path.
        return Ok(None);
    }

    let parsed = run_h2_exchange(tls, target, req).await?;
    Ok(Some(parsed))
}

async fn send_h2_plain(target: &ConnectTarget, req: HttpRequest) -> Result<ParsedH2Response> {
    let tcp = tokio::net::TcpStream::connect((target.host.as_str(), target.port)).await?;
    run_h2_exchange(tcp, target, req).await
}

async fn run_h2_exchange<IO>(
    io: IO,
    target: &ConnectTarget,
    req: HttpRequest,
) -> Result<ParsedH2Response>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (h2, connection) = h2::client::handshake(io)
        .await
        .context("h2 client handshake")?;
    // Drive the connection in a background task. The drive future
    // completes when the connection closes; we don't need to await it
    // before the response — h2's SendRequest::send_request returns
    // immediately and the response future polls the connection.
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut h2 = h2.ready().await.context("h2 client ready")?;

    // Build an http::Request from the HttpRequest.
    let scheme = if std::env::var("VP_TRANSPARENT_TEST_FORCE_H2")
        .ok()
        .as_deref()
        == Some("1")
        || std::env::var("VP_TRANSPARENT_TEST_HTTP").ok().as_deref() == Some("1")
    {
        "http"
    } else {
        "https"
    };
    let uri_str = format!("{scheme}://{}:{}{}", target.host, target.port, req.path);
    let mut builder = http::Request::builder()
        .method(http::Method::from_bytes(req.method.as_bytes())?)
        .uri(&uri_str);
    for (k, v) in &req.headers {
        let lk = k.to_ascii_lowercase();
        // Skip http/1-only and connection-specific headers; h2
        // rejects them at frame-encode time.
        if matches!(
            lk.as_str(),
            "host"
                | "connection"
                | "keep-alive"
                | "proxy-connection"
                | "transfer-encoding"
                | "upgrade"
                | "content-length"
        ) {
            continue;
        }
        builder = builder.header(k, v);
    }
    let body_bytes = req.body.clone();
    let has_body = !body_bytes.is_empty();
    let http_req = builder.body(()).context("h2 build request")?;

    let (resp_fut, mut send_body) = h2
        .send_request(http_req, !has_body)
        .context("h2 send_request")?;
    if has_body {
        send_body
            .send_data(body_bytes, true)
            .context("h2 send_data")?;
    }
    let resp = resp_fut.await.context("h2 response")?;
    let status = resp.status().as_u16();
    let mut headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                v.to_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    let mut body_stream = resp.into_body();
    let mut body = Vec::new();
    while let Some(chunk) = body_stream.data().await {
        let c = chunk.context("h2 body chunk")?;
        let _ = body_stream.flow_control().release_capacity(c.len());
        body.extend_from_slice(&c);
    }
    // h2's `Body` doesn't surface trailers via the data() iterator;
    // we don't propagate trailers in v1.8.
    headers.retain(|(k, _)| !k.starts_with(':'));
    Ok((status, headers, Bytes::from(body)))
}
