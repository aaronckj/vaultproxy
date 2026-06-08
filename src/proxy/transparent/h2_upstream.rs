//! Upstream HTTP/2 forwarder. Tries TLS+ALPN h2 against `target`; on
//! success runs a single h2 request and returns the parsed response.
//! When the upstream picks http/1.1 (or h2 negotiation fails for a
//! transport reason), returns `Ok(None)` so the caller can fall back
//! to the existing http/1.1 forwarder.
//!
//! Connection pool (v1.10.0+): `AppState.h2_upstream_pool` holds one
//! `SendRequest<Bytes>` per `(host, port)`. `SendRequest` is `Clone`
//! and thread-safe, so multiple in-flight requests against the same
//! upstream share one h2 connection (one frame multiplexer, one
//! flow-control budget). On send error (GOAWAY / RST_STREAM / TCP
//! close) the entry is evicted and the next request re-handshakes.
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

/// Parsed h2 response shape: (status, headers, body, trailers).
/// `trailers` is `None` when the upstream sent no TRAILERS frame.
/// gRPC clients put `grpc-status` / `grpc-message` here, so the
/// trailer pass-through (v1.11.0+) is required for gRPC end-to-end.
pub type ParsedH2Response = (
    u16,
    Vec<(String, String)>,
    Bytes,
    Option<Vec<(String, String)>>,
);

/// Serialise a parsed h2 response into raw HTTP/1.1 wire bytes for the
/// http/1.1 MITM path (agent speaks HTTP/1.1; upstream spoke h2). The
/// status line uses a fixed reason phrase ("OK" for 2xx, "Error"
/// otherwise) since h2 doesn't carry one. `Content-Length` is recomputed
/// from `body`. Connection-specific h2-forbidden headers
/// (Connection / Keep-Alive / Transfer-Encoding / Proxy-Connection /
/// Upgrade) are dropped; h2 wouldn't carry them anyway.
pub fn serialise_as_http1(
    status: u16,
    headers: &[(String, String)],
    body: &Bytes,
    trailers: Option<&[(String, String)]>,
) -> Bytes {
    if trailers.is_some_and(|t| !t.is_empty()) {
        tracing::warn!(
            "h2-to-http/1.1 conversion: upstream returned trailers but the agent is on \
             http/1.1; trailers dropped (gRPC over http/1.1 not supported by the http/1.1 \
             MITM path).",
        );
    }
    let reason = if (200..300).contains(&status) {
        "OK"
    } else if (300..400).contains(&status) {
        "Redirect"
    } else {
        "Error"
    };
    let mut buf: Vec<u8> = Vec::with_capacity(body.len() + 512);
    buf.extend_from_slice(format!("HTTP/1.1 {status} {reason}\r\n").as_bytes());
    let mut wrote_content_length = false;
    for (k, v) in headers {
        let lk = k.to_ascii_lowercase();
        if matches!(
            lk.as_str(),
            "connection"
                | "keep-alive"
                | "proxy-connection"
                | "transfer-encoding"
                | "upgrade"
                | "content-length"
        ) {
            continue;
        }
        buf.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
        if lk == "content-length" {
            wrote_content_length = true;
        }
    }
    if !wrote_content_length {
        buf.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }
    buf.extend_from_slice(b"Connection: close\r\n\r\n");
    buf.extend_from_slice(body);
    Bytes::from(buf)
}

/// Attempt to send `req` over h2 to `target`. Returns:
///   * `Ok(Some(parsed))` if the upstream negotiated h2 and responded.
///   * `Ok(None)` if the upstream picked http/1.1 on ALPN (caller
///     should fall back).
///   * `Err(e)` for network/TLS/protocol errors.
pub async fn try_h2(target: &ConnectTarget, req: HttpRequest) -> Result<Option<ParsedH2Response>> {
    try_h2_inner(target, req, None).await
}

/// Pool-aware variant: reuses a cached `SendRequest<Bytes>` per
/// `(host, port)` from `AppState.h2_upstream_pool` when present;
/// stores the handshake result on first miss. Evicts on send error
/// so the next caller re-handshakes against a healthy upstream.
pub async fn try_h2_pooled(
    state: &crate::proxy::AppState,
    target: &ConnectTarget,
    req: HttpRequest,
) -> Result<Option<ParsedH2Response>> {
    try_h2_inner(target, req, Some(&state.h2_upstream_pool)).await
}

type H2Pool = dashmap::DashMap<(String, u16), h2::client::SendRequest<Bytes>>;

async fn try_h2_inner(
    target: &ConnectTarget,
    req: HttpRequest,
    pool: Option<&H2Pool>,
) -> Result<Option<ParsedH2Response>> {
    let force_h2c = std::env::var("VP_TRANSPARENT_TEST_FORCE_H2")
        .ok()
        .as_deref()
        == Some("1");

    // Pool hit path: try the cached SendRequest first. On any send
    // error, evict + fall through to a fresh handshake.
    if let Some(p) = pool {
        let key = (target.host.clone(), target.port);
        let cached: Option<h2::client::SendRequest<Bytes>> = p.get(&key).map(|e| e.clone());
        if let Some(send_req) = cached {
            match send_request_on(send_req, target, &req).await {
                Ok(parsed) => return Ok(Some(parsed)),
                Err(e) => {
                    tracing::debug!(
                        host = %target,
                        error = %e,
                        "pooled h2 send failed; evicting and reconnecting",
                    );
                    p.remove(&key);
                    // Fall through to fresh handshake below.
                }
            }
        }
    }

    if force_h2c {
        let send_req = handshake_plain(target).await?;
        let parsed = send_request_on(send_req.clone(), target, &req).await?;
        if let Some(p) = pool {
            p.insert((target.host.clone(), target.port), send_req);
        }
        return Ok(Some(parsed));
    }
    if std::env::var("VP_TRANSPARENT_TEST_HTTP").ok().as_deref() == Some("1") {
        return Ok(None);
    }
    match handshake_tls(target).await? {
        Some(send_req) => {
            let parsed = send_request_on(send_req.clone(), target, &req).await?;
            if let Some(p) = pool {
                p.insert((target.host.clone(), target.port), send_req);
            }
            Ok(Some(parsed))
        }
        None => Ok(None),
    }
}

/// TLS handshake + h2 client handshake. Returns `Some(SendRequest)` when
/// the upstream negotiated h2; `None` when it picked http/1.1.
async fn handshake_tls(target: &ConnectTarget) -> Result<Option<h2::client::SendRequest<Bytes>>> {
    use rustls::{ClientConfig, RootCertStore};
    use tokio_rustls::TlsConnector;

    let mut roots = RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    let mut cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
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
        return Ok(None);
    }
    let send_req = drive_handshake(tls).await?;
    Ok(Some(send_req))
}

/// Plain-TCP h2c handshake (test-only, gated by `VP_TRANSPARENT_TEST_FORCE_H2`).
async fn handshake_plain(target: &ConnectTarget) -> Result<h2::client::SendRequest<Bytes>> {
    let tcp = tokio::net::TcpStream::connect((target.host.as_str(), target.port)).await?;
    drive_handshake(tcp).await
}

async fn drive_handshake<IO>(io: IO) -> Result<h2::client::SendRequest<Bytes>>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (h2, connection) = h2::client::handshake(io)
        .await
        .context("h2 client handshake")?;
    // Spawn the connection driver. Stays alive until the connection
    // closes (GOAWAY, TCP RST, EOF). After that the cached
    // SendRequest's send_request calls start failing and the pool
    // entry gets evicted by the caller.
    tokio::spawn(async move {
        let _ = connection.await;
    });
    h2.ready().await.context("h2 client ready")
}

/// Send a single h2 request over `send_req` and return the parsed
/// response. The `SendRequest` is consumed for the duration of the
/// call but may be cloned by the caller before passing in if it
/// expects to issue more requests on the same connection.
async fn send_request_on(
    mut send_req: h2::client::SendRequest<Bytes>,
    target: &ConnectTarget,
    req: &HttpRequest,
) -> Result<ParsedH2Response> {
    // Wait until the connection has capacity (poll_ready cycle).
    let send_req = std::future::poll_fn(|cx| send_req.poll_ready(cx))
        .await
        .map(|_| send_req)
        .context("h2 SendRequest poll_ready")?;
    let mut send_req = send_req;

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

    let (resp_fut, mut send_body) = send_req
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
    // SEC/DoS: cap the upstream-controlled response body held in memory.
    const MAX_H2_BODY_BYTES: usize = 256 * 1024 * 1024;
    let mut body = Vec::new();
    while let Some(chunk) = body_stream.data().await {
        let c = chunk.context("h2 body chunk")?;
        let _ = body_stream.flow_control().release_capacity(c.len());
        if body.len() + c.len() > MAX_H2_BODY_BYTES {
            anyhow::bail!("upstream h2 response body exceeded {MAX_H2_BODY_BYTES} bytes");
        }
        body.extend_from_slice(&c);
    }
    // Drain trailers if any. Returns None when no TRAILERS frame
    // arrived; gRPC always sends them with grpc-status + grpc-message.
    let trailers = match body_stream.trailers().await.context("h2 trailers")? {
        Some(map) => {
            let pairs: Vec<(String, String)> = map
                .iter()
                .map(|(k, v)| {
                    (
                        k.as_str().to_string(),
                        v.to_str().unwrap_or_default().to_string(),
                    )
                })
                .collect();
            Some(pairs)
        }
        None => None,
    };
    headers.retain(|(k, _)| !k.starts_with(':'));
    Ok((status, headers, Bytes::from(body), trailers))
}
