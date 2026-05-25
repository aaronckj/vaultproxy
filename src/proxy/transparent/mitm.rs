//! MITM path: present a freshly signed leaf cert to the agent, decrypt
//! the agent's HTTP/1.1 request, hand it to an injector, forward over
//! a real TLS connection to upstream, stream the response back.
//!
//! Phase 3 ships the host_inject path. Placeholder substitution lands
//! in Phase 5.

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio_rustls::TlsAcceptor;
use tracing::info;

use crate::proxy::registry::ServiceEntry;
use crate::proxy::transparent::cert_factory::{CertFactory, LeafCert};
use crate::proxy::transparent::connect::ConnectTarget;

/// Minimal HTTP/1.1 request: method, path, headers, optional body.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

/// Run the MITM loop for one CONNECT request. v1.7.0+ inspects ALPN
/// after the TLS handshake and dispatches to either the HTTP/1.1 path
/// (existing) or the HTTP/2 path (`h2_mitm::run_h2`).
#[allow(clippy::too_many_arguments)]
pub async fn run<A>(
    mut agent_plaintext: A,
    target: ConnectTarget,
    service: Arc<ServiceEntry>,
    cert_factory: Arc<CertFactory>,
    vault: Arc<crate::vault::VaultManager>,
    vault_folder: String,
    placeholders: Arc<Vec<crate::proxy::registry::TransparentPlaceholder>>,
    audit_log: Arc<crate::security::audit_log::AuditLog>,
    state: Arc<crate::proxy::AppState>,
) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // 1. Tell the agent the tunnel is open (BEFORE the leaf cert prep
    //    so the agent will begin TLS handshake without extra latency).
    agent_plaintext
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await
        .context("write 200 to agent")?;

    // 2. Build TlsAcceptor with the leaf for this host.
    let leaf = cert_factory.leaf_for(&target.host, target.port).await?;
    let acceptor = build_acceptor(&leaf)?;
    let agent_tls = acceptor
        .accept(agent_plaintext)
        .await
        .context("TLS handshake with agent")?;

    // 3. Check which protocol got negotiated via ALPN.
    let alpn = agent_tls
        .get_ref()
        .1
        .alpn_protocol()
        .map(|b| b.to_vec())
        .unwrap_or_default();
    if alpn == b"h2" {
        return crate::proxy::transparent::h2_mitm::run_h2(
            agent_tls,
            target,
            service,
            vault,
            vault_folder,
            placeholders,
            audit_log,
            state,
        )
        .await;
    }
    // ALPN was http/1.1 (or empty — old clients that don't speak ALPN).
    run_http1(
        agent_tls,
        target,
        service,
        vault,
        vault_folder,
        placeholders,
        audit_log,
        state,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_http1<A>(
    mut agent_tls: tokio_rustls::server::TlsStream<A>,
    target: ConnectTarget,
    service: Arc<ServiceEntry>,
    vault: Arc<crate::vault::VaultManager>,
    vault_folder: String,
    placeholders: Arc<Vec<crate::proxy::registry::TransparentPlaceholder>>,
    audit_log: Arc<crate::security::audit_log::AuditLog>,
    state: Arc<crate::proxy::AppState>,
) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
{
    let start = Instant::now();

    // 3. Read the agent's HTTP/1.1 request.
    let req = read_http_request(&mut agent_tls).await?;

    // 4. Dispatch.
    let injected = match service.transparent_mode {
        crate::proxy::registry::TransparentMode::HostInject => {
            crate::proxy::transparent::inject_host::inject(
                req,
                &service,
                vault.clone(),
                &vault_folder,
                state.clone(),
            )
            .await?
        }
        crate::proxy::registry::TransparentMode::Placeholder => {
            match crate::proxy::transparent::inject_placeholder::substitute(
                req,
                &placeholders,
                vault.clone(),
                &vault_folder,
                32 * 1024 * 1024,
            )
            .await
            {
                Ok(r) => r,
                Err(e) => {
                    let code = if e
                        .downcast_ref::<crate::proxy::transparent::inject_placeholder::PlaceholderUnresolved>()
                        .is_some()
                    {
                        crate::proxy::transparent::errors::TransparentErrorCode::PlaceholderUnresolved
                    } else {
                        // Includes "resolve placeholder" vault lookup
                        // failures + any other substitute() error.
                        crate::proxy::transparent::errors::TransparentErrorCode::VaultResolutionFailed
                    };
                    crate::proxy::transparent::errors::write_error_response(
                        &mut agent_tls,
                        code,
                        &e.to_string(),
                    )
                    .await?;
                    agent_tls.shutdown().await.ok();
                    return Ok(());
                }
            }
        }
        _ => unreachable!("mitm::run only called for HostInject / Placeholder"),
    };

    // 5. Forward to upstream. v1.9.0+: try h2 first; on Ok(None) the
    //    upstream picked http/1.1 on ALPN so fall back to the existing
    //    http/1.1 forwarder. The h2 parsed response is serialised back
    //    to http/1.1 wire bytes so downstream sanitisation + the agent
    //    write path stay unchanged (agent itself is on http/1.1 here).
    let bytes_out = injected.body.len() as u64;
    let response = match crate::proxy::transparent::h2_upstream::try_h2_pooled(
        &state,
        &target,
        injected.clone(),
    )
    .await
    {
        Ok(Some((status, headers, body))) => {
            crate::proxy::transparent::h2_upstream::serialise_as_http1(status, &headers, &body)
        }
        Ok(None) => forward_to_upstream(&target, injected).await?,
        Err(e) => {
            tracing::warn!(host = %target, error = %e, "h2 upstream attempt failed; falling back to http/1.1");
            forward_to_upstream(&target, injected).await?
        }
    };
    // Optional response sanitisation. Off by default. Operators flip on
    // via --transparent-sanitize-responses / TRANSPARENT_SANITIZE_RESPONSES.
    let response = if state.transparent_sanitize_responses {
        maybe_sanitize_response(response)
    } else {
        response
    };
    let bytes_in = response.len() as u64;
    let upstream_status = parse_http_status(&response);

    // 6. Stream response back to agent.
    agent_tls.write_all(&response).await?;
    agent_tls.shutdown().await.ok();

    let duration_ms = start.elapsed().as_millis() as u64;
    let mode_str = match service.transparent_mode {
        crate::proxy::registry::TransparentMode::HostInject => "host_inject",
        crate::proxy::registry::TransparentMode::Placeholder => "placeholder",
        _ => "unknown",
    };
    audit_log.log_transparent(
        mode_str,
        &target.host,
        upstream_status,
        bytes_in,
        bytes_out,
        duration_ms,
    );

    info!(
        host = %target,
        duration_ms = duration_ms,
        mode = mode_str,
        status = ?upstream_status,
        bytes_in = bytes_in,
        bytes_out = bytes_out,
        "transparent MITM closed",
    );
    Ok(())
}

/// Parse "HTTP/1.1 NNN " prefix from a raw HTTP response buffer.
fn parse_http_status(buf: &[u8]) -> Option<u16> {
    let head = &buf[..buf.len().min(64)];
    let s = std::str::from_utf8(head).ok()?;
    let mut parts = s.split_whitespace();
    parts.next()?; // HTTP/1.1
    parts.next()?.parse().ok()
}

/// When `sanitize_responses` is on, run the upstream response body
/// through `security::sanitize::sanitize_for_wire` (strips zero-width
/// characters + dangerous markup tags). Skips non-textual content
/// types and bodies the response can't separate into head/body
/// (chunked / no terminator). Preserves the original byte ordering
/// otherwise. Rebuilds Content-Length so downstream parsers don't
/// see a stale value.
pub(crate) fn maybe_sanitize_response(buf: Bytes) -> Bytes {
    // Find end of headers.
    let sep = match find_subseq(&buf, b"\r\n\r\n") {
        Some(i) => i,
        None => return buf, // can't safely split — pass through
    };
    let (head_bytes, rest) = buf.split_at(sep + 4);
    let head = match std::str::from_utf8(head_bytes) {
        Ok(s) => s,
        Err(_) => return buf,
    };
    // Look at Content-Type to decide whether the body is textual.
    let textual = head.lines().any(|line| {
        let lower = line.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-type:") {
            let v = v.trim();
            v.starts_with("application/json")
                || v.starts_with("text/")
                || v.starts_with("application/x-www-form-urlencoded")
        } else {
            false
        }
    });
    if !textual {
        return buf;
    }
    // Refuse to touch chunked / streaming bodies — sanitising into
    // them would corrupt the framing.
    if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        return buf;
    }
    let body_str = match std::str::from_utf8(rest) {
        Ok(s) => s,
        Err(_) => return buf,
    };
    let cleaned = crate::security::sanitize::sanitize_for_wire(body_str);
    if cleaned == body_str {
        return buf;
    }
    // Rebuild head with Content-Length updated.
    let new_len = cleaned.len();
    let mut new_head = String::with_capacity(head.len());
    for line in head.lines() {
        if line.to_ascii_lowercase().starts_with("content-length:") {
            new_head.push_str(&format!("Content-Length: {new_len}\r\n"));
        } else {
            new_head.push_str(line);
            new_head.push_str("\r\n");
        }
    }
    // `head.lines()` strips the trailing blank line — re-add CRLF.
    let mut out = Vec::with_capacity(new_head.len() + new_len + 2);
    out.extend_from_slice(new_head.as_bytes());
    if !new_head.ends_with("\r\n\r\n") {
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(cleaned.as_bytes());
    Bytes::from(out)
}

fn find_subseq(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    for i in 0..=hay.len() - needle.len() {
        if &hay[i..i + needle.len()] == needle {
            return Some(i);
        }
    }
    None
}

fn build_acceptor(leaf: &LeafCert) -> Result<TlsAcceptor> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::ServerConfig;

    let mut cert_reader: &[u8] = leaf.cert_chain_pem.as_bytes();
    let cert_chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse leaf cert PEM")?;
    let mut key_reader: &[u8] = leaf.key_pem.as_bytes();
    let key = rustls_pemfile::pkcs8_private_keys(&mut key_reader)
        .next()
        .ok_or_else(|| anyhow::anyhow!("no PKCS8 key in leaf PEM"))?
        .context("parse leaf key PEM")?;

    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, PrivateKeyDer::Pkcs8(key))
        .context("rustls ServerConfig")?;
    // Advertise BOTH h2 and http/1.1 on the MITM leaf (v1.7.0+). Clients
    // that natively prefer h2 (modern reqwest, fetch in browsers) now
    // get an h2-framed channel to the proxy; clients that only do
    // http/1.1 keep their existing path. The MITM dispatcher inspects
    // the negotiated protocol after the handshake and routes to either
    // `mitm::run` (http/1.1) or `h2_mitm::run` (h2).
    //
    // Order matters: rustls picks the first overlap between server +
    // client ALPN lists. Listing "h2" first means h2-capable clients
    // get h2; http/1.1-only clients still negotiate http/1.1.
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

async fn read_http_request<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
) -> Result<HttpRequest> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;
    let mut parts = request_line.trim_end_matches("\r\n").splitn(3, ' ');
    let method = parts.next().context("HTTP method")?.to_string();
    let path = parts.next().context("HTTP path")?.to_string();
    let version = parts.next().context("HTTP version")?;
    if version != "HTTP/1.1" {
        bail!("agent sent unsupported HTTP version '{version}'");
    }
    let mut headers = Vec::new();
    let mut content_length: usize = 0;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
        let trimmed = line.trim_end_matches("\r\n");
        if let Some((k, v)) = trimmed.split_once(':') {
            let key = k.trim().to_string();
            let val = v.trim().to_string();
            if key.eq_ignore_ascii_case("content-length") {
                content_length = val.parse().unwrap_or(0);
            }
            headers.push((key, val));
        }
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).await?;
    }
    Ok(HttpRequest {
        method,
        path,
        headers,
        body: Bytes::from(body),
    })
}

/// Public re-export under a distinct name so `h2_mitm` can reuse the
/// existing upstream forwarder without exposing every helper in this
/// module. Same semantics as the private `forward_to_upstream` used by
/// `run_http1`.
pub(crate) async fn forward_to_upstream_for_h2(
    target: &ConnectTarget,
    req: HttpRequest,
) -> Result<Bytes> {
    forward_to_upstream(target, req).await
}

async fn forward_to_upstream(target: &ConnectTarget, req: HttpRequest) -> Result<Bytes> {
    // Test affordance: when VP_TRANSPARENT_TEST_HTTP=1, forward over
    // plain HTTP. Lets integration tests against wiremock (which speaks
    // HTTP, not HTTPS, by default) exercise the request-rewriting and
    // response-relay paths without standing up a TLS upstream.
    let use_http = std::env::var("VP_TRANSPARENT_TEST_HTTP").ok().as_deref() == Some("1");
    if use_http {
        return forward_plaintext(target, req).await;
    }
    forward_tls(target, req).await
}

async fn forward_tls(target: &ConnectTarget, req: HttpRequest) -> Result<Bytes> {
    use rustls::{ClientConfig, RootCertStore};
    use tokio_rustls::TlsConnector;

    let mut roots = RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    let cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(cfg));
    let server_name = target
        .host
        .clone()
        .try_into()
        .map_err(|e| anyhow::anyhow!("invalid server name '{}': {e}", target.host))?;
    let tcp = tokio::net::TcpStream::connect((target.host.as_str(), target.port)).await?;
    let mut tls = connector.connect(server_name, tcp).await?;

    let buf = serialize_request(&req, &target.host);
    tls.write_all(&buf).await?;
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await?;
    Ok(Bytes::from(response))
}

async fn forward_plaintext(target: &ConnectTarget, req: HttpRequest) -> Result<Bytes> {
    let mut tcp = tokio::net::TcpStream::connect((target.host.as_str(), target.port)).await?;
    let buf = serialize_request(&req, &target.host);
    tcp.write_all(&buf).await?;
    let mut response = Vec::new();
    tcp.read_to_end(&mut response).await?;
    Ok(Bytes::from(response))
}

fn serialize_request(req: &HttpRequest, target_host: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(req.body.len() + 1024);
    buf.extend_from_slice(format!("{} {} HTTP/1.1\r\n", req.method, req.path).as_bytes());
    let mut has_host = false;
    for (k, v) in &req.headers {
        if k.eq_ignore_ascii_case("host") {
            has_host = true;
        }
        if k.eq_ignore_ascii_case("content-length")
            || k.eq_ignore_ascii_case("connection")
            || k.eq_ignore_ascii_case("proxy-connection")
        {
            continue;
        }
        buf.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    if !has_host {
        buf.extend_from_slice(format!("Host: {target_host}\r\n").as_bytes());
    }
    // Force close so read_to_end on the upstream stream sees EOF
    // instead of hanging on a keep-alive socket. We don't pool
    // upstream connections per request anyway — every transparent
    // request opens a fresh TCP/TLS to upstream.
    buf.extend_from_slice(b"Connection: close\r\n");
    buf.extend_from_slice(format!("Content-Length: {}\r\n\r\n", req.body.len()).as_bytes());
    buf.extend_from_slice(&req.body);
    buf
}
