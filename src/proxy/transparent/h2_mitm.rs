//! HTTP/2 transparent MITM (v1.7.0+). Engages when the outer TLS
//! handshake negotiates ALPN "h2"; otherwise the dispatcher in
//! `mitm::run` falls through to `mitm::run_http1`.
//!
//! Wire shape: native h2 framing on the agent side. The upstream side
//! still speaks HTTP/1.1 — we synthesise an `HttpRequest` from the
//! decoded h2 headers + body, hand it through the existing
//! `inject_host` / `inject_placeholder` injectors, forward via the
//! shared `forward_to_upstream` helper, then re-frame the response
//! into a single h2 stream back to the agent.
//!
//! Multi-stream support: a single h2 connection can carry many
//! concurrent streams. Each accepted stream gets its own injector +
//! upstream forward in its own tokio task; streams are independent.
//! The connection runs until the agent disconnects or h2 surfaces a
//! protocol-level error.
//!
//! Limitations (will tighten in follow-up releases):
//!   * Upstream still HTTP/1.1 — we don't yet pool h2 connections
//!     to the upstream. h2-required upstreams should run the agent
//!     through the http/1.1 path instead.
//!   * Trailers + server push not supported.

#![allow(dead_code)]

use anyhow::{Context, Result};
use bytes::Bytes;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;
use tracing::{info, warn};

use crate::proxy::registry::ServiceEntry;
use crate::proxy::transparent::connect::ConnectTarget;
use crate::proxy::transparent::mitm::HttpRequest;

#[allow(clippy::too_many_arguments)]
pub async fn run_h2<A>(
    agent_tls: TlsStream<A>,
    target: ConnectTarget,
    service: Arc<ServiceEntry>,
    vault: Arc<crate::vault::VaultManager>,
    vault_folder: String,
    placeholders: Arc<Vec<crate::proxy::registry::TransparentPlaceholder>>,
    audit_log: Arc<crate::security::audit_log::AuditLog>,
    state: Arc<crate::proxy::AppState>,
) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut conn = h2::server::handshake(agent_tls)
        .await
        .context("h2 server handshake")?;

    info!(
        host = %target,
        "h2 MITM connection established",
    );

    while let Some(stream) = conn.accept().await {
        let (req, mut respond) = match stream {
            Ok(p) => p,
            Err(e) => {
                warn!(host = %target, error = %e, "h2 accept stream failed");
                continue;
            }
        };

        let target = target.clone();
        let service = service.clone();
        let vault = vault.clone();
        let vault_folder = vault_folder.clone();
        let placeholders = placeholders.clone();
        let audit_log = audit_log.clone();
        let state = state.clone();

        tokio::spawn(async move {
            let start = Instant::now();
            // 1. Drain the h2 request body so we can convert into the
            //    HttpRequest shape the existing injectors expect.
            let (parts, mut body) = req.into_parts();
            // SEC/DoS: cap the agent-controlled request body held in memory.
            const MAX_H2_BODY_BYTES: usize = 256 * 1024 * 1024;
            let mut body_bytes = Vec::new();
            while let Some(chunk) = body.data().await {
                match chunk {
                    Ok(c) => {
                        let _ = body.flow_control().release_capacity(c.len());
                        if body_bytes.len() + c.len() > MAX_H2_BODY_BYTES {
                            warn!(host = %target, "h2 request body exceeded cap, dropping stream");
                            return;
                        }
                        body_bytes.extend_from_slice(&c);
                    }
                    Err(e) => {
                        warn!(host = %target, error = %e, "h2 body read failed");
                        return;
                    }
                }
            }

            // 2. Build the HttpRequest from h2 parts + body.
            let method = parts.method.to_string();
            let path = parts
                .uri
                .path_and_query()
                .map(|p| p.to_string())
                .unwrap_or_else(|| "/".to_string());
            let mut headers: Vec<(String, String)> = parts
                .headers
                .iter()
                .filter(|(k, _)| {
                    // h2 pseudo-headers (`:method`, `:path`, `:scheme`,
                    // `:authority`) aren't in `parts.headers` per the
                    // http crate's split, so this is just a defensive
                    // filter for any name beginning with a colon that
                    // sneaks through downstream serialisation.
                    !k.as_str().starts_with(':')
                })
                .map(|(k, v)| {
                    (
                        k.as_str().to_string(),
                        v.to_str().unwrap_or_default().to_string(),
                    )
                })
                .collect();
            // h2 carries Host in :authority; the http/1.1 forwarder
            // expects a Host header. Re-introduce it from :authority.
            if let Some(authority) = parts.uri.authority() {
                headers.push(("host".to_string(), authority.to_string()));
            }
            let req = HttpRequest {
                method,
                path,
                headers,
                body: Bytes::from(body_bytes),
            };

            // 3. Hand to injector (same code path as http/1.1).
            let injected = match service.transparent_mode {
                crate::proxy::registry::TransparentMode::HostInject => {
                    match crate::proxy::transparent::inject_host::inject(
                        req,
                        &service,
                        vault.clone(),
                        &vault_folder,
                        state.clone(),
                    )
                    .await
                    {
                        Ok(r) => r,
                        Err(e) => {
                            warn!(host = %target, error = %e, "h2 host_inject failed");
                            return;
                        }
                    }
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
                            warn!(host = %target, error = %e, "h2 placeholder substitute failed");
                            return;
                        }
                    }
                }
                _ => {
                    warn!(
                        host = %target,
                        mode = ?service.transparent_mode,
                        "h2 stream reached run_h2 with unsupported transparent_mode",
                    );
                    return;
                }
            };

            // 4. Forward to upstream. Try h2 first (v1.8.0+); fall back
            //    to http/1.1 when the upstream picks http/1.1 on ALPN.
            let bytes_out = injected.body.len() as u64;
            let (status, hdrs, body, trailers) =
                match crate::proxy::transparent::h2_upstream::try_h2_pooled(
                    &state,
                    &target,
                    injected.clone(),
                )
                .await
                {
                    Ok(Some((s, h, b, t))) => (s, h, b.to_vec(), t),
                    Ok(None) => {
                        // Upstream picked http/1.1; do the http/1.1 path.
                        // No trailers when upstream itself is http/1.1.
                        let response_bytes =
                            match crate::proxy::transparent::mitm::forward_to_upstream_for_h2(
                                &target, injected,
                            )
                            .await
                            {
                                Ok(b) => b,
                                Err(e) => {
                                    warn!(
                                        host = %target,
                                        error = %e,
                                        "h2 upstream http/1.1 forward failed",
                                    );
                                    return;
                                }
                            };
                        match parse_http1_response(&response_bytes) {
                            Some((s, h, b)) => (s, h, b, None),
                            None => {
                                warn!(
                                    host = %target,
                                    "h2 unable to parse upstream http/1.1 response",
                                );
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        warn!(host = %target, error = %e, "h2 upstream forward failed");
                        return;
                    }
                };

            // 6. Build the h2 response. h2 forbids the connection-
            //    specific http/1.1 headers (Connection, Keep-Alive,
            //    Transfer-Encoding, Proxy-Connection, Upgrade) on the
            //    response; strip them before send_response.
            let mut h2_resp = http::Response::builder().status(status);
            for (k, v) in &hdrs {
                let lk = k.to_ascii_lowercase();
                if matches!(
                    lk.as_str(),
                    "connection"
                        | "keep-alive"
                        | "proxy-connection"
                        | "transfer-encoding"
                        | "upgrade"
                ) {
                    continue;
                }
                h2_resp = h2_resp.header(k, v);
            }
            let h2_resp = match h2_resp.body(()) {
                Ok(r) => r,
                Err(e) => {
                    warn!(host = %target, error = %e, "h2 response builder failed");
                    return;
                }
            };

            // end_of_stream is true only when there are NO body bytes
            // AND NO trailers — otherwise we still need to send those
            // frames after the HEADERS.
            let has_trailers = trailers.as_ref().is_some_and(|t| !t.is_empty());
            let end_of_stream = body.is_empty() && !has_trailers;
            let mut send = match respond.send_response(h2_resp, end_of_stream) {
                Ok(s) => s,
                Err(e) => {
                    warn!(host = %target, error = %e, "h2 send_response failed");
                    return;
                }
            };
            if !body.is_empty() {
                // end_stream on DATA = true only if no trailers follow.
                let body_end = !has_trailers;
                if let Err(e) = send.send_data(Bytes::from(body.clone()), body_end) {
                    warn!(host = %target, error = %e, "h2 send_data failed");
                    return;
                }
            }
            if let Some(tr_pairs) = trailers {
                if !tr_pairs.is_empty() {
                    let mut tr_map = http::HeaderMap::new();
                    for (k, v) in &tr_pairs {
                        // Defence-in-depth: a malicious or buggy upstream
                        // could send pseudo-header names (`:`-prefixed) or
                        // h2-forbidden connection-specific names inside
                        // TRAILERS. RFC 9113 §8.1 / §8.2 forbid both;
                        // h2-the-crate enforces this on send, but failing
                        // here would abort the stream after we've already
                        // sent the response body. Drop them quietly.
                        let lk = k.to_ascii_lowercase();
                        if lk.starts_with(':')
                            || matches!(
                                lk.as_str(),
                                "connection"
                                    | "keep-alive"
                                    | "proxy-connection"
                                    | "transfer-encoding"
                                    | "upgrade"
                                    | "te"
                                    | "trailer"
                                    | "host"
                                    | "content-length"
                            )
                        {
                            continue;
                        }
                        if let (Ok(name), Ok(val)) = (
                            http::HeaderName::from_bytes(k.as_bytes()),
                            http::HeaderValue::from_str(v),
                        ) {
                            tr_map.insert(name, val);
                        }
                    }
                    if !tr_map.is_empty() {
                        if let Err(e) = send.send_trailers(tr_map) {
                            warn!(host = %target, error = %e, "h2 send_trailers failed");
                            return;
                        }
                    }
                }
            }

            let duration_ms = start.elapsed().as_millis() as u64;
            audit_log.log_transparent(
                "host_inject",
                &target.host,
                Some(status),
                body.len() as u64,
                bytes_out,
                duration_ms,
            );
        });
    }

    Ok(())
}

/// Parsed http/1.1 response shape: (status, headers, body).
type ParsedHttp1 = (u16, Vec<(String, String)>, Vec<u8>);

/// Parse a minimal HTTP/1.1 response wire-format buffer into
/// `(status, headers, body)`. Returns `None` if the response can't
/// be split at the first `\r\n\r\n` boundary or the status line is
/// malformed.
fn parse_http1_response(buf: &[u8]) -> Option<ParsedHttp1> {
    let sep = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let (head, rest) = buf.split_at(sep);
    let body = rest.get(4..).unwrap_or_default().to_vec();
    let head_str = std::str::from_utf8(head).ok()?;
    let mut lines = head_str.split("\r\n");
    let status_line = lines.next()?;
    let mut parts = status_line.split_whitespace();
    let _http_version = parts.next()?; // HTTP/1.1
    let status: u16 = parts.next()?.parse().ok()?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Some((status, headers, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(buf: &[u8]) -> ParsedHttp1 {
        parse_http1_response(buf).expect("parse")
    }

    #[test]
    fn parse_status_and_headers() {
        let (status, hdrs, body) = raw(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\nok",
        );
        assert_eq!(status, 200);
        assert!(hdrs
            .iter()
            .any(|(k, v)| k == "Content-Type" && v == "application/json"));
        assert_eq!(body, b"ok");
    }

    #[test]
    fn parse_204_no_body() {
        let (status, _hdrs, body) = raw(b"HTTP/1.1 204 No Content\r\n\r\n");
        assert_eq!(status, 204);
        assert!(body.is_empty());
    }

    #[test]
    fn parse_returns_none_on_malformed() {
        assert!(parse_http1_response(b"garbage").is_none());
        assert!(parse_http1_response(b"HTTP/1.1\r\n\r\n").is_none());
    }
}
