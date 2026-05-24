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
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tracing::info;

use crate::proxy::registry::ServiceEntry;
use crate::proxy::transparent::cert_factory::{CertFactory, LeafCert};
use crate::proxy::transparent::connect::ConnectTarget;

/// Minimal HTTP/1.1 request: method, path, headers, optional body.
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

/// Run the MITM loop for one CONNECT request.
pub async fn run(
    mut agent_plaintext: TcpStream,
    target: ConnectTarget,
    service: Arc<ServiceEntry>,
    cert_factory: Arc<CertFactory>,
    vault: Arc<crate::vault::VaultManager>,
    vault_folder: String,
) -> Result<()> {
    let start = Instant::now();

    // 1. Tell the agent the tunnel is open (BEFORE the leaf cert prep
    //    so the agent will begin TLS handshake without extra latency).
    agent_plaintext
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await
        .context("write 200 to agent")?;

    // 2. Build TlsAcceptor with the leaf for this host.
    let leaf = cert_factory.leaf_for(&target.host, target.port).await?;
    let acceptor = build_acceptor(&leaf)?;
    let mut agent_tls = acceptor
        .accept(agent_plaintext)
        .await
        .context("TLS handshake with agent")?;

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
            )
            .await?
        }
        crate::proxy::registry::TransparentMode::Placeholder => {
            // Phase 5.
            bail!("placeholder mode not yet implemented (Phase 5)");
        }
        _ => unreachable!("mitm::run only called for HostInject / Placeholder"),
    };

    // 5. Forward to upstream over real TLS.
    let response = forward_to_upstream(&target, injected).await?;

    // 6. Stream response back to agent.
    agent_tls.write_all(&response).await?;
    agent_tls.shutdown().await.ok();

    info!(
        host = %target,
        duration_ms = start.elapsed().as_millis() as u64,
        mode = ?service.transparent_mode,
        "transparent MITM closed",
    );
    Ok(())
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

    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, PrivateKeyDer::Pkcs8(key))
        .context("rustls ServerConfig")?;
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
    let tcp = TcpStream::connect((target.host.as_str(), target.port)).await?;
    let mut tls = connector.connect(server_name, tcp).await?;

    let buf = serialize_request(&req, &target.host);
    tls.write_all(&buf).await?;
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await?;
    Ok(Bytes::from(response))
}

async fn forward_plaintext(target: &ConnectTarget, req: HttpRequest) -> Result<Bytes> {
    let mut tcp = TcpStream::connect((target.host.as_str(), target.port)).await?;
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
