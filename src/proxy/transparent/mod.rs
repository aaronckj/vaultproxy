//! Transparent HTTPS_PROXY mode. See docs/superpowers/specs/2026-05-24-transparent-https-proxy-design.md
//!
//! Module is compiled only when the `transparent` Cargo feature is enabled.
//! Operators opt in via `cargo build --features transparent` or
//! `docker build --build-arg FEATURES=transparent`. When off (default
//! through v1.1) the binary has zero new behaviour — no listener, no CA
//! cert, no new CLI flags.

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use crate::proxy::AppState;

pub mod cert_factory;
pub mod connect;
pub mod init;
pub mod inject_host;
pub mod inject_placeholder;
pub mod mitm;
pub mod passthrough;
pub mod registry;

/// Spawn the transparent listener. Returns immediately; the listener task
/// runs in the background until the runtime shuts down.
///
/// Bind failures are returned to the caller so startup can fail fast with
/// a clear error rather than silently leaving the listener offline.
pub async fn spawn_listener_with_ca(
    addr: SocketAddr,
    state: Arc<AppState>,
    ca: Arc<crate::tls::ca::TransparentCa>,
) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("transparent listener failed to bind {addr}: {e}"))?;
    let cert_factory = Arc::new(cert_factory::CertFactory::new(ca, 1024));

    // Build initial registry snapshot. SIGHUP reload (Phase 6) updates
    // this cell in place.
    let (snapshot, placeholder_vec) = {
        let reg = state.registry.read().await;
        (
            registry::TransparentRegistry::build(&reg)?,
            reg.transparent_placeholders().to_vec(),
        )
    };
    let tr_registry: registry::TransparentRegistryCell =
        Arc::new(tokio::sync::RwLock::new(snapshot));
    let placeholders = Arc::new(placeholder_vec);

    info!(
        addr = %addr,
        "transparent HTTPS_PROXY listener started — agents set HTTPS_PROXY=http://{addr}"
    );

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let state = state.clone();
                    let cf = cert_factory.clone();
                    let tr = tr_registry.clone();
                    let ph = placeholders.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, peer, state, cf, tr, ph).await {
                            warn!(
                                peer = %peer,
                                error = %e,
                                "transparent connection ended with error",
                            );
                        }
                    });
                }
                Err(e) => {
                    error!(error = %e, "transparent listener accept failed");
                }
            }
        }
    });

    Ok(())
}

/// Phase-1 entry point (CA-less). Kept until callers migrate to
/// `spawn_listener_with_ca`. Tests that don't need MITM continue to use
/// this. Internally constructs a throwaway CA so `cert_factory` has a
/// dependency satisfied even though it isn't exercised in passthrough.
/// Used only by integration tests; production main.rs goes through
/// `spawn_listener_with_ca` directly.
#[allow(dead_code)]
pub async fn spawn_listener(addr: SocketAddr, state: Arc<AppState>) -> Result<()> {
    let ca = Arc::new(crate::tls::ca::TransparentCa::generate(
        "test-spawn-listener",
    )?);
    spawn_listener_with_ca(addr, state, ca).await
}

async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    state: Arc<AppState>,
    cert_factory: Arc<cert_factory::CertFactory>,
    tr_registry: registry::TransparentRegistryCell,
    placeholders: Arc<Vec<crate::proxy::registry::TransparentPlaceholder>>,
) -> Result<()> {
    let target = match connect::read_connect_line(&mut stream).await {
        Ok(t) => t,
        Err(e) => {
            return reply_error(&mut stream, 400, "malformed_connect", &e.to_string()).await;
        }
    };
    info!(peer = %peer, target = %target, "transparent CONNECT received");

    let svc = tr_registry.read().await.lookup(&target.host, target.port);
    use crate::proxy::registry::TransparentMode;
    match svc.as_ref().map(|s| s.transparent_mode) {
        Some(TransparentMode::HostInject) | Some(TransparentMode::Placeholder) => {
            let service = svc.unwrap();
            let vault = state.vault.clone();
            let folder = state.vault_folder.clone();
            if let Err(e) = mitm::run(
                stream,
                target.clone(),
                service,
                cert_factory,
                vault,
                folder,
                placeholders,
            )
            .await
            {
                warn!(target = %target, error = %e, "MITM error");
            }
        }
        _ => {
            // Off / Passthrough / unregistered: tunnel through.
            if let Err(e) = passthrough::tunnel(stream, target.clone()).await {
                warn!(target = %target, error = %e, "passthrough tunnel error");
            }
        }
    }
    Ok(())
}

async fn reply_error<S: tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    status: u16,
    code: &str,
    message: &str,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let reason = match status {
        400 => "Bad Request",
        502 => "Bad Gateway",
        504 => "Gateway Timeout",
        _ => "Error",
    };
    let body = serde_json::json!({
        "ok": false,
        "error": message,
        "transparent_error_code": code,
    });
    let body_bytes = serde_json::to_vec(&body)?;
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body_bytes.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&body_bytes).await?;
    Ok(())
}
