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

pub mod connect;
pub mod passthrough;

/// Spawn the transparent listener. Returns immediately; the listener task
/// runs in the background until the runtime shuts down.
///
/// Bind failures are returned to the caller so startup can fail fast with
/// a clear error rather than silently leaving the listener offline.
pub async fn spawn_listener(addr: SocketAddr, state: Arc<AppState>) -> Result<()> {
    let listener = TcpListener::bind(addr).await.map_err(|e| {
        anyhow::anyhow!("transparent listener failed to bind {addr}: {e}")
    })?;

    info!(
        addr = %addr,
        "transparent HTTPS_PROXY listener started — agents set HTTPS_PROXY=http://{addr}"
    );

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let state = state.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, peer, state).await {
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

async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    _state: Arc<AppState>,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    // Phase 1 stub: read the CONNECT line, then reject everything with 501.
    // Real dispatch (passthrough vs MITM) lands in Task 1.3 / Phase 2.
    let target = connect::read_connect_line(&mut stream).await?;
    info!(peer = %peer, target = %target, "transparent CONNECT received");

    stream
        .write_all(b"HTTP/1.1 501 Not Implemented\r\nContent-Type: application/json\r\n\r\n{\"ok\":false,\"error\":\"transparent listener stub - Phase 1\",\"transparent_error_code\":\"not_implemented\"}\n")
        .await?;
    Ok(())
}
