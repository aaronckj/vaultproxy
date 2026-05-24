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
pub mod errors;
pub mod init;
pub mod inject_host;
pub mod inject_placeholder;
pub mod mitm;
pub mod passthrough;
pub mod registry;
pub mod uds_listener;

/// Spawn the transparent listener. Returns immediately; the listener task
/// runs in the background until the runtime shuts down.
///
/// Bind failures are returned to the caller so startup can fail fast with
/// a clear error rather than silently leaving the listener offline.
/// Policy for hosts that aren't in any `[[service]]` block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnregisteredPolicy {
    /// Tunnel TCP unchanged (default).
    Passthrough,
    /// Reject with 502 + transparent_error_code = "unregistered_host_blocked".
    Allowlist,
}

impl UnregisteredPolicy {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        Ok(match s {
            "passthrough" => Self::Passthrough,
            "allowlist" => Self::Allowlist,
            other => anyhow::bail!(
                "unknown transparent-unregistered-policy '{other}' — valid: passthrough | allowlist"
            ),
        })
    }
}

pub async fn spawn_listener_with_ca(
    addr: SocketAddr,
    state: Arc<AppState>,
    ca: Arc<crate::tls::ca::TransparentCa>,
) -> Result<ListenerHandles> {
    spawn_listener_with_policy(addr, state, ca, UnregisteredPolicy::Passthrough).await
}

/// Bundle returned by `spawn_listener_with_policy` so main.rs can
/// stash the live cells on AppState for the SIGHUP rebuild handler.
pub type ListenerHandles = (
    registry::TransparentRegistryCell,
    Arc<tokio::sync::RwLock<Vec<crate::proxy::registry::TransparentPlaceholder>>>,
);

pub async fn spawn_listener_with_policy(
    addr: SocketAddr,
    state: Arc<AppState>,
    ca: Arc<crate::tls::ca::TransparentCa>,
    unregistered_policy: UnregisteredPolicy,
) -> Result<ListenerHandles> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("transparent listener failed to bind {addr}: {e}"))?;
    let cert_factory = Arc::new(cert_factory::CertFactory::new(ca, 1024));

    // Build initial registry snapshot. SIGHUP rebuild (rebuild_from_state)
    // updates these cells in place, so AppState.transparent_registry +
    // AppState.transparent_placeholders need to point at THESE cells —
    // not fresh copies.
    let (snapshot, placeholder_vec) = {
        let reg = state.registry.read().await;
        (
            registry::TransparentRegistry::build(&reg)?,
            reg.transparent_placeholders().to_vec(),
        )
    };
    let tr_registry: registry::TransparentRegistryCell =
        Arc::new(tokio::sync::RwLock::new(snapshot));
    let placeholders: Arc<
        tokio::sync::RwLock<Vec<crate::proxy::registry::TransparentPlaceholder>>,
    > = Arc::new(tokio::sync::RwLock::new(placeholder_vec));
    let tr_registry_handle = tr_registry.clone();
    let placeholders_handle = placeholders.clone();

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
                    let ph_cell = placeholders.clone();
                    let policy = unregistered_policy;
                    tokio::spawn(async move {
                        // Snapshot the placeholder Vec under a short read
                        // lock so SIGHUP rebuilds can swap the list while
                        // in-flight requests work from their captured
                        // snapshot.
                        let ph_snapshot = Arc::new(ph_cell.read().await.clone());
                        if let Err(e) =
                            handle_connection(stream, peer, state, cf, tr, ph_snapshot, policy)
                                .await
                        {
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

    Ok((tr_registry_handle, placeholders_handle))
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
    spawn_listener_with_ca(addr, state, ca).await?;
    Ok(())
}

/// SIGHUP rebuild entry point. Rebuilds the TransparentRegistry from
/// the AppState's current `state.registry` snapshot and refreshes the
/// placeholder list in place. Existing in-flight requests work from
/// their captured snapshot — only new accepts see the swap.
pub async fn rebuild_from_state(state: &AppState) -> Result<()> {
    let registry_cell = state.transparent_registry.read().await.clone();
    let placeholders_cell = state.transparent_placeholders.read().await.clone();
    let (registry_cell, placeholders_cell) = match (registry_cell, placeholders_cell) {
        (Some(r), Some(p)) => (r, p),
        _ => return Ok(()), // listener never spawned; nothing to rebuild
    };
    let reg = state.registry.read().await;
    let new_snapshot = registry::TransparentRegistry::build(&reg)?;
    let new_placeholders = reg.transparent_placeholders().to_vec();
    drop(reg);
    *registry_cell.write().await = new_snapshot;
    *placeholders_cell.write().await = new_placeholders;
    tracing::info!("SIGHUP: transparent registry + placeholders rebuilt");
    Ok(())
}

async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    state: Arc<AppState>,
    cert_factory: Arc<cert_factory::CertFactory>,
    tr_registry: registry::TransparentRegistryCell,
    placeholders: Arc<Vec<crate::proxy::registry::TransparentPlaceholder>>,
    unregistered_policy: UnregisteredPolicy,
) -> Result<()> {
    let target = match connect::read_connect_line(&mut stream).await {
        Ok(t) => t,
        Err(e) => {
            return errors::write_error_response(
                &mut stream,
                errors::TransparentErrorCode::MalformedConnect,
                &e.to_string(),
            )
            .await;
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
            let audit = state.audit_log.clone();
            if let Err(e) = mitm::run(
                stream,
                target.clone(),
                service,
                cert_factory,
                vault,
                folder,
                placeholders,
                audit,
            )
            .await
            {
                warn!(target = %target, error = %e, "MITM error");
            }
        }
        _ => {
            // Off / Passthrough / unregistered. Allowlist policy blocks
            // unregistered hosts; everything else tunnels.
            if svc.is_none() && unregistered_policy == UnregisteredPolicy::Allowlist {
                let msg =
                    format!("host {target} has no [[service]] block; allowlist policy active");
                return errors::write_error_response(
                    &mut stream,
                    errors::TransparentErrorCode::UnregisteredHostBlocked,
                    &msg,
                )
                .await;
            }
            let audit = state.audit_log.clone();
            if let Err(e) =
                passthrough::tunnel_with_audit(stream, target.clone(), Some(audit)).await
            {
                warn!(target = %target, error = %e, "passthrough tunnel error");
            }
        }
    }
    Ok(())
}
