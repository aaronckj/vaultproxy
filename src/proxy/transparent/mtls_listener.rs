//! Optional TLS-fronted listener with mutual client-certificate auth.
//!
//! The plain TCP listener trusts loopback callers only. For deployments
//! that want to expose the transparent listener beyond loopback (e.g.
//! over Tailscale to other hosts in the same tailnet), this variant
//! requires the agent to present a client cert signed by an operator-
//! supplied CA, AND to trust the proxy's server cert. The TLS-protected
//! channel carries the same plaintext CONNECT + per-host MITM flow as
//! the TCP listener — the only difference is the outer TLS jacket.
//!
//! Standard HTTPS_PROXY clients (curl with `--proxy-cacert`/`--proxy-cert`/
//! `--proxy-key`, reqwest with `Proxy::https()`) speak this protocol.
//! Clients that don't support proxy-side TLS won't work here; those
//! callers should use the loopback TCP or UDS listener instead.

#![allow(dead_code)]

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

use crate::proxy::AppState;

use super::cert_factory::CertFactory;
use super::registry::{TransparentRegistry, TransparentRegistryCell};
use super::UnregisteredPolicy;

/// Material for the outer mTLS jacket: the server cert+key the proxy
/// presents to the agent, plus the CA used to verify agent client
/// certs. Constructed by main.rs from CLI flags.
pub struct MtlsMaterial {
    pub server_cert_pem: String,
    pub server_key_pem: String,
    pub client_ca_pem: String,
}

/// Spawn the mTLS-fronted listener. Returns the same registry/placeholder
/// cells as `spawn_listener_with_policy` so main.rs can register them on
/// AppState for the SIGHUP rebuild path.
pub async fn spawn_mtls_listener(
    addr: SocketAddr,
    state: Arc<AppState>,
    ca: Arc<crate::tls::ca::TransparentCa>,
    mtls: MtlsMaterial,
    unregistered_policy: UnregisteredPolicy,
) -> Result<super::ListenerHandles> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("mtls listener bind {addr}"))?;

    let acceptor = Arc::new(build_mtls_acceptor(&mtls)?);
    let cert_factory = Arc::new(CertFactory::new(ca, 1024));

    let (snapshot, placeholder_vec) = {
        let reg = state.registry.read().await;
        (
            TransparentRegistry::build(&reg)?,
            reg.transparent_placeholders().to_vec(),
        )
    };
    let tr_registry: TransparentRegistryCell = Arc::new(tokio::sync::RwLock::new(snapshot));
    let placeholders: Arc<
        tokio::sync::RwLock<Vec<crate::proxy::registry::TransparentPlaceholder>>,
    > = Arc::new(tokio::sync::RwLock::new(placeholder_vec));
    let tr_registry_handle = tr_registry.clone();
    let placeholders_handle = placeholders.clone();

    info!(
        addr = %addr,
        "transparent mTLS listener started — agents must present a client cert signed by the \
         configured CA",
    );

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((tcp, peer)) => {
                    let acceptor = acceptor.clone();
                    let state = state.clone();
                    let cf = cert_factory.clone();
                    let tr = tr_registry.clone();
                    let ph_cell = placeholders.clone();
                    let policy = unregistered_policy;
                    tokio::spawn(async move {
                        // Outer TLS handshake. With_client_cert_verifier
                        // requires + verifies the client cert here; a
                        // missing/invalid client cert aborts the
                        // handshake before we ever see CONNECT bytes.
                        let tls = match acceptor.accept(tcp).await {
                            Ok(s) => s,
                            Err(e) => {
                                warn!(
                                    peer = %peer,
                                    error = %e,
                                    "transparent mTLS handshake failed — connection rejected",
                                );
                                return;
                            }
                        };
                        let ph_snapshot = Arc::new(ph_cell.read().await.clone());
                        if let Err(e) = super::handle_connection(
                            tls,
                            peer.to_string(),
                            state,
                            cf,
                            tr,
                            ph_snapshot,
                            policy,
                        )
                        .await
                        {
                            warn!(
                                peer = %peer,
                                error = %e,
                                "transparent mTLS connection ended with error",
                            );
                        }
                    });
                }
                Err(e) => {
                    error!(error = %e, "transparent mTLS accept failed");
                }
            }
        }
    });

    Ok((tr_registry_handle, placeholders_handle))
}

fn build_mtls_acceptor(mtls: &MtlsMaterial) -> Result<TlsAcceptor> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::server::WebPkiClientVerifier;
    use rustls::{RootCertStore, ServerConfig};

    let mut cert_reader: &[u8] = mtls.server_cert_pem.as_bytes();
    let cert_chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse mTLS server cert PEM")?;
    let mut key_reader: &[u8] = mtls.server_key_pem.as_bytes();
    let key = rustls_pemfile::pkcs8_private_keys(&mut key_reader)
        .next()
        .ok_or_else(|| anyhow::anyhow!("no PKCS8 key in mTLS server key PEM"))?
        .context("parse mTLS server key PEM")?;

    let mut roots = RootCertStore::empty();
    let mut ca_reader: &[u8] = mtls.client_ca_pem.as_bytes();
    let ca_certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut ca_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse mTLS client-CA PEM")?;
    if ca_certs.is_empty() {
        anyhow::bail!("mTLS client-CA PEM contained no certificates");
    }
    for c in ca_certs {
        roots
            .add(c)
            .context("add mTLS client-CA cert to verifier roots")?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .context("build mTLS client-cert verifier")?;

    let cfg = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert_chain, PrivateKeyDer::Pkcs8(key))
        .context("rustls mTLS ServerConfig")?;
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}
