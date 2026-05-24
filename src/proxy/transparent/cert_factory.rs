//! Per-host leaf cert signing for transparent MITM.
//!
//! On CONNECT, optionally fetch the upstream's real cert (so SAN/CN
//! match), sign a fresh leaf with our CA, and present it to the agent
//! over the TLS handshake. Cached LRU keyed on `host:port`.

use anyhow::{Context, Result};
use lru::LruCache;
use rcgen::{CertificateParams, DnType, KeyPair, SanType};
use std::num::NonZeroUsize;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::tls::ca::TransparentCa;

/// Signed leaf cert + private key, in PEM form, ready for rustls.
/// Fields are consumed by the MITM TLS handshake added in Phase 3.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct LeafCert {
    pub cert_chain_pem: String,
    pub key_pem: String,
}

pub struct CertFactory {
    ca: Arc<TransparentCa>,
    // Used by `leaf_for`; Phase 3's MITM dispatch wires the calls.
    #[allow(dead_code)]
    cache: Mutex<LruCache<String, LeafCert>>,
}

impl CertFactory {
    pub fn new(ca: Arc<TransparentCa>, capacity: usize) -> Self {
        Self {
            ca,
            cache: Mutex::new(LruCache::new(NonZeroUsize::new(capacity.max(1)).unwrap())),
        }
    }

    /// Look up or generate a leaf for the given `host:port`. On first
    /// miss, attempts to mirror upstream SANs; falls back to host-only
    /// SAN on upstream unreachable.
    #[allow(dead_code)]
    pub async fn leaf_for(&self, host: &str, port: u16) -> Result<LeafCert> {
        let key = format!("{host}:{port}");
        if let Some(hit) = self.cache.lock().await.get(&key).cloned() {
            return Ok(hit);
        }
        let sans = fetch_upstream_sans(host, port).await.unwrap_or_else(|e| {
            tracing::warn!(
                host,
                port,
                error = %e,
                "upstream SAN fetch failed; falling back to host-only SAN",
            );
            Vec::new()
        });
        let leaf = self.sign_leaf(host, sans)?;
        self.cache.lock().await.put(key, leaf.clone());
        Ok(leaf)
    }

    fn sign_leaf(&self, host: &str, mut upstream_sans: Vec<SanType>) -> Result<LeafCert> {
        // Always include the requested host as a SAN, plus any mirrored SANs.
        let host_san = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            SanType::IpAddress(ip)
        } else {
            SanType::DnsName(
                rcgen::Ia5String::try_from(host.to_string()).context("invalid DNS SAN")?,
            )
        };
        upstream_sans.push(host_san);

        let mut params =
            CertificateParams::new(Vec::<String>::new()).context("init leaf params")?;
        params.distinguished_name.push(DnType::CommonName, host);
        params.subject_alt_names = upstream_sans;
        params.not_before = time::OffsetDateTime::now_utc();
        params.not_after = params.not_before + time::Duration::days(30);

        let leaf_key =
            KeyPair::generate_for(&rcgen::PKCS_ED25519).context("generate leaf ED25519 key")?;

        // Reconstruct an in-memory CA Certificate to act as the issuer.
        // rcgen does not store the original Certificate on TransparentCa
        // (it isn't Clone/Send-friendly), so we re-derive it from PEM.
        // ~5ms cost; covered by the LRU cache.
        let ca_der = pem::parse(&self.ca.cert_pem)
            .context("parse CA cert PEM")?
            .into_contents();
        let ca_params = CertificateParams::from_ca_cert_der(&ca_der.into())
            .context("rehydrate CA params from DER")?;
        let ca_cert = ca_params
            .self_signed(&self.ca.key_pair)
            .context("rehydrate CA cert")?;

        let cert = params
            .signed_by(&leaf_key, &ca_cert, &self.ca.key_pair)
            .context("sign leaf with CA")?;

        // Chain: leaf cert + CA cert (so the agent can build a valid
        // chain even if it only trusts the root by fingerprint).
        let cert_chain_pem = format!("{}{}", cert.pem(), self.ca.cert_pem);
        Ok(LeafCert {
            cert_chain_pem,
            key_pem: leaf_key.serialize_pem(),
        })
    }
}

/// Open a TLS connection to upstream, snag its leaf cert's SAN list,
/// return them so the local leaf can mirror them. 5s timeout.
pub async fn fetch_upstream_sans(host: &str, port: u16) -> Result<Vec<SanType>> {
    use rustls::{ClientConfig, RootCertStore};
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;
    use tokio::time::{timeout, Duration};
    use tokio_rustls::TlsConnector;

    let mut roots = RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = host
        .to_string()
        .try_into()
        .map_err(|e| anyhow::anyhow!("invalid server name '{host}': {e}"))?;

    let tcp = timeout(Duration::from_secs(5), TcpStream::connect((host, port)))
        .await
        .map_err(|_| anyhow::anyhow!("upstream tcp connect timed out"))?
        .with_context(|| format!("connect to {host}:{port}"))?;
    let tls_conn: tokio_rustls::client::TlsStream<TcpStream> =
        timeout(Duration::from_secs(5), connector.connect(server_name, tcp))
            .await
            .map_err(|_| anyhow::anyhow!("upstream TLS handshake timed out"))?
            .with_context(|| format!("upstream TLS to {host}:{port}"))?;

    let (_, conn) = tls_conn.get_ref();
    let peer_certs = conn
        .peer_certificates()
        .ok_or_else(|| anyhow::anyhow!("upstream did not present a cert chain"))?;
    if peer_certs.is_empty() {
        return Err(anyhow::anyhow!("upstream cert chain empty"));
    }
    let (_, parsed) = x509_parser::parse_x509_certificate(peer_certs[0].as_ref())
        .map_err(|e| anyhow::anyhow!("parse upstream cert: {e}"))?;

    let mut sans = Vec::new();
    if let Ok(Some(ext)) = parsed.subject_alternative_name() {
        for gn in &ext.value.general_names {
            match gn {
                x509_parser::extensions::GeneralName::DNSName(d) => {
                    if let Ok(s) = rcgen::Ia5String::try_from(d.to_string()) {
                        sans.push(SanType::DnsName(s));
                    }
                }
                x509_parser::extensions::GeneralName::IPAddress(bytes) => {
                    if let Some(ip) = ipaddr_from_bytes(bytes) {
                        sans.push(SanType::IpAddress(ip));
                    }
                }
                _ => {}
            }
        }
    }

    let mut tls_conn = tls_conn;
    let _ = tls_conn.shutdown().await;
    Ok(sans)
}

fn ipaddr_from_bytes(b: &[u8]) -> Option<std::net::IpAddr> {
    match b.len() {
        4 => Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            b[0], b[1], b[2], b[3],
        ))),
        16 => {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(b);
            Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(arr)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_factory() -> CertFactory {
        let ca = Arc::new(TransparentCa::generate("test-host").unwrap());
        CertFactory::new(ca, 16)
    }

    #[tokio::test]
    async fn sign_leaf_returns_pem() {
        let f = mock_factory();
        let leaf = f.sign_leaf("api.github.com", Vec::new()).unwrap();
        assert!(leaf
            .cert_chain_pem
            .starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(leaf.key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    }

    #[tokio::test]
    async fn sign_leaf_distinct_hosts_distinct_leaves() {
        let f = mock_factory();
        let a = f.sign_leaf("api.github.com", Vec::new()).unwrap();
        let b = f.sign_leaf("api.gitlab.com", Vec::new()).unwrap();
        assert_ne!(a.cert_chain_pem, b.cert_chain_pem);
    }

    #[tokio::test]
    async fn sign_leaf_ipv4_san_works() {
        let f = mock_factory();
        let leaf = f.sign_leaf("10.0.0.1", Vec::new()).unwrap();
        assert!(leaf.cert_chain_pem.contains("CERTIFICATE"));
    }

    // Network-bound smoke; run manually with --ignored.
    #[tokio::test]
    #[ignore]
    async fn fetches_real_sans() {
        let sans = fetch_upstream_sans("badssl.com", 443).await.unwrap();
        assert!(!sans.is_empty());
    }
}
