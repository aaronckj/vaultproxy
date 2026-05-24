//! One-shot initialiser called before the transparent listener starts.
//! Loads (or generates) the CA, validates BYO if provided, prints the
//! fingerprint banner.

use anyhow::Result;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::tls::ca::{self, TransparentCa};

/// Source of the CA: auto-managed by vault-proxy, or operator BYO.
#[derive(Debug)]
pub enum CaSource {
    Auto {
        config_dir: PathBuf,
    },
    Byo {
        cert_path: PathBuf,
        key_path: PathBuf,
    },
}

/// Resolve a CA per source. Generates + persists on first run if Auto.
pub fn init(source: &CaSource) -> Result<Arc<TransparentCa>> {
    let ca = match source {
        CaSource::Auto { config_dir } => init_auto(config_dir)?,
        CaSource::Byo {
            cert_path,
            key_path,
        } => ca::load_byo(cert_path, key_path)?,
    };
    print_banner(&ca, source);
    Ok(Arc::new(ca))
}

fn init_auto(config_dir: &Path) -> Result<TransparentCa> {
    let cert_path = config_dir.join("transparent-ca.crt");
    let key_path = config_dir.join("transparent-ca.key");
    if cert_path.exists() && key_path.exists() {
        return TransparentCa::load(config_dir);
    }
    let hostname = hostname::get()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|_| "vaultproxy-host".into());
    let ca = TransparentCa::generate(&hostname)?;
    ca.persist(config_dir)?;
    tracing::info!(
        cert = %cert_path.display(),
        key = %key_path.display(),
        "generated new transparent-proxy CA",
    );
    Ok(ca)
}

fn print_banner(ca: &TransparentCa, source: &CaSource) {
    let (kind, path) = match source {
        CaSource::Auto { config_dir } => ("auto-generated", config_dir.join("transparent-ca.crt")),
        CaSource::Byo { cert_path, .. } => ("operator-provided (BYO)", cert_path.clone()),
    };
    eprintln!();
    eprintln!("┌─────────────────────────────────────────────────────────────────────┐");
    eprintln!("│ TRANSPARENT PROXY CA  ({kind})");
    eprintln!("│ SHA-256: {}", ca.fingerprint_sha256);
    eprintln!("│ File:    {}", path.display());
    eprintln!("│");
    eprintln!("│ Install on every agent host that uses HTTPS_PROXY=…3203.");
    eprintln!("│ Setup guide: docs/operator/TRANSPARENT-CA.md");
    eprintln!("└─────────────────────────────────────────────────────────────────────┘");
    eprintln!();
}
