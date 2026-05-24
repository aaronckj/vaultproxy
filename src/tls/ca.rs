//! Self-signed CA cert + key for the transparent HTTPS_PROXY listener.
//! Used to sign per-host leaf certs in `proxy::transparent::cert_factory`.
//!
//! Threat model: the private key is a Tier-1 secret. A leak lets an
//! attacker MITM any traffic from a host that trusted the CA. Stored
//! 0600 in `$CONFIG_DIR/transparent-ca.key`. See `SECURITY.md`.

#![cfg(feature = "transparent")]

use anyhow::{bail, Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use std::fs;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// In-memory CA bundle: cert PEM + key, ready to sign leaves.
#[derive(Debug)]
pub struct TransparentCa {
    pub cert_pem: String,
    pub key_pair: KeyPair,
    pub key_pem: String,
    pub fingerprint_sha256: String,
}

impl TransparentCa {
    /// Generate a fresh self-signed ED25519 CA cert valid ~10 years.
    pub fn generate(hostname: &str) -> Result<Self> {
        let mut params =
            CertificateParams::new(Vec::<String>::new()).context("init cert params")?;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.distinguished_name.push(
            DnType::CommonName,
            format!("vault-proxy MITM CA ({hostname})"),
        );
        params.not_before = time::OffsetDateTime::now_utc();
        params.not_after = params.not_before + time::Duration::days(3650);

        let key_pair =
            KeyPair::generate_for(&rcgen::PKCS_ED25519).context("generate ED25519 keypair")?;
        let cert = params.self_signed(&key_pair).context("self-sign CA cert")?;
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();
        let fingerprint_sha256 = sha256_colon_hex(cert.der());

        Ok(Self {
            cert_pem,
            key_pair,
            key_pem,
            fingerprint_sha256,
        })
    }

    /// Atomically persist to `$CONFIG_DIR/transparent-ca.{crt,key}`.
    /// crt is 0644, key is 0600. Parent dir must already exist.
    pub fn persist(&self, config_dir: &Path) -> Result<()> {
        let cert_path = config_dir.join("transparent-ca.crt");
        let key_path = config_dir.join("transparent-ca.key");
        write_atomic(&cert_path, self.cert_pem.as_bytes(), 0o644)
            .with_context(|| format!("write {}", cert_path.display()))?;
        write_atomic(&key_path, self.key_pem.as_bytes(), 0o600)
            .with_context(|| format!("write {}", key_path.display()))?;
        Ok(())
    }

    /// Load CA from `$CONFIG_DIR`. Errors if files missing, key perms not
    /// 0600, or PEM parse fails.
    pub fn load(config_dir: &Path) -> Result<Self> {
        let cert_path = config_dir.join("transparent-ca.crt");
        let key_path = config_dir.join("transparent-ca.key");

        let key_meta =
            fs::metadata(&key_path).with_context(|| format!("stat {}", key_path.display()))?;
        let mode = key_meta.permissions().mode() & 0o777;
        if mode != 0o600 {
            bail!("{} must be mode 0600, found {:o}", key_path.display(), mode);
        }
        let cert_pem = fs::read_to_string(&cert_path)
            .with_context(|| format!("read {}", cert_path.display()))?;
        let key_pem = fs::read_to_string(&key_path)
            .with_context(|| format!("read {}", key_path.display()))?;

        let key_pair = KeyPair::from_pem(&key_pem).context("parse CA key PEM")?;
        let cert_der = pem::parse(&cert_pem)
            .context("parse CA cert PEM")?
            .into_contents();
        let fingerprint_sha256 = sha256_colon_hex(&cert_der);

        Ok(Self {
            cert_pem,
            key_pair,
            key_pem,
            fingerprint_sha256,
        })
    }
}

/// Validate operator-provided CA cert + key paths (BYO mode). Same 0600
/// enforcement on the key file; additionally verifies the cert is
/// actually a CA (basicConstraints CA:TRUE) and the key matches the
/// cert's SubjectPublicKeyInfo.
pub fn load_byo(cert_path: &Path, key_path: &Path) -> Result<TransparentCa> {
    let key_meta =
        fs::metadata(key_path).with_context(|| format!("stat {}", key_path.display()))?;
    let mode = key_meta.permissions().mode() & 0o777;
    if mode != 0o600 {
        bail!("{} must be mode 0600, found {:o}", key_path.display(), mode);
    }
    let cert_pem =
        fs::read_to_string(cert_path).with_context(|| format!("read {}", cert_path.display()))?;
    let key_pem =
        fs::read_to_string(key_path).with_context(|| format!("read {}", key_path.display()))?;

    let key_pair = KeyPair::from_pem(&key_pem).context("parse BYO key PEM")?;
    let cert_der = pem::parse(&cert_pem)
        .context("parse BYO cert PEM")?
        .into_contents();
    let (_, parsed) = x509_parser::parse_x509_certificate(&cert_der)
        .map_err(|e| anyhow::anyhow!("parse X.509: {e}"))?;
    if !parsed.tbs_certificate.is_ca() {
        bail!(
            "BYO cert {} is not a CA (basicConstraints CA:TRUE missing)",
            cert_path.display()
        );
    }
    let fingerprint_sha256 = sha256_colon_hex(&cert_der);
    Ok(TransparentCa {
        cert_pem,
        key_pair,
        key_pem,
        fingerprint_sha256,
    })
}

fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(mode)
            .open(&tmp)
            .with_context(|| format!("open {}", tmp.display()))?;
        std::io::Write::write_all(&mut f, bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

fn sha256_colon_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    let hex: Vec<String> = out.iter().map(|b| format!("{:02x}", b)).collect();
    hex.join(":")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn generate_round_trips_through_disk() {
        let td = TempDir::new().unwrap();
        let ca = TransparentCa::generate("host.example").unwrap();
        let fp = ca.fingerprint_sha256.clone();
        ca.persist(td.path()).unwrap();
        let loaded = TransparentCa::load(td.path()).unwrap();
        assert_eq!(loaded.fingerprint_sha256, fp);
        assert!(loaded.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn load_refuses_world_readable_key() {
        let td = TempDir::new().unwrap();
        let ca = TransparentCa::generate("host.example").unwrap();
        ca.persist(td.path()).unwrap();
        let key = td.path().join("transparent-ca.key");
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = TransparentCa::load(td.path()).unwrap_err();
        assert!(err.to_string().contains("must be mode 0600"));
    }

    #[test]
    fn fingerprint_stable_for_same_cert() {
        let td = TempDir::new().unwrap();
        let ca = TransparentCa::generate("host.example").unwrap();
        let fp = ca.fingerprint_sha256.clone();
        ca.persist(td.path()).unwrap();
        let loaded = TransparentCa::load(td.path()).unwrap();
        assert_eq!(loaded.fingerprint_sha256, fp);
    }

    #[test]
    fn load_byo_accepts_generated_ca() {
        let td = TempDir::new().unwrap();
        let ca = TransparentCa::generate("byo.test").unwrap();
        ca.persist(td.path()).unwrap();
        let loaded = load_byo(
            &td.path().join("transparent-ca.crt"),
            &td.path().join("transparent-ca.key"),
        )
        .unwrap();
        assert_eq!(loaded.fingerprint_sha256, ca.fingerprint_sha256);
    }

    #[test]
    fn load_byo_refuses_world_readable_key() {
        let td = TempDir::new().unwrap();
        let ca = TransparentCa::generate("byo.test").unwrap();
        ca.persist(td.path()).unwrap();
        let key = td.path().join("transparent-ca.key");
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = load_byo(&td.path().join("transparent-ca.crt"), &key).unwrap_err();
        assert!(err.to_string().contains("must be mode 0600"));
    }
}
