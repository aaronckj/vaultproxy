//! TPM 2.0 integration and mTLS certificate generation.
//!
//! Provides:
//! - `seal_to_tpm` / `unseal_from_tpm` — encrypt/decrypt data using the TPM chip.
//!   The sealed blob is useless without physical access to the same TPM.
//! - `generate_mtls_certs` — ephemeral mTLS certificate generation (software keys).

use std::net::IpAddr;
use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;

use anyhow::Context;
use rcgen::{
    Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
    SanType,
};

// -------------------------------------------------------------------------- //
// TPM 2.0 seal/unseal                                                        //
// -------------------------------------------------------------------------- //

/// Check if a TPM device is available.
///
/// The result is cached on first call via `OnceLock` — subsequent calls return
/// the cached value with zero syscall overhead.
///
/// Rationale: `GET /vault/health` calls this on every request; Docker fires
/// healthchecks every 30 s.  On a host without TPM hardware the `stat("/dev/tpm0")`
/// always fails, producing ~2 880 failed syscalls per day.  TPM availability is
/// a hardware fact that does not change at runtime: once the process starts the
/// chip is either present or not.  Caching is therefore both safe and correct.
pub fn tpm_available() -> bool {
    static CACHE: OnceLock<bool> = OnceLock::new();
    *CACHE.get_or_init(|| Path::new("/dev/tpm0").exists())
}

/// Lock down a temp directory to owner-only before writing secrets into it.
/// Called by both `seal_to_tpm` and `unseal_from_tpm`.
fn restrict_tmp_dir(path: &str) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 0700 {}", path))?;
    }
    let _ = path; // silence unused on non-unix
    Ok(())
}

/// Seal data to the TPM. The output file can only be decrypted by this
/// specific TPM chip. Uses tpm2-tools CLI for reliability.
///
/// Creates a primary key in the owner hierarchy, then seals the data under it.
/// The primary key context and sealed object are stored at `sealed_path`.
///
/// Wrapper ensures the tmp plaintext is zeroized-and-removed on EVERY exit
/// path — including error bails. Before iter-18 only the success path did
/// cleanup; a `tpm2_createprimary`/`tpm2_create` failure left the plaintext
/// key in `/tmp/tpm_seal/plaintext` for the next process restart to find.
pub fn seal_to_tpm(data: &[u8], sealed_path: &str) -> anyhow::Result<()> {
    let tmp_dir = "/tmp/tpm_seal";
    let result = seal_to_tpm_inner(data, sealed_path, tmp_dir);
    // Cleanup runs regardless of success — zeroize then remove. Ignore
    // errors: the file may not exist (early failure before write), or the
    // parent dir may have been cleaned up already.
    let data_file = format!("{}/plaintext", tmp_dir);
    let zeros = vec![0u8; data.len()];
    std::fs::write(&data_file, &zeros).ok();
    std::fs::remove_dir_all(tmp_dir).ok();
    result
}

fn seal_to_tpm_inner(data: &[u8], sealed_path: &str, tmp_dir: &str) -> anyhow::Result<()> {
    if !tpm_available() {
        anyhow::bail!("TPM device /dev/tpm0 not available");
    }

    std::fs::create_dir_all(tmp_dir)?;
    // Restrict the tmp dir to owner-only BEFORE writing the plaintext key —
    // otherwise any other uid in the container can snapshot the blob during
    // the brief window before remove_dir_all runs.
    restrict_tmp_dir(tmp_dir)?;

    let data_file = format!("{}/plaintext", tmp_dir);
    let ctx_file = format!("{}/primary.ctx", tmp_dir);
    let pub_file = format!("{}/sealed.pub", tmp_dir);
    let priv_file = format!("{}/sealed.priv", tmp_dir);

    // Write data to temp file
    std::fs::write(&data_file, data)?;

    // Create primary key in owner hierarchy
    let output = Command::new("tpm2_createprimary")
        .args(["-C", "o", "-c", &ctx_file])
        .output()
        .context("tpm2_createprimary failed to execute")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("tpm2_createprimary failed: {}", stderr);
    }

    // Seal the data
    let output = Command::new("tpm2_create")
        .args([
            "-C", &ctx_file, "-i", &data_file, "-u", &pub_file, "-r", &priv_file,
        ])
        .output()
        .context("tpm2_create failed to execute")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("tpm2_create (seal) failed: {}", stderr);
    }

    // Bundle pub + priv into a single file for storage.
    // We do NOT save the primary context — it's transient and will be
    // recreated via tpm2_createprimary at unseal time.
    let pub_bytes = std::fs::read(&pub_file)?;
    let priv_bytes = std::fs::read(&priv_file)?;

    let bundle = SealedBundle {
        ctx: Vec::new(), // not used; kept for backwards compat with existing bundles
        pub_key: pub_bytes,
        priv_key: priv_bytes,
    };

    let bundle_bytes = serde_json::to_vec(&bundle)?;
    // Use safe_write_config so the final sealed bundle lands atomically
    // (tempfile + fsync + rename) with 0600 perms. Previously `fs::write`
    // could leave a truncated bundle on a mid-write crash and inherited
    // umask perms (often 0644 → world-readable).
    crate::secure::safe_write_config(sealed_path, &bundle_bytes)
        .with_context(|| format!("write sealed bundle to {}", sealed_path))?;

    tracing::info!("sealed {} bytes to TPM at {}", data.len(), sealed_path);
    Ok(())
}

/// Unseal data from the TPM. Only works on the same TPM chip that sealed it.
///
/// The primary key is recreated at unseal time using `tpm2_createprimary` with
/// the same hierarchy (owner) and default algorithm. TPM primary keys are
/// deterministic — same parameters always produce the same key on the same TPM.
/// We do NOT reuse the saved context because contexts are transient handles
/// that become invalid after reboot or TPM reset.
///
/// Wrapper guarantees /tmp/tpm_unseal is cleaned up on every exit path —
/// matches the iter-18 seal_to_tpm pattern. Before iter-19, an early bail
/// left sealed.pub/sealed.priv/loaded.ctx in /tmp/tpm_unseal.
pub fn unseal_from_tpm(sealed_path: &str) -> anyhow::Result<Vec<u8>> {
    let tmp_dir = "/tmp/tpm_unseal";
    let result = unseal_from_tpm_inner(sealed_path, tmp_dir);
    std::fs::remove_dir_all(tmp_dir).ok();
    result
}

fn unseal_from_tpm_inner(sealed_path: &str, tmp_dir: &str) -> anyhow::Result<Vec<u8>> {
    if !tpm_available() {
        anyhow::bail!("TPM device /dev/tpm0 not available");
    }

    let bundle_bytes = std::fs::read(sealed_path).context("failed to read sealed bundle")?;
    let bundle: SealedBundle =
        serde_json::from_slice(&bundle_bytes).context("failed to parse sealed bundle")?;

    std::fs::create_dir_all(tmp_dir)?;
    restrict_tmp_dir(tmp_dir)?;

    let ctx_file = format!("{}/primary.ctx", tmp_dir);
    let pub_file = format!("{}/sealed.pub", tmp_dir);
    let priv_file = format!("{}/sealed.priv", tmp_dir);
    let loaded_ctx = format!("{}/loaded.ctx", tmp_dir);

    // Recreate the primary key (deterministic — same hierarchy + algo = same key)
    let output = Command::new("tpm2_createprimary")
        .args(["-C", "o", "-c", &ctx_file])
        .output()
        .context("tpm2_createprimary failed to execute")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("tpm2_createprimary (unseal) failed: {}", stderr);
    }

    std::fs::write(&pub_file, &bundle.pub_key)?;
    std::fs::write(&priv_file, &bundle.priv_key)?;

    // Load the sealed object under the recreated primary
    let output = Command::new("tpm2_load")
        .args([
            "-C",
            &ctx_file,
            "-u",
            &pub_file,
            "-r",
            &priv_file,
            "-c",
            &loaded_ctx,
        ])
        .output()
        .context("tpm2_load failed to execute")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("tpm2_load failed: {}", stderr);
    }

    // Unseal
    let output = Command::new("tpm2_unseal")
        .args(["-c", &loaded_ctx])
        .output()
        .context("tpm2_unseal failed to execute")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("tpm2_unseal failed: {}", stderr);
    }

    // Cleanup happens in the wrapper — do NOT remove_dir_all here or the
    // wrapper's post-call cleanup would be redundant. The wrapper is the
    // single exit-point guarantee.
    tracing::info!("unsealed data from TPM at {}", sealed_path);
    Ok(output.stdout)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SealedBundle {
    ctx: Vec<u8>,
    pub_key: Vec<u8>,
    priv_key: Vec<u8>,
}

// -------------------------------------------------------------------------- //
// Public types                                                                //
// -------------------------------------------------------------------------- //

/// All PEM-encoded material needed to run mutual TLS between vault-proxy
/// (server) and Connecterr (client).
#[derive(Clone)]
pub struct CertMaterial {
    /// Self-signed CA certificate (PEM).
    pub ca_cert_pem: String,
    /// Server certificate signed by the CA (PEM).
    // Used by dashboard TLS setup, which is #[cfg(feature = "dashboard")].
    #[allow(dead_code)]
    pub server_cert_pem: String,
    /// Server private key (PEM).
    // Used by dashboard TLS setup, which is #[cfg(feature = "dashboard")].
    #[allow(dead_code)]
    pub server_key_pem: String,
    /// Client certificate signed by the CA (PEM).
    pub client_cert_pem: String,
    /// Client private key (PEM).
    pub client_key_pem: String,
}

// -------------------------------------------------------------------------- //
// Certificate generation                                                      //
// -------------------------------------------------------------------------- //

/// Generate ephemeral mTLS certificates using software ECDSA P-256 keys.
///
/// Returns a [`CertMaterial`] containing all five PEM blobs required for
/// mutual TLS.  The CA is self-signed; both the server and client certs are
/// signed by the CA.
pub fn generate_mtls_certs() -> anyhow::Result<CertMaterial> {
    // ------------------------------------------------------------------ //
    // 1. CA                                                                //
    // ------------------------------------------------------------------ //
    let ca_key = KeyPair::generate().context("failed to generate CA key pair")?;

    let mut ca_params = CertificateParams::default();
    let mut ca_dn = DistinguishedName::new();
    ca_dn.push(DnType::CommonName, "vault-proxy-ca");
    ca_params.distinguished_name = ca_dn;
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    let ca_cert: Certificate = ca_params
        .self_signed(&ca_key)
        .context("failed to self-sign CA certificate")?;

    let ca_cert_pem = ca_cert.pem();

    // ------------------------------------------------------------------ //
    // 2. Server cert (CN=vault-proxy, SAN=127.0.0.1)                     //
    // ------------------------------------------------------------------ //
    let server_key = KeyPair::generate().context("failed to generate server key pair")?;

    let mut server_params = CertificateParams::default();
    let mut server_dn = DistinguishedName::new();
    server_dn.push(DnType::CommonName, "vault-proxy");
    server_params.distinguished_name = server_dn;
    server_params.subject_alt_names = vec![
        SanType::IpAddress(IpAddr::from([127, 0, 0, 1])),
        SanType::DnsName("vault-proxy".try_into().unwrap()),
        SanType::DnsName("localhost".try_into().unwrap()),
    ];
    // Broad validity window: 1975-01-01 to 2099-12-31.
    // Previously hardcoded to 2025-01-01..2026-12-31 — those certs will be
    // rejected by rustls as expired after Dec 2026 (and any restart after that
    // date would have silently generated an already-expired cert). These certs
    // are ephemeral (regenerated on every restart), so a long window is safe.
    // The 1975 not_before follows rcgen's own default and provides generous
    // clock-skew tolerance.
    //
    // HSTS: we intentionally do NOT set Strict-Transport-Security on the
    // dashboard because (a) the cert is self-signed and cannot be trusted by
    // a standard browser, and (b) the dashboard is localhost-only. The
    // effective MITM defence is the mTLS client-cert requirement — an attacker
    // would need the client cert in addition to intercepting the connection.
    server_params.not_before = rcgen::date_time_ymd(1975, 1, 1);
    server_params.not_after = rcgen::date_time_ymd(2099, 12, 31);
    server_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];

    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .context("failed to sign server certificate")?;

    let server_cert_pem = server_cert.pem();
    let server_key_pem = server_key.serialize_pem();

    // ------------------------------------------------------------------ //
    // 3. Client cert (CN=connecterr-client)                               //
    // ------------------------------------------------------------------ //
    let client_key = KeyPair::generate().context("failed to generate client key pair")?;

    let mut client_params = CertificateParams::default();
    let mut client_dn = DistinguishedName::new();
    client_dn.push(DnType::CommonName, "connecterr-client");
    client_params.distinguished_name = client_dn;
    client_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];

    let client_cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .context("failed to sign client certificate")?;

    let client_cert_pem = client_cert.pem();
    let client_key_pem = client_key.serialize_pem();

    Ok(CertMaterial {
        ca_cert_pem,
        server_cert_pem,
        server_key_pem,
        client_cert_pem,
        client_key_pem,
    })
}
