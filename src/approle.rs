//! AppRole-style alternative keystore unlock for environments where TPM
//! is unavailable (cloud VMs, containers, headless CI). The operator
//! provisions a (role_id, secret_id) pair once via `approle-setup`; the
//! daemon reads secret_id from a file at runtime, derives a KEK, and
//! unlocks the credential bundle without prompting for a master password
//! or touching the TPM.
//!
//! Security envelope:
//!   KEK   = HKDF-SHA256(IKM=secret_id, salt=role_id, info="vp-approle-v1")
//!   blob  = AES-256-GCM(KEK, nonce, serde_json(Credentials))
//!   stored at <config_dir>/approles/<role_id>.json (mode 0600)
//!
//! Compared to MASTER_PASSWORD in the daemon's env (which leaks via
//! /proc/<pid>/environ), the secret_id file is read once at startup,
//! parsed, zeroized, and never re-read. The plaintext never enters the
//! daemon's environment.

use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hkdf::Hkdf;
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use sha2::Sha256;
use std::fs::{OpenOptions, Permissions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use zeroize::Zeroizing;

const APPROLE_SUBDIR: &str = "approles";
const SECRET_ID_BYTES: usize = 32;
const HKDF_INFO: &[u8] = b"vp-approle-v1";

#[derive(serde::Serialize, serde::Deserialize)]
struct StoredApprole {
    role_id: String,
    nonce_b64: String,
    ciphertext_b64: String,
}

/// Generate a fresh `secret_id`, encrypt the supplied `Credentials` under a
/// KEK derived from `(secret_id, role_id)`, and persist to
/// `<config_dir>/approles/<role_id>.json` (mode 0600).
///
/// Returns the `secret_id` encoded as a 64-character hex string for the
/// operator to write to a 0600 file referenced by `--approle-secret-id-file`.
pub fn setup_approle(
    config_dir: &Path,
    role_id: &str,
    creds: &crate::keystore::Credentials,
) -> Result<SecretString> {
    if role_id.is_empty()
        || role_id
            .chars()
            .any(|c| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
    {
        bail!("role_id must be non-empty and [A-Za-z0-9_-]+ only");
    }
    let mut sid_bytes = Zeroizing::new(vec![0u8; SECRET_ID_BYTES]);
    rand::thread_rng().fill_bytes(&mut sid_bytes);
    let kek = derive_kek(&sid_bytes, role_id);

    let plaintext = Zeroizing::new(serde_json::to_vec(creds).context("serialize Credentials")?);
    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut OsRng, &mut nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(kek.expose_secret())
        .map_err(|e| anyhow!("AES-256-GCM init: {e}"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_slice())
        .map_err(|e| anyhow!("AES-256-GCM encrypt: {e}"))?;

    let dir = config_dir.join(APPROLE_SUBDIR);
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    std::fs::set_permissions(&dir, Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 0700 {}", dir.display()))?;

    let stored = StoredApprole {
        role_id: role_id.to_string(),
        nonce_b64: B64.encode(nonce_bytes),
        ciphertext_b64: B64.encode(ciphertext),
    };
    let path = dir.join(format!("{role_id}.json"));
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("create {}", path.display()))?;
    f.write_all(&serde_json::to_vec(&stored)?)?;
    f.sync_data()?;
    std::fs::set_permissions(&path, Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", path.display()))?;

    Ok(SecretString::from(hex::encode(sid_bytes.as_slice())))
}

/// Decrypt the persisted `Credentials` for `role_id` using the hex-encoded
/// `secret_id`. Returns the unlocked `Credentials` or an error if the file
/// is missing, the secret_id is wrong (AEAD tag mismatch), or the
/// persisted file is malformed.
pub fn unlock_with_approle(
    config_dir: &Path,
    role_id: &str,
    secret_id_hex: &str,
) -> Result<crate::keystore::Credentials> {
    if role_id.is_empty() {
        bail!("role_id must not be empty");
    }
    let sid_bytes = Zeroizing::new(
        hex::decode(secret_id_hex.trim())
            .with_context(|| format!("decode secret_id for role {role_id}"))?,
    );
    if sid_bytes.len() != SECRET_ID_BYTES {
        bail!(
            "secret_id must be {SECRET_ID_BYTES} bytes ({} hex chars)",
            SECRET_ID_BYTES * 2
        );
    }
    let path = config_dir
        .join(APPROLE_SUBDIR)
        .join(format!("{role_id}.json"));
    let body =
        std::fs::read(&path).with_context(|| format!("read approle {}", path.display()))?;
    let stored: StoredApprole = serde_json::from_slice(&body)
        .with_context(|| format!("parse approle {}", path.display()))?;
    if stored.role_id != role_id {
        bail!(
            "role_id mismatch in {} (file says '{}')",
            path.display(),
            stored.role_id
        );
    }

    let kek = derive_kek(&sid_bytes, role_id);
    let nonce_bytes = B64.decode(&stored.nonce_b64).context("decode nonce")?;
    if nonce_bytes.len() != 12 {
        bail!("malformed nonce length: {}", nonce_bytes.len());
    }
    let ciphertext = B64
        .decode(&stored.ciphertext_b64)
        .context("decode ciphertext")?;
    let cipher = Aes256Gcm::new_from_slice(kek.expose_secret())
        .map_err(|e| anyhow!("AES-256-GCM init: {e}"))?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_slice())
            .map_err(|_| {
                anyhow!("approle decrypt failed (wrong secret_id, role_id, or tampered file)")
            })?,
    );
    let creds: crate::keystore::Credentials =
        serde_json::from_slice(&plaintext).context("deserialize Credentials")?;
    Ok(creds)
}

fn derive_kek(secret_id: &[u8], role_id: &str) -> secrecy::SecretSlice<u8> {
    let hk = Hkdf::<Sha256>::new(Some(role_id.as_bytes()), secret_id);
    let mut out = Zeroizing::new(vec![0u8; 32]);
    hk.expand(HKDF_INFO, &mut out)
        .expect("hkdf expand 32-byte output");
    // Move into SecretSlice for zeroize-on-drop. The Zeroizing wrapper above
    // also zeroizes the original buffer if expand had panicked partway.
    secrecy::SecretSlice::from(out.to_vec())
}
