//! Credential keystore — RSA-2048 envelope encryption for Vaultwarden credentials.

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::rngs::OsRng;
use rsa::pkcs1::{
    DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey,
};
use rsa::pkcs8::LineEnding;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;

// -------------------------------------------------------------------------- //
// Credential types                                                            //
// -------------------------------------------------------------------------- //

#[derive(Serialize, Deserialize, Clone)]
pub struct Credentials {
    pub version: u32,
    pub vaultwarden: VaultwardenCreds,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloud: Option<CloudCreds>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setup_password_hash: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct VaultwardenCreds {
    pub url: String,
    pub email: String,
    pub master_password: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CloudCreds {
    pub email: String,
    pub master_password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Bitwarden API key client_id (e.g., "user.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_client_id: Option<String>,
    /// Bitwarden API key client_secret
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_client_secret: Option<String>,
    /// KDF iterations override (Bitwarden prelogin/profile can return wrong values)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kdf_iterations: Option<u32>,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedCredentials {
    /// RSA-OAEP encrypted AES-256 key (base64)
    pub encrypted_key: String,
    /// AES-256-GCM nonce (base64)
    pub nonce: String,
    /// AES-256-GCM encrypted credential JSON (base64)
    pub ciphertext: String,
}

/// Argon2id + AES-256-GCM wrapped private key, stored on disk as `private_key.enc`.
#[derive(Serialize, Deserialize)]
pub struct WrappedPrivateKey {
    /// Argon2id salt (base64, 16 bytes).
    pub salt: String,
    /// AES-256-GCM nonce (base64, 12 bytes).
    pub nonce: String,
    /// AES-256-GCM encrypted private key DER (base64).
    pub ciphertext: String,
}

// -------------------------------------------------------------------------- //
// File name constants                                                         //
// -------------------------------------------------------------------------- //

pub const CREDENTIALS_FILE: &str = "credentials.enc";
pub const PUBLIC_KEY_FILE: &str = "public_key.pem";
pub const PRIVATE_KEY_ENC_FILE: &str = "private_key.enc";
pub const PRIVATE_KEY_SEALED_FILE: &str = "private_key.sealed";
/// AES-256 key sealed in TPM (32 bytes — fits TPM's 256-byte seal limit).
/// Used to decrypt `private_key.tpm_enc` without needing the setup password.
pub const TPM_AES_KEY_SEALED_FILE: &str = "tpm_aes_key.sealed";
/// Private key DER encrypted with the TPM-sealed AES key.
pub const PRIVATE_KEY_TPM_ENC_FILE: &str = "private_key.tpm_enc";

// -------------------------------------------------------------------------- //
// Keypair generation                                                          //
// -------------------------------------------------------------------------- //

/// Generate an RSA-2048 keypair.
pub fn generate_keypair() -> Result<(RsaPrivateKey, RsaPublicKey)> {
    let private_key =
        RsaPrivateKey::new(&mut OsRng, 2048).context("failed to generate RSA-2048 keypair")?;
    let public_key = RsaPublicKey::from(&private_key);
    Ok((private_key, public_key))
}

// -------------------------------------------------------------------------- //
// Envelope encryption                                                         //
// -------------------------------------------------------------------------- //

/// Encrypt credentials using RSA-OAEP envelope encryption.
///
/// 1. Generate a random AES-256-GCM key
/// 2. Encrypt the credential JSON with AES-256-GCM
/// 3. Encrypt the AES key with RSA-OAEP (SHA-256)
/// 4. Zeroize plaintext and AES key
pub fn encrypt_credentials(
    public_key: &RsaPublicKey,
    creds: &Credentials,
) -> Result<EncryptedCredentials> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    // Serialize credentials to JSON.
    let mut plaintext = serde_json::to_vec(creds).context("failed to serialize credentials")?;

    // Generate random AES-256 key (32 bytes).
    let mut aes_key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut OsRng, &mut aes_key);

    // Encrypt plaintext with AES-256-GCM.
    let cipher =
        Aes256Gcm::new_from_slice(&aes_key).context("failed to create AES-256-GCM cipher")?;
    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut OsRng, &mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| anyhow::anyhow!("AES-256-GCM encryption failed: {}", e))?;

    // Zeroize plaintext.
    plaintext.zeroize();

    // Encrypt AES key with RSA-OAEP (SHA-256).
    let padding = Oaep::new::<Sha256>();
    let encrypted_key = public_key
        .encrypt(&mut OsRng, padding, &aes_key)
        .context("RSA-OAEP encryption of AES key failed")?;

    // Zeroize AES key.
    aes_key.zeroize();

    Ok(EncryptedCredentials {
        encrypted_key: STANDARD.encode(&encrypted_key),
        nonce: STANDARD.encode(nonce_bytes),
        ciphertext: STANDARD.encode(&ciphertext),
    })
}

/// Decrypt credentials using RSA-OAEP envelope decryption.
pub fn decrypt_credentials(
    private_key: &RsaPrivateKey,
    blob: &EncryptedCredentials,
) -> Result<Credentials> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    // Decode base64 fields.
    let encrypted_key = STANDARD
        .decode(&blob.encrypted_key)
        .context("invalid base64 in encrypted_key")?;
    let nonce_bytes = STANDARD
        .decode(&blob.nonce)
        .context("invalid base64 in nonce")?;
    let ciphertext = STANDARD
        .decode(&blob.ciphertext)
        .context("invalid base64 in ciphertext")?;

    // Decrypt AES key with RSA-OAEP.
    let padding = Oaep::new::<Sha256>();
    let mut aes_key = private_key
        .decrypt(padding, &encrypted_key)
        .context("RSA-OAEP decryption of AES key failed")?;

    // Decrypt ciphertext with AES-256-GCM.
    let cipher =
        Aes256Gcm::new_from_slice(&aes_key).context("failed to create AES-256-GCM cipher")?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| anyhow::anyhow!("AES-256-GCM decryption failed: {}", e))?;

    // Zeroize AES key.
    aes_key.zeroize();

    // Deserialize credentials.
    let creds: Credentials = serde_json::from_slice(&plaintext)
        .context("failed to deserialize decrypted credentials")?;

    // Zeroize plaintext.
    plaintext.zeroize();

    Ok(creds)
}

// -------------------------------------------------------------------------- //
// Private key wrapping (software mode)                                        //
// -------------------------------------------------------------------------- //

/// Wrap a private key DER with Argon2id + AES-256-GCM.
///
/// 1. Generate random 16-byte salt and 12-byte nonce.
/// 2. Derive AES-256 key from password via Argon2id (256 MB memory, 3 iterations, 1 lane).
/// 3. AES-256-GCM encrypt the private key DER with derived key.
/// 4. Zeroize derived key.
/// 5. Return WrappedPrivateKey with base64-encoded fields.
pub fn wrap_private_key(private_key_der: &[u8], password: &str) -> Result<WrappedPrivateKey> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use argon2::{Algorithm, Argon2, Params, Version};

    // Generate random salt (16 bytes) and nonce (12 bytes).
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut OsRng, &mut salt);
    rand::RngCore::fill_bytes(&mut OsRng, &mut nonce_bytes);

    // Derive AES-256 key via Argon2id (256 MB memory = 262144 KB, 3 iterations, 1 lane, 32-byte output).
    let params = Params::new(262144, 3, 1, Some(32))
        .map_err(|e| anyhow::anyhow!("Argon2 params error: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut derived_key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut derived_key)
        .map_err(|e| anyhow::anyhow!("Argon2id key derivation failed: {}", e))?;

    // AES-256-GCM encrypt the private key DER.
    let cipher =
        Aes256Gcm::new_from_slice(&derived_key).context("failed to create AES-256-GCM cipher")?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, private_key_der)
        .map_err(|e| anyhow::anyhow!("AES-256-GCM encryption failed: {}", e))?;

    // Zeroize derived key.
    derived_key.zeroize();

    Ok(WrappedPrivateKey {
        salt: STANDARD.encode(salt),
        nonce: STANDARD.encode(nonce_bytes),
        ciphertext: STANDARD.encode(&ciphertext),
    })
}

/// Unwrap a private key DER encrypted with [`wrap_private_key`].
///
/// Returns an error with message "decryption failed — wrong password?" on authentication failure.
pub fn unwrap_private_key(wrapped: &WrappedPrivateKey, password: &str) -> Result<Vec<u8>> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use argon2::{Algorithm, Argon2, Params, Version};

    // Decode base64 fields.
    let salt = STANDARD
        .decode(&wrapped.salt)
        .context("invalid base64 in salt")?;
    let nonce_bytes = STANDARD
        .decode(&wrapped.nonce)
        .context("invalid base64 in nonce")?;
    let ciphertext = STANDARD
        .decode(&wrapped.ciphertext)
        .context("invalid base64 in ciphertext")?;

    // Re-derive AES key with same Argon2id params.
    let params = Params::new(262144, 3, 1, Some(32))
        .map_err(|e| anyhow::anyhow!("Argon2 params error: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut derived_key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut derived_key)
        .map_err(|e| anyhow::anyhow!("Argon2id key derivation failed: {}", e))?;

    // AES-256-GCM decrypt.
    let cipher =
        Aes256Gcm::new_from_slice(&derived_key).context("failed to create AES-256-GCM cipher")?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| anyhow::anyhow!("decryption failed — wrong password?"))?;

    // Zeroize derived key.
    derived_key.zeroize();

    Ok(plaintext)
}

// -------------------------------------------------------------------------- //
// Key serialization helpers                                                   //
// -------------------------------------------------------------------------- //

/// Serialize an RSA public key to PEM (PKCS#1).
pub fn public_key_to_pem(key: &RsaPublicKey) -> Result<String> {
    key.to_pkcs1_pem(LineEnding::LF)
        .context("failed to encode public key to PEM")
}

/// Deserialize an RSA public key from PEM (PKCS#1).
#[allow(dead_code)] // only called from reencrypt_credentials which is dashboard-gated
pub fn public_key_from_pem(pem: &str) -> Result<RsaPublicKey> {
    RsaPublicKey::from_pkcs1_pem(pem).context("failed to decode public key from PEM")
}

/// Serialize an RSA private key to DER (PKCS#1).
pub fn private_key_to_der(key: &RsaPrivateKey) -> Result<Vec<u8>> {
    let der = key
        .to_pkcs1_der()
        .context("failed to encode private key to DER")?;
    Ok(der.as_bytes().to_vec())
}

/// Deserialize an RSA private key from DER (PKCS#1).
pub fn private_key_from_der(der: &[u8]) -> Result<RsaPrivateKey> {
    RsaPrivateKey::from_pkcs1_der(der).context("failed to decode private key from DER")
}

// -------------------------------------------------------------------------- //
// TPM wrappers                                                                //
// -------------------------------------------------------------------------- //

/// Seal the private key DER to the TPM chip. The resulting file can only be
/// decrypted on the same physical TPM.
pub fn seal_private_key_to_tpm(private_key_der: &[u8], sealed_path: &str) -> Result<()> {
    crate::tpm::seal_to_tpm(private_key_der, sealed_path)
}

/// Unseal the private key DER from a TPM-sealed blob.
#[allow(dead_code)] // post-v1.0: will be called when TPM-backed auto-unlock path is wired
pub fn unseal_private_key_from_tpm(sealed_path: &str) -> Result<Vec<u8>> {
    crate::tpm::unseal_from_tpm(sealed_path)
}

// -------------------------------------------------------------------------- //
// High-level keystore operations                                              //
// -------------------------------------------------------------------------- //

/// Set up the credential keystore for the first time.
///
/// 1. Generates an RSA-2048 keypair.
/// 2. Encrypts credentials with the public key (envelope encryption).
/// 3. Writes public key PEM, encrypted credentials, and password-wrapped
///    private key to `config_dir`.
/// 4. If a TPM is available, also seals the private key to the TPM.
pub fn setup_keystore(config_dir: &str, creds: Credentials, setup_password: &str) -> Result<()> {
    let (private_key, public_key) = generate_keypair()?;

    // Encrypt credentials with public key.
    let encrypted = encrypt_credentials(&public_key, &creds)?;
    let encrypted_json =
        serde_json::to_vec(&encrypted).context("failed to serialize encrypted credentials")?;
    crate::secure::safe_write_config(
        &format!("{}/{}", config_dir, CREDENTIALS_FILE),
        &encrypted_json,
    )?;

    // Save public key PEM.
    let pem = public_key_to_pem(&public_key)?;
    crate::secure::safe_write_config(
        &format!("{}/{}", config_dir, PUBLIC_KEY_FILE),
        pem.as_bytes(),
    )?;

    // Serialize private key to DER.
    let mut der = private_key_to_der(&private_key)?;

    // If TPM available, seal to TPM.
    if crate::tpm::tpm_available() {
        let sealed_path = format!("{}/{}", config_dir, PRIVATE_KEY_SEALED_FILE);
        if let Err(e) = seal_private_key_to_tpm(&der, &sealed_path) {
            tracing::warn!("TPM sealing failed, software fallback only: {}", e);
        }
    }

    // Always write password-wrapped key (software fallback).
    let wrapped = wrap_private_key(&der, setup_password)?;
    let wrapped_json =
        serde_json::to_vec(&wrapped).context("failed to serialize wrapped private key")?;
    crate::secure::safe_write_config(
        &format!("{}/{}", config_dir, PRIVATE_KEY_ENC_FILE),
        &wrapped_json,
    )?;

    // Zeroize private key DER.
    der.zeroize();

    Ok(())
}

/// Unlock the keystore and return decrypted credentials.
///
/// Tries TPM unseal first if available. Falls back to password-based unwrap.
pub fn unlock_keystore(config_dir: &str, setup_password: Option<&str>) -> Result<Credentials> {
    // Read encrypted credentials.
    let enc_bytes = std::fs::read(format!("{}/{}", config_dir, CREDENTIALS_FILE))
        .context("failed to read credentials.enc")?;
    let encrypted: EncryptedCredentials =
        serde_json::from_slice(&enc_bytes).context("failed to parse credentials.enc")?;

    // Try TPM unseal first: unseal the AES key, then decrypt the private key from disk.
    let sealed_path = format!("{}/{}", config_dir, TPM_AES_KEY_SEALED_FILE);
    let tpm_enc_path = format!("{}/{}", config_dir, PRIVATE_KEY_TPM_ENC_FILE);
    let mut der = if crate::tpm::tpm_available()
        && std::path::Path::new(&sealed_path).exists()
        && std::path::Path::new(&tpm_enc_path).exists()
    {
        match unlock_with_tpm(config_dir) {
            Ok(der) => der,
            Err(e) => {
                tracing::warn!("TPM unseal failed, trying password fallback: {}", e);
                unlock_with_password(config_dir, setup_password)?
            }
        }
    } else {
        unlock_with_password(config_dir, setup_password)?
    };

    let private_key = private_key_from_der(&der)?;
    der.zeroize();

    decrypt_credentials(&private_key, &encrypted)
}

/// Helper: unwrap private key using the setup password.
/// Unseal the AES key from TPM and decrypt the private key DER.
fn unlock_with_tpm(config_dir: &str) -> Result<Vec<u8>> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    // Unseal AES key from TPM.
    let sealed_path = format!("{}/{}", config_dir, TPM_AES_KEY_SEALED_FILE);
    let mut aes_key =
        crate::tpm::unseal_from_tpm(&sealed_path).context("failed to unseal AES key from TPM")?;

    // Read AES-encrypted private key from disk.
    let enc_bytes = std::fs::read(format!("{}/{}", config_dir, PRIVATE_KEY_TPM_ENC_FILE))
        .context("failed to read private_key.tpm_enc")?;
    let wrapped: WrappedPrivateKey =
        serde_json::from_slice(&enc_bytes).context("failed to parse private_key.tpm_enc")?;

    let nonce_bytes = STANDARD
        .decode(&wrapped.nonce)
        .context("invalid base64 in nonce")?;
    let ciphertext = STANDARD
        .decode(&wrapped.ciphertext)
        .context("invalid base64 in ciphertext")?;

    // Decrypt with AES-256-GCM.
    let cipher =
        Aes256Gcm::new_from_slice(&aes_key).context("failed to create AES-256-GCM cipher")?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let der = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| anyhow::anyhow!("AES-256-GCM decryption failed: {}", e))?;

    aes_key.zeroize();
    tracing::info!("private key decrypted via TPM-sealed AES key");
    Ok(der)
}

fn unlock_with_password(config_dir: &str, setup_password: Option<&str>) -> Result<Vec<u8>> {
    let password = setup_password
        .ok_or_else(|| anyhow::anyhow!("setup password required to unlock (no TPM available)"))?;

    let wrapped_bytes = std::fs::read(format!("{}/{}", config_dir, PRIVATE_KEY_ENC_FILE))
        .context("failed to read private_key.enc")?;
    let wrapped: WrappedPrivateKey =
        serde_json::from_slice(&wrapped_bytes).context("failed to parse private_key.enc")?;

    unwrap_private_key(&wrapped, password)
}

/// Re-encrypt credentials with the existing public key.
///
/// Useful when rotating credential values without changing the keypair.
#[allow(dead_code)] // dashboard-gated: called from dashboard/api.rs credential rotation handlers
pub fn reencrypt_credentials(config_dir: &str, creds: &Credentials) -> Result<()> {
    let pem = std::fs::read_to_string(format!("{}/{}", config_dir, PUBLIC_KEY_FILE))
        .context("failed to read public_key.pem")?;
    let public_key = public_key_from_pem(&pem)?;

    let encrypted = encrypt_credentials(&public_key, creds)?;
    let encrypted_json =
        serde_json::to_vec(&encrypted).context("failed to serialize encrypted credentials")?;
    crate::secure::safe_write_config(
        &format!("{}/{}", config_dir, CREDENTIALS_FILE),
        &encrypted_json,
    )?;

    Ok(())
}

/// Seal the private key to TPM after a successful password-based unlock.
///
/// Generates a random AES-256 key (32 bytes), encrypts the private key DER
/// with AES-256-GCM, seals the AES key to TPM, and writes the encrypted
/// private key to disk. Independent of the setup password — password changes
/// don't invalidate the TPM seal.
#[allow(dead_code)] // called by start_dashboard_only() which is #[cfg(feature = "dashboard")]
pub fn seal_after_unlock(config_dir: &str, setup_password: &str) -> Result<()> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    // Unwrap the private key using the setup password.
    let mut der = unlock_with_password(config_dir, Some(setup_password))?;

    // Generate random AES-256 key and nonce.
    let mut aes_key = [0u8; 32];
    let mut nonce_bytes = [0u8; 12];
    rand::RngCore::fill_bytes(&mut OsRng, &mut aes_key);
    rand::RngCore::fill_bytes(&mut OsRng, &mut nonce_bytes);

    // Encrypt private key DER with AES-256-GCM.
    let cipher =
        Aes256Gcm::new_from_slice(&aes_key).context("failed to create AES-256-GCM cipher")?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, der.as_ref())
        .map_err(|e| anyhow::anyhow!("AES-256-GCM encryption failed: {}", e))?;

    // Zeroize plaintext DER.
    der.zeroize();

    // Seal the 32-byte AES key to TPM.
    let sealed_path = format!("{}/{}", config_dir, TPM_AES_KEY_SEALED_FILE);
    crate::tpm::seal_to_tpm(&aes_key, &sealed_path).context("failed to seal AES key to TPM")?;
    aes_key.zeroize();

    // Write AES-encrypted private key + nonce to disk.
    let tpm_enc = WrappedPrivateKey {
        salt: String::new(), // not used for TPM path
        nonce: STANDARD.encode(nonce_bytes),
        ciphertext: STANDARD.encode(&ciphertext),
    };
    let tpm_enc_json =
        serde_json::to_vec(&tpm_enc).context("failed to serialize TPM-encrypted private key")?;
    crate::secure::safe_write_config(
        &format!("{}/{}", config_dir, PRIVATE_KEY_TPM_ENC_FILE),
        &tpm_enc_json,
    )?;

    tracing::info!("private key sealed via TPM (AES key in TPM, encrypted DER on disk)");
    Ok(())
}

/// Returns `true` if a credential file exists in `config_dir`.
pub fn is_configured(config_dir: &str) -> bool {
    std::path::Path::new(&format!("{}/{}", config_dir, CREDENTIALS_FILE)).exists()
}

/// Returns `true` if TPM is available and sealed AES key + encrypted private key exist.
pub fn has_tpm_key(config_dir: &str) -> bool {
    crate::tpm::tpm_available()
        && std::path::Path::new(&format!("{}/{}", config_dir, TPM_AES_KEY_SEALED_FILE)).exists()
        && std::path::Path::new(&format!("{}/{}", config_dir, PRIVATE_KEY_TPM_ENC_FILE)).exists()
}

/// Delete all keystore files from `config_dir`.
///
/// Called by `dashboard/api.rs::handle_reset` (iter-93: corrected stale
/// annotation — the function IS wired to the dashboard "factory reset"
/// endpoint; the old `#[allow(dead_code)]` comment was left from before the
/// dashboard wiring landed). When the `dashboard` feature is absent the only
/// call site is compiled out, so we scope the allow to that configuration.
#[cfg_attr(not(feature = "dashboard"), allow(dead_code))]
pub fn reset_keystore(config_dir: &str) -> Result<()> {
    for filename in &[
        CREDENTIALS_FILE,
        PUBLIC_KEY_FILE,
        PRIVATE_KEY_ENC_FILE,
        PRIVATE_KEY_SEALED_FILE,
        TPM_AES_KEY_SEALED_FILE,
        PRIVATE_KEY_TPM_ENC_FILE,
    ] {
        let path = format!("{}/{}", config_dir, filename);
        if std::path::Path::new(&path).exists() {
            std::fs::remove_file(&path).with_context(|| format!("failed to remove {}", path))?;
        }
    }
    Ok(())
}

// -------------------------------------------------------------------------- //
// Tests                                                                       //
// -------------------------------------------------------------------------- //

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::traits::PublicKeyParts;

    fn sample_creds() -> Credentials {
        Credentials {
            version: 1,
            vaultwarden: VaultwardenCreds {
                url: "https://vault.example.com".to_string(),
                email: "user@example.com".to_string(),
                master_password: "hunter2".to_string(),
            },
            cloud: None,
            setup_password_hash: None,
        }
    }

    fn sample_creds_with_cloud() -> Credentials {
        Credentials {
            version: 1,
            vaultwarden: VaultwardenCreds {
                url: "https://vault.example.com".to_string(),
                email: "user@example.com".to_string(),
                master_password: "hunter2".to_string(),
            },
            cloud: Some(CloudCreds {
                email: "cloud@example.com".to_string(),
                master_password: "cloud-pass".to_string(),
                refresh_token: Some("rt_abc123".to_string()),
                api_client_id: None,
                api_client_secret: None,
                kdf_iterations: None,
            }),
            setup_password_hash: Some("$2b$12$hash".to_string()),
        }
    }

    #[test]
    fn test_credential_serialization_roundtrip() {
        let creds = sample_creds();
        let json = serde_json::to_string(&creds).unwrap();
        let parsed: Credentials = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.vaultwarden.url, "https://vault.example.com");
        assert_eq!(parsed.vaultwarden.email, "user@example.com");
        assert_eq!(parsed.vaultwarden.master_password, "hunter2");
        assert!(parsed.cloud.is_none());
        assert!(parsed.setup_password_hash.is_none());

        // Verify optional fields are omitted from JSON.
        assert!(!json.contains("cloud"));
        assert!(!json.contains("setup_password_hash"));
    }

    #[test]
    fn test_credential_with_cloud() {
        let creds = sample_creds_with_cloud();
        let json = serde_json::to_string(&creds).unwrap();
        let parsed: Credentials = serde_json::from_str(&json).unwrap();

        let cloud = parsed.cloud.as_ref().unwrap();
        assert_eq!(cloud.email, "cloud@example.com");
        assert_eq!(cloud.master_password, "cloud-pass");
        assert_eq!(cloud.refresh_token.as_deref(), Some("rt_abc123"));
        assert_eq!(parsed.setup_password_hash.as_deref(), Some("$2b$12$hash"));
    }

    #[test]
    fn test_generate_keypair() {
        let (private_key, public_key) = generate_keypair().unwrap();
        // RSA-2048 key size = 256 bytes.
        assert_eq!(public_key.size(), 256);
        assert_eq!(private_key.size(), 256);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (private_key, public_key) = generate_keypair().unwrap();
        let creds = sample_creds_with_cloud();

        let blob = encrypt_credentials(&public_key, &creds).unwrap();

        // Verify blob fields are non-empty base64.
        assert!(!blob.encrypted_key.is_empty());
        assert!(!blob.nonce.is_empty());
        assert!(!blob.ciphertext.is_empty());

        let decrypted = decrypt_credentials(&private_key, &blob).unwrap();

        assert_eq!(decrypted.version, creds.version);
        assert_eq!(decrypted.vaultwarden.url, creds.vaultwarden.url);
        assert_eq!(decrypted.vaultwarden.email, creds.vaultwarden.email);
        assert_eq!(
            decrypted.vaultwarden.master_password,
            creds.vaultwarden.master_password
        );

        let cloud = decrypted.cloud.as_ref().unwrap();
        assert_eq!(cloud.email, "cloud@example.com");
        assert_eq!(cloud.master_password, "cloud-pass");
        assert_eq!(cloud.refresh_token.as_deref(), Some("rt_abc123"));
        assert_eq!(
            decrypted.setup_password_hash.as_deref(),
            Some("$2b$12$hash")
        );
    }

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let (_private_key1, public_key1) = generate_keypair().unwrap();
        let (private_key2, _public_key2) = generate_keypair().unwrap();

        let creds = sample_creds();
        let blob = encrypt_credentials(&public_key1, &creds).unwrap();

        // Decrypting with wrong private key should fail.
        let result = decrypt_credentials(&private_key2, &blob);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_serialization_roundtrip() {
        let (private_key, public_key) = generate_keypair().unwrap();

        // Public key PEM roundtrip.
        let pem = public_key_to_pem(&public_key).unwrap();
        assert!(pem.starts_with("-----BEGIN RSA PUBLIC KEY-----"));
        let restored_pub = public_key_from_pem(&pem).unwrap();
        assert_eq!(restored_pub, public_key);

        // Private key DER roundtrip.
        let der = private_key_to_der(&private_key).unwrap();
        assert!(!der.is_empty());
        let restored_priv = private_key_from_der(&der).unwrap();
        assert_eq!(restored_priv, private_key);
    }

    #[test]
    fn test_wrap_unwrap_private_key() {
        let (priv_key, _pub_key) = generate_keypair().unwrap();
        let der = private_key_to_der(&priv_key).unwrap();
        let wrapped = wrap_private_key(&der, "my-setup-password").unwrap();
        let unwrapped = unwrap_private_key(&wrapped, "my-setup-password").unwrap();
        assert_eq!(der, unwrapped);
    }

    #[test]
    fn test_wrap_wrong_password_fails() {
        let (priv_key, _pub_key) = generate_keypair().unwrap();
        let der = private_key_to_der(&priv_key).unwrap();
        let wrapped = wrap_private_key(&der, "correct-password").unwrap();
        let result = unwrap_private_key(&wrapped, "wrong-password");
        assert!(result.is_err());
    }

    // ---------------------------------------------------------------------- //
    // High-level keystore operation tests                                     //
    // ---------------------------------------------------------------------- //

    fn sample_credentials() -> Credentials {
        Credentials {
            version: 1,
            vaultwarden: VaultwardenCreds {
                url: "https://vault.example.com".to_string(),
                email: "user@example.com".to_string(),
                master_password: "test-master-password-123".to_string(),
            },
            cloud: None,
            setup_password_hash: None,
        }
    }

    #[test]
    fn test_setup_and_unlock_software_mode() {
        let tmp = std::env::temp_dir().join("keystore_test_setup");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let config_dir = tmp.to_str().unwrap();

        let creds = sample_credentials();
        setup_keystore(config_dir, creds, "my-setup-password").unwrap();

        assert!(std::path::Path::new(&format!("{}/credentials.enc", config_dir)).exists());
        assert!(std::path::Path::new(&format!("{}/public_key.pem", config_dir)).exists());
        assert!(std::path::Path::new(&format!("{}/private_key.enc", config_dir)).exists());

        let decrypted = unlock_keystore(config_dir, Some("my-setup-password")).unwrap();
        assert_eq!(decrypted.vaultwarden.url, "https://vault.example.com");
        assert_eq!(
            decrypted.vaultwarden.master_password,
            "test-master-password-123"
        );

        let result = unlock_keystore(config_dir, Some("wrong-password"));
        assert!(result.is_err());

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_reencrypt_credentials() {
        let tmp = std::env::temp_dir().join("keystore_test_reencrypt");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let config_dir = tmp.to_str().unwrap();

        setup_keystore(config_dir, sample_credentials(), "password123").unwrap();

        let mut new_creds = sample_credentials();
        new_creds.vaultwarden.master_password = "rotated-password".into();
        reencrypt_credentials(config_dir, &new_creds).unwrap();

        let decrypted = unlock_keystore(config_dir, Some("password123")).unwrap();
        assert_eq!(decrypted.vaultwarden.master_password, "rotated-password");

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_reset_keystore() {
        let tmp = std::env::temp_dir().join("keystore_test_reset");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let config_dir = tmp.to_str().unwrap();

        setup_keystore(config_dir, sample_credentials(), "pw").unwrap();
        assert!(is_configured(config_dir));

        reset_keystore(config_dir).unwrap();
        assert!(!is_configured(config_dir));

        std::fs::remove_dir_all(&tmp).ok();
    }
}
