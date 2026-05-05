//! Bitwarden/Vaultwarden cryptographic primitives.
//!
//! Key derivation flow (mirrors the TypeScript reference implementation):
//!   1. PBKDF2-SHA256(password, email.to_lowercase(), iterations, 32) → master_key
//!   2. PBKDF2-SHA256(master_key, password, 1, 32)                    → password_hash (base64)
//!   3. HKDF-expand(master_key, "enc") + HKDF-expand(master_key, "mac") → stretched keys
//!   4. AES-256-CBC + HMAC-SHA256 decryption of cipher strings (type 2)

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use rand::RngCore;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use zeroize::Zeroize;

use rsa::{pkcs8::DecodePrivateKey, Oaep, RsaPrivateKey};
use sha1::Sha1;

use crate::secure::SecureBuffer;

type HmacSha256 = Hmac<Sha256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

// -------------------------------------------------------------------------- //
// Public API                                                                  //
// -------------------------------------------------------------------------- //

/// Derive the 32-byte master key from the user's master password and email.
///
/// The email is lowercased before use, matching Bitwarden's behaviour.
pub fn derive_master_key(password: &str, email: &str, iterations: u32) -> SecureBuffer {
    let email_lower = email.to_lowercase();
    let mut out = vec![0u8; 32];
    pbkdf2_hmac::<Sha256>(
        password.as_bytes(),
        email_lower.as_bytes(),
        iterations,
        &mut out,
    );
    SecureBuffer::new(out)
}

/// Derive the password hash that is sent to the identity server.
///
/// Returns a base64-encoded string suitable for the `password` field of the
/// token request.
pub fn hash_master_password(master_key: &[u8], password: &str) -> String {
    let mut out = vec![0u8; 32];
    pbkdf2_hmac::<Sha256>(master_key, password.as_bytes(), 1, &mut out);
    let encoded = B64.encode(&out);
    out.zeroize();
    encoded
}

/// Decrypt the encrypted symmetric key returned by the token endpoint.
///
/// Returns `(enc_key, mac_key)` — two 32-byte `SecureBuffer`s.
pub fn decrypt_symmetric_key(
    encrypted_key: &str,
    master_key: &[u8],
) -> Result<(SecureBuffer, SecureBuffer)> {
    let (mut stretch_enc, mut stretch_mac) = stretch_master_key(master_key);

    let decrypted = decrypt_cipher_string(encrypted_key, &stretch_enc, &stretch_mac)
        .context("failed to decrypt symmetric key")?;

    // Zeroize stretched keys immediately after use.
    stretch_enc.zeroize();
    stretch_mac.zeroize();

    if decrypted.len() < 64 {
        bail!(
            "decrypted symmetric key is too short: {} bytes (expected 64)",
            decrypted.len()
        );
    }

    let enc_key = SecureBuffer::new(decrypted[..32].to_vec());
    let mac_key = SecureBuffer::new(decrypted[32..64].to_vec());
    Ok((enc_key, mac_key))
}

/// Decrypt a Bitwarden cipher string (type 2: AES-256-CBC + HMAC-SHA256).
///
/// Format: `"2.{iv_b64}|{data_b64}|{mac_b64}"`
pub fn decrypt_cipher_string(
    cipher_string: &str,
    enc_key: &[u8],
    mac_key: &[u8],
) -> Result<SecureBuffer> {
    // Split "2.iv|data|mac"
    let dot_pos = cipher_string
        .find('.')
        .ok_or_else(|| anyhow!("cipher string missing type prefix"))?;
    let type_str = &cipher_string[..dot_pos];
    let rest = &cipher_string[dot_pos + 1..];

    if type_str != "2" {
        bail!("unsupported cipher type: {}", type_str);
    }

    let parts: Vec<&str> = rest.splitn(3, '|').collect();
    if parts.len() != 3 {
        bail!("invalid cipher string format: expected 3 parts, got {}", parts.len());
    }

    let iv = B64
        .decode(parts[0])
        .context("failed to base64-decode IV")?;
    let data = B64
        .decode(parts[1])
        .context("failed to base64-decode ciphertext")?;
    let expected_mac = B64
        .decode(parts[2])
        .context("failed to base64-decode MAC")?;

    // Verify HMAC-SHA256(mac_key, iv || data)
    let mut mac = HmacSha256::new_from_slice(mac_key)
        .map_err(|e| anyhow!("HMAC key error: {}", e))?;
    mac.update(&iv);
    mac.update(&data);
    mac.verify_slice(&expected_mac)
        .map_err(|_| anyhow!("HMAC verification failed"))?;

    // AES-256-CBC decrypt with PKCS7 unpadding
    let iv_arr: [u8; 16] = iv
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("IV must be 16 bytes, got {}", iv.len()))?;
    let enc_key_arr: [u8; 32] = enc_key
        .try_into()
        .map_err(|_| anyhow!("enc_key must be 32 bytes, got {}", enc_key.len()))?;

    let mut buf = data.clone();
    let result = Aes256CbcDec::new(&enc_key_arr.into(), &iv_arr.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| anyhow!("AES-CBC decrypt/unpad failed: {}", e))
        .map(|plaintext| SecureBuffer::new(plaintext.to_vec()));

    // Zeroize the intermediate `buf` — it holds the CBC-decrypted plaintext
    // of every vault field (passwords, API keys, private key material).
    // `SecureBuffer` zeroizes its own contents on drop, but the original
    // `buf` binding is a plain `Vec<u8>` the allocator might not overwrite.
    use zeroize::Zeroize;
    buf.zeroize();

    result
}

/// Attempt to decrypt an optional cipher string to a `String`.
///
/// Returns `None` if `cipher_string` is `None`, or if decryption/UTF-8
/// conversion fails (silently — callers use this for best-effort field
/// decryption).
pub fn decrypt_to_string(
    cipher_string: Option<&str>,
    enc_key: &[u8],
    mac_key: &[u8],
) -> Option<String> {
    let cs = cipher_string?;
    let buf = decrypt_cipher_string(cs, enc_key, mac_key).ok()?;
    String::from_utf8(buf.to_vec()).ok()
}

/// Decrypt a type-4 cipher string (RSA-OAEP with SHA-1).
///
/// Format: `"4.{base64_data}"` — no IV or MAC, just RSA-encrypted data.
/// The `private_key_der` must be PKCS#8 DER bytes of the user's RSA private key.
pub fn decrypt_cipher_string_rsa(
    cipher_string: &str,
    private_key_der: &[u8],
) -> Result<SecureBuffer> {
    let dot_pos = cipher_string
        .find('.')
        .ok_or_else(|| anyhow!("cipher string missing type prefix"))?;
    let type_str = &cipher_string[..dot_pos];
    let rest = &cipher_string[dot_pos + 1..];

    if type_str != "4" {
        bail!("expected RSA cipher type 4, got type {}", type_str);
    }

    let ciphertext = B64
        .decode(rest)
        .context("failed to base64-decode RSA ciphertext")?;

    let private_key = RsaPrivateKey::from_pkcs8_der(private_key_der)
        .context("failed to parse RSA private key from PKCS#8 DER")?;

    let padding = Oaep::new::<Sha1>();
    let plaintext = private_key
        .decrypt(padding, &ciphertext)
        .context("RSA-OAEP decryption failed")?;

    Ok(SecureBuffer::new(plaintext))
}

/// Decrypt the user's RSA private key from the profile.
///
/// The private key is a type-2 cipher string encrypted with the user's symmetric key.
/// Returns the raw PKCS#8 DER bytes as a SecureBuffer.
pub fn decrypt_private_key(
    encrypted_private_key: &str,
    enc_key: &[u8],
    mac_key: &[u8],
) -> Result<SecureBuffer> {
    decrypt_cipher_string(encrypted_private_key, enc_key, mac_key)
        .context("failed to decrypt RSA private key")
}

/// Encrypt raw bytes into a Bitwarden cipher string (type 2: AES-256-CBC + HMAC-SHA256).
///
/// Format: `"2.{iv_b64}|{ciphertext_b64}|{mac_b64}"`
pub fn encrypt_cipher_string(plaintext: &[u8], enc_key: &[u8], mac_key: &[u8]) -> Result<String> {
    // Generate a random 16-byte IV.
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    // Validate key lengths.
    let enc_key_arr: [u8; 32] = enc_key
        .try_into()
        .map_err(|_| anyhow!("enc_key must be 32 bytes, got {}", enc_key.len()))?;

    // AES-256-CBC encrypt with PKCS7 padding.
    let ciphertext = Aes256CbcEnc::new(&enc_key_arr.into(), &iv.into())
        .encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    // HMAC-SHA256(mac_key, iv || ciphertext)
    let mut mac = HmacSha256::new_from_slice(mac_key)
        .map_err(|e| anyhow!("HMAC key error: {}", e))?;
    mac.update(&iv);
    mac.update(&ciphertext);
    let mac_bytes = mac.finalize().into_bytes();

    Ok(format!(
        "2.{}|{}|{}",
        B64.encode(iv),
        B64.encode(&ciphertext),
        B64.encode(mac_bytes)
    ))
}

/// Encrypt a UTF-8 string into a Bitwarden cipher string (type 2: AES-256-CBC + HMAC-SHA256).
pub fn encrypt_to_cipher_string(plaintext: &str, enc_key: &[u8], mac_key: &[u8]) -> Result<String> {
    encrypt_cipher_string(plaintext.as_bytes(), enc_key, mac_key)
}

// -------------------------------------------------------------------------- //
// Private helpers                                                             //
// -------------------------------------------------------------------------- //

/// HKDF-expand step using HMAC-SHA256.
///
/// This is a single-block expand: HMAC-SHA256(key, info || 0x01).
/// Matches the TypeScript reference implementation.
fn hkdf_expand(key: &[u8], info: &str) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(info.as_bytes());
    mac.update(&[0x01u8]);
    mac.finalize().into_bytes().to_vec()
}

/// Stretch a 32-byte master key into separate enc and mac keys using HKDF.
///
/// Both returned `Vec<u8>` values should be zeroized after use.
pub fn stretch_master_key(master_key: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let enc = hkdf_expand(master_key, "enc");
    let mac = hkdf_expand(master_key, "mac");
    (enc, mac)
}

// -------------------------------------------------------------------------- //
// Tests                                                                       //
// -------------------------------------------------------------------------- //

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_master_key_deterministic() {
        let k1 = derive_master_key("hunter2", "user@example.com", 100_000);
        let k2 = derive_master_key("hunter2", "user@example.com", 100_000);
        assert_eq!(k1.as_bytes(), k2.as_bytes(), "same inputs must produce same key");
        assert_eq!(k1.len(), 32);
    }

    #[test]
    fn test_derive_master_key_email_case_insensitive() {
        let lower = derive_master_key("hunter2", "user@example.com", 100_000);
        let upper = derive_master_key("hunter2", "USER@EXAMPLE.COM", 100_000);
        let mixed = derive_master_key("hunter2", "User@Example.Com", 100_000);
        assert_eq!(lower.as_bytes(), upper.as_bytes(), "email case must not affect key");
        assert_eq!(lower.as_bytes(), mixed.as_bytes(), "email case must not affect key");
    }

    #[test]
    fn test_hash_master_password() {
        let master_key = derive_master_key("hunter2", "user@example.com", 100_000);
        let hash = hash_master_password(master_key.as_bytes(), "hunter2");
        assert!(!hash.is_empty(), "hash must not be empty");
        // Valid base64 — should decode without error.
        B64.decode(&hash).expect("hash must be valid base64");
        assert_eq!(B64.decode(&hash).unwrap().len(), 32, "hash must decode to 32 bytes");
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let enc_key = [0x01u8; 32];
        let mac_key = [0x02u8; 32];
        let original = b"Hello, Bitwarden!";

        let cipher_string = encrypt_cipher_string(original, &enc_key, &mac_key)
            .expect("encryption must succeed");

        println!("cipher_string: {}", cipher_string);

        let decrypted = decrypt_cipher_string(&cipher_string, &enc_key, &mac_key)
            .expect("decryption must succeed");

        assert_eq!(decrypted.as_bytes(), original, "roundtrip must preserve plaintext");
    }

    #[test]
    fn test_encrypt_decrypt_empty_string() {
        let enc_key = [0xAAu8; 32];
        let mac_key = [0xBBu8; 32];
        let original = b"";

        let cipher_string = encrypt_cipher_string(original, &enc_key, &mac_key)
            .expect("encryption of empty string must succeed");

        println!("empty cipher_string: {}", cipher_string);

        let decrypted = decrypt_cipher_string(&cipher_string, &enc_key, &mac_key)
            .expect("decryption of empty string must succeed");

        assert_eq!(decrypted.as_bytes(), original, "empty string roundtrip must work");
    }

    #[test]
    fn test_hkdf_expand_deterministic() {
        let key = b"test_key_32_bytes_padding_here__";
        let enc1 = hkdf_expand(key, "enc");
        let enc2 = hkdf_expand(key, "enc");
        assert_eq!(enc1, enc2);
        assert_ne!(hkdf_expand(key, "enc"), hkdf_expand(key, "mac"),
            "enc and mac expansions must differ");
    }
}
