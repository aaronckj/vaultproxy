// iter-50: scaffold module — not yet fully wired to production call sites.
#![allow(dead_code)]
//! Security audit — analyzes credential health without exposing passwords.

use crate::vault::VaultManager;
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;
use std::collections::HashMap;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Serialize)]
pub struct AuditResult {
    pub total_items: usize,
    pub weak_passwords: Vec<AuditItem>,
    pub reused_passwords: Vec<Vec<AuditItem>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditItem {
    pub name: String,
    pub username: Option<String>,
    pub item_type: String,
    pub password_strength: String, // "weak", "fair", "strong"
}

/// Determine password strength without storing the plaintext.
///
/// Rules:
///  - len < 8                                  → "weak"
///  - len >= 16 with 3+ character classes      → "strong"
///  - everything else                          → "fair"
fn password_strength(pw: &[u8]) -> &'static str {
    let len = pw.len();
    if len < 8 {
        return "weak";
    }
    if len >= 16 {
        let has_lower = pw.iter().any(|b| b.is_ascii_lowercase());
        let has_upper = pw.iter().any(|b| b.is_ascii_uppercase());
        let has_digit = pw.iter().any(|b| b.is_ascii_digit());
        let has_symbol = pw.iter().any(|b| b.is_ascii_punctuation());
        let classes = [has_lower, has_upper, has_digit, has_symbol]
            .iter()
            .filter(|&&v| v)
            .count();
        if classes >= 3 {
            return "strong";
        }
    }
    "fair"
}

/// Compute HMAC-SHA256(key, data) and return the hex-encoded digest.
fn hmac_hex(key: &[u8], data: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    result.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Run a full credential health audit against the vault.
///
/// - Passwords are decrypted transiently and zeroized immediately after use.
/// - The HMAC key is ephemeral: generated once per call, never stored.
/// - Plaintext passwords are never included in the return value.
pub async fn run_audit(vault: &VaultManager) -> AuditResult {
    // Generate an ephemeral key for reuse detection — valid only for this run.
    let ephemeral_key = crate::secure::secure_random(32);

    let masked_items = vault.list_items().await;
    let total_items = masked_items.len();

    let mut weak_passwords: Vec<AuditItem> = Vec::new();
    // Map from HMAC digest → list of AuditItems that share that password.
    let mut reuse_map: HashMap<String, Vec<AuditItem>> = HashMap::new();

    for masked in &masked_items {
        let item_type = masked.item_type.clone();

        // Only login items have passwords; skip others silently.
        let pw_buf = match vault.decrypt_password(&masked.name) {
            Ok(buf) => buf,
            Err(_) => continue,
        };

        let strength = password_strength(pw_buf.as_bytes());

        let audit_item = AuditItem {
            name: masked.name.clone(),
            username: masked.username.clone(),
            item_type,
            password_strength: strength.to_string(),
        };

        if strength == "weak" {
            weak_passwords.push(audit_item.clone());
        }

        // Compute HMAC fingerprint for reuse grouping; pw_buf is dropped below.
        let digest = hmac_hex(ephemeral_key.as_bytes(), pw_buf.as_bytes());

        // pw_buf is dropped here — SecureBuffer zeroizes on drop.
        drop(pw_buf);

        reuse_map.entry(digest).or_default().push(audit_item);
    }

    // Drop the ephemeral key — SecureBuffer zeroizes it.
    drop(ephemeral_key);

    // Collect groups that have more than one item (actual reuse).
    let reused_passwords: Vec<Vec<AuditItem>> = reuse_map
        .into_values()
        .filter(|group| group.len() > 1)
        .collect();

    AuditResult {
        total_items,
        weak_passwords,
        reused_passwords,
    }
}
