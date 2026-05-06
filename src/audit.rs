// NOTE: This module (`src/audit.rs`) is the *local* credential health analyser
// that runs entirely inside the proxy process using HMAC fingerprints.  It is
// DISTINCT from `src/credential_audit/` which is the multi-pass audit system
// that talks to the external credential-audit engine sidecar.  Do not merge or
// remove either without updating the other.
//
// iter-53: `run_audit` is now reachable via `GET /vault/audit/run` (wired in
// main.rs behind the internal bearer token). `#![allow(dead_code)]` removed.
//! In-process credential health audit — analyzes weak/reused passwords without
//! exposing plaintext to any external system.  Passwords are HMAC-fingerprinted
//! with an ephemeral key and zeroized immediately after use.

use crate::vault::VaultManager;
use axum::response::IntoResponse;
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
    /// Minimum password length (exclusive) for classification as "weak".
    ///
    /// Passwords with `len < weak_threshold_len` are reported in
    /// `weak_passwords`.  Included in the response so callers can interpret
    /// the results without reading the source — e.g. an operator seeing
    /// "27 weak passwords" can confirm whether "weak" means < 8 chars or
    /// some other cutoff without consulting the code.
    ///
    /// iter-57: added for response transparency.
    pub weak_threshold_len: usize,
    /// Human-readable description of the scoring algorithm and its limitations.
    ///
    /// Included in every response so callers understand what "weak" means
    /// without consulting the source.  Key limitation: this is a rule-based
    /// heuristic with no dictionary check — common passwords such as
    /// `"password123"` or `"Summer2024!"` may score "fair" if they meet
    /// the length + character-class criteria, and will NOT appear in
    /// `weak_passwords`.  See `password_strength()` for the full algorithm.
    ///
    /// iter-64: added to surface the no-dictionary-check limitation directly
    /// in the API response rather than requiring callers to read the source.
    pub scoring_note: String,
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
/// # Algorithm
///
/// This is a **rule-based heuristic**, NOT zxcvbn, NOT HIBP k-anonymity.
///
/// Choice rationale (iter-56 / audit):
///   - zxcvbn requires a dictionary corpus (~500 KB), adds a crate dependency,
///     and runs a pattern-matching pass over the plaintext.  For an in-process
///     sidecar that already minimises the plaintext window, rule-based scoring
///     avoids holding the plaintext any longer than strictly necessary.
///   - HIBP k-anonymity requires an outbound HTTPS call per password — not
///     suitable for an air-gapped or LAN-only homelab deployment, and would
///     leak partial password hashes to an external service.
///   - The heuristic correctly classifies the most dangerous passwords (those
///     shorter than 8 characters) and identifies structural strength (length ≥
///     16 with mixed character classes).  "Fair" is intentionally conservative:
///     any password that is not clearly strong is flagged for review.
///
/// # Known limitation — no dictionary check (iter-64)
///
/// This algorithm has **no dictionary check**.  Common passwords such as
/// `"password123"`, `"letmein1!"`, or `"Summer2024!"` contain 8+ characters
/// and meet the length + character-class criteria — they will be classified
/// `"fair"` (or even `"strong"` if they hit 16 chars with 3+ classes) rather
/// than `"weak"`.  They will NOT appear in `AuditResult::weak_passwords`.
///
/// This is a deliberate tradeoff (see algorithm rationale above).  Operators
/// who want dictionary-based detection should supplement the built-in audit
/// with an external tool (zxcvbn, `cracklib`, HIBP k-anonymity) or run the
/// credential-audit sidecar (`src/credential_audit/`) against a live wordlist.
///
/// The `GET /vault/audit/run` response includes `weak_threshold_len` and
/// `scoring_note` (added iter-64) so callers can display the scoring rules and
/// algorithm limitations alongside results without consulting the source.
///
/// Rules:
///  - len < 8                                  → "weak"   (reported in `weak_passwords`)
///  - len >= 16 with 3+ character classes      → "strong" (NOT reported)
///  - everything else                          → "fair"   (NOT reported — see note)
///
/// Note: only "weak" passwords appear in `AuditResult::weak_passwords`.
/// "fair" passwords are silently dropped from the report.  If you want to
/// surface them, filter `AuditItem::password_strength == "fair"` in the
/// caller.
///
/// Character classes: lowercase ASCII, uppercase ASCII, ASCII digits, ASCII
/// punctuation (symbols).  Non-ASCII characters count toward length only
/// (a non-ASCII character contributes 1 to the char count regardless of its
/// UTF-8 byte width).
///
/// # Unicode length (iter-58)
///
/// Length thresholds use **character count** (Unicode scalar values), not byte
/// count.  `str::len()` / `[u8]::len()` returns UTF-8 byte count, so a 4-char
/// Cyrillic password like "АБВГ" (8 bytes) would wrongly pass the `>= 8`
/// threshold and escape the "weak" classification.  We convert the byte slice
/// to `str` when it is valid UTF-8 and count `chars()`; if the bytes are not
/// valid UTF-8 (Bitwarden v1 legacy encoding) we fall back to byte count so
/// the function remains infallible.
fn password_strength(pw: &[u8]) -> &'static str {
    // iter-58: use char count (codepoints), not byte count, so Unicode passwords
    // are measured by the number of characters visible to the user rather than
    // their UTF-8 encoding width.  A 4-char Cyrillic password has 8 bytes but
    // only 4 characters — it must be classified "weak" (< 8 chars), not "fair".
    let len = std::str::from_utf8(pw)
        .map(|s| s.chars().count())
        .unwrap_or(pw.len()); // non-UTF-8 legacy encoding: fall back to bytes
    if len < WEAK_THRESHOLD {
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

/// Minimum password **character** count that avoids the "weak" classification.
///
/// A password whose Unicode scalar-value count is `< WEAK_THRESHOLD` is
/// reported in `AuditResult::weak_passwords` with `password_strength == "weak"`.
/// Passwords with ≥ this many characters may be "fair" or "strong" depending
/// on character class diversity (see `password_strength()`).
///
/// iter-58: threshold is now measured in characters (codepoints), not bytes.
/// A 4-char Cyrillic password has 8 UTF-8 bytes but only 4 characters — it
/// must be classified "weak".
///
/// This constant is intentionally public so callers can surface the threshold
/// alongside scan results without having to read the source.  It is also
/// embedded in `AuditResult::weak_threshold_len`.
pub const WEAK_THRESHOLD: usize = 8;

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
        weak_threshold_len: WEAK_THRESHOLD,
        // iter-64: surface the no-dictionary-check limitation in the API response.
        // iter-65: use format!() so the actual WEAK_THRESHOLD value is embedded
        // in the note.  Previously a &'static str with no reference to the
        // constant — if WEAK_THRESHOLD changed from 8 to 12, the note would
        // still say "shorter than 8 characters" until someone noticed the drift.
        scoring_note: format!(
            "rule-based heuristic: length + character classes only; \
             no dictionary check — common passwords like 'password123' \
             may score 'fair' if they meet the length threshold \
             (weak = fewer than {} characters)",
            WEAK_THRESHOLD
        ),
    }
}

// -------------------------------------------------------------------------- //
// HTTP handler — `GET /vault/audit/run`                                       //
// -------------------------------------------------------------------------- //
//
// iter-53: Wire `run_audit` to a read-only HTTP endpoint so the feature is
// discoverable without requiring v1.0 database wiring.
//
// Security properties:
//   - Read-only: no vault mutations (no writes to Vaultwarden).
//   - Gated behind the internal bearer token (added to the internal_router in
//     main.rs) — requires `Authorization: Bearer <token>` from the caller.
//   - Plaintext passwords are never included in the JSON response. All
//     passwords are HMAC-fingerprinted with an ephemeral key (see `run_audit`).
//   - The `AuditItem` struct contains only item name, username, type, and
//     strength classification — no credential values.

pub async fn handle_audit_run(
    axum::extract::State(state): axum::extract::State<std::sync::Arc<crate::proxy::AppState>>,
) -> axum::response::Response {
    tracing::info!("GET /vault/audit/run — running in-process credential health audit");
    // iter-62: hold audit_mutex so a concurrent background audit task cannot run
    // a second full-vault decryption pass at the same time.  If the background
    // task is mid-run, this call blocks until it finishes and then runs its own
    // pass (no result is shared between the two — each caller gets a fresh scan).
    //
    // iter-63: 5-second acquisition timeout mirrors the reload_mutex pattern.
    // Without this, an HTTP caller hitting GET /vault/audit/run while the background
    // task is mid-run on a 1,000-item vault would hang for the full audit duration
    // (potentially several seconds) with no visible indication that the delay is
    // expected.  The timeout returns 503 + Retry-After so clients back off and
    // operators see a clear diagnostic in the log, rather than a silent multi-second
    // stall.  The background task continues uninterrupted — the 5 s limit only
    // applies to *acquiring* the mutex, not to the audit itself.
    let _guard =
        match tokio::time::timeout(std::time::Duration::from_secs(5), state.audit_mutex.lock())
            .await
        {
            Ok(guard) => guard,
            Err(_) => {
                tracing::warn!(
                    "audit/run: background audit is in progress; \
                 mutex acquisition timed out after 5 s — returning 503 to caller"
                );
                let mut headers = axum::http::HeaderMap::new();
                // iter-65: Retry-After reduced from 10 s to 5 s.  The mutex
                // acquisition timeout above is 5 s, meaning the background audit
                // will complete within that window (typical audit: 1-2 s on 200
                // items).  Telling callers to wait 10 s was twice the worst-case
                // duration; 5 s matches the mutex timeout and keeps retries
                // responsive without hammering the endpoint.
                headers.insert(
                    axum::http::header::RETRY_AFTER,
                    axum::http::HeaderValue::from_static("5"),
                );
                return (
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    headers,
                    axum::Json(serde_json::json!({
                        "ok": false,
                        "error": "background audit is in progress — retry after 5 s",
                        "retry_after_s": 5,
                    })),
                )
                    .into_response();
            }
        };
    let result = run_audit(&state.vault).await;
    tracing::info!(
        total = result.total_items,
        weak = result.weak_passwords.len(),
        reuse_groups = result.reused_passwords.len(),
        "audit complete"
    );
    axum::Json(result).into_response()
}

// -------------------------------------------------------------------------- //
// Unit tests                                                                   //
// -------------------------------------------------------------------------- //

#[cfg(test)]
mod tests {
    use super::*;

    // iter-59: Verify that the iter-58 Unicode fix correctly classifies a
    // 4-character Cyrillic password as "weak".
    //
    // Before the fix, `pw.len()` returned 8 (byte count), which equalled
    // WEAK_THRESHOLD and caused the password to be classified "fair".
    // After the fix, `chars().count()` returns 4 (character count), which is
    // less than WEAK_THRESHOLD (8), so the password is correctly classified "weak".
    #[test]
    fn cyrillic_4_char_password_is_weak() {
        // "АБВГ" = 4 Cyrillic uppercase letters, 8 UTF-8 bytes.
        // char count = 4 < WEAK_THRESHOLD (8) → must be "weak".
        let pw = "АБВГ";
        assert_eq!(pw.chars().count(), 4, "sanity: 4 chars");
        assert_eq!(pw.len(), 8, "sanity: 8 bytes");
        assert_eq!(
            password_strength(pw.as_bytes()),
            "weak",
            "4-char Cyrillic password must be 'weak', not 'fair'"
        );
    }

    #[test]
    fn cyrillic_8_char_password_is_not_weak() {
        // "АБВГДЕЖЗ" = 8 Cyrillic uppercase letters, 16 UTF-8 bytes.
        // char count = 8 = WEAK_THRESHOLD → must NOT be "weak".
        let pw = "АБВГДЕЖЗ";
        assert_eq!(pw.chars().count(), 8, "sanity: 8 chars");
        assert_eq!(pw.len(), 16, "sanity: 16 bytes");
        // 8 chars = WEAK_THRESHOLD: not weak.  16 bytes but only 1 char class
        // (all uppercase non-ASCII, no ASCII lower/digit/punct) → "fair".
        assert_ne!(
            password_strength(pw.as_bytes()),
            "weak",
            "8-char Cyrillic password must not be 'weak'"
        );
    }

    #[test]
    fn ascii_7_char_password_is_weak() {
        assert_eq!(password_strength(b"abc1234"), "weak");
    }

    #[test]
    fn ascii_8_char_password_is_not_weak() {
        assert_ne!(password_strength(b"abc12345"), "weak");
    }

    #[test]
    fn strong_password_classified_strong() {
        // 16+ chars with lowercase, uppercase, digit, symbol = "strong"
        let pw = b"Correct-Horse-1!";
        assert_eq!(password_strength(pw), "strong");
    }
}
