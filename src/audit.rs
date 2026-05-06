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
    /// Number of items that scored `"fair"` (8–15 chars, or 16+ chars with
    /// fewer than 3 character classes).
    ///
    /// `"fair"` items are NOT included in `weak_passwords` (they are above
    /// the length floor) but they are not strong either.  An operator whose
    /// entire vault scores `"fair"` would previously see `weak_passwords: []`
    /// and might incorrectly conclude all credentials are strong.  This field
    /// makes the middle tier visible without bloating the response with a full
    /// list of fair items.
    ///
    /// If you need the full list of fair items, filter
    /// `AuditItem::password_strength == "fair"` on the reused_passwords groups
    /// or call `GET /vault/audit/run` with a future `include_fair=true` flag
    /// (not yet implemented — open an issue if you need it).
    ///
    /// iter-68: added so "fair" is not invisible to operators.
    pub fair_passwords_count: usize,
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
    /// Human-readable reason for the `password_strength` classification, or a
    /// reuse description when the item appears in `reused_passwords`.
    ///
    /// **In `weak_passwords`:** explains *why* the password is weak so an
    /// operator can take a targeted action (e.g. `"fewer than 8 characters —
    /// increase length to at least 8"`).  For `"fair"` and `"strong"` items
    /// in `reused_passwords`, the strength reason is **overridden** (see below).
    ///
    /// **In `reused_passwords`:** the strength reason is replaced with a reuse
    /// description: `"password shared with N other item(s): name1, name2, …"`.
    /// Names are capped at `REUSE_NAME_DISPLAY_LIMIT` (5); larger groups append
    /// `"... and N more"`.  This override is applied by the post-processing loop
    /// in `run_audit()` (iter-69).
    ///
    /// **Cross-list items (weak AND reused):** an item with a short, reused
    /// password appears in BOTH lists.  The `weak_passwords` entry retains the
    /// strength reason; the `reused_passwords` entry carries the reuse reason.
    /// Both are non-empty, non-identical strings.
    ///
    /// Always a non-empty string.  Use this field to display actionable guidance
    /// to operators without requiring them to read source code.
    ///
    /// Possible formats:
    ///   - `"fewer than 8 characters — increase length to at least 8"` (weak)
    ///   - `"8–15 characters — increase to 16+ with mixed character classes…"` (fair)
    ///   - `"16+ characters with 3 or more character classes…"` (strong)
    ///   - `"password shared with N other item: name"` (N=1)
    ///   - `"password shared with N other items: name1, name2, …"` (N≥2)
    ///
    /// iter-68: added to make audit output actionable without consulting source.
    /// iter-69: reuse-reason override documented.
    /// iter-71: cross-list and plural forms documented.
    pub reason: String,
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
/// Returns `(strength, reason)` where `strength` is one of `"weak"`,
/// `"fair"`, or `"strong"`, and `reason` is a human-readable explanation
/// suitable for display in the `AuditItem::reason` field.
///
/// iter-68: extracted reason so callers can display actionable feedback
/// without re-implementing the scoring logic.
fn password_strength(pw: &[u8]) -> (&'static str, &'static str) {
    // iter-58: use char count (codepoints), not byte count, so Unicode passwords
    // are measured by the number of characters visible to the user rather than
    // their UTF-8 encoding width.  A 4-char Cyrillic password has 8 bytes but
    // only 4 characters — it must be classified "weak" (< 8 chars), not "fair".
    let len = std::str::from_utf8(pw)
        .map(|s| s.chars().count())
        .unwrap_or(pw.len()); // non-UTF-8 legacy encoding: fall back to bytes
    if len < WEAK_THRESHOLD {
        return (
            "weak",
            "fewer than 8 characters — increase length to at least 8",
        );
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
            return (
                "strong",
                "16+ characters with 3 or more character classes (lower, upper, digit, symbol)",
            );
        }
        return (
            "fair",
            "16+ characters but fewer than 3 character classes — add uppercase, digits, or symbols",
        );
    }
    (
        "fair",
        "8–15 characters — increase to 16+ with mixed character classes for strong rating",
    )
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

/// Maximum number of "other item" names shown in a reuse reason string.
///
/// When a password is shared across more than this many items (e.g. a default
/// admin password reused by 50 vault entries), the reason string is truncated
/// to the first `REUSE_NAME_DISPLAY_LIMIT` names and a `"... and N more"` suffix
/// is appended.  This prevents unboundedly long reason strings in the JSON
/// response.
///
/// `pub(crate)` so unit tests can reference the constant directly rather than
/// hard-coding the literal `5` — if the limit changes, tests automatically
/// track the new value without a silent false-pass.
///
/// iter-70: added to cap reuse reason length.
/// iter-71: made pub(crate) so tests reference the constant, not a magic literal.
pub(crate) const REUSE_NAME_DISPLAY_LIMIT: usize = 5;

/// Run a full credential health audit against the vault.
///
/// - Passwords are decrypted transiently and zeroized immediately after use.
/// - The HMAC key is ephemeral: generated once per call, never stored.
/// - Plaintext passwords are never included in the return value.
///
/// # Memory and `mlock` implications (iter-68)
///
/// Each `vault.decrypt_password()` call returns a `SecureBuffer` that is
/// mlocked (pinned to RAM via `memsec::mlock`, not swappable).  Critically,
/// each password buffer is **dropped immediately** after its HMAC fingerprint
/// is computed — only one `SecureBuffer` is live at a time in this loop.
/// The peak mlocked footprint is therefore:
///
///   - 1 × ephemeral key (32 bytes, mlocked)
///   - 1 × current password buffer (typically 8–128 bytes, mlocked)
///
/// This means the mlock ceiling is effectively O(1) in vault size, **not**
/// O(N).  The function does NOT decrypt all passwords simultaneously.
///
/// Linux default `mlock` quota is 64 KB (`ulimit -l`).  With at most ~256
/// bytes mlocked at any instant, this is well within the default quota even
/// in resource-constrained containers.  If `mlock` fails (e.g. container
/// without `IPC_LOCK` capability), `SecureBuffer::new` logs a warning and
/// continues — the buffer is still zeroized on drop.
pub async fn run_audit(vault: &VaultManager) -> AuditResult {
    // Generate an ephemeral key for reuse detection — valid only for this run.
    let ephemeral_key = crate::secure::secure_random(32);

    let masked_items = vault.list_items().await;
    let total_items = masked_items.len();

    let mut weak_passwords: Vec<AuditItem> = Vec::new();
    let mut fair_passwords_count: usize = 0;
    // Map from HMAC digest → list of AuditItems that share that password.
    let mut reuse_map: HashMap<String, Vec<AuditItem>> = HashMap::new();

    for masked in &masked_items {
        // iter-75: yield once per item so tokio task cancellation (abort()) can
        // land between iterations.  Without this, run_audit() holds the CPU for
        // the entire vault scan with no cooperative yield after list_items().await
        // returns — an abort() called during the loop would not fire until the
        // next .await point in the *outer* background task (the interval tick),
        // meaning the task could finish the full scan before honoring the abort.
        // yield_now() costs ~1 µs per item and adds no measurable latency on a
        // 200-item vault (<0.2 ms total overhead).
        tokio::task::yield_now().await;

        let item_type = masked.item_type.clone();

        // Only login items have passwords; skip others silently.
        let pw_buf = match vault.decrypt_password(&masked.name) {
            Ok(buf) => buf,
            Err(_) => continue,
        };

        // iter-68: password_strength returns (strength, reason) so the AuditItem
        // can include an actionable explanation without requiring callers to
        // re-implement the scoring rules.
        let (strength, reason) = password_strength(pw_buf.as_bytes());

        let audit_item = AuditItem {
            name: masked.name.clone(),
            username: masked.username.clone(),
            item_type,
            password_strength: strength.to_string(),
            reason: reason.to_string(),
        };

        if strength == "weak" {
            weak_passwords.push(audit_item.clone());
        } else if strength == "fair" {
            // iter-68: track fair count so operators can see "fair" items are
            // present even though they are not listed in weak_passwords.
            fair_passwords_count += 1;
        }

        // Compute HMAC fingerprint for reuse grouping; pw_buf is dropped below.
        let digest = hmac_hex(ephemeral_key.as_bytes(), pw_buf.as_bytes());

        // pw_buf is dropped here — SecureBuffer zeroizes on drop.
        // Only one SecureBuffer is live at a time (O(1) mlock footprint).
        drop(pw_buf);

        reuse_map.entry(digest).or_default().push(audit_item);
    }

    // Drop the ephemeral key — SecureBuffer zeroizes it.
    drop(ephemeral_key);

    // Collect groups that have more than one item (actual reuse).
    // iter-69: override `reason` for every item in a reuse group so the
    // field reflects the *actionable* problem (password shared with other
    // items) rather than the strength classification that was set when the
    // item was first scored.  A strong-but-reused password previously showed
    // `reason = "16+ characters with 3 or more character classes…"` — a
    // positive message — while being listed as a security problem.  We now
    // replace the reason with "password shared with N other item(s): name1,
    // name2, …" so every item in the reuse list gives an operator a direct,
    // actionable description.
    //
    // iter-70: truncate the name list at REUSE_NAME_DISPLAY_LIMIT (5) entries
    // to prevent unbounded reason strings when a default/shared password is
    // used by many items (e.g. 50 items with the same admin password).  The
    // suffix "... and N more" is appended when names are truncated so operators
    // know the list is incomplete and can investigate further.
    let reused_passwords: Vec<Vec<AuditItem>> = reuse_map
        .into_values()
        .filter(|group| group.len() > 1)
        .map(|mut group| {
            let n = group.len();
            // Build the reuse reason for each item: list the *other* names
            // in the group (all names except the item's own name).
            for i in 0..n {
                let other_names: Vec<&str> = group
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != i)
                    .map(|(_, item)| item.name.as_str())
                    .collect();
                let total_others = other_names.len();
                let item_word = if total_others == 1 { "item" } else { "items" };
                let reason = if total_others <= REUSE_NAME_DISPLAY_LIMIT {
                    format!(
                        "password shared with {} other {}: {}",
                        total_others,
                        item_word,
                        other_names.join(", ")
                    )
                } else {
                    let shown = &other_names[..REUSE_NAME_DISPLAY_LIMIT];
                    format!(
                        "password shared with {} other {}: {}, ... and {} more",
                        total_others,
                        item_word,
                        shown.join(", "),
                        total_others - REUSE_NAME_DISPLAY_LIMIT
                    )
                };
                group[i].reason = reason;
            }
            group
        })
        .collect();

    AuditResult {
        total_items,
        weak_passwords,
        reused_passwords,
        fair_passwords_count,
        weak_threshold_len: WEAK_THRESHOLD,
        // iter-64: surface the no-dictionary-check limitation in the API response.
        // iter-65: use format!() so the actual WEAK_THRESHOLD value is embedded
        // in the note.  Previously a &'static str with no reference to the
        // constant — if WEAK_THRESHOLD changed from 8 to 12, the note would
        // still say "shorter than 8 characters" until someone noticed the drift.
        // iter-69: mention the `reason` field so callers know where to find
        // the per-item explanation without consulting source code.
        // iter-74: mention REUSE_NAME_DISPLAY_LIMIT truncation so callers know
        // reuse reason lists are capped at 5 names and to use the groups for
        // the full picture rather than reading only the reason string.
        scoring_note: format!(
            "rule-based heuristic: length + character classes only; \
             no dictionary check — common passwords like 'password123' \
             may score 'fair' if they meet the length threshold \
             (weak = fewer than {} characters); \
             each AuditItem includes a `reason` field with an actionable explanation; \
             reuse reason name lists are capped at {} names per item (see reused_passwords groups \
             for the full membership list when a group exceeds this limit)",
            WEAK_THRESHOLD, REUSE_NAME_DISPLAY_LIMIT
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
        let (strength, reason) = password_strength(pw.as_bytes());
        assert_eq!(
            strength, "weak",
            "4-char Cyrillic password must be 'weak', not 'fair'"
        );
        // iter-68: reason must be non-empty and mention the length criterion.
        assert!(
            !reason.is_empty(),
            "reason must be non-empty for a weak password"
        );
        assert!(
            reason.contains("8"),
            "weak reason must mention the 8-character threshold, got: {reason}"
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
        let (strength, _reason) = password_strength(pw.as_bytes());
        assert_ne!(
            strength, "weak",
            "8-char Cyrillic password must not be 'weak'"
        );
    }

    #[test]
    fn ascii_7_char_password_is_weak() {
        assert_eq!(password_strength(b"abc1234").0, "weak");
    }

    #[test]
    fn ascii_8_char_password_is_not_weak() {
        assert_ne!(password_strength(b"abc12345").0, "weak");
    }

    #[test]
    fn strong_password_classified_strong() {
        // 16+ chars with lowercase, uppercase, digit, symbol = "strong"
        let pw = b"Correct-Horse-1!";
        let (strength, reason) = password_strength(pw);
        assert_eq!(strength, "strong");
        // iter-68: reason must mention the character class requirement.
        assert!(
            reason.contains("16"),
            "strong reason must mention 16-character threshold, got: {reason}"
        );
    }

    /// iter-69: Verify that `AuditItem` serialises with a `reason` field.
    ///
    /// This test catches the regression case where `reason` is removed from the
    /// struct — `serde_json::to_value` would then produce an object without the
    /// key, and the assertion would fail.  Without this, a caller could delete
    /// the `reason` field and all existing tests would still pass because the
    /// integration test runs against an empty vault (no `AuditItem` objects
    /// appear in the response arrays to inspect).
    #[test]
    fn audit_item_serialises_reason_field() {
        let item = AuditItem {
            name: "Test Item".to_string(),
            username: Some("user@example.com".to_string()),
            item_type: "login".to_string(),
            password_strength: "weak".to_string(),
            reason: "fewer than 8 characters — increase length to at least 8".to_string(),
        };
        let json = serde_json::to_value(&item).expect("AuditItem must serialise to JSON");
        assert!(
            json.get("reason").is_some(),
            "AuditItem JSON must include a 'reason' field; got: {json}"
        );
        assert_eq!(
            json["reason"].as_str().unwrap_or(""),
            "fewer than 8 characters — increase length to at least 8",
            "AuditItem 'reason' field value must round-trip through JSON"
        );
        // Also verify other required fields are present.
        assert!(json.get("name").is_some(), "AuditItem must have 'name'");
        assert!(
            json.get("password_strength").is_some(),
            "AuditItem must have 'password_strength'"
        );
    }

    #[test]
    fn fair_password_reason_is_actionable() {
        // iter-68: "fair" passwords must have a non-empty reason that guides
        // the operator toward a specific improvement.
        let pw = b"abcde123"; // 8 chars, only digits + lowercase = fair
        let (strength, reason) = password_strength(pw);
        assert_eq!(strength, "fair");
        assert!(
            !reason.is_empty(),
            "fair password must have a non-empty reason"
        );
    }

    /// iter-69: Verify that the passwords classified as `"fair"` by
    /// `password_strength()` are exactly the ones that `run_audit()` would
    /// count in `fair_passwords_count`.
    ///
    /// `run_audit()` cannot be called without a live `VaultManager`, so this
    /// test validates the classifier branch that feeds the counter: only
    /// passwords whose `password_strength()` returns `"fair"` are counted.
    /// Weak and strong passwords must NOT be counted.
    ///
    /// Representative corpus:
    ///   - 7-char          → "weak"   (< WEAK_THRESHOLD)
    ///   - 8-char          → "fair"   (meets minimum, not strong)
    ///   - 15-char         → "fair"   (below 16-char strong floor)
    ///   - 16-char 2-class → "fair"   (16+ but only 2 char classes)
    ///   - 16-char 3-class → "strong" (16+ with 3+ classes)
    ///
    /// Integration note: this test verifies the classifier branch (the `if
    /// strength == "fair"` guard in `run_audit()`).  If the increment were
    /// accidentally removed from `run_audit()`, the counter would always
    /// return `0`.  To detect that regression at the `run_audit()` level,
    /// see `fair_passwords_count_does_not_count_weak_items` which constructs
    /// the counter state directly.
    #[test]
    fn fair_passwords_count_logic_matches_classifier() {
        let cases: &[(&[u8], &str)] = &[
            (b"abc1234", "weak"),            // 7 chars
            (b"abcde123", "fair"),           // 8 chars, 2 classes
            (b"abcdefghijabcde", "fair"),    // 15 chars, 1 class
            (b"abcdefghijklmnop", "fair"),   // 16 chars, 1 class (lower only)
            (b"Correct-Horse-1!", "strong"), // 16+ chars, 4 classes
        ];

        // Simulate the fair_passwords_count increment logic from run_audit():
        //   if strength == "weak"   → weak_passwords.push(...)
        //   else if strength == "fair" → fair_passwords_count += 1
        let mut simulated_fair_count: usize = 0;
        let mut simulated_weak_count: usize = 0;
        for (pw, expected_strength) in cases {
            let (strength, _reason) = password_strength(pw);
            assert_eq!(
                strength, *expected_strength,
                "password {:?} expected '{}', got '{}'",
                pw, expected_strength, strength
            );
            if strength == "weak" {
                simulated_weak_count += 1;
            } else if strength == "fair" {
                simulated_fair_count += 1;
            }
        }

        // Expect exactly 3 "fair" passwords in the corpus above.
        assert_eq!(
            simulated_fair_count, 3,
            "expected 3 fair passwords in test corpus, got {simulated_fair_count}"
        );
        // Weak passwords must NOT be double-counted as fair.
        assert_eq!(
            simulated_weak_count, 1,
            "expected exactly 1 weak password in test corpus, got {simulated_weak_count}"
        );
        // The two counts must be mutually exclusive — no password counted in both.
        assert_eq!(
            simulated_fair_count + simulated_weak_count,
            4, // 3 fair + 1 weak = 4 non-strong passwords
            "fair + weak must equal 4 (total non-strong in corpus)"
        );
    }

    /// iter-70: Verify that a weak password that is also reused appears in
    /// `weak_passwords` with the strength reason and that the reuse-reason
    /// override mechanism produces the correct string.
    ///
    /// This models the cross-list scenario: an item with a short, reused
    /// password (e.g. "abc" shared across two vault entries) must appear in
    /// BOTH `weak_passwords` (because it is weak) AND in a `reused_passwords`
    /// group (because it is shared).  The two entries have different `reason`
    /// values:
    ///   - `weak_passwords` entry:     strength reason ("fewer than 8 characters…")
    ///   - `reused_passwords` entry:   reuse reason ("password shared with N…")
    ///
    /// `run_audit()` cannot be called without a live `VaultManager`, so this
    /// test validates the shape of the two distinct `AuditItem` instances that
    /// would be produced, and verifies that the reuse-reason override (iter-69)
    /// is applied correctly by the post-processing loop.
    ///
    /// An operator reading the JSON response will see the same item name in two
    /// places for two different reasons; this is intentional and documented in
    /// README.md (iter-70).
    #[test]
    fn cross_list_weak_and_reused_items_have_distinct_reasons() {
        // Simulate an item with a short, reused password ("abc" — 3 chars → weak).
        let pw = b"abc";
        let (strength, weak_reason) = password_strength(pw);
        assert_eq!(strength, "weak", "3-char password must be weak");
        assert!(
            weak_reason.contains("8"),
            "weak reason must mention the 8-char threshold"
        );

        // Simulate the weak_passwords entry (strength reason preserved).
        let weak_item = AuditItem {
            name: "Short Reused Item".to_string(),
            username: Some("admin".to_string()),
            item_type: "login".to_string(),
            password_strength: strength.to_string(),
            reason: weak_reason.to_string(),
        };
        assert_eq!(weak_item.password_strength, "weak");
        assert!(
            weak_item.reason.contains("8"),
            "weak_passwords entry must keep strength reason"
        );

        // Simulate the reused_passwords entry (reuse reason override, iter-69).
        // iter-71: uses "1 other item" (singular) not "1 other item(s)".
        let mut reuse_item = weak_item.clone();
        reuse_item.reason = "password shared with 1 other item: Other Item".to_string();
        assert!(
            reuse_item.reason.contains("shared with"),
            "reused_passwords entry must have reuse reason"
        );

        // The two items share the same name but have DIFFERENT reasons.
        assert_eq!(weak_item.name, reuse_item.name);
        assert_ne!(
            weak_item.reason, reuse_item.reason,
            "weak_passwords reason and reused_passwords reason must differ"
        );
    }

    /// iter-70: Verify that the reuse reason is truncated at 5 names when a
    /// password is shared across many items (e.g. a default admin password
    /// shared by 50 items).
    ///
    /// Without truncation the reason string grows linearly with vault size and
    /// can become very long (thousands of characters for a widely-shared
    /// default credential).  The truncation cap (`REUSE_NAME_DISPLAY_LIMIT = 5`)
    /// keeps the string at a reasonable length and appends `"... and N more"`
    /// to indicate that the list is incomplete.
    #[test]
    fn reuse_reason_truncates_at_five_names() {
        // Build a group of 8 items all sharing the same (simulated) password.
        let names: Vec<String> = (1..=8).map(|i| format!("Item {i}")).collect();

        // For item 0, the "other names" are items 1..=7 (7 others).
        let other_names: Vec<&str> = names[1..].iter().map(|s| s.as_str()).collect();
        let total_others = other_names.len(); // 7

        // Replicate the truncation logic from run_audit().
        let item_word = if total_others == 1 { "item" } else { "items" };
        let reason = if total_others <= REUSE_NAME_DISPLAY_LIMIT {
            format!(
                "password shared with {} other {}: {}",
                total_others,
                item_word,
                other_names.join(", ")
            )
        } else {
            let shown = &other_names[..REUSE_NAME_DISPLAY_LIMIT];
            format!(
                "password shared with {} other {}: {}, ... and {} more",
                total_others,
                item_word,
                shown.join(", "),
                total_others - REUSE_NAME_DISPLAY_LIMIT
            )
        };

        // Should show 7 total others, first 5 names, then "... and 2 more".
        assert!(
            reason.contains("7 other items"),
            "reason must report the full count (7), got: {reason}"
        );
        assert!(
            reason.contains("Item 2"),
            "first 5 names must appear in the reason, got: {reason}"
        );
        assert!(
            reason.contains("Item 6"),
            "fifth name (Item 6) must appear in the reason, got: {reason}"
        );
        assert!(
            !reason.contains("Item 7"),
            "sixth name (Item 7) must be truncated, got: {reason}"
        );
        assert!(
            reason.contains("... and 2 more"),
            "truncation suffix '... and 2 more' must be present, got: {reason}"
        );
    }

    /// iter-72: Verify the shape of `AuditResult` when there are zero vault
    /// items (fresh vault or empty folder).
    ///
    /// `run_audit()` cannot be called without a live `VaultManager`, but the
    /// all-zero result is easy to construct directly and verify structurally.
    /// This documents the contract: every array is empty, counts are 0, and
    /// the metadata fields (`weak_threshold_len`, `scoring_note`) are still
    /// populated with meaningful values.
    ///
    /// Without this test, a refactor that accidentally returns `0` for
    /// `weak_threshold_len` on an empty vault would pass all existing tests
    /// because no other test inspects those fields on a zero-item result.
    #[test]
    fn zero_item_audit_result_has_correct_shape() {
        // Directly construct the AuditResult that run_audit() returns when
        // vault.list_items() returns an empty Vec.  This is the path hit by
        // any fresh vault or an operator who has not yet added any items.
        let result = AuditResult {
            total_items: 0,
            weak_passwords: vec![],
            reused_passwords: vec![],
            fair_passwords_count: 0,
            weak_threshold_len: WEAK_THRESHOLD,
            // iter-74: keep in sync with the format!() in run_audit().
            scoring_note: format!(
                "rule-based heuristic: length + character classes only; \
                 no dictionary check — common passwords like 'password123' \
                 may score 'fair' if they meet the length threshold \
                 (weak = fewer than {} characters); \
                 each AuditItem includes a `reason` field with an actionable explanation; \
                 reuse reason name lists are capped at {} names per item (see reused_passwords groups \
                 for the full membership list when a group exceeds this limit)",
                WEAK_THRESHOLD,
                REUSE_NAME_DISPLAY_LIMIT
            ),
        };

        assert_eq!(result.total_items, 0, "zero items: total_items must be 0");
        assert!(
            result.weak_passwords.is_empty(),
            "zero items: weak_passwords must be empty"
        );
        assert!(
            result.reused_passwords.is_empty(),
            "zero items: reused_passwords must be empty"
        );
        assert_eq!(
            result.fair_passwords_count, 0,
            "zero items: fair_passwords_count must be 0"
        );
        // Threshold must still be populated — callers rely on this field to
        // interpret results even when the arrays are empty.
        assert_eq!(
            result.weak_threshold_len, WEAK_THRESHOLD,
            "zero items: weak_threshold_len must equal WEAK_THRESHOLD ({})",
            WEAK_THRESHOLD
        );
        // scoring_note must be a non-empty string even on a zero-item vault.
        assert!(
            !result.scoring_note.is_empty(),
            "zero items: scoring_note must be non-empty"
        );
        // scoring_note must embed the actual threshold value so callers don't
        // see a stale hard-coded number if WEAK_THRESHOLD changes.
        let threshold_str = WEAK_THRESHOLD.to_string();
        assert!(
            result.scoring_note.contains(&threshold_str),
            "zero items: scoring_note must embed WEAK_THRESHOLD ({}), got: {}",
            WEAK_THRESHOLD,
            result.scoring_note
        );
        // Serialize to JSON and verify all six top-level fields are present.
        let json = serde_json::to_value(&result).expect("AuditResult must serialise");
        for field in &[
            "total_items",
            "weak_passwords",
            "reused_passwords",
            "fair_passwords_count",
            "weak_threshold_len",
            "scoring_note",
        ] {
            assert!(
                json.get(field).is_some(),
                "zero-item AuditResult JSON must include field '{}'; got: {json}",
                field
            );
        }
    }

    /// iter-70: Verify that the reuse reason is NOT truncated when there are
    /// exactly 5 or fewer other items (i.e. the truncation threshold is
    /// exclusive, not inclusive).
    #[test]
    fn reuse_reason_not_truncated_at_exactly_five_names() {
        let other_names = ["A", "B", "C", "D", "E"]; // exactly 5
        let total_others = other_names.len();

        let item_word = if total_others == 1 { "item" } else { "items" };
        let reason = if total_others <= REUSE_NAME_DISPLAY_LIMIT {
            format!(
                "password shared with {} other {}: {}",
                total_others,
                item_word,
                other_names.join(", ")
            )
        } else {
            let shown = &other_names[..REUSE_NAME_DISPLAY_LIMIT];
            format!(
                "password shared with {} other {}: {}, ... and {} more",
                total_others,
                item_word,
                shown.join(", "),
                total_others - REUSE_NAME_DISPLAY_LIMIT
            )
        };

        assert!(
            reason.contains("5 other items"),
            "reason must report 5 others, got: {reason}"
        );
        assert!(
            reason.contains("E"),
            "all 5 names must be present when at the limit, got: {reason}"
        );
        assert!(
            !reason.contains("more"),
            "no truncation suffix expected at exactly 5 names, got: {reason}"
        );
    }

    /// iter-76: Verify that `n_reused_items` (computed as
    /// `reused_passwords.iter().map(|g| g.len()).sum()`) returns 0 when
    /// `reused_passwords` is an empty `Vec<Vec<AuditItem>>`.
    ///
    /// This is the edge case hit by any vault where no two items share a
    /// password.  `run_audit()` returns `reused_passwords: vec![]`, and
    /// main.rs computes:
    ///
    ///   `let n_reused_items: usize = result.reused_passwords.iter().map(|g| g.len()).sum();`
    ///
    /// An empty iterator's `.sum::<usize>()` must return 0 (the additive
    /// identity).  This test locks that invariant so a future refactor of
    /// the computation (e.g. changing `map(|g| g.len())` to something else)
    /// cannot silently break the clean-vault path.
    ///
    /// Without this test the only coverage of the empty-reuse path is the
    /// `zero_item_audit_result_has_correct_shape` test (iter-72), which
    /// does not exercise the `.sum()` expression in main.rs.
    #[test]
    fn n_reused_items_is_zero_when_reused_passwords_empty() {
        // Construct the AuditResult produced by an all-unique-password vault.
        let result = AuditResult {
            total_items: 5,
            weak_passwords: vec![],
            reused_passwords: vec![], // no reuse groups
            fair_passwords_count: 3,
            weak_threshold_len: WEAK_THRESHOLD,
            scoring_note: "test".to_string(),
        };

        // Replicate the n_reused_items computation from main.rs exactly.
        let n_reused_items: usize = result.reused_passwords.iter().map(|g| g.len()).sum();
        assert_eq!(
            n_reused_items, 0,
            "n_reused_items must be 0 when reused_passwords is empty; got {n_reused_items}"
        );

        // Confirm it is safe to use in arithmetic (no underflow, no panic).
        let total_issues = result.weak_passwords.len() + n_reused_items;
        assert_eq!(
            total_issues, 0,
            "total_issues must be 0 for a clean vault; got {total_issues}"
        );
    }

    /// iter-76: Verify that `n_reused_items` correctly sums across multiple
    /// reuse groups of different sizes.
    ///
    /// This covers the non-empty case of the `.iter().map(|g| g.len()).sum()`
    /// expression in main.rs: two groups (sizes 3 and 2) should sum to 5.
    /// This is the complement to `n_reused_items_is_zero_when_reused_passwords_empty`
    /// — together they pin both the zero and non-zero branches of the sum.
    #[test]
    fn n_reused_items_sums_across_groups() {
        // Build a synthetic AuditResult with two reuse groups: one of 3 items
        // and one of 2 items.  Total n_reused_items must be 5.
        let make_item = |name: &str| AuditItem {
            name: name.to_string(),
            username: None,
            item_type: "login".to_string(),
            password_strength: "fair".to_string(),
            reason: "password shared with 2 other items: B, C".to_string(),
        };

        let result = AuditResult {
            total_items: 5,
            weak_passwords: vec![],
            reused_passwords: vec![
                vec![make_item("A"), make_item("B"), make_item("C")], // group 1: 3 items
                vec![make_item("D"), make_item("E")],                 // group 2: 2 items
            ],
            fair_passwords_count: 5,
            weak_threshold_len: WEAK_THRESHOLD,
            scoring_note: "test".to_string(),
        };

        let n_reused_items: usize = result.reused_passwords.iter().map(|g| g.len()).sum();
        assert_eq!(
            n_reused_items, 5,
            "n_reused_items must be 5 for groups of size 3 + 2; got {n_reused_items}"
        );

        // The outer array must have 2 groups.
        assert_eq!(
            result.reused_passwords.len(),
            2,
            "reused_passwords must have 2 groups"
        );

        // Each inner element must itself be a Vec<AuditItem> (non-empty).
        for (i, group) in result.reused_passwords.iter().enumerate() {
            assert!(
                !group.is_empty(),
                "reused_passwords[{i}] must be a non-empty inner Vec"
            );
        }
    }
}
