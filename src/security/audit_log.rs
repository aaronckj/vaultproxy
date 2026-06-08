//! Audit log — records tool invocations with timestamps, permissions,
//! and truncated argument/result summaries.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Mutex;

/// Maximum number of entries to keep in memory and on disk.
const MAX_ENTRIES: usize = 1000;

/// Maximum length for args/result summaries.
const MAX_SUMMARY_LEN: usize = 200;

/// Sensitive field names whose values should be masked. The `contains`
/// check on the lowercased key catches hyphen/underscore variants with a
/// single entry, so we only need the bare stems. Expanded in iter-15 to
/// cover session cookies (UniFi), bearer tokens (HA), TOTP/2FA codes, and
/// passphrase spellings that the pre-iter-15 list missed.
const SENSITIVE_FIELDS: &[&str] = &[
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "api-key",
    "master_password",
    "credential",
    "cred",
    "auth",
    "auth_key",
    "bearer",
    "cookie",
    "session",
    "otp",
    "tfa",
    "2fa",
    "passphrase",
    "pass_phrase",
    "access_key",
    "private_key",
];

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub tool_name: String,
    pub args_summary: String,
    pub result_summary: String,
    pub permission: String,
    pub trigger: String,
    /// Transparent-mode entries only. When `trigger == "transparent"`
    /// these carry the per-request telemetry the regular /proxy
    /// fields cannot represent. `None` on all non-transparent entries
    /// so the JSON file stays backwards compatible — serde will omit
    /// the field when None.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transparent_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_in: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_out: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

pub struct AuditLog {
    /// Entries + unpersisted-write counter under one lock. Previously these
    /// were two separate `RwLock`s; poison on the second while holding the
    /// first could leave the counter frozen and silently disable the
    /// periodic save path for the rest of the process lifetime.
    state: Mutex<AuditState>,
    path: String,
    /// SIEM-friendly sinks. Empty = file-only (the v1.4.x behaviour).
    /// Each `log()` fans out to every sink in order; sink errors are
    /// logged at WARN and never block the live append path.
    sinks: Vec<Box<dyn crate::security::audit_sinks::AuditSink>>,
}

struct AuditState {
    entries: VecDeque<AuditEntry>,
    /// Counter to batch saves (save every N writes). Reset to zero after save.
    write_count: usize,
}

impl AuditLog {
    /// Create a new audit log, loading existing entries from disk if available.
    pub fn new(path: &str) -> Self {
        let mut entries = match std::fs::read_to_string(path) {
            Ok(contents) => {
                serde_json::from_str::<VecDeque<AuditEntry>>(&contents).unwrap_or_default()
            }
            Err(_) => VecDeque::new(),
        };

        // Enforce cap on entries loaded from disk — the file could have been
        // manually edited or corrupted to contain more than MAX_ENTRIES.
        while entries.len() > MAX_ENTRIES {
            entries.pop_back();
        }

        Self {
            state: Mutex::new(AuditState {
                entries,
                write_count: 0,
            }),
            path: path.to_string(),
            sinks: Vec::new(),
        }
    }

    /// Replace the SIEM sink list. main.rs calls this once at startup
    /// after parsing `--audit-sink`. Existing sinks are dropped.
    pub fn set_sinks(&mut self, sinks: Vec<Box<dyn crate::security::audit_sinks::AuditSink>>) {
        self.sinks = sinks;
    }

    /// Acquire the state lock, recovering from poisoning so a panicked
    /// writer doesn't permanently kill audit logging. `tracing::warn` the
    /// poison event — silent recovery would hide the root-cause panic.
    fn lock_state(&self) -> std::sync::MutexGuard<'_, AuditState> {
        match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                tracing::warn!("audit log state mutex was poisoned — recovering");
                poisoned.into_inner()
            }
        }
    }

    /// Log a new audit entry. Caps at MAX_ENTRIES and saves periodically.
    /// Entries evicted from the front file (because the cap was hit) are
    /// appended to a JSONL archive at `<path>.archive` so transparent or
    /// high-frequency traffic does not lose audit history.
    pub fn log(&self, entry: AuditEntry) {
        // Fan out to SIEM sinks first, using the original entry (before
        // it's moved into the in-memory deque). Sinks are best-effort
        // and synchronous — they MUST not block significant time.
        // Empty sink list = no-op fast path.
        if !self.sinks.is_empty() {
            for sink in &self.sinks {
                sink.emit(&entry);
            }
        }

        // Single-lock critical section: push, cap, bump counter, decide on
        // save. Gather a snapshot of entries if a save is due so `save_impl`
        // can run without re-acquiring the lock.
        let mut evicted: Vec<AuditEntry> = Vec::new();
        let snapshot: Option<Vec<AuditEntry>> = {
            let mut st = self.lock_state();
            st.entries.push_front(entry);
            while st.entries.len() > MAX_ENTRIES {
                if let Some(old) = st.entries.pop_back() {
                    evicted.push(old);
                }
            }
            st.write_count += 1;
            if st.write_count >= 10 {
                st.write_count = 0;
                Some(st.entries.iter().cloned().collect())
            } else {
                None
            }
        };

        if !evicted.is_empty() {
            self.append_to_archive(&evicted);
        }
        if let Some(entries) = snapshot {
            self.save_impl(&entries);
        }
    }

    /// Append evicted entries to a JSONL archive next to the main file.
    /// One JSON object per line so appending is cheap and atomic at the
    /// OS write boundary (typical entry < 4 KiB, well under PIPE_BUF).
    /// Failures log a WARN — archive writes are best-effort and never
    /// block the live append path.
    fn append_to_archive(&self, evicted: &[AuditEntry]) {
        use std::io::Write;
        let archive_path = format!("{}.archive", self.path);
        let mut f = match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&archive_path)
        {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!(
                    path = %archive_path,
                    error = %e,
                    "audit archive open failed; evicted entries lost",
                );
                return;
            }
        };
        for entry in evicted {
            match serde_json::to_string(entry) {
                Ok(line) => {
                    if let Err(e) = writeln!(f, "{line}") {
                        tracing::warn!(error = %e, "audit archive write failed");
                        return;
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "audit archive serialise failed");
                }
            }
        }
    }

    /// Return recent entries (newest first).
    #[allow(dead_code)] // called by dashboard audit log endpoint (#[cfg(feature = "dashboard")])
    pub fn entries(&self) -> Vec<AuditEntry> {
        self.lock_state().entries.iter().cloned().collect()
    }

    /// Convenience for the transparent listener. Pre-fills the
    /// shared fields and the transparent-specific fields in a single
    /// call site so mitm.rs / passthrough.rs don't repeat the
    /// boilerplate. `mode` is a stringified TransparentMode
    /// (`"host_inject"` | `"placeholder"` | `"passthrough"`).
    #[allow(dead_code, clippy::too_many_arguments)]
    pub fn log_transparent(
        &self,
        mode: &str,
        host: &str,
        upstream_status: Option<u16>,
        bytes_in: u64,
        bytes_out: u64,
        duration_ms: u64,
    ) {
        let entry = AuditEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            tool_name: format!("transparent::{mode}::{host}"),
            args_summary: format!("host={host} mode={mode}"),
            result_summary: format!(
                "status={} bytes_in={} bytes_out={}",
                upstream_status
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "?".into()),
                bytes_in,
                bytes_out,
            ),
            permission: "Log".to_string(),
            trigger: "transparent".to_string(),
            transparent_mode: Some(mode.to_string()),
            upstream_host: Some(host.to_string()),
            upstream_status,
            bytes_in: Some(bytes_in),
            bytes_out: Some(bytes_out),
            duration_ms: Some(duration_ms),
        };
        self.log(entry);
    }

    /// Persist the log to disk. Uses safe_write_config to reject symlinks.
    pub fn save(&self) {
        let snapshot: Vec<AuditEntry> = self.lock_state().entries.iter().cloned().collect();
        self.save_impl(&snapshot);
    }

    fn save_impl(&self, entries: &[AuditEntry]) {
        match serde_json::to_string_pretty(entries) {
            Ok(json) => {
                if let Err(e) = crate::secure::safe_write_config(&self.path, json.as_bytes()) {
                    tracing::warn!("failed to save audit log: {}", e);
                }
            }
            Err(e) => {
                tracing::warn!("failed to serialize audit log: {}", e);
            }
        }
    }

    /// Create an args summary string with sensitive values masked.
    pub fn summarize_args(args: &serde_json::Value) -> String {
        let mut summary = if let Some(obj) = args.as_object() {
            let mut parts = Vec::new();
            for (k, v) in obj {
                let val = if SENSITIVE_FIELDS
                    .iter()
                    .any(|f| k.to_lowercase().contains(f))
                {
                    "***".to_string()
                } else {
                    truncate_str(&mask_sensitive(v).to_string(), 50)
                };
                parts.push(format!("{}={}", k, val));
            }
            parts.join(", ")
        } else {
            truncate_str(&mask_sensitive(args).to_string(), MAX_SUMMARY_LEN)
        };

        if summary.len() > MAX_SUMMARY_LEN {
            summary = truncate_str(&summary, MAX_SUMMARY_LEN);
        }
        summary
    }

    /// Create a result summary string with sensitive values masked, then
    /// truncated.
    ///
    /// Issue-6 (iter-6): The previous implementation serialised the result
    /// JSON verbatim into the audit log. An upstream service that returns a
    /// body containing credential-adjacent field names (e.g. `{"token":
    /// "eyJ…"}`, `{"password": "hunter2"}`, `{"api_key": "sk-…"}`) would
    /// persist those values to disk in plaintext. The audit log is world-
    /// readable by any process running as the same UID as vault-proxy.
    ///
    /// Fix: recursively mask values under known-sensitive keys (see
    /// `mask_sensitive`) so secrets in objects, arrays, and nested values are
    /// replaced with `***` before the entry is written; the result is then
    /// truncated.
    ///
    /// Known limitation: masking is key-based on parsed JSON. A secret embedded
    /// inside a JSON *string* leaf (e.g. `{"text":"{\"token\":\"…\"}"}`) is not
    /// inspected, and is masked only if a higher-level key name matches.
    pub fn summarize_result(result: &serde_json::Value) -> String {
        let summary = if let Some(obj) = result.as_object() {
            let mut parts = Vec::new();
            for (k, v) in obj {
                let val = if SENSITIVE_FIELDS
                    .iter()
                    .any(|f| k.to_lowercase().contains(f))
                {
                    "***".to_string()
                } else {
                    truncate_str(&mask_sensitive(v).to_string(), 50)
                };
                parts.push(format!("{}={}", k, val));
            }
            parts.join(", ")
        } else {
            mask_sensitive(result).to_string()
        };
        truncate_str(&summary, MAX_SUMMARY_LEN)
    }
}

impl Drop for AuditLog {
    fn drop(&mut self) {
        self.save();
    }
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        // Truncate at the largest char boundary <= max_len. Tool args and
        // upstream results are attacker-influenced; `&s[..max_len]` panics on a
        // multi-byte boundary.
        let mut end = max_len;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        let mut result = s[..end].to_string();
        result.push_str("...");
        result
    }
}

/// Recursively clone `value`, replacing any value whose KEY name contains a
/// `SENSITIVE_FIELDS` token with `"***"`. Walks nested objects and arrays, so a
/// secret nested under e.g. `{"data":{"token":"…"}}` is masked — not just
/// top-level keys (iter audit fix: the previous top-level-only masking
/// stringified nested objects verbatim and only byte-truncated them into the
/// on-disk / SIEM audit log). String leaves are not parsed for embedded JSON,
/// so this is key-based masking only.
fn mask_sensitive(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(obj) => {
            let mut out = serde_json::Map::with_capacity(obj.len());
            for (k, v) in obj {
                if SENSITIVE_FIELDS
                    .iter()
                    .any(|f| k.to_lowercase().contains(f))
                {
                    out.insert(k.clone(), serde_json::Value::String("***".to_string()));
                } else {
                    out.insert(k.clone(), mask_sensitive(v));
                }
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(mask_sensitive).collect())
        }
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Regression test for iter-6: `summarize_result` must mask values of
    /// known-sensitive keys, not just truncate verbatim JSON.
    #[test]
    fn summarize_result_masks_sensitive_fields() {
        let result = json!({
            "status": "ok",
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "password": "hunter2",
            "api_key": "sk-1234567890",
            "items_count": 42,
        });
        let summary = AuditLog::summarize_result(&result);
        // Sensitive values must not appear in the summary.
        assert!(
            !summary.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"),
            "token value must be masked: {summary}"
        );
        assert!(
            !summary.contains("hunter2"),
            "password must be masked: {summary}"
        );
        assert!(
            !summary.contains("sk-1234567890"),
            "api_key must be masked: {summary}"
        );
        // Non-sensitive fields must still appear.
        assert!(
            summary.contains("status"),
            "status key must appear: {summary}"
        );
        assert!(
            summary.contains("items_count"),
            "items_count key must appear: {summary}"
        );
        // Masked fields show ***.
        assert!(
            summary.contains("***"),
            "masked value must be *** in: {summary}"
        );
    }

    /// v1.12.0 regression test: secrets NESTED under a non-sensitive key, and
    /// inside arrays of objects, must be masked too — not just top-level keys.
    /// Guards the recursive `mask_sensitive` against a silent revert.
    #[test]
    fn summarize_result_masks_nested_and_array_secrets() {
        let result = json!({
            "data": { "token": "SECRET_NESTED" },
            "list": [ { "password": "P_IN_ARRAY" } ],
            "status": "ok",
        });
        let summary = AuditLog::summarize_result(&result);
        assert!(
            !summary.contains("SECRET_NESTED"),
            "nested token must be masked: {summary}"
        );
        assert!(
            !summary.contains("P_IN_ARRAY"),
            "password inside array-of-objects must be masked: {summary}"
        );
        assert!(
            summary.contains("***"),
            "masked value must be *** in: {summary}"
        );
    }

    /// summarize_args (pre-existing) should still mask sensitive fields.
    #[test]
    fn summarize_args_masks_sensitive_fields() {
        let args = json!({ "service": "plex", "password": "s3cr3t", "url": "http://x" });
        let summary = AuditLog::summarize_args(&args);
        assert!(
            !summary.contains("s3cr3t"),
            "password must be masked: {summary}"
        );
        assert!(
            summary.contains("service"),
            "service key must appear: {summary}"
        );
    }

    /// Non-object result (e.g. array) is still serialised without crashing.
    #[test]
    fn summarize_result_handles_non_object() {
        let result = json!(["a", "b", "c"]);
        let summary = AuditLog::summarize_result(&result);
        assert!(!summary.is_empty());
    }

    /// When MAX_ENTRIES is exceeded, evicted entries land in
    /// `<path>.archive` as JSONL — one entry per line — so no audit
    /// history is lost under high traffic.
    #[test]
    fn evicted_entries_appended_to_archive() {
        let td = tempfile::tempdir().unwrap();
        let path = td.path().join("audit.json");
        let log = AuditLog::new(path.to_str().unwrap());
        // Fill past the cap. MAX_ENTRIES = 1000; push 1003.
        for i in 0..1003 {
            log.log(AuditEntry {
                timestamp: format!("ts-{i}"),
                tool_name: format!("tool-{i}"),
                args_summary: "args".into(),
                result_summary: "ok".into(),
                permission: "Log".into(),
                trigger: "test".into(),
                transparent_mode: None,
                upstream_host: None,
                upstream_status: None,
                bytes_in: None,
                bytes_out: None,
                duration_ms: None,
            });
        }
        let archive_path = format!("{}.archive", path.display());
        let archive =
            std::fs::read_to_string(&archive_path).expect("archive file should have been created");
        let lines: Vec<&str> = archive.lines().collect();
        // The 3 oldest (i=0, 1, 2) should be evicted in insertion-order.
        assert_eq!(lines.len(), 3);
        for (idx, line) in lines.iter().enumerate() {
            let entry: AuditEntry = serde_json::from_str(line).unwrap();
            assert_eq!(entry.tool_name, format!("tool-{idx}"));
        }
    }
}
