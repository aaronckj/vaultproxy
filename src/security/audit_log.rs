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
    "password", "secret", "token", "api_key", "apikey", "api-key",
    "master_password", "credential", "cred", "auth", "auth_key",
    "bearer", "cookie", "session", "otp", "tfa", "2fa",
    "passphrase", "pass_phrase", "access_key", "private_key",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub tool_name: String,
    pub args_summary: String,
    pub result_summary: String,
    pub permission: String,
    pub trigger: String,
}

pub struct AuditLog {
    /// Entries + unpersisted-write counter under one lock. Previously these
    /// were two separate `RwLock`s; poison on the second while holding the
    /// first could leave the counter frozen and silently disable the
    /// periodic save path for the rest of the process lifetime.
    state: Mutex<AuditState>,
    path: String,
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
                serde_json::from_str::<VecDeque<AuditEntry>>(&contents)
                    .unwrap_or_default()
            }
            Err(_) => VecDeque::new(),
        };

        // Enforce cap on entries loaded from disk — the file could have been
        // manually edited or corrupted to contain more than MAX_ENTRIES.
        while entries.len() > MAX_ENTRIES {
            entries.pop_back();
        }

        Self {
            state: Mutex::new(AuditState { entries, write_count: 0 }),
            path: path.to_string(),
        }
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
    pub fn log(&self, entry: AuditEntry) {
        // Single-lock critical section: push, cap, bump counter, decide on
        // save. Gather a snapshot of entries if a save is due so `save_impl`
        // can run without re-acquiring the lock.
        let snapshot: Option<Vec<AuditEntry>> = {
            let mut st = self.lock_state();
            st.entries.push_front(entry);
            while st.entries.len() > MAX_ENTRIES {
                st.entries.pop_back();
            }
            st.write_count += 1;
            if st.write_count >= 10 {
                st.write_count = 0;
                Some(st.entries.iter().cloned().collect())
            } else {
                None
            }
        };

        if let Some(entries) = snapshot {
            self.save_impl(&entries);
        }
    }

    /// Return recent entries (newest first).
    pub fn entries(&self) -> Vec<AuditEntry> {
        self.lock_state().entries.iter().cloned().collect()
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
                let val = if SENSITIVE_FIELDS.iter().any(|f| k.to_lowercase().contains(f)) {
                    "***".to_string()
                } else {
                    truncate_str(&v.to_string(), 50)
                };
                parts.push(format!("{}={}", k, val));
            }
            parts.join(", ")
        } else {
            truncate_str(&args.to_string(), MAX_SUMMARY_LEN)
        };

        if summary.len() > MAX_SUMMARY_LEN {
            summary.truncate(MAX_SUMMARY_LEN);
            summary.push_str("...");
        }
        summary
    }

    /// Create a result summary string, truncated.
    pub fn summarize_result(result: &serde_json::Value) -> String {
        let s = result.to_string();
        truncate_str(&s, MAX_SUMMARY_LEN)
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
        let mut result = s[..max_len].to_string();
        result.push_str("...");
        result
    }
}
