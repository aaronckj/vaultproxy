//! Verifies the AuditLog fan-out path drives the configured sinks.
//!
//! Goes via a custom test sink (captures emissions into an Arc<Mutex<Vec>>)
//! so we don't have to capture process stdout. The wiring is identical to
//! what the built-in StdoutSink / SyslogSink use, so this exercises the
//! contract without the platform-specific output capture dance.

#![cfg(feature = "test-utils")]

use std::sync::{Arc, Mutex};
use vaultproxy::security::audit_log::{AuditEntry, AuditLog};
use vaultproxy::security::audit_sinks::AuditSink;

struct CapturingSink(Arc<Mutex<Vec<AuditEntry>>>);

impl AuditSink for CapturingSink {
    fn emit(&self, entry: &AuditEntry) {
        self.0.lock().unwrap().push(entry.clone());
    }
}

fn sample_entry(tool: &str) -> AuditEntry {
    AuditEntry {
        timestamp: "2026-05-25T00:00:00Z".into(),
        tool_name: tool.into(),
        args_summary: "{}".into(),
        result_summary: "{}".into(),
        permission: "Allowed".into(),
        trigger: "test".into(),
        transparent_mode: None,
        upstream_host: None,
        upstream_status: None,
        bytes_in: None,
        bytes_out: None,
        duration_ms: None,
    }
}

#[test]
fn audit_log_fans_out_to_sink_in_order() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit-log.json");
    let captured: Arc<Mutex<Vec<AuditEntry>>> = Arc::new(Mutex::new(Vec::new()));

    let mut log = AuditLog::new(path.to_str().unwrap());
    log.set_sinks(vec![Box::new(CapturingSink(captured.clone()))]);

    for n in 0..3 {
        log.log(sample_entry(&format!("tool_{n}")));
    }

    let got = captured.lock().unwrap().clone();
    assert_eq!(got.len(), 3, "sink must observe every log() call");
    assert_eq!(got[0].tool_name, "tool_0");
    assert_eq!(got[1].tool_name, "tool_1");
    assert_eq!(got[2].tool_name, "tool_2");
}

#[test]
fn audit_log_with_no_sinks_does_not_emit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit-log.json");
    let log = AuditLog::new(path.to_str().unwrap());
    log.log(sample_entry("no_sinks"));
    // Confirm the on-disk path still wrote eventually: log() doesn't
    // flush every call, but with no sinks configured the fan-out
    // branch should be a quiet no-op. This test asserts the absence
    // of panics + the entry made it into memory.
    assert_eq!(log.entries().len(), 1);
}
