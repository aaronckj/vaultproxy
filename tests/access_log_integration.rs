use vaultproxy::access_log::{AccessLog, Event};

#[test]
fn records_and_verifies_chain() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("access.log");
    let key_path = dir.path().join("access_log_hmac.key");
    let log = AccessLog::open(log_path.clone(), key_path.clone()).unwrap();
    for i in 0..5 {
        log.record(&Event {
            ts: chrono::Utc::now(),
            action: "get_item_fields",
            item: Some("WI MCP - Bearer"),
            fields: &["password"],
            peer_pid: Some(1000 + i as u32),
            peer_uid: Some(1000),
            peer_cmdline: Some("integration-test"),
            outcome: "ok",
        })
        .unwrap();
    }
    drop(log);
    AccessLog::verify(&log_path, &key_path).expect("chain valid after 5 entries");
}

#[test]
fn detects_tamper_appended_line() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("access.log");
    let key_path = dir.path().join("access_log_hmac.key");
    let log = AccessLog::open(log_path.clone(), key_path.clone()).unwrap();
    log.record(&Event {
        ts: chrono::Utc::now(),
        action: "rotate",
        item: Some("Hive MCP - Bearer"),
        fields: &[],
        peer_pid: None,
        peer_uid: None,
        peer_cmdline: None,
        outcome: "ok",
    })
    .unwrap();
    drop(log);
    // Append a forged line with prev_hmac pointing nowhere.
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(&log_path)
        .unwrap();
    writeln!(
        f,
        r#"{{"ts":"2099-01-01T00:00:00Z","action":"injected","item":null,"fields":[],"peer_pid":null,"peer_uid":null,"peer_cmdline":null,"outcome":"ok","prev_hmac":"deadbeef","hmac":"00"}}"#
    )
    .unwrap();
    let err = AccessLog::verify(&log_path, &key_path).unwrap_err();
    assert!(
        err.to_string().contains("hmac mismatch") || err.to_string().contains("prev_hmac"),
        "expected chain-break error, got: {err}"
    );
}

#[test]
fn key_file_is_chmod_0600() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("k");
    let _log = AccessLog::open(dir.path().join("log"), key_path.clone()).unwrap();
    let mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "key file must be 0600, got {:o}", mode);
}

#[test]
fn log_file_is_chmod_0600_on_create() {
    // First open: we create the log file, so it must end up at 0600.
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("log");
    let key_path = dir.path().join("k");
    let _log = AccessLog::open(log_path.clone(), key_path.clone()).unwrap();
    let mode = std::fs::metadata(&log_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "log file must be 0600 on create, got {:o}", mode);
}

#[test]
fn log_file_mode_preserved_on_reopen() {
    // If the operator sets the log to a non-default mode (e.g. 0640 to grant
    // an audit group read access), reopening the daemon must NOT silently
    // downgrade it back to 0600. The fix in #2 only chmods on create.
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("log");
    let key_path = dir.path().join("k");
    {
        let _log = AccessLog::open(log_path.clone(), key_path.clone()).unwrap();
    }
    // Operator widens read for audit group.
    std::fs::set_permissions(&log_path, Permissions::from_mode(0o640)).unwrap();
    // Reopen — the second open is the "existed before" path; it must leave
    // the 0640 mode alone.
    let _log2 = AccessLog::open(log_path.clone(), key_path.clone()).unwrap();
    let mode = std::fs::metadata(&log_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o640,
        "reopening the log must preserve operator-set mode 0640, got {:o}",
        mode
    );
}

#[test]
fn reopen_continues_chain() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("a.log");
    let key_path = dir.path().join("k");
    {
        let log = AccessLog::open(log_path.clone(), key_path.clone()).unwrap();
        log.record(&Event {
            ts: chrono::Utc::now(),
            action: "first",
            item: None,
            fields: &[],
            peer_pid: None,
            peer_uid: None,
            peer_cmdline: None,
            outcome: "ok",
        })
        .unwrap();
    }
    {
        let log = AccessLog::open(log_path.clone(), key_path.clone()).unwrap();
        log.record(&Event {
            ts: chrono::Utc::now(),
            action: "second",
            item: None,
            fields: &[],
            peer_pid: None,
            peer_uid: None,
            peer_cmdline: None,
            outcome: "ok",
        })
        .unwrap();
    }
    AccessLog::verify(&log_path, &key_path).expect("chain spans reopen");
}
