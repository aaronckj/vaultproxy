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
