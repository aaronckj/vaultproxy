use secrecy::ExposeSecret;
use vaultproxy::approle::{setup_approle, unlock_with_approle};
use vaultproxy::keystore::{Credentials, VaultwardenCreds};

fn make_creds() -> Credentials {
    Credentials {
        version: 1,
        vaultwarden: VaultwardenCreds {
            url: "https://vw.example.com".into(),
            email: "ops@example.com".into(),
            master_password: "MasterP@ss!".into(),
        },
        cloud: None,
        setup_password_hash: None,
    }
}

#[test]
fn setup_then_unlock_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let creds = make_creds();
    let sid = setup_approle(dir.path(), "deploy-bot", &creds).unwrap();
    let unlocked = unlock_with_approle(dir.path(), "deploy-bot", sid.expose_secret()).unwrap();
    assert_eq!(unlocked.vaultwarden.email, "ops@example.com");
    assert_eq!(unlocked.vaultwarden.master_password, "MasterP@ss!");
}

#[test]
fn wrong_secret_id_fails() {
    let dir = tempfile::tempdir().unwrap();
    let creds = make_creds();
    let _real = setup_approle(dir.path(), "r1", &creds).unwrap();
    let wrong = "ff".repeat(32);
    let err = unlock_with_approle(dir.path(), "r1", &wrong)
        .err()
        .expect("expected error");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("decrypt failed") || msg.to_lowercase().contains("aead"),
        "expected decrypt-failed error, got: {msg}"
    );
}

#[test]
fn wrong_role_id_fails() {
    let dir = tempfile::tempdir().unwrap();
    let creds = make_creds();
    let sid = setup_approle(dir.path(), "real", &creds).unwrap();
    let err = unlock_with_approle(dir.path(), "fake", sid.expose_secret())
        .err()
        .expect("expected error");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("approles/fake.json") || msg.contains("read approle"),
        "expected file-not-found error, got: {msg}"
    );
}

#[test]
fn rejects_bad_role_id_chars() {
    let dir = tempfile::tempdir().unwrap();
    let creds = make_creds();
    let err = setup_approle(dir.path(), "bad/role", &creds).unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("[A-Za-z0-9_-]"),
        "expected charset error, got: {msg}"
    );
}

#[test]
fn approle_file_is_chmod_0600() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let creds = make_creds();
    let _sid = setup_approle(dir.path(), "r", &creds).unwrap();
    let path = dir.path().join("approles").join("r.json");
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "approle file must be 0600, got {:o}", mode);
}

#[test]
fn tampered_ciphertext_fails() {
    let dir = tempfile::tempdir().unwrap();
    let creds = make_creds();
    let sid = setup_approle(dir.path(), "r", &creds).unwrap();
    let path = dir.path().join("approles").join("r.json");
    let body = std::fs::read_to_string(&path).unwrap();
    // Flip a hex byte deep in the ciphertext_b64 to corrupt the AEAD tag /
    // ciphertext. base64 with one char changed will still decode but to a
    // different byte sequence, which fails AES-GCM authentication.
    let tampered = body.replace("\"ciphertext_b64\":\"A", "\"ciphertext_b64\":\"B");
    if tampered == body {
        // The first ciphertext char wasn't 'A'; try a different sentinel.
        // For simplicity, flip the LAST base64 char before the trailing
        // quote. Use serde to mutate cleanly.
        let mut v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let mut s = v["ciphertext_b64"].as_str().unwrap().to_string();
        if let Some(c) = s.pop() {
            s.push(if c == 'A' { 'B' } else { 'A' });
        }
        v["ciphertext_b64"] = serde_json::Value::String(s);
        std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
    } else {
        std::fs::write(&path, tampered).unwrap();
    }
    let err = unlock_with_approle(dir.path(), "r", sid.expose_secret())
        .err()
        .expect("expected error");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("decrypt failed") || msg.to_lowercase().contains("aead"),
        "expected decrypt-failed error after tamper, got: {msg}"
    );
}
