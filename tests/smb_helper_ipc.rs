//! Integration tests for the SMB helper IPC contract.
//!
//! Exercises `perform_unmount` (which does not require a live VaultManager)
//! against a fake helper shell script. The script captures stdin to a file so
//! we can assert that the proxy emits the expected JSON request and never
//! includes credential material in the request envelope.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use axum::http::StatusCode;
use serde_json::Value;
use vaultproxy::vault::smb::{perform_unmount, SmbConfig, SmbUnmountRequest};

fn unique_dir(label: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let p = std::env::temp_dir().join(format!(
        "vp-smb-ipc-{label}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}

/// Write a bash helper script that captures stdin to `stdin.json` and prints
/// `response` to stdout. Returns the script's absolute path.
fn write_fake_helper(dir: &PathBuf, response: &str, exit_code: u8) -> PathBuf {
    let stdin_capture = dir.join("stdin.json");
    let script = dir.join("helper.sh");
    let body = format!(
        "#!/usr/bin/env bash\nset -e\ncat > {stdin}\nprintf '%s' {resp}\nexit {exit}\n",
        stdin = stdin_capture.display(),
        resp = shell_quote(response),
        exit = exit_code,
    );
    fs::write(&script, body).unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    script
}

fn shell_quote(s: &str) -> String {
    let mut out = String::from("'");
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

fn cfg(dir: &PathBuf, helper: &PathBuf) -> SmbConfig {
    SmbConfig {
        helper_path: helper.display().to_string(),
        mount_root: "/mnt".into(),
        creds_dir: "/etc/samba".into(),
        fstab_path: dir.join("fstab").display().to_string(),
    }
}

#[tokio::test]
async fn unmount_invokes_helper_and_returns_ok() {
    let dir = unique_dir("ok");
    let helper = write_fake_helper(&dir, r#"{"ok":true}"#, 0);
    let smb = cfg(&dir, &helper);
    let (code, body) = perform_unmount(
        &smb,
        SmbUnmountRequest {
            slug: "demo".into(),
            mount_point: "/mnt/demo".into(),
        },
    )
    .await;
    assert_eq!(code, StatusCode::OK, "body: {body}");
    assert_eq!(body.get("ok").and_then(|v| v.as_bool()), Some(true));

    let stdin_path = dir.join("stdin.json");
    let captured: Value =
        serde_json::from_str(&fs::read_to_string(&stdin_path).unwrap()).unwrap();
    assert_eq!(captured.get("action").and_then(|v| v.as_str()), Some("unmount"));
    assert_eq!(captured.get("slug").and_then(|v| v.as_str()), Some("demo"));
    assert_eq!(
        captured.get("mount_point").and_then(|v| v.as_str()),
        Some("/mnt/demo")
    );
    // Unmount must not contain credential material.
    assert!(
        captured.get("password").is_none()
            || captured.get("password").and_then(|v| v.as_str()) == Some(""),
        "unmount request leaked password field: {captured}"
    );
    assert!(
        captured.get("username").is_none()
            || captured.get("username").and_then(|v| v.as_str()) == Some(""),
        "unmount request leaked username field: {captured}"
    );
}

#[tokio::test]
async fn helper_error_response_propagates() {
    let dir = unique_dir("err");
    let helper = write_fake_helper(&dir, r#"{"ok":false,"error":"bad slug"}"#, 1);
    let smb = cfg(&dir, &helper);
    let (code, body) = perform_unmount(
        &smb,
        SmbUnmountRequest {
            slug: "demo".into(),
            mount_point: "/mnt/demo".into(),
        },
    )
    .await;
    assert_eq!(code, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body.get("ok").and_then(|v| v.as_bool()), Some(false));
    assert_eq!(
        body.get("error").and_then(|v| v.as_str()),
        Some("bad slug")
    );
}

#[tokio::test]
async fn disabled_when_helper_path_empty() {
    let smb = SmbConfig {
        helper_path: String::new(),
        mount_root: "/mnt".into(),
        creds_dir: "/etc/samba".into(),
        fstab_path: "/etc/fstab".into(),
    };
    let (code, body) = perform_unmount(
        &smb,
        SmbUnmountRequest {
            slug: "demo".into(),
            mount_point: "/mnt/demo".into(),
        },
    )
    .await;
    assert_eq!(code, StatusCode::NOT_IMPLEMENTED);
    let msg = body.get("error").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("disabled"), "got: {msg}");
}

#[tokio::test]
async fn sanity_rejects_path_outside_mount_root() {
    let dir = unique_dir("escape");
    let helper = write_fake_helper(&dir, r#"{"ok":true}"#, 0);
    let smb = cfg(&dir, &helper);
    let (code, body) = perform_unmount(
        &smb,
        SmbUnmountRequest {
            slug: "demo".into(),
            mount_point: "/etc/passwd".into(),
        },
    )
    .await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    assert!(
        !dir.join("stdin.json").exists(),
        "helper should not have been invoked"
    );
    let _ = body;
}

#[tokio::test]
async fn sanity_rejects_bad_slug() {
    let dir = unique_dir("badslug");
    let helper = write_fake_helper(&dir, r#"{"ok":true}"#, 0);
    let smb = cfg(&dir, &helper);
    let (code, _body) = perform_unmount(
        &smb,
        SmbUnmountRequest {
            slug: "Bad Slug".into(),
            mount_point: "/mnt/x".into(),
        },
    )
    .await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    assert!(!dir.join("stdin.json").exists());
}

#[tokio::test]
async fn helper_garbage_stdout_returns_500() {
    let dir = unique_dir("garbage");
    let helper = write_fake_helper(&dir, "not json at all", 0);
    let smb = cfg(&dir, &helper);
    let (code, body) = perform_unmount(
        &smb,
        SmbUnmountRequest {
            slug: "demo".into(),
            mount_point: "/mnt/demo".into(),
        },
    )
    .await;
    assert_eq!(code, StatusCode::INTERNAL_SERVER_ERROR);
    let msg = body.get("error").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("unparseable"), "got: {msg}");
}
