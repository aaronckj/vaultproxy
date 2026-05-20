//! SMB mount setup endpoint. The proxy never returns credentials to the MCP
//! caller — instead it resolves the vault item, spawns the setuid mount
//! helper, and pipes a single-shot JSON request (containing the decrypted
//! username + password) over stdin. The helper writes the credentials file,
//! edits `/etc/fstab`, and runs `mount`. The caller learns only success/
//! failure plus the operations performed.
//!
//! Privilege model: vault-proxy runs unprivileged. The helper binary at
//! `--smb-helper-path` is installed setuid-root (mode 4750, owner `root`,
//! group = vault-proxy's runtime group) so only the proxy can invoke it.
//! The helper validates every input against tight allowlists; see
//! `src/bin/mount_helper.rs`.

use std::process::Stdio;
use std::sync::Arc;

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::proxy::AppState;
pub use crate::proxy::SmbConfig;
use crate::vault::VaultManager;

/// Maximum bytes accepted from the helper's stdout. The helper is supposed
/// to emit a single line of small JSON — anything larger is a bug.
const MAX_HELPER_OUTPUT: usize = 16 * 1024;

#[derive(Debug, Deserialize)]
pub struct SmbMountRequest {
    /// Vaultwarden cipher id (uuid) whose login holds the SMB username +
    /// password. The caller never supplies credentials directly.
    pub vault_item_id: String,
    /// SMB UNC path, e.g. `//10.0.0.30/screenshots`.
    pub share: String,
    /// Local mount point, e.g. `/mnt/screenshots`. Must live under
    /// `--smb-mount-root`.
    pub mount_point: String,
    /// Stable identifier baked into the creds filename + fstab markers.
    /// `[a-z0-9-]{1,32}`. Choose deliberately — changing this orphans
    /// previously-written rows.
    pub slug: String,
    /// Optional extra cifs mount options (e.g. `["vers=3.0","iocharset=utf8"]`).
    /// `credentials=`, `username=`, `password=` are reserved and rejected.
    #[serde(default)]
    pub fs_options: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct SmbUnmountRequest {
    pub slug: String,
    pub mount_point: String,
}

#[derive(Debug, Serialize)]
struct HelperRequest<'a> {
    action: &'a str,
    slug: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    share: &'a str,
    mount_point: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    username: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    password: &'a str,
    fs_options: &'a [String],
    creds_dir: &'a str,
    fstab_path: &'a str,
    allowed_mount_root: &'a str,
}

pub async fn smb_mount(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SmbMountRequest>,
) -> (StatusCode, Json<Value>) {
    let (code, body) = perform_mount(&state.vault, &state.smb, req).await;
    (code, Json(body))
}

pub async fn smb_unmount(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SmbUnmountRequest>,
) -> (StatusCode, Json<Value>) {
    let (code, body) = perform_unmount(&state.smb, req).await;
    (code, Json(body))
}

/// Core mount routine — usable from both the axum handler and the MCP tool.
/// Returns `(status, json-body)`. Never includes credential material in the
/// response body.
pub async fn perform_mount(
    vault: &VaultManager,
    smb: &SmbConfig,
    req: SmbMountRequest,
) -> (StatusCode, Value) {
    if smb.helper_path.is_empty() {
        return disabled_response_body();
    }
    if let Err((code, msg)) = sanity_check(&req.slug, &req.mount_point, smb) {
        return (code, json!({"error": msg}));
    }

    let (username_sb, password_sb) = match vault.decrypt_credentials_by_id(&req.vault_item_id).await
    {
        Ok(pair) => pair,
        Err(e) => {
            return (
                StatusCode::NOT_FOUND,
                json!({"error": format!("vault item not found or has no login: {e}")}),
            );
        }
    };
    let username = match username_sb {
        Some(u) => match std::str::from_utf8(u.as_bytes()) {
            Ok(s) => s.to_owned(),
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    json!({"error": "vault username is not valid utf-8"}),
                );
            }
        },
        None => {
            return (
                StatusCode::BAD_REQUEST,
                json!({"error": "vault item has no username"}),
            );
        }
    };
    let password = match std::str::from_utf8(password_sb.as_bytes()) {
        Ok(s) => s.to_owned(),
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                json!({"error": "vault password is not valid utf-8"}),
            );
        }
    };

    let helper_req = HelperRequest {
        action: "mount",
        slug: &req.slug,
        share: &req.share,
        mount_point: &req.mount_point,
        username: &username,
        password: &password,
        fs_options: &req.fs_options,
        creds_dir: &smb.creds_dir,
        fstab_path: &smb.fstab_path,
        allowed_mount_root: &smb.mount_root,
    };

    invoke_helper(&smb.helper_path, "smb_mount", &req.slug, &helper_req).await
}

pub async fn perform_unmount(smb: &SmbConfig, req: SmbUnmountRequest) -> (StatusCode, Value) {
    if smb.helper_path.is_empty() {
        return disabled_response_body();
    }
    if let Err((code, msg)) = sanity_check(&req.slug, &req.mount_point, smb) {
        return (code, json!({"error": msg}));
    }
    let helper_req = HelperRequest {
        action: "unmount",
        slug: &req.slug,
        share: "",
        mount_point: &req.mount_point,
        username: "",
        password: "",
        fs_options: &[],
        creds_dir: &smb.creds_dir,
        fstab_path: &smb.fstab_path,
        allowed_mount_root: &smb.mount_root,
    };
    invoke_helper(&smb.helper_path, "smb_unmount", &req.slug, &helper_req).await
}

fn disabled_response_body() -> (StatusCode, Value) {
    (
        StatusCode::NOT_IMPLEMENTED,
        json!({
            "error": "SMB mount endpoints are disabled. \
                      Set --smb-helper-path to the absolute path of the \
                      setuid vaultproxy-mount-helper binary, plus --smb-mount-root \
                      (e.g. /mnt) to enable."
        }),
    )
}

/// Fast-fail input checks that don't require decrypting anything. The helper
/// re-validates every field — these checks just give a friendlier error
/// before we spend a syscall and a vault decryption.
fn sanity_check(
    slug: &str,
    mount_point: &str,
    smb: &SmbConfig,
) -> Result<(), (StatusCode, String)> {
    if slug.is_empty() || slug.len() > 32 {
        return Err((StatusCode::BAD_REQUEST, "slug length must be 1..=32".into()));
    }
    if !slug
        .bytes()
        .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "slug must match [a-z0-9-]".into(),
        ));
    }
    if slug.starts_with('-') || slug.ends_with('-') {
        return Err((
            StatusCode::BAD_REQUEST,
            "slug must not start or end with '-'".into(),
        ));
    }
    if smb.mount_root.is_empty() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "smb_mount_root is unset".into(),
        ));
    }
    let prefix = format!("{}/", smb.mount_root.trim_end_matches('/'));
    if !mount_point.starts_with(&prefix) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("mount_point must begin with {prefix}"),
        ));
    }
    Ok(())
}

async fn invoke_helper(
    helper_path: &str,
    op: &str,
    slug: &str,
    helper_req: &HelperRequest<'_>,
) -> (StatusCode, Value) {
    let stdin_payload = match serde_json::to_vec(helper_req) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": format!("encode helper request: {e}")}),
            );
        }
    };

    let mut child = match Command::new(helper_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(op, helper = %helper_path, "spawn helper: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": format!("spawn helper: {e}")}),
            );
        }
    };

    // Best-effort: send the payload, then wait for the process. We don't time
    // out the wait here — `mount` itself can take seconds under load and there
    // is no good single timeout that fits both LAN and slow VPN paths. Operators
    // can SIGTERM the helper externally if needed.
    {
        let mut stdin_handle = child.stdin.take().expect("stdin was piped above");
        if let Err(e) = stdin_handle.write_all(&stdin_payload).await {
            tracing::error!(op, "write helper stdin: {e}");
            let _ = child.kill().await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": format!("write helper stdin: {e}")}),
            );
        }
        drop(stdin_handle);
    }

    let output = match child.wait_with_output().await {
        Ok(o) => o,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": format!("wait helper: {e}")}),
            );
        }
    };

    let stdout_bytes = if output.stdout.len() > MAX_HELPER_OUTPUT {
        &output.stdout[..MAX_HELPER_OUTPUT]
    } else {
        &output.stdout
    };
    let stdout_str = String::from_utf8_lossy(stdout_bytes);
    let stderr_str = String::from_utf8_lossy(&output.stderr);

    let parsed: Value = match serde_json::from_str(stdout_str.trim()) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(
                op,
                exit = ?output.status,
                stderr = %stderr_str,
                "helper produced unparseable stdout: {e}"
            );
            audit(op, slug, false, "helper stdout unparseable");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": "helper output unparseable"}),
            );
        }
    };

    let ok = parsed.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
    if !ok {
        let err = parsed
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("helper reported failure")
            .to_string();
        tracing::warn!(op, slug, exit = ?output.status, "helper error: {err}");
        audit(op, slug, false, &err);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"ok": false, "error": err}),
        );
    }

    audit(op, slug, true, "ok");
    (StatusCode::OK, json!({"ok": true}))
}

fn audit(op: &str, slug: &str, ok: bool, msg: &str) {
    tracing::info!(target: "vaultproxy::smb", op, slug, ok, "{msg}");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(root: &str) -> SmbConfig {
        SmbConfig {
            helper_path: "/nonexistent/never-invoked".into(),
            mount_root: root.into(),
            creds_dir: "/etc/samba".into(),
            fstab_path: "/etc/fstab".into(),
        }
    }

    #[test]
    fn sanity_passes_clean_inputs() {
        assert!(sanity_check("unraid", "/mnt/screenshots", &cfg("/mnt")).is_ok());
    }
    #[test]
    fn sanity_rejects_bad_slug() {
        let c = cfg("/mnt");
        assert!(sanity_check("", "/mnt/x", &c).is_err());
        assert!(sanity_check("Bad", "/mnt/x", &c).is_err());
        assert!(sanity_check("-leading", "/mnt/x", &c).is_err());
    }
    #[test]
    fn sanity_rejects_path_escape() {
        let c = cfg("/mnt");
        assert!(sanity_check("ok", "/etc/passwd", &c).is_err());
        assert!(sanity_check("ok", "/mnt", &c).is_err());
        assert!(sanity_check("ok", "/mnt2/x", &c).is_err());
    }
}
