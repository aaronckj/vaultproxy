//! Local UNIX-socket RPC for credential fetch by colocated processes.
//!
//! The HTTP API at :3201 refuses to hand out plaintext passwords by design,
//! so `vaultproxy --launch` previously did its own VW cloud auth on every
//! invocation — which trips Bitwarden's rate-limit when raven launches
//! several MCP extensions in quick succession.
//!
//! This module exposes the already-authed in-memory item cache to colocated
//! same-UID processes via a UNIX domain socket. Authentication is
//! SO_PEERCRED: the kernel guarantees the connecting peer's real UID, and we
//! reject any connection whose UID doesn't match this process's. Only the
//! fields the caller explicitly names are returned — there is no enumeration
//! endpoint over the socket.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::vault::VaultManager;

pub fn default_socket_path() -> PathBuf {
    // Explicit override wins. Children spawned by `vaultproxy --launch` see
    // this var instead of XDG_RUNTIME_DIR (which is intentionally stripped
    // from their environment by the launcher).
    if let Ok(p) = std::env::var("VAULT_PROXY_SOCKET") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime_dir).join("vaultproxy.sock");
    }
    let uid = unsafe { libc::getuid() };
    PathBuf::from(format!("/tmp/vaultproxy-{}.sock", uid))
}

#[derive(Debug, Deserialize)]
#[serde(tag = "op")]
enum Request {
    #[serde(rename = "get_item_fields")]
    GetItemFields {
        item: String,
        fields: Vec<String>,
    },
    #[serde(rename = "ping")]
    Ping,
}

#[derive(Debug, Serialize)]
struct ErrorResponse<'a> {
    ok: bool,
    error: &'a str,
}

#[derive(Debug, Serialize)]
struct FieldsResponse {
    ok: bool,
    fields: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
struct PingResponse {
    ok: bool,
    pong: bool,
}

pub async fn run(vault: Arc<VaultManager>, socket_path: PathBuf) -> anyhow::Result<()> {
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path)?;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(&socket_path, perms)?;
    tracing::info!(
        socket = %socket_path.display(),
        "local credential socket listening (SO_PEERCRED-authenticated, same-UID only)"
    );
    let self_uid = unsafe { libc::getuid() };
    loop {
        let (stream, _addr) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!("local socket accept failed: {}", e);
                continue;
            }
        };
        let peer_uid = peer_uid(&stream);
        if peer_uid != Some(self_uid) {
            tracing::warn!(
                "local socket rejected: peer uid {:?} != self uid {}",
                peer_uid,
                self_uid
            );
            continue;
        }
        let vault = vault.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, vault).await {
                tracing::debug!("local socket conn error: {}", e);
            }
        });
    }
}

fn peer_uid(stream: &UnixStream) -> Option<u32> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc == 0 {
        Some(cred.uid)
    } else {
        None
    }
}

async fn handle_conn(stream: UnixStream, vault: Arc<VaultManager>) -> anyhow::Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        return Ok(());
    }
    let response_json = match serde_json::from_str::<Request>(line.trim()) {
        Ok(Request::Ping) => serde_json::to_string(&PingResponse {
            ok: true,
            pong: true,
        })?,
        Ok(Request::GetItemFields { item, fields }) => {
            let mut out: std::collections::BTreeMap<String, String> =
                std::collections::BTreeMap::new();
            let mut error: Option<String> = None;
            for f in &fields {
                match vault.get_field_resolved(&item, f).await {
                    Ok(v) => {
                        out.insert(f.clone(), v);
                    }
                    Err(e) => {
                        error = Some(format!("field '{}' fetch failed: {}", f, e));
                        break;
                    }
                }
            }
            if let Some(err) = error {
                serde_json::to_string(&ErrorResponse {
                    ok: false,
                    error: &err,
                })?
            } else {
                serde_json::to_string(&FieldsResponse {
                    ok: true,
                    fields: out,
                })?
            }
        }
        Err(e) => serde_json::to_string(&ErrorResponse {
            ok: false,
            error: &format!("invalid request: {}", e),
        })?,
    };
    write_half.write_all(response_json.as_bytes()).await?;
    write_half.write_all(b"\n").await?;
    write_half.shutdown().await?;
    Ok(())
}

/// Client for fetching credentials over the local socket. Used by
/// `vaultproxy --launch` when a daemon-side socket is alive — skips the
/// re-auth-to-VW path that triggers cloud rate-limits.
pub mod client {
    use std::path::Path;

    use anyhow::{anyhow, Context, Result};
    use serde::Deserialize;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    #[derive(Debug, Deserialize)]
    struct FieldsResponse {
        ok: bool,
        #[serde(default)]
        fields: std::collections::BTreeMap<String, String>,
        #[serde(default)]
        error: Option<String>,
    }

    pub async fn get_field(socket_path: &Path, item: &str, field: &str) -> Result<String> {
        let stream = UnixStream::connect(socket_path)
            .await
            .with_context(|| format!("connect to credential socket {:?}", socket_path))?;
        let (read_half, mut write_half) = stream.into_split();
        let req = serde_json::json!({
            "op": "get_item_fields",
            "item": item,
            "fields": [field],
        });
        let line = serde_json::to_string(&req)?;
        write_half.write_all(line.as_bytes()).await?;
        write_half.write_all(b"\n").await?;
        write_half.shutdown().await?;
        let mut reader = BufReader::new(read_half);
        let mut response = String::new();
        reader.read_line(&mut response).await?;
        let parsed: FieldsResponse =
            serde_json::from_str(response.trim()).context("parse socket response")?;
        if !parsed.ok {
            return Err(anyhow!(
                "socket get_field('{}','{}') error: {}",
                item,
                field,
                parsed.error.unwrap_or_else(|| "unknown".to_string())
            ));
        }
        parsed
            .fields
            .get(field)
            .cloned()
            .ok_or_else(|| anyhow!("socket response missing field '{}'", field))
    }
}
