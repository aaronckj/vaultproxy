//! Token-resolution helper (formerly backing the `mcp-bearer-bridge` binary,
//! which was retired in v1.12.0 because it leaked the token via the spawned
//! `npx mcp-remote` argv — `/proc/<pid>/cmdline`. Use the native
//! `mcp-rpc-bridge` instead). This module is retained for its socket-based
//! token-resolution logic and its tests.
//!
//! Resolves the Bearer token for the upstream HTTP MCP server using, in
//! priority order:
//!
//! 1. `VAULT_ITEM` env (preferred) — names a Vaultwarden item; the actual
//!    token is fetched at startup over the vault-proxy credential socket.
//!    The token is never embedded in this process's env, so a same-UID
//!    `cat /proc/<pid>/environ` attacker cannot recover it from the bridge
//!    process itself. (The token does end up in the spawned `npx mcp-remote`
//!    argv — that is a separate, smaller leak to address with a native
//!    Rust HTTP MCP proxy in a follow-up.)
//!
//! 2. `BEARER_TOKEN` env (legacy) — the token verbatim. Preserved so the
//!    rollout can land without breaking unmigrated `mcp-servers.toml` entries.
//!
//! Neither env causes an immediate failure on its own; the resolver tries
//! `VAULT_ITEM` first and falls through to `BEARER_TOKEN` only when no item
//! is configured. If both are unset, returns `TokenError::Missing`.

use std::path::Path;

use anyhow::Context as _;

#[derive(Debug)]
pub enum TokenError {
    Missing,
    SocketFailed(anyhow::Error),
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenError::Missing => write!(
                f,
                "neither VAULT_ITEM nor BEARER_TOKEN env var is set — \
                 nothing to resolve",
            ),
            TokenError::SocketFailed(e) => {
                write!(
                    f,
                    "VAULT_ITEM resolution via vault-proxy socket failed: {}",
                    e
                )
            }
        }
    }
}

impl std::error::Error for TokenError {}

/// Resolve the bearer token using env vars read from `get_env`.
///
/// `socket_path_provider` lets tests inject a per-test socket path; the
/// production caller passes `local_socket::default_socket_path()`.
///
/// Field name on the vault item defaults to `password`; can be overridden via
/// `VAULT_FIELD` env (rarely needed — passwords live in `password`).
pub async fn resolve_token<F, P>(
    get_env: F,
    socket_path_provider: P,
) -> Result<zeroize::Zeroizing<String>, TokenError>
where
    F: Fn(&str) -> Option<String>,
    P: FnOnce() -> std::path::PathBuf,
{
    if let Some(item) = get_env("VAULT_ITEM") {
        let field = get_env("VAULT_FIELD").unwrap_or_else(|| "password".to_string());
        let socket_path = socket_path_provider();
        return fetch_from_socket(&socket_path, &item, &field)
            .await
            .map(zeroize::Zeroizing::new)
            .map_err(TokenError::SocketFailed);
    }
    if let Some(tok) = get_env("BEARER_TOKEN") {
        return Ok(zeroize::Zeroizing::new(tok));
    }
    Err(TokenError::Missing)
}

async fn fetch_from_socket(socket_path: &Path, item: &str, field: &str) -> anyhow::Result<String> {
    crate::local_socket::client::get_field(socket_path, item, field)
        .await
        .with_context(|| format!("get_field('{}', '{}')", item, field))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    fn env_from(
        map: &'static HashMap<&'static str, &'static str>,
    ) -> impl Fn(&str) -> Option<String> {
        move |k: &str| map.get(k).map(|s| s.to_string())
    }

    async fn spawn_fake_socket(
        responses: HashMap<String, Result<String, String>>,
    ) -> (PathBuf, tokio::task::JoinHandle<()>) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vp.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let path_clone = path.clone();
        // Keep tempdir alive for the listener's lifetime via leaking it.
        std::mem::forget(dir);
        let responses = Arc::new(responses);
        let handle = tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let r = Arc::clone(&responses);
                tokio::spawn(async move {
                    let (read_half, mut write_half) = stream.into_split();
                    let mut reader = BufReader::new(read_half);
                    let mut line = String::new();
                    if reader.read_line(&mut line).await.is_err() {
                        return;
                    }
                    let req: serde_json::Value =
                        serde_json::from_str(line.trim()).unwrap_or(serde_json::Value::Null);
                    let item = req["item"].as_str().unwrap_or("").to_string();
                    let field = req["fields"][0].as_str().unwrap_or("password").to_string();
                    let resp = match r.get(&item) {
                        Some(Ok(token)) => serde_json::json!({
                            "ok": true,
                            "fields": { field: token },
                        }),
                        Some(Err(e)) => serde_json::json!({"ok": false, "error": e}),
                        None => {
                            serde_json::json!({"ok": false, "error": format!("unknown item '{}'", item)})
                        }
                    };
                    let mut body = serde_json::to_string(&resp).unwrap();
                    body.push('\n');
                    let _ = write_half.write_all(body.as_bytes()).await;
                    let _ = write_half.shutdown().await;
                });
            }
        });
        (path_clone, handle)
    }

    #[tokio::test]
    async fn resolves_via_vault_item_when_set() {
        let mut responses = HashMap::new();
        responses.insert("My Item".to_string(), Ok("tok_from_socket".to_string()));
        let (sock_path, _h) = spawn_fake_socket(responses).await;
        let mut env_map = HashMap::new();
        env_map.insert("VAULT_ITEM", "My Item");
        let env_map_ref: &'static HashMap<&'static str, &'static str> =
            Box::leak(Box::new(env_map));
        let result = resolve_token(env_from(env_map_ref), || sock_path.clone()).await;
        let tok = result.expect("should resolve");
        assert_eq!(&*tok, "tok_from_socket");
    }

    #[tokio::test]
    async fn falls_back_to_bearer_token_env() {
        // No socket needed; provider must not even be invoked.
        let mut env_map = HashMap::new();
        env_map.insert("BEARER_TOKEN", "legacy_token");
        let env_map_ref: &'static HashMap<&'static str, &'static str> =
            Box::leak(Box::new(env_map));
        let result = resolve_token(env_from(env_map_ref), || {
            panic!("socket provider must not be called when VAULT_ITEM is unset")
        })
        .await;
        let tok = result.expect("should resolve");
        assert_eq!(&*tok, "legacy_token");
    }

    #[tokio::test]
    async fn vault_item_wins_over_bearer_token() {
        let mut responses = HashMap::new();
        responses.insert("My Item".to_string(), Ok("from_socket".to_string()));
        let (sock_path, _h) = spawn_fake_socket(responses).await;
        let mut env_map = HashMap::new();
        env_map.insert("VAULT_ITEM", "My Item");
        env_map.insert("BEARER_TOKEN", "legacy_token");
        let env_map_ref: &'static HashMap<&'static str, &'static str> =
            Box::leak(Box::new(env_map));
        let result = resolve_token(env_from(env_map_ref), || sock_path.clone()).await;
        let tok = result.expect("should resolve");
        assert_eq!(&*tok, "from_socket");
    }

    #[tokio::test]
    async fn errors_when_neither_set() {
        let env_map: HashMap<&'static str, &'static str> = HashMap::new();
        let env_map_ref: &'static HashMap<&'static str, &'static str> =
            Box::leak(Box::new(env_map));
        let result = resolve_token(env_from(env_map_ref), || {
            panic!("socket provider must not be called")
        })
        .await;
        match result {
            Err(TokenError::Missing) => {}
            other => panic!("expected Missing, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn socket_error_surfaces_as_socket_failed() {
        // Socket path that does not exist; resolution must surface a
        // SocketFailed error, not silently fall through to BEARER_TOKEN.
        let mut env_map = HashMap::new();
        env_map.insert("VAULT_ITEM", "Some Item");
        env_map.insert("BEARER_TOKEN", "this_should_not_be_used");
        let env_map_ref: &'static HashMap<&'static str, &'static str> =
            Box::leak(Box::new(env_map));
        let result = resolve_token(env_from(env_map_ref), || {
            std::path::PathBuf::from("/does/not/exist.sock")
        })
        .await;
        match result {
            Err(TokenError::SocketFailed(_)) => {}
            other => panic!("expected SocketFailed, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn custom_vault_field_honored() {
        let mut responses = HashMap::new();
        responses.insert(
            "Item w/ Custom Field".to_string(),
            Ok("custom_value".to_string()),
        );
        let (sock_path, _h) = spawn_fake_socket(responses).await;
        let mut env_map = HashMap::new();
        env_map.insert("VAULT_ITEM", "Item w/ Custom Field");
        env_map.insert("VAULT_FIELD", "custom_field");
        let env_map_ref: &'static HashMap<&'static str, &'static str> =
            Box::leak(Box::new(env_map));
        let result = resolve_token(env_from(env_map_ref), || sock_path.clone()).await;
        let tok = result.expect("should resolve");
        assert_eq!(&*tok, "custom_value");
    }
}
