//! Rotation strategy implementations for each supported service.

use anyhow::Context as _;
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

// -------------------------------------------------------------------------- //
// Result type                                                                  //
// -------------------------------------------------------------------------- //

/// Outcome of a single rotation attempt.
#[derive(Debug, Serialize)]
pub struct RotationResult {
    pub service: String,
    pub status: String,
    pub message: String,
}

/// Abstracts the channel used to mint a fresh bearer token for a backing
/// service. Production impl is `SshDockerMintExecutor`; tests substitute a
/// fake.
#[async_trait::async_trait]
pub trait MintExecutor: Send + Sync {
    /// Mint a new bearer token using `username`/`password` as the dashboard
    /// auth credentials. Implementations MUST NOT log `password` or include
    /// it in returned errors.
    async fn mint(&self, username: &str, password: &str) -> anyhow::Result<Zeroizing<String>>;
}

/// Vault read/write surface needed by `rotate_wi_mcp`. Production impl wraps
/// `AppState` (see `crate::rotate::wi_mcp_adapter`); tests substitute a fake.
#[async_trait::async_trait]
pub trait RotateContext: Send + Sync {
    /// Decrypt the `username` field of `item`. Returns a `Zeroizing<String>`
    /// so the plaintext is wiped on drop.
    fn decrypt_username(&self, item: &str) -> anyhow::Result<Zeroizing<String>>;

    /// Decrypt the `password` field of `item`.
    fn decrypt_password(&self, item: &str) -> anyhow::Result<Zeroizing<String>>;

    /// Re-encrypt `new_password` and push the cipher update to the upstream
    /// vault. Concrete impls MUST scope writes to the configured vault folder.
    async fn update_password(&self, item: &str, new_password: &str) -> anyhow::Result<()>;

    /// Path to the vault-proxy config directory. Used as the parent for
    /// `wi-mcp-token-recovery-*.txt` on vault-write failure.
    fn config_dir(&self) -> &Path;
}

// -------------------------------------------------------------------------- //
// Strategies                                                                   //
// -------------------------------------------------------------------------- //

/// Sonarr rotation is not API-based — it requires direct config file access.
pub async fn rotate_sonarr() -> RotationResult {
    RotationResult {
        service: "sonarr".to_string(),
        status: "unsupported".to_string(),
        message: "Sonarr API key rotation requires config file access and is not supported via the API strategy.".to_string(),
    }
}

/// Radarr rotation is not API-based — it requires direct config file access.
pub async fn rotate_radarr() -> RotationResult {
    RotationResult {
        service: "radarr".to_string(),
        status: "unsupported".to_string(),
        message: "Radarr API key rotation requires config file access and is not supported via the API strategy.".to_string(),
    }
}

/// Bootstrap a UniFi OS API key from local admin credentials.
///
/// Authenticates to the UniFi OS REST API using username+password, generates
/// an API key, logs out, and returns the key. No retries on auth failure —
/// each retry extends the account lockout window.
///
/// # Arguments
/// * `uri` — UniFi OS base URL, e.g. `https://unifi.splendidus.live`
/// * `username` — local admin username (NOT an SSO account)
/// * `password` — local admin password
/// * `verify_ssl` — set false to skip TLS verification (self-signed certs)
pub async fn bootstrap_unifi_api_key(
    uri: &str,
    username: &str,
    password: &str,
    verify_ssl: bool,
) -> anyhow::Result<zeroize::Zeroizing<String>> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(!verify_ssl)
        .cookie_store(true)
        .build()
        .context("build reqwest client for UniFi bootstrap")?;

    // Step 1: Authenticate — obtain session cookie.
    // X-Csrf-Token must be present (any non-empty value); UniFi OS rejects
    // the request with 403 if the header is absent entirely.
    let login_resp = client
        .post(format!("{}/api/auth/login", uri))
        .header("X-Csrf-Token", "bootstrap")
        .json(&serde_json::json!({
            "username": username,
            "password": password
        }))
        .send()
        .await
        .context("UniFi login request failed")?;

    if !login_resp.status().is_success() {
        let status = login_resp.status();
        anyhow::bail!(
            "bootstrap: UniFi login failed ({}) — check local admin credentials in auth_item",
            status
        );
    }

    // Step 2: Generate API key. Logout runs regardless of outcome.
    let key_result: anyhow::Result<zeroize::Zeroizing<String>> = async {
        let key_resp = client
            .post(format!("{}/api/users/self/api-key", uri))
            .json(&serde_json::json!({}))
            .send()
            .await
            .context("UniFi API key generation request failed")?;

        if !key_resp.status().is_success() {
            let status = key_resp.status();
            anyhow::bail!("bootstrap: UniFi API key generation failed ({})", status);
        }

        let body: serde_json::Value = key_resp
            .json()
            .await
            .context("parse UniFi API key response")?;

        let api_key = body["data"]["apiKey"]
            .as_str()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "bootstrap: 'apiKey' not found in UniFi response: {}",
                    body
                )
            })?
            .to_string();

        Ok(zeroize::Zeroizing::new(api_key))
    }
    .await;

    // Step 3: Logout — always, even if step 2 failed.
    let _ = client
        .delete(format!("{}/api/auth/logout", uri))
        .send()
        .await;

    key_result
}

const WI_MCP_BEARER_ITEM: &str = "WI MCP - Bearer";
const WI_MCP_ADMIN_ITEM: &str = "WI MCP - Admin";

fn wi_mcp_err(message: impl Into<String>) -> RotationResult {
    RotationResult {
        service: "wi-mcp".to_string(),
        status: "error".to_string(),
        message: message.into(),
    }
}

/// Rotate the `wi-mcp` bearer token: read admin creds from the vault,
/// mint a fresh token via the injected `MintExecutor`, write the new token
/// back to the bearer item.
///
/// On vault-write failure the minted token is persisted to a 0600 recovery
/// file under `ctx.config_dir()`; the `RotationResult.message` points the
/// operator at it.
pub async fn rotate_wi_mcp<E: MintExecutor + ?Sized>(
    ctx: &dyn RotateContext,
    mint_executor: &E,
) -> RotationResult {
    // --- admin lookup ----------------------------------------------------
    let username = match ctx.decrypt_username(WI_MCP_ADMIN_ITEM) {
        Ok(u) => u,
        Err(e) => return wi_mcp_err(format!("admin-lookup: {}", e)),
    };
    let password = match ctx.decrypt_password(WI_MCP_ADMIN_ITEM) {
        Ok(p) => p,
        Err(e) => return wi_mcp_err(format!("admin-lookup: {}", e)),
    };
    if username.is_empty() {
        return wi_mcp_err(format!(
            "admin-lookup: item '{}' has empty 'username'",
            WI_MCP_ADMIN_ITEM,
        ));
    }
    if password.is_empty() {
        return wi_mcp_err(format!(
            "admin-lookup: item '{}' has empty 'password'",
            WI_MCP_ADMIN_ITEM,
        ));
    }

    // --- mint ------------------------------------------------------------
    let new_token = match mint_executor.mint(&username, &password).await {
        Ok(t) => t,
        Err(e) => return wi_mcp_err(format!("mint: {}", e)),
    };

    // --- persist ---------------------------------------------------------
    if let Err(e) = ctx.update_password(WI_MCP_BEARER_ITEM, &new_token).await {
        let recovery = write_recovery_file(ctx.config_dir(), &new_token);
        let path_str = match recovery {
            Ok(p) => p.display().to_string(),
            Err(rerr) => format!("<recovery write failed: {}>", rerr),
        };
        return wi_mcp_err(format!(
            "persist: vault write failed: {}; token written to {}",
            e, path_str
        ));
    }

    RotationResult {
        service: "wi-mcp".to_string(),
        status: "success".to_string(),
        message: format!("rotated wi-mcp bearer; token len={}", new_token.len()),
    }
}

/// Write `token` to `<config_dir>/wi-mcp-token-recovery-<unix-ts>.txt` with
/// mode 0600. Used as a fallback when vault write fails but the token was
/// successfully minted.
fn write_recovery_file(config_dir: &std::path::Path, token: &str) -> anyhow::Result<PathBuf> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let path = config_dir.join(format!("wi-mcp-token-recovery-{}.txt", ts));

    let mut opts = OpenOptions::new();
    opts.create_new(true).write(true);
    #[cfg(unix)]
    {
        opts.mode(0o600);
    }
    let mut f = opts
        .open(&path)
        .with_context(|| format!("open recovery file {}", path.display()))?;
    writeln!(f, "WI MCP - Bearer")?;
    writeln!(f, "{}", token)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bootstrap_unifi_api_key_exists() {
        // Compile-time check: verify the function exists with the correct
        // parameter types and return type. The if-false guard means the future
        // is never polled and no network call is made.
        if false {
            let _ = bootstrap_unifi_api_key("uri", "user", "pass", false);
        }
    }

    use std::sync::Arc;

    struct FakeMintExecutor {
        result: Result<String, String>,
        last_call: tokio::sync::Mutex<Option<(String, String)>>,
    }

    #[async_trait::async_trait]
    impl MintExecutor for FakeMintExecutor {
        async fn mint(&self, username: &str, password: &str) -> anyhow::Result<Zeroizing<String>> {
            *self.last_call.lock().await = Some((username.to_string(), password.to_string()));
            match &self.result {
                Ok(tok) => Ok(Zeroizing::new(tok.clone())),
                Err(msg) => Err(anyhow::anyhow!("{}", msg)),
            }
        }
    }

    #[tokio::test]
    async fn fake_mint_executor_returns_configured_token() {
        let fake = FakeMintExecutor {
            result: Ok("tok_abc".to_string()),
            last_call: tokio::sync::Mutex::new(None),
        };
        let exec: Arc<dyn MintExecutor> = Arc::new(fake);
        let out = exec.mint("user1", "pw1").await.unwrap();
        assert_eq!(&*out, "tok_abc");
    }

    use std::path::{Path, PathBuf};

    struct FakeRotateContext {
        username: Result<String, String>,
        password: Result<String, String>,
        update_should_fail: bool,
        last_update: tokio::sync::Mutex<Option<(String, String)>>,
        config_dir: PathBuf,
    }

    #[async_trait::async_trait]
    impl RotateContext for FakeRotateContext {
        fn decrypt_username(&self, _item: &str) -> anyhow::Result<Zeroizing<String>> {
            match &self.username {
                Ok(u) => Ok(Zeroizing::new(u.clone())),
                Err(m) => Err(anyhow::anyhow!("{}", m)),
            }
        }
        fn decrypt_password(&self, _item: &str) -> anyhow::Result<Zeroizing<String>> {
            match &self.password {
                Ok(p) => Ok(Zeroizing::new(p.clone())),
                Err(m) => Err(anyhow::anyhow!("{}", m)),
            }
        }
        async fn update_password(&self, item: &str, new: &str) -> anyhow::Result<()> {
            *self.last_update.lock().await = Some((item.to_string(), new.to_string()));
            if self.update_should_fail {
                anyhow::bail!("simulated vault write failure");
            }
            Ok(())
        }
        fn config_dir(&self) -> &Path {
            &self.config_dir
        }
    }

    #[tokio::test]
    async fn fake_rotate_context_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = FakeRotateContext {
            username: Ok("admin".to_string()),
            password: Ok("hunter2".to_string()),
            update_should_fail: false,
            last_update: tokio::sync::Mutex::new(None),
            config_dir: dir.path().to_path_buf(),
        };
        assert_eq!(&*ctx.decrypt_username("x").unwrap(), "admin");
        assert_eq!(&*ctx.decrypt_password("x").unwrap(), "hunter2");
        ctx.update_password("WI MCP - Bearer", "tok_new")
            .await
            .unwrap();
        let snap = ctx.last_update.lock().await.clone().unwrap();
        assert_eq!(snap.0, "WI MCP - Bearer");
        assert_eq!(snap.1, "tok_new");
    }

    fn make_fakes(
        token: &str,
        user: &str,
        pass: &str,
    ) -> (Arc<FakeMintExecutor>, FakeRotateContext, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let mint = Arc::new(FakeMintExecutor {
            result: Ok(token.to_string()),
            last_call: tokio::sync::Mutex::new(None),
        });
        let ctx = FakeRotateContext {
            username: Ok(user.to_string()),
            password: Ok(pass.to_string()),
            update_should_fail: false,
            last_update: tokio::sync::Mutex::new(None),
            config_dir: dir.path().to_path_buf(),
        };
        (mint, ctx, dir)
    }

    #[tokio::test]
    async fn rotate_wi_mcp_happy_path() {
        let (mint, ctx, _dir) = make_fakes("tok_abc", "admin", "hunter2");
        let result = rotate_wi_mcp(&ctx, mint.as_ref()).await;
        assert_eq!(result.status, "success", "msg={}", result.message);
        let updated = ctx.last_update.lock().await.clone().unwrap();
        assert_eq!(updated.0, "WI MCP - Bearer");
        assert_eq!(updated.1, "tok_abc");
        let minted = mint.last_call.lock().await.clone().unwrap();
        assert_eq!(minted.0, "admin");
        assert_eq!(minted.1, "hunter2");
    }

    #[tokio::test]
    async fn rotate_wi_mcp_admin_username_missing() {
        let dir = tempfile::tempdir().unwrap();
        let mint = Arc::new(FakeMintExecutor {
            result: Ok("tok".to_string()),
            last_call: tokio::sync::Mutex::new(None),
        });
        let ctx = FakeRotateContext {
            username: Err("item 'WI MCP - Admin' not found in vault".to_string()),
            password: Ok("hunter2".to_string()),
            update_should_fail: false,
            last_update: tokio::sync::Mutex::new(None),
            config_dir: dir.path().to_path_buf(),
        };
        let result = rotate_wi_mcp(&ctx, mint.as_ref()).await;
        assert_eq!(result.status, "error");
        assert!(
            result.message.starts_with("admin-lookup:"),
            "got: {}",
            result.message
        );
        // Mint must NOT have been called.
        assert!(mint.last_call.lock().await.is_none());
    }

    #[tokio::test]
    async fn rotate_wi_mcp_admin_username_empty() {
        let dir = tempfile::tempdir().unwrap();
        let mint = Arc::new(FakeMintExecutor {
            result: Ok("tok".to_string()),
            last_call: tokio::sync::Mutex::new(None),
        });
        let ctx = FakeRotateContext {
            username: Ok("".to_string()),
            password: Ok("hunter2".to_string()),
            update_should_fail: false,
            last_update: tokio::sync::Mutex::new(None),
            config_dir: dir.path().to_path_buf(),
        };
        let result = rotate_wi_mcp(&ctx, mint.as_ref()).await;
        assert_eq!(result.status, "error");
        assert!(
            result.message.contains("empty 'username'"),
            "got: {}",
            result.message
        );
    }

    #[tokio::test]
    async fn rotate_wi_mcp_mint_fails() {
        let dir = tempfile::tempdir().unwrap();
        let mint = Arc::new(FakeMintExecutor {
            result: Err("ssh exit=1; stderr=ERROR: authentication failed".to_string()),
            last_call: tokio::sync::Mutex::new(None),
        });
        let ctx = FakeRotateContext {
            username: Ok("admin".to_string()),
            password: Ok("hunter2".to_string()),
            update_should_fail: false,
            last_update: tokio::sync::Mutex::new(None),
            config_dir: dir.path().to_path_buf(),
        };
        let result = rotate_wi_mcp(&ctx, mint.as_ref()).await;
        assert_eq!(result.status, "error");
        assert!(
            result.message.starts_with("mint:"),
            "got: {}",
            result.message
        );
        // update_password must NOT have been called.
        assert!(ctx.last_update.lock().await.is_none());
    }

    #[tokio::test]
    async fn rotate_wi_mcp_persist_fails_writes_recovery_file() {
        let dir = tempfile::tempdir().unwrap();
        let mint = Arc::new(FakeMintExecutor {
            result: Ok("tok_xyz".to_string()),
            last_call: tokio::sync::Mutex::new(None),
        });
        let ctx = FakeRotateContext {
            username: Ok("admin".to_string()),
            password: Ok("hunter2".to_string()),
            update_should_fail: true,
            last_update: tokio::sync::Mutex::new(None),
            config_dir: dir.path().to_path_buf(),
        };
        let result = rotate_wi_mcp(&ctx, mint.as_ref()).await;
        assert_eq!(result.status, "error");
        assert!(
            result.message.contains("persist: vault write failed"),
            "got: {}",
            result.message
        );
        // Recovery file exists and contains the token.
        let mut found: Option<std::path::PathBuf> = None;
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let p = entry.unwrap().path();
            if p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("wi-mcp-token-recovery-")
            {
                found = Some(p);
                break;
            }
        }
        let path = found.expect("recovery file should exist");
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("tok_xyz"), "body: {}", body);
        assert!(body.contains("WI MCP - Bearer"), "body: {}", body);
        // Mode is 0600 on unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "recovery file should be 0600, got {:o}", mode);
        }
    }
}
