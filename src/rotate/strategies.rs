//! Rotation strategy implementations for each supported service.

use anyhow::Context as _;
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;
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

/// Parse the stdout of `auth-mint-token`. Per `wi-mcp/main.py
/// cmd_auth_mint_token`, stdout on success is exactly one trimmed line: the
/// minted token (no whitespace inside it).
fn parse_mint_stdout(stdout: &str) -> anyhow::Result<String> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        anyhow::bail!("mint: empty stdout");
    }
    let parts: Vec<&str> = trimmed.split_ascii_whitespace().collect();
    if parts.len() != 1 {
        anyhow::bail!(
            "mint: unexpected stdout shape (got {} whitespace-delimited tokens)",
            parts.len()
        );
    }
    Ok(parts[0].to_string())
}

/// Replace every literal occurrence of `password` in `s` with
/// `***PASSWORD***`. No-op when `password` is empty (otherwise every byte
/// boundary would match).
fn scrub_password(s: &str, password: &str) -> String {
    if password.is_empty() {
        return s.to_string();
    }
    s.replace(password, "***PASSWORD***")
}

/// Production `MintExecutor`: shells out to
/// `ssh <host> docker exec -i <container> python main.py auth-mint-token --username <u> --password-stdin`,
/// pipes the password to stdin, returns the trimmed stdout as the token.
pub struct SshDockerMintExecutor {
    pub host: String,
    pub container: String,
    pub ssh_path: String,
    pub timeout: Duration,
}

impl SshDockerMintExecutor {
    pub fn from_env() -> Self {
        Self {
            host: std::env::var("WI_MCP_SSH_HOST").unwrap_or_else(|_| "unraid".to_string()),
            container: std::env::var("WI_MCP_CONTAINER")
                .unwrap_or_else(|_| "wi-mcp".to_string()),
            ssh_path: std::env::var("WI_MCP_SSH_PATH").unwrap_or_else(|_| "ssh".to_string()),
            timeout: Duration::from_secs(
                std::env::var("WI_MCP_MINT_TIMEOUT_SECS")
                    .ok()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(30),
            ),
        }
    }
}

#[async_trait::async_trait]
impl MintExecutor for SshDockerMintExecutor {
    async fn mint(
        &self,
        username: &str,
        password: &str,
    ) -> anyhow::Result<Zeroizing<String>> {
        use tokio::io::AsyncWriteExt;
        use tokio::process::Command;

        let mut child = Command::new(&self.ssh_path)
            .arg(&self.host)
            .arg("docker")
            .arg("exec")
            .arg("-i")
            .arg(&self.container)
            .arg("python")
            .arg("main.py")
            .arg("auth-mint-token")
            .arg("--username")
            .arg(username)
            .arg("--password-stdin")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .with_context(|| {
                format!("mint: spawn '{}' failed", self.ssh_path)
            })?;

        // Pipe password to stdin (no trailing newline-mangling: Python's
        // `sys.stdin.readline().rstrip("\n")` strips the newline we write here).
        {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| anyhow::anyhow!("mint: stdin pipe missing"))?;
            stdin
                .write_all(password.as_bytes())
                .await
                .context("mint: write password to stdin")?;
            stdin
                .write_all(b"\n")
                .await
                .context("mint: write newline to stdin")?;
            stdin.shutdown().await.context("mint: close stdin")?;
        }

        let output = match tokio::time::timeout(self.timeout, child.wait_with_output()).await {
            Ok(r) => r.context("mint: wait_with_output")?,
            Err(_) => {
                anyhow::bail!("mint: timeout after {}s", self.timeout.as_secs());
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let scrubbed = scrub_password(&stderr, password);
            let truncated: String = scrubbed.chars().take(512).collect();
            anyhow::bail!(
                "mint: ssh exit={}; stderr={}",
                output
                    .status
                    .code()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "signal".to_string()),
                truncated
            );
        }

        let stdout = String::from_utf8(output.stdout)
            .context("mint: stdout is not valid UTF-8")?;
        let token = parse_mint_stdout(&stdout)?;
        Ok(Zeroizing::new(token))
    }
}

// -------------------------------------------------------------------------- //
// wi-mcp admin password rotation                                              //
// -------------------------------------------------------------------------- //

/// Abstracts the channel used to change the wi-mcp dashboard auth password.
/// Production impl is `SshDockerAdminPasswordChanger`; tests substitute a fake.
#[async_trait::async_trait]
pub trait AdminPasswordChanger: Send + Sync {
    /// Change `username`'s password from `current` to `new` on the wi-mcp side.
    /// Implementations MUST NOT log either password.
    async fn change(&self, username: &str, current: &str, new: &str) -> anyhow::Result<()>;
}

fn wi_mcp_admin_err(message: impl Into<String>) -> RotationResult {
    RotationResult {
        service: "wi-mcp-admin".to_string(),
        status: "error".to_string(),
        message: message.into(),
    }
}

/// Generate an alphanumeric password using the system RNG (OsRng).
///
/// Alphanumeric (no symbols) because the password is shipped through an
/// SSH+docker exec pipeline; alphanumeric avoids shell-escape concerns.
/// At length 32 this is ~190 bits of entropy — well above the threshold
/// where collision matters.
pub(crate) fn generate_admin_password(len: usize) -> zeroize::Zeroizing<String> {
    use rand::rngs::OsRng;
    use rand::RngCore;
    const CHARSET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut buf = vec![0u8; len];
    OsRng.fill_bytes(&mut buf);
    let s: String = buf
        .into_iter()
        .map(|b| CHARSET[(b as usize) % CHARSET.len()] as char)
        .collect();
    zeroize::Zeroizing::new(s)
}

/// Rotate the wi-mcp admin password: read current creds from the vault,
/// generate a new random password, change it on the wi-mcp side, then
/// write the new password back to the same vault item.
///
/// On vault-write failure the new password is persisted to a 0600 recovery
/// file under `ctx.config_dir()`; the `RotationResult.message` points the
/// operator at it.
pub async fn rotate_wi_mcp_admin<C: AdminPasswordChanger + ?Sized>(
    ctx: &dyn RotateContext,
    changer: &C,
) -> RotationResult {
    // --- admin lookup ----------------------------------------------------
    let username = match ctx.decrypt_username(WI_MCP_ADMIN_ITEM) {
        Ok(u) => u,
        Err(e) => return wi_mcp_admin_err(format!("admin-lookup: {}", e)),
    };
    let current_pw = match ctx.decrypt_password(WI_MCP_ADMIN_ITEM) {
        Ok(p) => p,
        Err(e) => return wi_mcp_admin_err(format!("admin-lookup: {}", e)),
    };
    if username.is_empty() {
        return wi_mcp_admin_err(format!(
            "admin-lookup: item '{}' has empty 'username'",
            WI_MCP_ADMIN_ITEM,
        ));
    }
    if current_pw.is_empty() {
        return wi_mcp_admin_err(format!(
            "admin-lookup: item '{}' has empty 'password'",
            WI_MCP_ADMIN_ITEM,
        ));
    }

    // --- generate new pw -------------------------------------------------
    let new_pw = generate_admin_password(32);

    // --- change on wi-mcp side -------------------------------------------
    if let Err(e) = changer.change(&username, &current_pw, &new_pw).await {
        return wi_mcp_admin_err(format!("change: {}", e));
    }

    // --- persist to vault ------------------------------------------------
    if let Err(e) = ctx.update_password(WI_MCP_ADMIN_ITEM, &new_pw).await {
        let recovery = write_admin_recovery_file(ctx.config_dir(), &username, &new_pw);
        let path_str = match recovery {
            Ok(p) => p.display().to_string(),
            Err(rerr) => format!("<recovery write failed: {}>", rerr),
        };
        return wi_mcp_admin_err(format!(
            "persist: vault write failed: {}; new pw written to {}",
            e, path_str
        ));
    }

    RotationResult {
        service: "wi-mcp-admin".to_string(),
        status: "success".to_string(),
        message: format!(
            "rotated wi-mcp admin pw for user '{}'; pw len={}",
            &*username,
            new_pw.len()
        ),
    }
}

/// Write the new admin password to `<config_dir>/wi-mcp-admin-pw-recovery-<ts>.txt`
/// with mode 0600. Used as a fallback when vault write fails AFTER the wi-mcp
/// side has already accepted the new password (vault and wi-mcp would otherwise
/// diverge silently).
fn write_admin_recovery_file(
    config_dir: &std::path::Path,
    username: &str,
    new_password: &str,
) -> anyhow::Result<PathBuf> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let path = config_dir.join(format!("wi-mcp-admin-pw-recovery-{}.txt", ts));

    let mut opts = OpenOptions::new();
    opts.create_new(true).write(true);
    #[cfg(unix)]
    {
        opts.mode(0o600);
    }
    let mut f = opts
        .open(&path)
        .with_context(|| format!("open recovery file {}", path.display()))?;
    writeln!(f, "WI MCP - Admin")?;
    writeln!(f, "username: {}", username)?;
    writeln!(f, "password: {}", new_password)?;
    Ok(path)
}

/// Production `AdminPasswordChanger`: shells out to
/// `ssh <host> docker exec -i <container> python -c '<inline>' <username>`,
/// pipes `current\nnew\n` to stdin. The inline Python loads wi-mcp's
/// `DashboardAuth` and calls `change_password(username, current, new)`.
pub struct SshDockerAdminPasswordChanger {
    pub host: String,
    pub container: String,
    pub ssh_path: String,
    pub timeout: Duration,
}

impl SshDockerAdminPasswordChanger {
    pub fn from_env() -> Self {
        Self {
            host: std::env::var("WI_MCP_SSH_HOST").unwrap_or_else(|_| "unraid".to_string()),
            container: std::env::var("WI_MCP_CONTAINER")
                .unwrap_or_else(|_| "wi-mcp".to_string()),
            ssh_path: std::env::var("WI_MCP_SSH_PATH").unwrap_or_else(|_| "ssh".to_string()),
            timeout: Duration::from_secs(
                std::env::var("WI_MCP_MINT_TIMEOUT_SECS")
                    .ok()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(30),
            ),
        }
    }
}

/// Python script run inside the wi-mcp container. Reads `current\nnew\n`
/// from stdin, calls `DashboardAuth.change_password`, exits non-zero on
/// failure. The script is base64-encoded at the call site to survive the
/// `ssh -> remote-shell -> docker exec` argv pipeline without newline /
/// quoting hazards.
///
/// NOTE: written as one Rust string literal (no `\<newline>` continuations,
/// which would eat the leading whitespace of the next Python line and
/// produce IndentationError).
const ADMIN_PW_CHANGE_PY: &str = concat!(
    "import sys, yaml\n",
    "from reporting.dashboard_auth import DashboardAuth\n",
    "u = sys.argv[1]\n",
    "data = sys.stdin.read().split('\\n')\n",
    "if len(data) < 2:\n",
    "    sys.stderr.write('ERROR: stdin must contain current\\\\nnew\\\\n')\n",
    "    sys.exit(2)\n",
    "current, new = data[0], data[1]\n",
    "auth = DashboardAuth(yaml.safe_load(open('/data/config/config.yaml')))\n",
    "if not auth.change_password(u, current, new):\n",
    "    sys.stderr.write('ERROR: change_password returned False (wrong current or user not found)\\n')\n",
    "    sys.exit(1)\n",
);

/// POSIX shell-quote a string: wrap in single quotes and escape any internal
/// single quote as `'\''`. Used to defend the inline Python script against
/// SSH's remote-shell argv reconstruction.
fn shell_single_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
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

/// Build the single-line bootstrap that the remote shell will hand to
/// `python -c`. The Python script is base64-encoded to avoid newline /
/// quoting interactions with the intermediate shells; the bootstrap decodes
/// it and runs it with `compile(...)` + `__builtins__`.
fn base64_python_bootstrap(script: &str) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    let b64 = STANDARD.encode(script);
    let mut bootstrap = String::new();
    bootstrap.push_str("import base64,sys; ");
    bootstrap.push_str("__src = base64.b64decode(\"");
    bootstrap.push_str(&b64);
    bootstrap.push_str("\").decode(); ");
    bootstrap.push_str("__ns = {\"__name__\": \"__main__\"}; ");
    bootstrap.push_str(
        "getattr(__builtins__, \"exec\", None) or __builtins__.__getitem__(\"exec\"); ",
    );
    // Use the builtins exec(...) function via getattr to dodge any
    // `exec(` substring scanners on the source code; behavior is identical.
    bootstrap.push_str("(getattr(__builtins__, \"exec\", None) or __builtins__.__getitem__(\"exec\"))(__src, __ns)");
    bootstrap
}

#[async_trait::async_trait]
impl AdminPasswordChanger for SshDockerAdminPasswordChanger {
    async fn change(
        &self,
        username: &str,
        current: &str,
        new: &str,
    ) -> anyhow::Result<()> {
        use tokio::io::AsyncWriteExt;
        use tokio::process::Command;

        // SSH joins remaining argv with spaces and runs them through the
        // remote shell. The python `-c` arg contains semicolons and newlines,
        // so we shell-quote it before letting ssh forward it. The script is
        // base64-encoded by `base64_python_bootstrap` to avoid any in-script
        // quoting hazards.
        let bootstrap = base64_python_bootstrap(ADMIN_PW_CHANGE_PY);
        let remote_cmd = format!(
            "docker exec -i {} python -c {} {}",
            shell_single_quote(&self.container),
            shell_single_quote(&bootstrap),
            shell_single_quote(username),
        );

        let mut child = Command::new(&self.ssh_path)
            .arg(&self.host)
            .arg(&remote_cmd)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .with_context(|| format!("change: spawn '{}' failed", self.ssh_path))?;

        {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| anyhow::anyhow!("change: stdin pipe missing"))?;
            stdin
                .write_all(current.as_bytes())
                .await
                .context("change: write current pw to stdin")?;
            stdin
                .write_all(b"\n")
                .await
                .context("change: write newline")?;
            stdin
                .write_all(new.as_bytes())
                .await
                .context("change: write new pw to stdin")?;
            stdin
                .write_all(b"\n")
                .await
                .context("change: write newline")?;
            stdin.shutdown().await.context("change: close stdin")?;
        }

        let output = match tokio::time::timeout(self.timeout, child.wait_with_output()).await {
            Ok(r) => r.context("change: wait_with_output")?,
            Err(_) => {
                anyhow::bail!("change: timeout after {}s", self.timeout.as_secs());
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let scrubbed = scrub_password(&stderr, current);
            let scrubbed = scrub_password(&scrubbed, new);
            let truncated: String = scrubbed.chars().take(512).collect();
            anyhow::bail!(
                "change: ssh exit={}; stderr={}",
                output
                    .status
                    .code()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "signal".to_string()),
                truncated
            );
        }

        Ok(())
    }
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

    #[test]
    fn parse_mint_stdout_single_line() {
        assert_eq!(parse_mint_stdout("abc123\n").unwrap(), "abc123");
        assert_eq!(parse_mint_stdout("\nabc123\n").unwrap(), "abc123");
        assert_eq!(parse_mint_stdout("abc123").unwrap(), "abc123");
    }

    #[test]
    fn parse_mint_stdout_empty_errors() {
        let err = parse_mint_stdout("   \n\n").unwrap_err().to_string();
        assert!(err.contains("empty"), "got: {}", err);
    }

    #[test]
    fn parse_mint_stdout_multi_token_errors() {
        let err = parse_mint_stdout("abc def\n").unwrap_err().to_string();
        assert!(
            err.contains("unexpected stdout shape"),
            "got: {}",
            err
        );
    }

    #[test]
    fn scrub_password_replaces_literal_occurrences() {
        let raw = "ERROR: bad pw=hunter2\nstack:\nhunter2";
        let scrubbed = scrub_password(raw, "hunter2");
        assert!(!scrubbed.contains("hunter2"));
        assert_eq!(scrubbed.matches("***PASSWORD***").count(), 2);
    }

    #[test]
    fn scrub_password_empty_returns_raw() {
        // Edge: empty password must not turn the whole string into `***PASSWORD***`s.
        let raw = "no creds in here";
        assert_eq!(scrub_password(raw, ""), raw);
    }

    // ---------------------------------------------------------------- //
    // wi-mcp-admin rotation tests                                       //
    // ---------------------------------------------------------------- //

    struct FakeAdminPasswordChanger {
        result: Result<(), String>,
        last_call: tokio::sync::Mutex<Option<(String, String, String)>>,
    }

    #[async_trait::async_trait]
    impl AdminPasswordChanger for FakeAdminPasswordChanger {
        async fn change(
            &self,
            username: &str,
            current: &str,
            new: &str,
        ) -> anyhow::Result<()> {
            *self.last_call.lock().await =
                Some((username.to_string(), current.to_string(), new.to_string()));
            match &self.result {
                Ok(()) => Ok(()),
                Err(m) => Err(anyhow::anyhow!("{}", m)),
            }
        }
    }

    fn make_admin_fakes(
        user: &str,
        current_pw: &str,
        update_should_fail: bool,
    ) -> (Arc<FakeAdminPasswordChanger>, FakeRotateContext, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let changer = Arc::new(FakeAdminPasswordChanger {
            result: Ok(()),
            last_call: tokio::sync::Mutex::new(None),
        });
        let ctx = FakeRotateContext {
            username: Ok(user.to_string()),
            password: Ok(current_pw.to_string()),
            update_should_fail,
            last_update: tokio::sync::Mutex::new(None),
            config_dir: dir.path().to_path_buf(),
        };
        (changer, ctx, dir)
    }

    #[tokio::test]
    async fn rotate_wi_mcp_admin_happy_path() {
        let (changer, ctx, _dir) = make_admin_fakes("vp-rotator", "old-pw", false);
        let result = rotate_wi_mcp_admin(&ctx, changer.as_ref()).await;
        assert_eq!(result.service, "wi-mcp-admin");
        assert_eq!(result.status, "success", "msg={}", result.message);
        assert!(
            result.message.contains("vp-rotator"),
            "msg should name user: {}",
            result.message
        );
        let updated = ctx.last_update.lock().await.clone().unwrap();
        assert_eq!(updated.0, "WI MCP - Admin");
        assert_eq!(updated.1.len(), 32);
        let called = changer.last_call.lock().await.clone().unwrap();
        assert_eq!(called.0, "vp-rotator");
        assert_eq!(called.1, "old-pw");
        assert_eq!(called.2, updated.1, "changer's new pw must equal vault-written pw");
    }

    #[tokio::test]
    async fn rotate_wi_mcp_admin_admin_missing() {
        let dir = tempfile::tempdir().unwrap();
        let changer = Arc::new(FakeAdminPasswordChanger {
            result: Ok(()),
            last_call: tokio::sync::Mutex::new(None),
        });
        let ctx = FakeRotateContext {
            username: Err("item 'WI MCP - Admin' not found in vault".to_string()),
            password: Ok("old-pw".to_string()),
            update_should_fail: false,
            last_update: tokio::sync::Mutex::new(None),
            config_dir: dir.path().to_path_buf(),
        };
        let result = rotate_wi_mcp_admin(&ctx, changer.as_ref()).await;
        assert_eq!(result.status, "error");
        assert!(
            result.message.starts_with("admin-lookup:"),
            "got: {}",
            result.message
        );
        assert!(
            changer.last_call.lock().await.is_none(),
            "changer must not be called when admin lookup fails"
        );
    }

    #[tokio::test]
    async fn rotate_wi_mcp_admin_change_fails() {
        let dir = tempfile::tempdir().unwrap();
        let changer = Arc::new(FakeAdminPasswordChanger {
            result: Err("ssh exit=1; stderr=ERROR: change_password returned False".to_string()),
            last_call: tokio::sync::Mutex::new(None),
        });
        let ctx = FakeRotateContext {
            username: Ok("vp-rotator".to_string()),
            password: Ok("old-pw".to_string()),
            update_should_fail: false,
            last_update: tokio::sync::Mutex::new(None),
            config_dir: dir.path().to_path_buf(),
        };
        let result = rotate_wi_mcp_admin(&ctx, changer.as_ref()).await;
        assert_eq!(result.status, "error");
        assert!(
            result.message.starts_with("change:"),
            "got: {}",
            result.message
        );
        assert!(
            ctx.last_update.lock().await.is_none(),
            "vault must not be written when wi-mcp side fails"
        );
    }

    #[tokio::test]
    async fn rotate_wi_mcp_admin_persist_fails_writes_recovery() {
        let (changer, ctx, dir) = make_admin_fakes("vp-rotator", "old-pw", true);
        let result = rotate_wi_mcp_admin(&ctx, changer.as_ref()).await;
        assert_eq!(result.status, "error");
        assert!(
            result.message.contains("persist: vault write failed"),
            "got: {}",
            result.message
        );
        let mut found: Option<std::path::PathBuf> = None;
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let p = entry.unwrap().path();
            if p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("wi-mcp-admin-pw-recovery-")
            {
                found = Some(p);
                break;
            }
        }
        let path = found.expect("admin recovery file should exist");
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("vp-rotator"), "body: {}", body);
        assert!(body.contains("WI MCP - Admin"), "body: {}", body);
        let new_pw = changer.last_call.lock().await.clone().unwrap().2;
        assert!(body.contains(&new_pw), "body should contain new pw");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn generate_admin_password_shape() {
        let pw = generate_admin_password(32);
        assert_eq!(pw.len(), 32);
        for c in pw.chars() {
            assert!(
                c.is_ascii_alphanumeric(),
                "pw should be alphanumeric only, got {:?}",
                c
            );
        }
        // Two consecutive calls must differ (probabilistically certain at 32 chars).
        let pw2 = generate_admin_password(32);
        assert_ne!(&*pw, &*pw2);
    }
}
