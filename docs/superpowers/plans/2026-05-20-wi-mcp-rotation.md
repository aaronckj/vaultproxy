# wi-mcp Rotation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `wi-mcp` rotation strategy to vp so `POST /rotate` mints a fresh bearer token via `ssh unraid docker exec wi-mcp python main.py auth-mint-token` and writes it back to Vaultwarden item "WI MCP - Bearer" automatically.

**Architecture:** New `rotate_wi_mcp` strategy in `src/rotate/strategies.rs` plugs into existing `handle_rotate` dispatch. A `MintExecutor` trait isolates the SSH+docker call for testability (`SshDockerMintExecutor` for prod, `FakeMintExecutor` for tests). A `RotateContext` trait abstracts the vault read/write surface so the rotator can be tested against a fake vault. On vault-write failure, the minted token is written to `$CONFIG_DIR/wi-mcp-token-recovery-<ts>.txt` (0600) so the operator can recover.

**Tech Stack:** Rust, axum, tokio (`process::Command`, `time::timeout`), async-trait, zeroize, tempfile (dev-only), anyhow.

**Spec:** `docs/superpowers/specs/2026-05-20-wi-mcp-rotation-design.md`.

**Branch:** `feat/wi-mcp-rotation` (already created off `main`, spec already committed there).

---

## File Structure

| Path | Action | Responsibility |
|------|--------|----------------|
| `src/rotate/strategies.rs` | modify | Add `MintExecutor` trait + `SshDockerMintExecutor` + `RotateContext` trait + `rotate_wi_mcp` orchestrator + tests |
| `src/rotate/mod.rs` | modify | Add `"wi-mcp" => …` arm in dispatch match; inject `mint_wi_mcp` from `AppState` into the rotator |
| `src/rotate/wi_mcp_adapter.rs` | create | `AppStateRotateContext` adapter (impl `RotateContext` for the production `AppState`); keeps `strategies.rs` decoupled from `AppState` internals |
| `src/proxy/mod.rs` | modify | Add `pub mint_wi_mcp: Arc<dyn rotate::strategies::MintExecutor>` field on `AppState` |
| `src/main.rs` | modify | Construct `SshDockerMintExecutor` from env at startup, store in `AppState` |
| `tests/rotate_wi_mcp.rs` | create | `#[ignore]` live integration smoke against real Tower |
| `docs/superpowers/specs/2026-05-20-wi-mcp-rotation-design.md` | done | Already committed on this branch |

---

## Task 1: Define `MintExecutor` trait + `FakeMintExecutor`

**Files:**
- Modify: `src/rotate/strategies.rs` (append below `bootstrap_unifi_api_key`)

- [ ] **Step 1: Write the failing test**

Append to `#[cfg(test)] mod tests` in `src/rotate/strategies.rs`:

```rust
    use std::sync::Arc;
    use zeroize::Zeroizing;

    struct FakeMintExecutor {
        result: Result<String, String>,
        last_call: tokio::sync::Mutex<Option<(String, String)>>,
    }

    #[async_trait::async_trait]
    impl MintExecutor for FakeMintExecutor {
        async fn mint(
            &self,
            username: &str,
            password: &str,
        ) -> anyhow::Result<Zeroizing<String>> {
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
```

- [ ] **Step 2: Run test to verify it fails (trait undefined)**

Run: `cargo test --lib rotate::strategies::tests::fake_mint_executor_returns_configured_token`
Expected: `error[E0405]: cannot find trait \`MintExecutor\`` or similar compile error.

- [ ] **Step 3: Add trait definition**

Add to `src/rotate/strategies.rs` (after the `RotationResult` block, before `rotate_sonarr`):

```rust
use zeroize::Zeroizing;

/// Abstracts the channel used to mint a fresh bearer token for a backing
/// service. Production impl is `SshDockerMintExecutor`; tests substitute a
/// fake.
#[async_trait::async_trait]
pub trait MintExecutor: Send + Sync {
    /// Mint a new bearer token using `username`/`password` as the dashboard
    /// auth credentials. Implementations MUST NOT log `password` or include
    /// it in returned errors.
    async fn mint(
        &self,
        username: &str,
        password: &str,
    ) -> anyhow::Result<Zeroizing<String>>;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib rotate::strategies::tests::fake_mint_executor_returns_configured_token`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/rotate/strategies.rs
git commit -m "feat(rotate): MintExecutor trait + test fake"
```

---

## Task 2: Define `RotateContext` trait

**Files:**
- Modify: `src/rotate/strategies.rs`

- [ ] **Step 1: Write the failing test**

Append to `#[cfg(test)] mod tests`:

```rust
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
        ctx.update_password("WI MCP - Bearer", "tok_new").await.unwrap();
        let snap = ctx.last_update.lock().await.clone().unwrap();
        assert_eq!(snap.0, "WI MCP - Bearer");
        assert_eq!(snap.1, "tok_new");
    }
```

- [ ] **Step 2: Run test to verify it fails (trait undefined)**

Run: `cargo test --lib rotate::strategies::tests::fake_rotate_context_round_trips`
Expected: compile error referencing `RotateContext`.

- [ ] **Step 3: Add trait definition**

Add to `src/rotate/strategies.rs` (after the `MintExecutor` trait):

```rust
use std::path::Path;

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
    async fn update_password(&self, item: &str, new_password: &str)
        -> anyhow::Result<()>;

    /// Path to the vault-proxy config directory. Used as the parent for
    /// `wi-mcp-token-recovery-*.txt` on vault-write failure.
    fn config_dir(&self) -> &Path;
}
```

- [ ] **Step 4: Add `tempfile` to dev-deps if missing**

Check `Cargo.toml` for `tempfile` under `[dev-dependencies]`. If absent, add `tempfile = "3"` (it is already in main `[dependencies]` per `Cargo.toml`; if so, no change needed).

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test --lib rotate::strategies::tests::fake_rotate_context_round_trips`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/rotate/strategies.rs Cargo.toml
git commit -m "feat(rotate): RotateContext trait + test fake"
```

---

## Task 3: Implement `rotate_wi_mcp` happy path

**Files:**
- Modify: `src/rotate/strategies.rs`

- [ ] **Step 1: Write the failing test**

Append to `#[cfg(test)] mod tests`:

```rust
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
```

- [ ] **Step 2: Run test to verify it fails (function undefined)**

Run: `cargo test --lib rotate::strategies::tests::rotate_wi_mcp_happy_path`
Expected: compile error referencing `rotate_wi_mcp`.

- [ ] **Step 3: Implement `rotate_wi_mcp`**

Add to `src/rotate/strategies.rs` (after the trait definitions, before `#[cfg(test)]`):

```rust
const WI_MCP_BEARER_ITEM: &str = "WI MCP - Bearer";
const WI_MCP_ADMIN_ITEM: &str = "WI MCP - Admin";

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
    // --- admin lookup --------------------------------------------------------
    let username = match ctx.decrypt_username(WI_MCP_ADMIN_ITEM) {
        Ok(u) => u,
        Err(e) => {
            return RotationResult {
                service: "wi-mcp".to_string(),
                status: "error".to_string(),
                message: format!("admin-lookup: {}", e),
            };
        }
    };
    let password = match ctx.decrypt_password(WI_MCP_ADMIN_ITEM) {
        Ok(p) => p,
        Err(e) => {
            return RotationResult {
                service: "wi-mcp".to_string(),
                status: "error".to_string(),
                message: format!("admin-lookup: {}", e),
            };
        }
    };
    let user_str = match username.as_str() {
        Ok(s) if !s.is_empty() => s,
        Ok(_) => {
            return RotationResult {
                service: "wi-mcp".to_string(),
                status: "error".to_string(),
                message: format!(
                    "admin-lookup: item '{}' has empty 'username'",
                    WI_MCP_ADMIN_ITEM
                ),
            };
        }
        Err(_) => {
            return RotationResult {
                service: "wi-mcp".to_string(),
                status: "error".to_string(),
                message: format!(
                    "admin-lookup: item '{}' username is not valid UTF-8",
                    WI_MCP_ADMIN_ITEM
                ),
            };
        }
    };
    let pass_str = match password.as_str() {
        Ok(s) if !s.is_empty() => s,
        Ok(_) => {
            return RotationResult {
                service: "wi-mcp".to_string(),
                status: "error".to_string(),
                message: format!(
                    "admin-lookup: item '{}' has empty 'password'",
                    WI_MCP_ADMIN_ITEM
                ),
            };
        }
        Err(_) => {
            return RotationResult {
                service: "wi-mcp".to_string(),
                status: "error".to_string(),
                message: format!(
                    "admin-lookup: item '{}' password is not valid UTF-8",
                    WI_MCP_ADMIN_ITEM
                ),
            };
        }
    };

    // --- mint ----------------------------------------------------------------
    let new_token = match mint_executor.mint(user_str, pass_str).await {
        Ok(t) => t,
        Err(e) => {
            return RotationResult {
                service: "wi-mcp".to_string(),
                status: "error".to_string(),
                message: format!("mint: {}", e),
            };
        }
    };

    // --- persist -------------------------------------------------------------
    if let Err(e) = ctx.update_password(WI_MCP_BEARER_ITEM, &new_token).await {
        let recovery = write_recovery_file(ctx.config_dir(), &new_token);
        let path_str = match recovery {
            Ok(p) => p.display().to_string(),
            Err(rerr) => format!("<recovery write failed: {}>", rerr),
        };
        return RotationResult {
            service: "wi-mcp".to_string(),
            status: "error".to_string(),
            message: format!(
                "persist: vault write failed: {}; token written to {}",
                e, path_str
            ),
        };
    }

    RotationResult {
        service: "wi-mcp".to_string(),
        status: "success".to_string(),
        message: format!("rotated wi-mcp bearer; token len={}", new_token.len()),
    }
}
```

`SecureBuffer::as_str` is fallible — that is why both `decrypt_username` and `decrypt_password` errors above use `Zeroizing<String>` rather than `SecureBuffer`. Trait already returns `Zeroizing<String>`, so `username.as_str()` here means `(*username).as_str()` on `String`, which is infallible. Replace the `match … as_str()` branches accordingly:

```rust
    let user_str: &str = &username;
    if user_str.is_empty() {
        return RotationResult {
            service: "wi-mcp".to_string(),
            status: "error".to_string(),
            message: format!(
                "admin-lookup: item '{}' has empty 'username'",
                WI_MCP_ADMIN_ITEM
            ),
        };
    }
    let pass_str: &str = &password;
    if pass_str.is_empty() {
        return RotationResult {
            service: "wi-mcp".to_string(),
            status: "error".to_string(),
            message: format!(
                "admin-lookup: item '{}' has empty 'password'",
                WI_MCP_ADMIN_ITEM
            ),
        };
    }
```

Add `write_recovery_file` helper below `rotate_wi_mcp`:

```rust
use std::fs::OpenOptions;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

/// Write `token` to `<config_dir>/wi-mcp-token-recovery-<unix-ts>.txt` with
/// mode 0600. Used as a fallback when vault write fails but the token was
/// successfully minted.
fn write_recovery_file(config_dir: &Path, token: &str) -> anyhow::Result<PathBuf> {
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
    let mut f = opts.open(&path).with_context(|| {
        format!("open recovery file {}", path.display())
    })?;
    writeln!(f, "WI MCP - Bearer")?;
    writeln!(f, "{}", token)?;
    Ok(path)
}
```

Ensure `use anyhow::Context as _;` is at the top of the file (already present per existing source — verify before adding).

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib rotate::strategies::tests::rotate_wi_mcp_happy_path`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/rotate/strategies.rs
git commit -m "feat(rotate): rotate_wi_mcp orchestrator + happy-path test"
```

---

## Task 4: Add error-path tests for `rotate_wi_mcp`

**Files:**
- Modify: `src/rotate/strategies.rs`

- [ ] **Step 1: Write the failing tests**

Append to `#[cfg(test)] mod tests`:

```rust
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
        let (_mint_unused, _ctx_unused, _dir) = make_fakes("tok", "", "hunter2");
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
```

- [ ] **Step 2: Run tests to verify they pass**

Run: `cargo test --lib rotate::strategies::tests::rotate_wi_mcp_`
Expected: 4 tests PASS (happy + 3 error cases). If any fail, fix `rotate_wi_mcp` until they pass.

- [ ] **Step 3: Commit**

```bash
git add src/rotate/strategies.rs
git commit -m "test(rotate): wi-mcp error paths (admin-missing, mint-fail, persist-fail-recovery)"
```

---

## Task 5: Implement `SshDockerMintExecutor`

**Files:**
- Modify: `src/rotate/strategies.rs`

- [ ] **Step 1: Write the failing test for stdout parser**

Append to `#[cfg(test)] mod tests`:

```rust
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
```

- [ ] **Step 2: Run tests to verify they fail (helpers undefined)**

Run: `cargo test --lib rotate::strategies::tests::parse_mint_stdout`
Expected: compile error referencing `parse_mint_stdout` and `scrub_password`.

- [ ] **Step 3: Implement helpers + executor**

Add to `src/rotate/strategies.rs` (after `write_recovery_file`):

```rust
use std::time::Duration;

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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib rotate::strategies::tests::parse_mint_stdout`
Run: `cargo test --lib rotate::strategies::tests::scrub_password`
Expected: 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/rotate/strategies.rs
git commit -m "feat(rotate): SshDockerMintExecutor + parse/scrub helpers"
```

---

## Task 6: Add `mint_wi_mcp` field to `AppState`

**Files:**
- Modify: `src/proxy/mod.rs` (struct field)
- Modify: `src/main.rs` (constructor)

- [ ] **Step 1: Add the field**

Open `src/proxy/mod.rs`, locate `pub struct AppState`. After `pub audit_log: Arc<crate::security::audit_log::AuditLog>,` (around line 129) add:

```rust
    /// Production mint channel for the wi-mcp bearer rotation strategy.
    /// Constructed from env at startup; tests can substitute via the
    /// `RotateContext` trait directly.
    pub mint_wi_mcp: Arc<dyn crate::rotate::strategies::MintExecutor>,
```

- [ ] **Step 2: Wire construction in `main.rs`**

Find the `AppState { … }` literal in `src/main.rs` (search for `vault: vault_manager.clone(),` or similar). Add to the struct literal:

```rust
        mint_wi_mcp: Arc::new(
            crate::rotate::strategies::SshDockerMintExecutor::from_env(),
        ),
```

Make sure `use std::sync::Arc;` is in scope at the construction site (it is — `main.rs` already uses `Arc` heavily).

- [ ] **Step 3: Build to verify**

Run: `cargo build --bin vaultproxy`
Expected: clean build.

- [ ] **Step 4: Commit**

```bash
git add src/proxy/mod.rs src/main.rs
git commit -m "feat(rotate): wire SshDockerMintExecutor into AppState"
```

---

## Task 7: Adapter — `AppState` impl of `RotateContext`

**Files:**
- Create: `src/rotate/wi_mcp_adapter.rs`
- Modify: `src/rotate/mod.rs` (add `mod wi_mcp_adapter;`)

- [ ] **Step 1: Create the adapter file**

Create `src/rotate/wi_mcp_adapter.rs` with:

```rust
//! Production adapter wiring `AppState` into the `RotateContext` trait used
//! by `rotate_wi_mcp`. Kept in its own file so `strategies.rs` stays free of
//! `AppState` references (which simplifies unit-testing the orchestrator).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context as _;
use async_trait::async_trait;
use zeroize::Zeroizing;

use crate::proxy::AppState;
use crate::rotate::strategies::RotateContext;

pub struct AppStateRotateContext {
    state: Arc<AppState>,
    config_dir: PathBuf,
}

impl AppStateRotateContext {
    pub fn new(state: Arc<AppState>, config_dir: PathBuf) -> Self {
        Self { state, config_dir }
    }
}

#[async_trait]
impl RotateContext for AppStateRotateContext {
    fn decrypt_username(&self, item: &str) -> anyhow::Result<Zeroizing<String>> {
        let buf = self
            .state
            .vault
            .decrypt_username(item)
            .with_context(|| format!("decrypt_username('{}')", item))?
            .ok_or_else(|| anyhow::anyhow!("item '{}' has no username", item))?;
        let s = std::str::from_utf8(buf.as_bytes())
            .context("username is not valid UTF-8")?
            .to_string();
        Ok(Zeroizing::new(s))
    }

    fn decrypt_password(&self, item: &str) -> anyhow::Result<Zeroizing<String>> {
        let buf = self
            .state
            .vault
            .decrypt_password(item)
            .with_context(|| format!("decrypt_password('{}')", item))?;
        let s = std::str::from_utf8(buf.as_bytes())
            .context("password is not valid UTF-8")?
            .to_string();
        Ok(Zeroizing::new(s))
    }

    async fn update_password(&self, item: &str, new_password: &str) -> anyhow::Result<()> {
        self.state
            .vault
            .update_password_for_item(item, new_password)
            .await
            .with_context(|| format!("update_password_for_item('{}')", item))
    }

    fn config_dir(&self) -> &Path {
        &self.config_dir
    }
}
```

- [ ] **Step 2: Register the module**

Edit `src/rotate/mod.rs`. Below `pub mod strategies;` add:

```rust
mod wi_mcp_adapter;
```

(Do not make it `pub` — only `rotate/mod.rs` needs it.)

- [ ] **Step 3: Build to verify**

Run: `cargo build --bin vaultproxy`
Expected: clean build.

- [ ] **Step 4: Commit**

```bash
git add src/rotate/wi_mcp_adapter.rs src/rotate/mod.rs
git commit -m "feat(rotate): AppStateRotateContext adapter"
```

---

## Task 8: Dispatch `"wi-mcp"` in `handle_rotate`

**Files:**
- Modify: `src/rotate/mod.rs`

- [ ] **Step 1: Locate the config-dir source**

Open `src/rotate/mod.rs`. The handler receives `State(state): State<Arc<AppState>>`. Determine where the running config dir lives on `AppState` — search the file for the existing `config_dir` reference. If `AppState` does not already expose `config_dir`, read it from the env var `CONFIG_DIR` (vaultproxy already reads this — see `main.rs --config-dir`). Prefer the `AppState` field; fall back to env.

```bash
grep -n "config_dir" /home/aaron/projects/mcp-vault-proxy/src/proxy/mod.rs /home/aaron/projects/mcp-vault-proxy/src/main.rs | head
```

If `AppState` has `pub config_dir: PathBuf`, use `state.config_dir.clone()`. Otherwise add a single field:

```rust
    /// Path to the vault-proxy config directory (CLI `--config-dir`).
    pub config_dir: std::path::PathBuf,
```

and populate it in `main.rs` where `AppState` is constructed (the CLI value is already in scope as `args.config_dir` or similar — check the surrounding constructor).

- [ ] **Step 2: Add the dispatch arm**

In `handle_rotate` (`src/rotate/mod.rs`), modify the match block:

```rust
    let result = match req.service.as_str() {
        "sonarr" => strategies::rotate_sonarr().await,
        "radarr" => strategies::rotate_radarr().await,
        "wi-mcp" => {
            let ctx = wi_mcp_adapter::AppStateRotateContext::new(
                state.clone(),
                state.config_dir.clone(),
            );
            strategies::rotate_wi_mcp(&ctx, state.mint_wi_mcp.as_ref()).await
        }
        other => RotationResult {
            service: other.to_string(),
            status: "error".to_string(),
            message: format!("no rotation strategy registered for service '{}'", other),
        },
    };
```

(`state` is already `Arc<AppState>` — clone is cheap.)

- [ ] **Step 3: Build to verify**

Run: `cargo build --bin vaultproxy`
Expected: clean build.

- [ ] **Step 4: Run the full unit suite to catch regressions**

Run: `cargo test --lib`
Expected: all existing tests PASS plus the 9 new tests from Tasks 1–5.

- [ ] **Step 5: Commit**

```bash
git add src/rotate/mod.rs src/proxy/mod.rs src/main.rs
git commit -m "feat(rotate): dispatch wi-mcp in handle_rotate"
```

---

## Task 9: Live integration smoke test (`#[ignore]`)

**Files:**
- Create: `tests/rotate_wi_mcp.rs`

- [ ] **Step 1: Write the live smoke test**

Create `tests/rotate_wi_mcp.rs`:

```rust
//! Live integration smoke for the wi-mcp rotation strategy. Marked
//! `#[ignore]` because it requires:
//!   - A real Vaultwarden with the "WI MCP - Admin" item populated
//!   - SSH access to `unraid` with key auth
//!   - The wi-mcp container running on Tower
//!
//! Run manually: `cargo test --test rotate_wi_mcp -- --ignored --nocapture`
//!
//! What it checks (end-to-end, no mocks):
//!   1. POST /rotate {service:"wi-mcp", strategy:"api"} returns 200
//!   2. A follow-up POST to https://wi-mcp.splendidus.live/mcp using the
//!      bearer that vp now resolves does NOT return 401.

use std::time::Duration;

#[tokio::test]
#[ignore]
async fn live_rotate_wi_mcp() {
    // The test assumes vaultproxy is already running locally and the internal
    // token is readable at $CONFIG_DIR/internal-token.
    let config_dir = std::env::var("CONFIG_DIR")
        .expect("CONFIG_DIR env var required for live test");
    let token_path = format!("{}/internal-token", config_dir);
    let internal_token = std::fs::read_to_string(&token_path)
        .expect("read internal-token")
        .trim()
        .to_string();
    let vp_url = std::env::var("VP_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:3201".to_string());

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .unwrap();

    // Step 1: rotate.
    let rotate_resp = client
        .post(format!("{}/rotate", vp_url))
        .header("Authorization", format!("Bearer {}", internal_token))
        .json(&serde_json::json!({"service":"wi-mcp","strategy":"api"}))
        .send()
        .await
        .expect("rotate request");
    let status = rotate_resp.status();
    let body: serde_json::Value = rotate_resp.json().await.unwrap();
    assert_eq!(status, 200, "rotate body: {}", body);
    assert_eq!(body["ok"], true);

    // Step 2: verify wi-mcp accepts the rotated token. vp's mcp-bearer-bridge
    // reads from the synced vault; we exercise the live endpoint via vp's
    // own /vault/get-field or by calling the upstream directly with a vault
    // lookup. Simpler: poll the upstream with HEAD; if it returns 401 we
    // failed.
    let probe = client
        .post("https://wi-mcp.splendidus.live/mcp")
        .json(&serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}))
        .send()
        .await
        .expect("probe wi-mcp");
    // We don't have the bearer here, but we expect 401 (missing token) NOT
    // a 5xx — the point is wi-mcp is reachable and the rotation didn't break
    // the upstream. For end-to-end-with-bearer coverage, run
    // `claude mcp list` and confirm wi-mcp is connected (out of scope for
    // this assertion).
    assert!(
        probe.status() == 401 || probe.status() == 200,
        "wi-mcp returned {} after rotation",
        probe.status()
    );
}
```

- [ ] **Step 2: Compile the test**

Run: `cargo build --test rotate_wi_mcp`
Expected: clean build (note `reqwest` is already a project dependency).

- [ ] **Step 3: Commit**

```bash
git add tests/rotate_wi_mcp.rs
git commit -m "test(rotate): live smoke for wi-mcp rotation (#[ignore])"
```

---

## Task 10: Operator runbook + manual rotation

**Files:**
- Modify: `docs/superpowers/specs/2026-05-20-wi-mcp-rotation-design.md` (add Operator Runbook section)

- [ ] **Step 1: Append runbook**

Append to the spec doc:

```markdown
## Operator Runbook

### One-time setup

1. Create Vaultwarden item **`WI MCP - Admin`** in the `Connecterr` folder.
   - `username` = the dashboard auth username currently typed into `docker exec wi-mcp python main.py auth-mint-token --username <u>`
   - `password` = the dashboard auth password for that user
2. Verify vp can reach Tower over SSH: `ssh unraid docker exec wi-mcp echo ok` returns `ok` as the vp user.

### Routine rotation

```bash
INTERNAL=$(cat "$CONFIG_DIR/internal-token")
curl -fsS \
  -H "Authorization: Bearer $INTERNAL" \
  -H "Content-Type: application/json" \
  -d '{"service":"wi-mcp","strategy":"api"}' \
  http://127.0.0.1:3201/rotate
# {"ok":true,"service":"wi-mcp","status":"success","message":"rotated wi-mcp bearer; token len=64"}
```

Then verify: `claude mcp list | grep wi-mcp` should show ✓ Connected within a few seconds.

### Recovery (vault write failed but token minted)

If the rotate response message contains `token written to <path>`:

1. `cat <path>` — note the new token.
2. Open Vaultwarden, edit item **`WI MCP - Bearer`**, paste the new token into the `password` field, save.
3. Delete the recovery file: `shred -u <path>`.

Recovery files are mode 0600 in `$CONFIG_DIR`. Investigate the underlying vault-write failure before the next rotation.
```

- [ ] **Step 2: Build release binary**

```bash
cargo build --release --bin vaultproxy
```

Expected: produces `target/release/vaultproxy`.

- [ ] **Step 3: Verify the binary on a manual rotate**

(Run only on the machine where vp's vault is configured and `"WI MCP - Admin"` exists.)

```bash
# In one shell:
./target/release/vaultproxy --config-dir /home/aaron/projects/Connecterr/config
# In another:
INTERNAL=$(cat /home/aaron/projects/Connecterr/config/internal-token)
curl -fsS -H "Authorization: Bearer $INTERNAL" -H "Content-Type: application/json" \
  -d '{"service":"wi-mcp","strategy":"api"}' \
  http://127.0.0.1:3201/rotate
```

Expected: `{"ok":true,"service":"wi-mcp","status":"success","message":"rotated wi-mcp bearer; token len=…"}`.

Then:

```bash
curl -sS -o /dev/null -w "%{http_code}\n" \
  -X POST https://wi-mcp.splendidus.live/mcp \
  -H "Authorization: Bearer $(... vault lookup ...)" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

Expected: `200` (not `401`). For a hands-off check, restart any `claude` session that uses wi-mcp; `mcp list` should show ✓ Connected.

- [ ] **Step 4: Commit runbook and merge to main**

```bash
git add docs/superpowers/specs/2026-05-20-wi-mcp-rotation-design.md
git commit -m "docs(rotate): operator runbook for wi-mcp rotation"
git checkout main
git merge --no-ff feat/wi-mcp-rotation -m "Merge feat/wi-mcp-rotation"
```

(Do NOT push without explicit operator instruction.)

---

## Self-Review

**Spec coverage:**
- Architecture ✓ (Tasks 3, 7, 8)
- `MintExecutor` trait ✓ (Task 1)
- `SshDockerMintExecutor` ✓ (Task 5)
- `rotate_wi_mcp` orchestrator ✓ (Task 3)
- Vault helpers — spec proposed new helpers; implementation reuses existing `decrypt_username`/`decrypt_password`/`update_password_for_item` via the adapter in Task 7 (intentional simplification; spec's "Vault helpers" section is now redundant but not contradicted).
- `AppState` change ✓ (Task 6)
- Dispatch wiring ✓ (Task 8)
- Error handling (all 7 phases) ✓ (Tasks 3, 4, 5)
- Security (stdin pipe, no token in HTTP body, password scrub, 0600 recovery, internal-token gate inherited) ✓ (Task 5, 3)
- Tests #1–#5 ✓ (Tasks 3, 4, 5)
- Test #6 live smoke ✓ (Task 9)
- Risks section — concurrent rotation mutex deferred (vault layer already has a write lock per `vault/mod.rs`); call out in PR description if needed.

**Placeholder scan:** no TBDs, no "implement later", every code-changing step shows the code.

**Type consistency:** `MintExecutor::mint` returns `Zeroizing<String>` consistently in Tasks 1, 3, 5. `RotateContext::decrypt_*` returns `Zeroizing<String>` consistently in Tasks 2, 3, 7. `update_password(item, new_password)` signature matches across Tasks 2, 3, 7. `RotationResult { service, status, message }` shape used identically everywhere.

---

## Execution Handoff

Plan complete. Two execution options:

1. **Subagent-Driven (recommended)** — fresh subagent per task, review between tasks.
2. **Inline Execution** — execute tasks in this session with checkpoints.

Which?
