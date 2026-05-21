# wi-mcp Admin Password Rotation — Design

**Date:** 2026-05-21
**Author:** aaron (with Claude)
**Status:** Approved.
**Predecessor spec:** `2026-05-20-wi-mcp-rotation-design.md` (bearer rotation; required for admin rotation to be useful).

## Problem

`WI MCP - Admin` vault item holds the dashboard auth credentials vp uses to mint bearer tokens. Today:

- Password is set once at user creation; never rotated.
- If lost or compromised, only path back is editing `dashboard_users.json` inside the container by hand.
- Bearer rotation depends on the admin password being valid; an unrotated admin password is the silent SPOF.

Goal: add a `wi-mcp-admin` rotation strategy that rotates the admin password on the wi-mcp side and writes the new password back to the same vault item.

## Architecture

```
POST /rotate {service:"wi-mcp-admin", strategy:"api"}        (gated by internal-token)
  │
  ▼
handle_rotate (src/rotate/mod.rs)
  │  match req.service { "wi-mcp-admin" => rotate_wi_mcp_admin(state).await, ... }
  ▼
rotate_wi_mcp_admin (src/rotate/strategies.rs)
  ├─ ctx.decrypt_username("WI MCP - Admin")     → user (e.g. "vp-rotator")
  ├─ ctx.decrypt_password("WI MCP - Admin")     → current_pw
  ├─ generate_new_password(32)                  → new_pw
  ├─ state.change_wi_mcp_admin.change(user, current_pw, new_pw)
  │     (SshDockerAdminPasswordChanger: ssh unraid docker exec -i wi-mcp python -c '<inline>')
  ├─ ctx.update_password("WI MCP - Admin", &new_pw)
  └─ RotationResult { status: "success", message: "rotated wi-mcp admin pw for user '<u>'; pw len=32" }
```

### New trait

```rust
#[async_trait::async_trait]
pub trait AdminPasswordChanger: Send + Sync {
    /// Change the wi-mcp admin password for `username` from `current` to `new`.
    /// Implementations MUST NOT log either password.
    async fn change(
        &self,
        username: &str,
        current: &str,
        new: &str,
    ) -> anyhow::Result<()>;
}
```

### Production impl

`SshDockerAdminPasswordChanger { host, container, ssh_path, timeout }`:

```
ssh <host> docker exec -i <container> python -c <PY_SCRIPT> <username>
```

Where `<PY_SCRIPT>` is a single-line inline script that:
1. Reads YAML config from `/data/config/config.yaml`
2. Instantiates `DashboardAuth(config)`
3. Reads `current\nnew\n` from stdin (split on first two `\n`s)
4. Calls `change_password(username, current, new)`; bails non-zero if it returns False
5. Prints nothing on success (or `OK\n`)

Stdin: `<current>\n<new>\n`. Username via argv.

Inline script (Rust string literal):
```python
import sys, yaml
from reporting.dashboard_auth import DashboardAuth
username = sys.argv[1]
current, new = sys.stdin.read().split('\n', 2)[:2]
auth = DashboardAuth(yaml.safe_load(open('/data/config/config.yaml')))
if not auth.change_password(username, current, new):
    sys.stderr.write('ERROR: change_password returned False (wrong current or user not found)\n')
    sys.exit(1)
```

Exec timeout: 30s (same default as `SshDockerMintExecutor`).

### Password generation

Use `crate::vault::generate_password::generate(32, charset_alnum)` if exists, otherwise:

```rust
fn generate_password(len: usize) -> Zeroizing<String> {
    use rand::Rng;
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    let s: String = (0..len).map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char).collect();
    Zeroizing::new(s)
}
```

Alphanumeric (no symbols) because we cannot guarantee shell-safety through the SSH+docker exec pipeline; alphanumeric is collision-resistant enough at 32 chars (~190 bits of entropy).

### Vault writeback

Reuse `RotateContext::update_password` exactly as bearer rotation does. Same recovery-file pattern (`<config_dir>/wi-mcp-admin-pw-recovery-<ts>.txt` 0600).

### AppState change

Add to `proxy::AppState`:

```rust
pub change_wi_mcp_admin: Arc<dyn crate::rotate::strategies::AdminPasswordChanger>,
```

Construct in `main.rs` from `SshDockerAdminPasswordChanger::from_env()` (same env vars as mint executor: `WI_MCP_SSH_HOST`, `WI_MCP_CONTAINER`, `WI_MCP_SSH_PATH`, `WI_MCP_MINT_TIMEOUT_SECS` reused).

### Dispatch

Add to `handle_rotate` match:

```rust
"wi-mcp-admin" => {
    let ctx = wi_mcp_adapter::AppStateRotateContext::new(
        state.clone(),
        std::path::PathBuf::from(state.config_dir.clone()),
    );
    strategies::rotate_wi_mcp_admin(&ctx, state.change_wi_mcp_admin.as_ref()).await
}
```

## Error handling

| Phase | Failure | Message |
|-------|---------|---------|
| admin lookup | item/folder/field missing | `admin-lookup: <err>` |
| change | ssh exit non-zero | `change: ssh exit=<code>; stderr=<scrubbed 512c>` |
| change | timeout | `change: timeout after 30s` |
| change | change_password returned False | (captured as ssh exit=1 + stderr containing `change_password returned False`) |
| persist | vault write failed | `persist: vault write failed: <err>; new pw written to <recovery-path>` |

Stderr scrubbing: replace both `current` and `new` literal occurrences. Reuse `scrub_password` helper but call twice.

## Security

- Both passwords zeroized.
- Stdin pipe; never argv.
- HTTP response never contains plaintext pw.
- Recovery file 0600; format:
  ```
  WI MCP - Admin
  username: <u>
  password: <new_pw>
  ```
- /rotate stays gated by internal-token.
- **Operational risk:** if `change_password` succeeds but vault write fails, the dashboard pw on wi-mcp is now in the recovery file only; the old pw in the vault item is dead. Bearer rotation will break until operator updates vault from recovery file. Acceptable per agreed atomicity choice ("wi-mcp first, then vault, recovery file on vault fail").

## Testing

`#[cfg(test)] mod tests` in `strategies.rs`:

1. `rotate_wi_mcp_admin_happy_path` — FakeAdminPasswordChanger returns Ok; vault.update_password called with new pw; status=success.
2. `rotate_wi_mcp_admin_admin_missing` — vault.decrypt_username returns Err; admin-lookup error.
3. `rotate_wi_mcp_admin_change_fails` — FakeAdminPasswordChanger returns Err; status=error, message starts with "change:"; vault.update_password NOT called.
4. `rotate_wi_mcp_admin_persist_fails` — FakeAdminPasswordChanger Ok, update_password Err. Status=error, recovery file exists with username + new pw, mode 0600.
5. `password_generator_len` — generate_password(32) returns exactly 32 chars, alphanumeric only.

No live test (covered by manual verification in runbook).

## Rollout

1. Implement on `feat/wi-mcp-admin-rotation` (branch already cut).
2. Unit tests green; build clean.
3. Build release; restart vp.
4. Trigger `/rotate {service:"wi-mcp-admin"}`. Verify success.
5. Trigger `/rotate {service:"wi-mcp"}`. Verify success (bearer rotation now uses the new admin pw).
6. Verify `claude mcp list | grep wi-mcp` ✓ Connected.

## Out of scope

- Auto-schedule (cron). Manual rotation only for v1.
- Generalization to other services. Each service's "admin pw change" mechanism is bespoke.
- TOTP / 2FA on admin user.
