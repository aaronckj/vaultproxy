# wi-mcp Bearer Token Rotation — Design

**Date:** 2026-05-20
**Author:** aaron (with Claude)
**Status:** Approved (sections 1–3); pending spec review.

## Problem

`wi-mcp` (Workstream Intelligence MCP, `https://wi-mcp.splendidus.live/mcp`) authenticates clients via a Vaultwarden-stored bearer token (`vault_item = "WI MCP - Bearer"`, field=`password`). When the token expires, the upstream returns `401 {"error":"invalid or expired token"}` and every MCP-bearer-bridge call fails silently until an operator manually:

1. SSHes to Tower (10.0.0.30)
2. Runs `docker exec wi-mcp python main.py auth-mint-token --username <u> --password-stdin`
3. Pastes the new token into the Vaultwarden item
4. Restarts/reloads dependent MCP clients

This is the third+ time the operator has done this by hand (per `feedback_mcp_install_at_end.md` and the prior `vp lacks bearer-token rotation` memory). Today, even cloudflare bearer rotations hit the same gap.

Goal: add a **`wi-mcp` rotation strategy** to vp's existing `POST /rotate` dispatch so the entire mint-and-writeback cycle becomes a single authenticated HTTP call.

## Non-goals

- **Auto-rotation on 401** from `mcp-bearer-bridge`. Manual `/rotate` only for v1.
- Generalizing the strategy to arbitrary bearer services (cloudflare, etc.). The mint mechanism is service-specific; a generic command-exec strategy is future work.
- Token TTL tracking / scheduled pre-expiry refresh.
- Bootstrap (creating the admin item from scratch). vp's existing UniFi-style bootstrap pattern can be added later if needed.

## Architecture

```
HTTP POST /rotate {service:"wi-mcp", strategy:"api"}     (gated by internal-token)
  │
  ▼
handle_rotate (src/rotate/mod.rs)
  │  match req.service { "wi-mcp" => rotate_wi_mcp(state).await, ... }
  ▼
rotate_wi_mcp (src/rotate/strategies.rs)
  ├─ vault.get_admin_credentials("WI MCP - Admin", "Connecterr")   → (user, pass)
  ├─ state.mint_wi_mcp.mint(user, pass)                            → new_token
  │     (SshDockerMintExecutor: `ssh unraid docker exec -i wi-mcp \
  │      python main.py auth-mint-token --username <u> --password-stdin`)
  ├─ vault.update_password_field("WI MCP - Bearer", "Connecterr", &new_token)
  └─ RotationResult { status: "success", message: "rotated wi-mcp bearer; token len=<n>" }
  │
  ▼
handle_rotate post-success:
  ├─ state.session_tokens.write().await.remove("wi-mcp")   (already exists)
  ├─ state.vault.sync().await                              (already exists)
  └─ audit_log.log(...)                                    (already exists)
```

### Components

#### `MintExecutor` trait (new, in `src/rotate/strategies.rs`)

```rust
#[async_trait]
pub trait MintExecutor: Send + Sync {
    async fn mint(
        &self,
        username: &str,
        password: &str,
    ) -> anyhow::Result<zeroize::Zeroizing<String>>;
}
```

Two implementations:

- `SshDockerMintExecutor { host, container, ssh_path, timeout }` — production default. `host="unraid"`, `container="wi-mcp"`, `ssh_path="ssh"`, `timeout=Duration::from_secs(30)`. Spawns `std::process::Command::new(ssh_path)` with args `[host, "docker", "exec", "-i", container, "python", "main.py", "auth-mint-token", "--username", username, "--password-stdin"]`, pipes password+"\n" to stdin, captures stdout/stderr, parses the trimmed stdout as the token. Per `cmd_auth_mint_token` in `wi-mcp/main.py`, stdout on success is exactly one line: the token. On failure stderr contains `ERROR: ...` and exit is non-zero.
- `FakeMintExecutor { result }` (test-only, `#[cfg(test)]`).

#### `rotate_wi_mcp(state: &AppState) -> RotationResult` (new)

Pure orchestration; no I/O beyond the four steps above. Returns a `RotationResult` with `status` ∈ {`"success"`, `"error"`}.

#### Vault helpers (new, in `src/vault/mod.rs`)

- `get_admin_credentials(item_name, folder_name) -> Result<(Zeroizing<String>, Zeroizing<String>)>` — looks up cipher by name within folder (reuses `find_folder_id_by_name_async` + `find_item_id_by_name` + the existing decrypt path), extracts `username` and `password` login fields, returns both as `Zeroizing`. Errors: item-not-found, folder-not-found, missing field.
- `update_password_field(item_name, folder_name, new_password) -> Result<()>` — thin wrapper around the existing `update_cipher` plumbing. Scoped to the configured `vault_folder` (same guard already used by `update_item` handler at `vault/handlers.rs:1208`).

#### `AppState` change (in `src/proxy/mod.rs`)

Add `pub mint_wi_mcp: Arc<dyn MintExecutor>`. Constructed in `main.rs` from optional env:

- `WI_MCP_SSH_HOST` (default `"unraid"`)
- `WI_MCP_CONTAINER` (default `"wi-mcp"`)
- `WI_MCP_SSH_PATH` (default `"ssh"`)
- `WI_MCP_MINT_TIMEOUT_SECS` (default `30`)

#### Dispatch wiring (in `src/rotate/mod.rs`)

```rust
let result = match req.service.as_str() {
    "sonarr" => strategies::rotate_sonarr().await,
    "radarr" => strategies::rotate_radarr().await,
    "wi-mcp" => strategies::rotate_wi_mcp(&state).await,
    other    => RotationResult { ... }
};
```

## Data flow

Happy path detail given in the diagram above. Two structural points:

1. **Cache eviction is already done by `handle_rotate`** after any `status=="success"` rotation: removes `session_tokens["wi-mcp"]` and calls `state.vault.sync().await`. The `mcp-bearer-bridge` for wi-mcp reads from the synced vault, so the next bridge call picks up the rotated token automatically.
2. **No restart required for `mcp-bearer-bridge`**: it reads the bearer at request-time from vp's `/vault/get-field` (or equivalent), not at process start.

## Error handling

All failures return HTTP 500 with body `{ok:false, status:"error", message:...}` via the existing `handle_rotate` envelope, and are written to `audit_log` (already wired).

| Phase | Failure | `message` shape | Recovery |
|-------|---------|-----------------|----------|
| admin lookup | folder/item missing | `"admin-lookup: vault item 'WI MCP - Admin' in folder 'Connecterr' not found"` | operator creates item |
| admin lookup | `username` or `password` field empty | `"admin-lookup: item 'WI MCP - Admin' missing field '<f>'"` | operator fixes fields |
| ssh exec | non-zero exit | `"mint: ssh exit=<code>; stderr=<truncated 512c, password-scrubbed>"` | check SSH key, Tower reachability, dashboard creds |
| ssh exec | timeout | `"mint: timeout after 30s"` | check Tower reachability |
| ssh exec | spawn failure (no `ssh` on PATH) | `"mint: spawn failed: <err>"` | install/repair openssh-client |
| parse | trimmed stdout empty | `"mint: empty stdout; stderr=<truncated 512c>"` | inspect `auth-mint-token` behavior |
| parse | stdout looks non-token (contains whitespace inside) | `"mint: unexpected stdout shape (got <n> tokens)"` | inspect output |
| vault write | `update_cipher` fails | `"persist: vault write failed: <err>; token written to <recovery-path>"` + **recovery file**: `$CONFIG_DIR/wi-mcp-token-recovery-<unix-ts>.txt` (0600) containing `\nWI MCP - Bearer\n<token>\n` | operator pastes manually, deletes recovery file |

### Security

- Password never logged (`tracing::debug` does not include it; `Zeroizing` drops it).
- SSH password passed via **stdin only**, never argv (argv visible in `ps`).
- HTTP response **never contains the new token**.
- Stderr scrub: before logging or returning stderr, replace any occurrence of the admin password with `***PASSWORD***`. Implemented as a regex-free literal `.replace(password, "***PASSWORD***")` to avoid pathological regex behavior on adversarial input.
- Recovery file: 0600, created with `OpenOptions::new().create_new(true).write(true).mode(0o600)`. Parent dir is `$CONFIG_DIR` (already 0700).
- /rotate endpoint stays gated by the existing `require_internal_token` middleware (per `rotate/mod.rs:44-47` comment).

## Testing

Add `#[cfg(test)] mod tests` in `src/rotate/strategies.rs`:

1. **`rotate_wi_mcp_happy_path`** — `FakeMintExecutor` returns `"tok_abc"`. Verify: `vault.update_password_field` called once with `("WI MCP - Bearer", "Connecterr", "tok_abc")`; result.status == `"success"`.
2. **`rotate_wi_mcp_admin_missing`** — vault has no `"WI MCP - Admin"` item. Result.status == `"error"`, message contains `"admin-lookup"`.
3. **`rotate_wi_mcp_mint_fails`** — `FakeMintExecutor` returns `Err(anyhow!("exit=1"))`. Result.status == `"error"`, message contains `"mint:"`. `update_password_field` **not** called.
4. **`rotate_wi_mcp_persist_fails`** — `FakeMintExecutor` returns `"tok_xyz"`; vault stub returns `Err` on update. Result.status == `"error"`; recovery file exists at `$CONFIG_DIR/wi-mcp-token-recovery-*.txt`; contents include `"tok_xyz"`. Tempdir cleanup at test end.
5. **`ssh_docker_mint_executor_parse`** — pure parse test on a fake stdout string (`"\nabc123\n"` → `"abc123"`, `"abc 123\n"` → error).

Integration smoke (`tests/rotate_wi_mcp.rs`, manual `--ignored` because it touches the live Tower):

6. **`live_rotate_wi_mcp`** (`#[ignore]`) — `cargo test --ignored live_rotate_wi_mcp`. Requires real vault + SSH + Tower. Spins up vp on `127.0.0.1:0`, POSTs `/rotate`, asserts 200, asserts subsequent `https://wi-mcp.splendidus.live/mcp` request returns 200 (or != 401).

## Rollout

1. Implement on branch `feat/wi-mcp-rotation`.
2. Run unit tests (`cargo test`).
3. Manually create `"WI MCP - Admin"` Vaultwarden item in `Connecterr` folder with username + password fields (record the dashboard creds the operator currently types).
4. Build release binary; replace `/home/aaron/projects/mcp-vault-proxy/target/release/vaultproxy`.
5. Restart any long-running vp instance.
6. Run `curl -H "Authorization: Bearer $(cat $CONFIG_DIR/internal-token)" -d '{"service":"wi-mcp","strategy":"api"}' http://127.0.0.1:3201/rotate`.
7. Verify: `claude mcp list | grep wi-mcp` → connected, `mcp__wi-mcp__*` tool calls succeed.

## Risks

- **SSH key absence on the machine vp runs from.** Mitigation: documented in error message; CONFIG_DIR pre-flight check at startup logs a warning if `ssh unraid true` fails.
- **`auth-mint-token` output format drift.** Mitigation: parse test #5; if format changes, only the parse function needs a fix.
- **Concurrent rotations.** Two simultaneous `/rotate` calls could race vault writes. Mitigation: serialize wi-mcp rotations behind an `Arc<Mutex<()>>` on `AppState`. The vault layer also has its own write lock.
- **Admin password rotation.** Out of scope; if the dashboard password ever changes, the admin item must be updated manually (same as today). A future iteration can bootstrap-rotate this too.

## Out-of-scope follow-ups

- Generic command-exec rotation strategy (for cloudflare and other bearer services).
- Auto-rotate on 401 inside `mcp-bearer-bridge` with single-flight semantics.
- Scheduled pre-expiry refresh (`auth-refresh-token` is already an option upstream).
- Dashboard UI button to trigger rotation.

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

### Configuration knobs

Env vars (read at startup by `SshDockerMintExecutor::from_env`):

- `WI_MCP_SSH_HOST` (default `unraid`) — SSH alias or hostname for the box running the `wi-mcp` container.
- `WI_MCP_CONTAINER` (default `wi-mcp`) — Docker container name.
- `WI_MCP_SSH_PATH` (default `ssh`) — Path to the SSH client binary.
- `WI_MCP_MINT_TIMEOUT_SECS` (default `30`) — Hard timeout for the mint exec.
