# Credential Bootstrap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When `vaultproxy --launch <server>` is invoked and the child MCP server needs an API key that doesn't exist yet, vaultproxy automatically generates it from stored credentials and writes it back to vault — no user interaction required after initial credential setup.

**Architecture:** Add an optional `[mcp_server.bootstrap]` block to `mcp-servers.toml`. At `--launch` time, after config parse but before env resolution, vaultproxy checks if the `key_item` vault entry is absent or empty — if so, calls the named strategy (e.g. `unifi_api_key`) which authenticates to the service, generates an API key, stores it in vault, and syncs. Env resolution then proceeds normally, picking up the freshly-written key.

**Tech Stack:** Rust, reqwest 0.12 (cookie_store feature already enabled), zeroize (already in deps), serde/toml for config parsing.

---

## File Map

| File | Change |
|------|--------|
| `src/vault/mod.rs` | Add `find_item_id_by_name()` method + `"uri"` arm in `get_field_by_item_name()` |
| `src/launcher.rs` | Add `BootstrapConfig` struct, `bootstrap` field to `McpServerConfig`, bootstrap check + dispatch block in `launch()` |
| `src/rotate/strategies.rs` | Add `bootstrap_unifi_api_key()` function |
| `config/mcp-servers.toml` | Add `[mcp_server.bootstrap]` block for unifi, update env entries |

---

## Task 1: Add `find_item_id_by_name` to VaultManager

**Files:**
- Modify: `src/vault/mod.rs` (after `get_cipher_by_id` at line ~933)

- [ ] **Step 1: Write failing test**

In `src/vault/mod.rs`, inside the `#[cfg(test)]` module at the bottom of the file, add:

```rust
#[tokio::test]
async fn test_find_item_id_by_name_returns_none_for_missing() {
    let vault = VaultManager::new_test_instance();
    let result = vault.find_item_id_by_name("nonexistent").await;
    assert!(result.is_none());
}
```

- [ ] **Step 2: Run test, confirm it fails**

```bash
cd /home/aaron/projects/mcp-vault-proxy
cargo test test_find_item_id_by_name_returns_none_for_missing 2>&1 | tail -5
```

Expected: compile error — method `find_item_id_by_name` not found.

- [ ] **Step 3: Add the method**

In `src/vault/mod.rs`, after `get_cipher_by_id` (~line 937), add:

```rust
/// Return the vault item id for the item with the given decrypted name,
/// or None if no item with that name exists.
pub async fn find_item_id_by_name(&self, item_name: &str) -> Option<String> {
    let items = self.items.read().await;
    items
        .iter()
        .find(|(_, (name, _))| name == item_name)
        .map(|(id, _)| id.clone())
}
```

- [ ] **Step 4: Run test, confirm it passes**

```bash
cargo test test_find_item_id_by_name_returns_none_for_missing 2>&1 | tail -5
```

Expected: `test test_find_item_id_by_name_returns_none_for_missing ... ok`

- [ ] **Step 5: Commit**

```bash
git add src/vault/mod.rs
git commit -m "feat(vault): add find_item_id_by_name helper"
```

---

## Task 2: Add `"uri"` field support to `get_field_by_item_name`

**Files:**
- Modify: `src/vault/mod.rs` (inside `get_field_by_item_name` at line ~1590)

- [ ] **Step 1: Write failing test**

In `src/vault/mod.rs` test module, add:

```rust
#[test]
fn test_get_field_by_item_name_rejects_uri_as_unsupported() {
    // Before the implementation: "uri" hits the `other =>` arm and returns Err.
    // We just verify the error message changes after implementation.
    // This test will be updated in Step 4.
    let vault = VaultManager::new_test_instance();
    // Use blocking version via try_read since this is sync context
    let result = vault.get_field_by_item_name_sync("nonexistent-item", "uri");
    // Should fail with "not found", not "unsupported field"
    let err = result.unwrap_err().to_string();
    assert!(!err.contains("unsupported field"), "got: {}", err);
}
```

Note: `get_field_by_item_name` is async. The test above uses a sync wrapper. Since the vault items map uses `try_read` for password/username, add a sync helper for tests OR just test via `tokio::test`:

```rust
#[tokio::test]
async fn test_uri_field_unsupported_before_impl() {
    let vault = VaultManager::new_test_instance();
    let result = vault.get_field_by_item_name("anything", "uri").await;
    // currently returns Err("unsupported field 'uri'")
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("unsupported"));
}
```

- [ ] **Step 2: Run test, confirm it fails with "unsupported field"**

```bash
cargo test test_uri_field_unsupported_before_impl 2>&1 | tail -5
```

Expected: `test ... ok` (this test passes before implementation — confirming the current error message).

- [ ] **Step 3: Add `"uri"` arm to `get_field_by_item_name`**

In `src/vault/mod.rs`, in `get_field_by_item_name` replace the `other =>` arm:

```rust
pub async fn get_field_by_item_name(&self, item_name: &str, field: &str) -> Result<String> {
    match field {
        "password" => {
            // ... existing code unchanged ...
        }
        "username" => {
            // ... existing code unchanged ...
        }
        "uri" => {
            let map = self
                .items
                .try_read()
                .map_err(|_| anyhow!("vault items lock is contended"))?;
            let cipher = map
                .values()
                .find(|(n, _)| n == item_name)
                .map(|(_, c)| c)
                .ok_or_else(|| anyhow!("item '{}' not found in vault", item_name))?;
            let enc_uri = cipher
                .login
                .as_ref()
                .and_then(|l| l.uris.as_ref())
                .and_then(|uris| uris.first())
                .and_then(|u| u.uri.as_deref())
                .ok_or_else(|| anyhow!("item '{}' has no URI", item_name))?;
            let decrypted = decrypt_cipher_string(
                enc_uri,
                self.enc_key.as_bytes(),
                self.mac_key.as_bytes(),
            )
            .with_context(|| format!("decrypt URI for '{}'", item_name))?;
            let s = std::str::from_utf8(&decrypted)
                .map_err(|e| anyhow!("URI for '{}' is not valid UTF-8: {}", item_name, e))?
                .to_string();
            Ok(s)
        }
        other => {
            anyhow::bail!(
                "unsupported field '{}' — must be 'password', 'username', or 'uri'",
                other
            )
        }
    }
}
```

- [ ] **Step 4: Update test to verify `"uri"` no longer hits the "unsupported" arm**

Replace the test:

```rust
#[tokio::test]
async fn test_uri_field_returns_not_found_not_unsupported() {
    let vault = VaultManager::new_test_instance();
    let result = vault.get_field_by_item_name("nonexistent", "uri").await;
    let err = result.unwrap_err().to_string();
    // "uri" is now a known field — fails with "not found", not "unsupported field"
    assert!(
        err.contains("not found"),
        "expected 'not found' error, got: {}",
        err
    );
    assert!(
        !err.contains("unsupported field"),
        "should not hit unsupported arm, got: {}",
        err
    );
}
```

- [ ] **Step 5: Run test, confirm it passes**

```bash
cargo test test_uri_field_returns_not_found_not_unsupported 2>&1 | tail -5
```

Expected: `test ... ok`

- [ ] **Step 6: Confirm existing field tests still pass**

```bash
cargo test --lib vault 2>&1 | grep -E "FAILED|error|ok" | tail -20
```

Expected: no FAILED lines.

- [ ] **Step 7: Commit**

```bash
git add src/vault/mod.rs
git commit -m "feat(vault): add 'uri' field support to get_field_by_item_name"
```

---

## Task 3: Add `BootstrapConfig` struct and parse it in `launcher.rs`

**Files:**
- Modify: `src/launcher.rs`

- [ ] **Step 1: Write failing test**

In `src/launcher.rs` test module, add:

```rust
#[test]
fn test_bootstrap_config_deserializes() {
    let toml = r#"
[[mcp_server]]
name    = "unifi"
command = "/usr/local/bin/go-unifi-mcp"

  [mcp_server.bootstrap]
  type      = "unifi_api_key"
  auth_item = "unifi/home"
  key_item  = "unifi/home-key"
  verify_ssl = false

  [[mcp_server.env]]
  var   = "UNIFI_HOST"
  vault_item = "unifi/home"
  field = "uri"
"#;
    let parsed: super::McpServersFile = toml::from_str(toml).unwrap();
    let server = &parsed.mcp_server[0];
    let bs = server.bootstrap.as_ref().expect("bootstrap should be present");
    assert_eq!(bs.strategy_type, "unifi_api_key");
    assert_eq!(bs.auth_item, "unifi/home");
    assert_eq!(bs.key_item, "unifi/home-key");
    assert!(!bs.verify_ssl);
}

#[test]
fn test_bootstrap_config_optional() {
    let toml = r#"
[[mcp_server]]
name    = "plain"
command = "echo"
  [[mcp_server.env]]
  var   = "X"
  value = "y"
"#;
    let parsed: super::McpServersFile = toml::from_str(toml).unwrap();
    assert!(parsed.mcp_server[0].bootstrap.is_none());
}
```

- [ ] **Step 2: Run tests, confirm they fail**

```bash
cargo test test_bootstrap_config 2>&1 | tail -10
```

Expected: compile errors — `BootstrapConfig` not defined, `bootstrap` field not on `McpServerConfig`.

- [ ] **Step 3: Add `BootstrapConfig` and update `McpServerConfig`**

In `src/launcher.rs`, after the `EnvMapping` struct (~line 113), add:

```rust
#[derive(serde::Deserialize)]
struct BootstrapConfig {
    /// Strategy identifier. Currently only "unifi_api_key" is supported.
    #[serde(rename = "type")]
    strategy_type: String,
    /// Vault item name containing the service URI, username, and password
    /// used to authenticate and generate the API key.
    auth_item: String,
    /// Vault item name where the generated API key will be stored.
    /// Created automatically if absent; updated if present but empty.
    key_item: String,
    /// Whether to verify TLS certificates when calling the service API.
    /// Default: true. Set false for self-signed certs (e.g. local UniFi).
    #[serde(default = "default_verify_ssl")]
    verify_ssl: bool,
}

fn default_verify_ssl() -> bool {
    true
}
```

Update `McpServerConfig`:

```rust
#[derive(serde::Deserialize)]
struct McpServerConfig {
    name: String,
    command: String,
    #[serde(default)]
    env: Vec<EnvMapping>,
    bootstrap: Option<BootstrapConfig>,
}
```

- [ ] **Step 4: Run tests, confirm they pass**

```bash
cargo test test_bootstrap_config 2>&1 | tail -5
```

Expected: both tests pass.

- [ ] **Step 5: Confirm all launcher tests still pass**

```bash
cargo test --lib launcher 2>&1 | grep -E "FAILED|error\[" | head -10
```

Expected: no failures.

- [ ] **Step 6: Commit**

```bash
git add src/launcher.rs
git commit -m "feat(launcher): add BootstrapConfig struct and bootstrap field to McpServerConfig"
```

---

## Task 4: Implement `bootstrap_unifi_api_key` strategy

**Files:**
- Modify: `src/rotate/strategies.rs`

- [ ] **Step 1: Write failing test**

In `src/rotate/strategies.rs`, add:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bootstrap_unifi_api_key_exists() {
        // Compile-time check that the function signature is correct.
        // Full integration requires a live UniFi instance.
        let _: fn(&str, &str, &str, bool) -> _ = |uri, user, pass, ssl| {
            bootstrap_unifi_api_key(uri, user, pass, ssl)
        };
    }
}
```

- [ ] **Step 2: Run test, confirm it fails**

```bash
cargo test test_bootstrap_unifi_api_key_exists 2>&1 | tail -5
```

Expected: compile error — `bootstrap_unifi_api_key` not found.

- [ ] **Step 3: Implement the strategy**

In `src/rotate/strategies.rs`, add after the existing stubs:

```rust
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
    let login_resp = client
        .post(format!("{}/api/auth/login", uri))
        .json(&serde_json::json!({
            "username": username,
            "password": password
        }))
        .send()
        .await
        .context("UniFi login request failed")?;

    if !login_resp.status().is_success() {
        let status = login_resp.status();
        let body = login_resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "bootstrap: UniFi login failed ({}) — check local admin credentials in auth_item. \
             Response: {}",
            status,
            body
        );
    }

    // Step 2: Generate API key. Logout runs regardless of outcome.
    let key_result: anyhow::Result<zeroize::Zeroizing<String>> = async {
        let key_resp = client
            .post(format!("{}/api/users/self/api-key", uri))
            .header("Content-Type", "application/json")
            .body("{}")
            .send()
            .await
            .context("UniFi API key generation request failed")?;

        if !key_resp.status().is_success() {
            let status = key_resp.status();
            let body = key_resp.text().await.unwrap_or_default();
            anyhow::bail!(
                "bootstrap: UniFi API key generation failed ({}): {}",
                status,
                body
            );
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
```

Add `use anyhow::Context;` at the top of the file if not already present.

- [ ] **Step 4: Run test, confirm it passes**

```bash
cargo test test_bootstrap_unifi_api_key_exists 2>&1 | tail -5
```

Expected: `test ... ok`

- [ ] **Step 5: Confirm crate compiles cleanly**

```bash
cargo build 2>&1 | grep -E "^error" | head -10
```

Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add src/rotate/strategies.rs
git commit -m "feat(rotate): implement bootstrap_unifi_api_key strategy"
```

---

## Task 5: Wire bootstrap dispatch into `launcher::launch()`

**Files:**
- Modify: `src/launcher.rs`

- [ ] **Step 1: Write failing test**

In `src/launcher.rs` test module, add:

```rust
#[test]
fn test_bootstrap_strategy_type_field_name() {
    // Verify the TOML key "type" deserializes to strategy_type field.
    let toml = r#"
[[mcp_server]]
name    = "s"
command = "echo"
  [mcp_server.bootstrap]
  type      = "unifi_api_key"
  auth_item = "a/b"
  key_item  = "a/b-key"
"#;
    let parsed: super::McpServersFile = toml::from_str(toml).unwrap();
    let bs = parsed.mcp_server[0].bootstrap.as_ref().unwrap();
    assert_eq!(bs.strategy_type, "unifi_api_key");
    assert!(bs.verify_ssl); // default true
}
```

- [ ] **Step 2: Run test, confirm it passes** (no new impl needed — this tests existing struct)

```bash
cargo test test_bootstrap_strategy_type_field_name 2>&1 | tail -5
```

Expected: `test ... ok`

- [ ] **Step 3: Add bootstrap dispatch block in `launch()`**

In `src/launcher.rs`, inside the `launch()` function, after this existing line:
```rust
    let server = parsed
        .mcp_server
        .into_iter()
```
...and after the server is found and before the env resolution loop (before the `let mut resolved: Vec<...> = Vec::new();` line), add:

```rust
    // ------------------------------------------------------------------ //
    // Bootstrap: auto-generate API key if key_item is absent or empty.   //
    // ------------------------------------------------------------------ //
    if let Some(ref bootstrap) = server.bootstrap {
        let needs_bootstrap = match vault.decrypt_password(&bootstrap.key_item) {
            Ok(buf) => std::str::from_utf8(&buf)
                .map(|s| s.is_empty())
                .unwrap_or(true),
            Err(_) => true, // item not found, or no password field
        };

        if needs_bootstrap {
            tracing::info!(
                server = %server_name,
                key_item = %bootstrap.key_item,
                "bootstrapping API key"
            );

            let uri = vault
                .get_field_by_item_name(&bootstrap.auth_item, "uri")
                .await
                .with_context(|| {
                    format!(
                        "bootstrap: auth_item '{}' missing URI",
                        bootstrap.auth_item
                    )
                })?;
            let username = vault
                .get_field_by_item_name(&bootstrap.auth_item, "username")
                .await
                .with_context(|| {
                    format!(
                        "bootstrap: auth_item '{}' missing username",
                        bootstrap.auth_item
                    )
                })?;
            let password = vault
                .get_field_by_item_name(&bootstrap.auth_item, "password")
                .await
                .with_context(|| {
                    format!(
                        "bootstrap: auth_item '{}' missing password",
                        bootstrap.auth_item
                    )
                })?;

            let api_key = match bootstrap.strategy_type.as_str() {
                "unifi_api_key" => {
                    crate::rotate::strategies::bootstrap_unifi_api_key(
                        &uri,
                        &username,
                        &password,
                        bootstrap.verify_ssl,
                    )
                    .await
                    .with_context(|| {
                        format!("bootstrap: unifi_api_key strategy failed for '{}'", server_name)
                    })?
                }
                other => {
                    anyhow::bail!("bootstrap: unknown strategy type '{}'", other);
                }
            };

            // Store key in vault — create item if missing, update if exists.
            let folder_id = vault
                .find_folder_id_by_name_async(&crate::vault::VAULT_FOLDER_DEFAULT)
                .await;
            let existing_id = vault.find_item_id_by_name(&bootstrap.key_item).await;

            match existing_id {
                None => {
                    vault
                        .create_login_item(
                            &bootstrap.key_item,
                            None,
                            api_key.as_str(),
                            vec![uri.clone()],
                            folder_id.as_deref(),
                        )
                        .await
                        .with_context(|| {
                            format!(
                                "bootstrap: failed to create key_item '{}'",
                                bootstrap.key_item
                            )
                        })?;
                }
                Some(id) => {
                    vault
                        .update_login_item_fields(&id, None, None, Some(api_key.as_str()))
                        .await
                        .with_context(|| {
                            format!(
                                "bootstrap: failed to update key_item '{}'",
                                bootstrap.key_item
                            )
                        })?;
                }
            }

            vault
                .sync()
                .await
                .context("bootstrap: vault sync failed after storing key")?;

            tracing::info!(
                server = %server_name,
                key_item = %bootstrap.key_item,
                "bootstrap complete, key stored"
            );
        }
    }
```

Note: `crate::vault::VAULT_FOLDER_DEFAULT` — check if this constant exists. If not, replace with the string `"Connecterr"` temporarily. Check with:

```bash
grep -rn "VAULT_FOLDER_DEFAULT\|vault_folder\|Connecterr" /home/aaron/projects/mcp-vault-proxy/src/vault/mod.rs | head -5
```

If no constant exists, the `launch()` function receives `config_dir` as an arg but not `vault_folder`. The folder name needs to come from somewhere. Look for how `state.vault_folder` is set in `main.rs`:

```bash
grep -n "vault_folder\|vault-folder\|--vault-folder" /home/aaron/projects/mcp-vault-proxy/src/main.rs | head -10
```

The `launch()` function signature is:
```rust
pub async fn launch(server_name: &str, config_dir: &str, vault: &VaultManager, listen_addr: SocketAddr) -> Result<()>
```

Add `vault_folder: &str` parameter if needed, OR read it from a config file in `config_dir`. The simplest approach: add `vault_folder: &str` to the `launch()` signature and pass it from `main.rs` where `--vault-folder` arg is already parsed.

Check the call site in `main.rs`:

```bash
grep -n "launch(" /home/aaron/projects/mcp-vault-proxy/src/main.rs | head -5
```

Then update the call site to pass the vault_folder value.

- [ ] **Step 4: Fix vault_folder reference**

After checking how `vault_folder` is available in `main.rs`, update `launch()` signature to:

```rust
pub async fn launch(
    server_name: &str,
    config_dir: &str,
    vault: &crate::vault::VaultManager,
    listen_addr: std::net::SocketAddr,
    vault_folder: &str,
) -> Result<()>
```

Replace `crate::vault::VAULT_FOLDER_DEFAULT` in the bootstrap block with `vault_folder`.

Update the call in `main.rs` — find the existing call and add the `vault_folder` argument. The vault_folder value is available as `args.vault_folder` or similar (grep for it in main.rs to confirm the exact variable name).

- [ ] **Step 5: Build and fix compile errors**

```bash
cargo build 2>&1 | grep "^error" | head -20
```

Fix any type/import errors. Common ones:
- Missing `use anyhow::Context;` in launcher.rs (likely already there — check with `grep "use anyhow" src/launcher.rs`)
- `password` binding from `Zeroizing<String>` returned by `get_field_by_item_name` needs `.as_str()` correctly

- [ ] **Step 6: Run all launcher tests**

```bash
cargo test --lib launcher 2>&1 | grep -E "FAILED|ok" | tail -20
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add src/launcher.rs src/main.rs
git commit -m "feat(launcher): wire bootstrap dispatch into --launch flow"
```

---

## Task 6: Update `config/mcp-servers.toml` for UniFi

**Files:**
- Modify: `config/mcp-servers.toml`

- [ ] **Step 1: Update the unifi block**

Replace the existing `[[mcp_server]]` block for `name = "unifi"` with:

```toml
# ── UniFi Network MCP (go-unifi-mcp) ────────────────────────────────────────
[[mcp_server]]
name    = "unifi"
command = "/home/aaron/.local/bin/go-unifi-mcp"

  [mcp_server.bootstrap]
  type       = "unifi_api_key"
  auth_item  = "unifi/home"       # uri + local-admin username + password
  key_item   = "unifi/home-key"   # generated API key stored here (auto-created)
  verify_ssl = false

  [[mcp_server.env]]
  var        = "UNIFI_HOST"
  vault_item = "unifi/home"
  field      = "uri"

  [[mcp_server.env]]
  var        = "UNIFI_API_KEY"
  vault_item = "unifi/home-key"
  field      = "password"

  [[mcp_server.env]]
  var   = "UNIFI_VERIFY_SSL"
  value = "false"
```

- [ ] **Step 2: Update `unifi/home` vault item**

Using the vaultproxy MCP tool `update_item`, set the `unifi/home` item (id: `203d917a-83e3-4ce2-82fb-a15daf9d5724`):
- `username` → the local admin account name you create on UniFi
- `password` → the local admin password
- The URI should already be set to `https://unifi.splendidus.live`

(User creates the local admin account on UniFi first. vaultproxy handles everything after.)

- [ ] **Step 3: Dry-run — test config parses correctly**

```bash
cd /home/aaron/projects/mcp-vault-proxy
cargo run -- --config-dir config/ --launch nonexistent 2>&1 | head -10
```

Expected: vault syncs, then `"server 'nonexistent' not found"` error — confirms config parses without TOML errors.

- [ ] **Step 4: Commit**

```bash
git add config/mcp-servers.toml
git commit -m "config: update unifi mcp-server block with bootstrap and uri field"
```

---

## Task 7: End-to-end smoke test

Prerequisites: local UniFi admin account created, credentials in `unifi/home` vault item.

- [ ] **Step 1: Run `cargo build --release`**

```bash
cd /home/aaron/projects/mcp-vault-proxy
cargo build --release 2>&1 | grep "^error" | head -10
```

Expected: no errors, binary at `target/release/vaultproxy`.

- [ ] **Step 2: Run `--launch unifi` and observe bootstrap**

```bash
./target/release/vaultproxy --launch unifi --config-dir /home/aaron/projects/Connecterr/config/ 2>&1 &
VP_PID=$!
sleep 6
kill $VP_PID 2>/dev/null
wait $VP_PID 2>/dev/null
```

Expected log output (in order):
```
INFO vaultproxy: vault sync complete — N items loaded
INFO vaultproxy::launcher: bootstrapping API key server=unifi key_item=unifi/home-key
INFO vaultproxy::launcher: bootstrap complete, key stored server=unifi key_item=unifi/home-key
INFO vaultproxy::launcher: launching 'unifi': /home/aaron/.local/bin/go-unifi-mcp (injecting N env vars)
```

If step 2 shows an auth error, check `unifi/home` credentials are correct for the local admin account.

- [ ] **Step 3: Verify `unifi/home-key` was created in vault**

```
mcp__vaultproxy__list_items (filter for "unifi/home-key")
```

Expected: item exists with non-empty password field (shown as `********`).

- [ ] **Step 4: Run `--launch unifi` a second time — confirm bootstrap is skipped**

```bash
./target/release/vaultproxy --launch unifi --config-dir /home/aaron/projects/Connecterr/config/ 2>&1 &
VP_PID=$!
sleep 5
kill $VP_PID 2>/dev/null
wait $VP_PID 2>/dev/null
```

Expected: NO `bootstrapping API key` log line — skips directly to launching go-unifi-mcp.

- [ ] **Step 5: Reload MCP in Claude Code `/mcp` dialog**

Confirm `unifi` shows as connected (green), not failed.

- [ ] **Step 6: Final commit**

```bash
git add -A
git commit -m "feat: credential bootstrap complete — unifi api key auto-generated from vault creds"
```
