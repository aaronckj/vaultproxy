# Credential Bootstrap Design

**Date:** 2026-05-09  
**Status:** Approved  
**Scope:** vaultproxy `--launch` mode gains the ability to auto-generate service API keys from stored credentials, removing any manual credential handling by the user.

---

## Problem

When a child MCP server (e.g. `go-unifi-mcp`) needs an API key but only a username/password exists in vault, the user currently has to:
1. Manually log into the service
2. Generate an API key
3. Paste it somewhere

This violates the vaultproxy design principle: creds never touch Claude, the user never handles credentials manually after initial vault setup.

Additionally, username/password auth against UniFi OS for SSO accounts causes account lockout. API key auth is the correct long-term approach.

---

## Solution

At `--launch` time, if the target API key vault item is absent or empty, vaultproxy automatically:
1. Reads service URL, username, and password from a vault item
2. Calls the service API to generate an API key
3. Writes the key back to vault
4. Proceeds with normal env injection and exec

The user's only manual step: create a local admin account on the service, store its credentials in Vaultwarden once. Everything after that is automated.

---

## Config Shape

`mcp-servers.toml` gains an optional `[mcp_server.bootstrap]` table:

```toml
[[mcp_server]]
name    = "unifi"
command = "/home/aaron/.local/bin/go-unifi-mcp"

  [mcp_server.bootstrap]
  type      = "unifi_api_key"   # strategy identifier
  auth_item = "unifi/home"      # vault item: uri + username + password for initial auth
  key_item  = "unifi/home-key"  # vault item to store generated API key (created if absent)

  [[mcp_server.env]]
  var        = "UNIFI_HOST"
  vault_item = "unifi/home"
  field      = "uri"            # NEW: resolves first URI from vault item

  [[mcp_server.env]]
  var        = "UNIFI_API_KEY"
  vault_item = "unifi/home-key"
  field      = "password"

  [[mcp_server.env]]
  var   = "UNIFI_VERIFY_SSL"
  value = "false"
```

`EnvMapping.field` gains a `"uri"` variant that resolves `item.uris[0]`. This is a general addition useful for any service whose URL is stored in Vaultwarden.

---

## Vault Item Structure

**`unifi/home`** — auth credential, user-created once, never modified by vaultproxy
- `uri` → `https://unifi.splendidus.live`
- `username` → local admin account name (e.g. `vp-admin`)
- `password` → local admin password

**`unifi/home-key`** — generated credential, fully managed by vaultproxy
- `uri` → `https://unifi.splendidus.live` (copied from auth_item on creation)
- `username` → (empty)
- `password` → generated API key

`unifi/home-key` is created automatically on first launch if absent. On subsequent launches, non-empty password → bootstrap skipped. Both items live in the Connecterr vault folder.

---

## Bootstrap Flow

Runs inside `launcher::launch()` after config parse, before env resolution and exec:

```
1. No [bootstrap] block → skip, proceed as today

2. Resolve key_item from vault:
   a. Item missing OR password empty → run bootstrap
   b. Item exists with non-empty password → skip, proceed

3. Bootstrap:
   a. Fetch auth_item → uri, username, password
   b. Call strategy (e.g. unifi_api_key::run(uri, username, password))
   c. Strategy returns API key string
   d. key_item missing → vault.create_item(name, folder=Connecterr, uri, password=key)
   e. key_item exists empty → vault.update_item(id, password=key)
   f. vault.sync() — ensures fresh item visible for env resolution in step 4

4. Normal env resolution + exec
```

Failures at step 3 are fatal. No retry on auth failures (avoids account lockout).

---

## UniFi API Key Strategy

Location: `rotate/strategies.rs` (new function `unifi_api_key::run`)

```
unifi_api_key::run(uri, username, password, verify_ssl) -> Result<String>

1. POST {uri}/api/auth/login
   body: {"username": username, "password": password}
   → extract TOKEN cookie from response

2. POST {uri}/api/users/self/api-key
   headers: Cookie: TOKEN=<value>
   → extract apiKey from {"data": {"apiKey": "..."}}

3. DELETE {uri}/api/auth/logout  (runs even on step-2 failure)

4. Return apiKey
```

`verify_ssl`: read from the server's static env entries (scan for `UNIFI_VERIFY_SSL` value before exec), default `true`. This runs before env injection so it must be read from config directly.

**Adding new services:** `launcher.rs` dispatches on `bootstrap.type`:
```rust
match bootstrap.r#type.as_str() {
    "unifi_api_key" => strategies::unifi_api_key::run(...).await,
    other => bail!("unknown bootstrap type '{}'", other),
}
```
New service = new match arm + strategy function. No trait objects.

---

## Error Handling

| Failure | Behavior |
|---------|----------|
| `auth_item` not in vault | Fatal: `"bootstrap: auth_item 'X' not found"` |
| `auth_item` missing uri/username/password | Fatal: `"bootstrap: auth_item 'X' missing field 'Y'"` |
| UniFi login 403 | Fatal: `"bootstrap: login failed — check local admin creds in 'X'"` |
| API key generation fails | Fatal, no vault write |
| vault create/update fails | Fatal, no exec |

No retries on auth failures — each retry extends lockout window.

---

## Security

- API key string wrapped in `Zeroizing<String>` — zeroed from memory after vault write
- Session TOKEN cookie zeroized after logout
- Logout runs on both success and error paths
- Logs: `INFO "bootstrapping 'unifi' API key"` and `INFO "bootstrap complete, key stored in 'unifi/home-key'"` — no credential values ever logged

---

## Re-bootstrap

If the stored API key is revoked on the service side, bootstrap is skipped on next launch (password field still non-empty). To force re-bootstrap: user clears `unifi/home-key` password via vaultproxy MCP (`update_item` with `password: ""`). Next launch regenerates it.

Automatic rotation (periodic key refresh) is out of scope — YAGNI.

---

## Files to Change

| File | Change |
|------|--------|
| `src/launcher.rs` | Add `BootstrapConfig` struct, `Option<BootstrapConfig>` to `McpServerConfig`, bootstrap check + dispatch in `launch()`, `"uri"` variant in `EnvMapping` field resolution |
| `src/rotate/strategies.rs` | Add `unifi_api_key` module with `run()` function |
| `config/mcp-servers.toml` | Add `[mcp_server.bootstrap]` block and update env entries for unifi |
