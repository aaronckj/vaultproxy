# Launcher mode (`--launch`)

For MCP servers that don't support vault-proxy natively, use launcher mode to inject credentials at spawn time:

```bash
vaultproxy --launch unifi-network
```

Configure servers in `mcp-servers.toml` inside your `--config-dir`:

```toml
[[mcp_server]]
name = "unifi-network"
command = "uvx unifi-network-mcp@latest"

  [[mcp_server.env]]
  var = "UNIFI_HOST"
  value = "https://unifi.local"

  [[mcp_server.env]]
  var = "UNIFI_API_KEY"
  vault_item = "vault-proxy - UniFi"
  field = "password"
```

See `mcp-servers.example.toml` for all options. See [SECURITY.md §Two-tier security model](../../SECURITY.md#two-tier-security-model) for the security tradeoffs between launcher mode (Tier 2) and native `/proxy` integration (Tier 1).

## Smart servers and `--launch`

When a "smart" MCP server (one with native vault-proxy support) is launched via `--launch`, vault-proxy automatically injects two environment variables into the child's environment:

| Variable | Value | Purpose |
|----------|-------|---------|
| `VAULT_PROXY_URL` | `http://127.0.0.1:3201` (or `VAULT_PROXY_PUBLIC_URL` if set) | URL of the vault-proxy sidecar — set by the proxy, not by the operator |
| `VAULT_PROXY_CALLER_ID` | The server name from `mcp-servers.toml` | Per-caller rate-limit identity |

The smart server uses `VAULT_PROXY_URL` to call `POST $VAULT_PROXY_URL/proxy` — vault-proxy injects the credential internally and forwards the request. No vault items appear in the smart server's environment.

### `VAULT_PROXY_CALLER_ID` and per-caller rate limiting

When vault-proxy receives a `/proxy` request it checks the `X-Caller-Id` header to assign the request to an isolated rate-limit bucket. Smart MCP servers should read `VAULT_PROXY_CALLER_ID` from their environment and forward it as `X-Caller-Id` on every call:

```
X-Caller-Id: <value of VAULT_PROXY_CALLER_ID>
```

This gives each `--launch`ed server its own independent rate-limit budget automatically, without manual configuration. The value is taken from `mcp-servers.toml` at deploy time — it is operator-controlled and cannot be changed by code inside the child process. Both `VAULT_PROXY_URL` and `VAULT_PROXY_CALLER_ID` are set before the per-server `[[mcp_server.env]]` list is applied, so an explicit entry in `mcp-servers.toml` can override either if needed.

### Calling `/proxy` from a launched smart server

This is the intended flow. The smart server calls `POST /proxy` with `{"service": "my_service", "method": "GET", "path": "/..."}` and vault-proxy resolves the credential, applies auth, and forwards to the downstream service. The corresponding `[[service]]` block must exist in `services.toml`.

### Calling `/vault/*` endpoints from a launched smart server

Internal endpoints (`/vault/reload-services`, `/vault/connecterr-secrets`, `/browser/*`, etc.) require the internal bearer token. If your smart server needs to call these endpoints, it must read `$CONFIG_DIR/internal-token` and include it as:

```
Authorization: Bearer <token>
```

The token file is written at vault-proxy startup (mode 0600, owner = vault-proxy process user). It is separate from all Vaultwarden credentials.
