# Smart MCP server examples

Three minimal "smart" MCP server implementations that call `POST /proxy` on vault-proxy instead of holding credentials themselves. Each exposes a single `ha_call_service` tool that flips a Home Assistant light on or off — illustrative, replace with your actual upstream calls.

| Directory | Language | Runtime | MCP SDK |
|---|---|---|---|
| [`smart-mcp-server-ts/`](smart-mcp-server-ts/) | TypeScript | Node 20+ | `@modelcontextprotocol/sdk` |
| [`smart-mcp-server-py/`](smart-mcp-server-py/) | Python | 3.10+ | `mcp` (official Python SDK) |
| [`smart-mcp-server-rs/`](smart-mcp-server-rs/) | Rust | edition 2021 | `rmcp` (official Rust SDK) |

## The pattern

All three implementations:

1. Read `VAULT_PROXY_URL` (default `http://127.0.0.1:3201`) and `VAULT_PROXY_CALLER_ID` from the environment — both are injected automatically when the server is started via `vaultproxy --launch <name>`.
2. Expose one MCP tool over stdio.
3. When the tool is called, POST to `$VAULT_PROXY_URL/proxy` with the `X-Caller-Id: $VAULT_PROXY_CALLER_ID` header so the server gets its own rate-limit bucket.
4. Forward the upstream response body back to the MCP client unchanged. **The credential is never seen by this process** — vault-proxy injects the Home Assistant Bearer token internally.

## Running standalone (without `--launch`)

For local development, set the env vars yourself:

```bash
export VAULT_PROXY_URL=http://127.0.0.1:3201
export VAULT_PROXY_CALLER_ID=ha-example
# ... then start the server per its README
```

vault-proxy must be running with a `[[service]]` block named `ha_home` in `services.toml`. See [`../services.example.toml`](../services.example.toml).

## Running under `--launch`

Add an entry to `mcp-servers.toml`:

```toml
[[mcp_server]]
name = "ha-example-ts"
command = "node /path/to/examples/smart-mcp-server-ts/dist/index.js"

[[mcp_server]]
name = "ha-example-py"
command = "python /path/to/examples/smart-mcp-server-py/server.py"

[[mcp_server]]
name = "ha-example-rs"
command = "/path/to/examples/smart-mcp-server-rs/target/release/smart-mcp-server"
```

Then:

```bash
vaultproxy --launch ha-example-ts
```

vault-proxy injects `VAULT_PROXY_URL` and `VAULT_PROXY_CALLER_ID=ha-example-ts` and `exec`s the command. The MCP host (Claude Desktop, Claude Code, etc.) connects over stdio in the usual way.
