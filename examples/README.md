# MCP server examples

Four minimal MCP server implementations against vault-proxy. The
first three are "smart" servers that call `POST /proxy` explicitly
(Tier 1 — credential never enters the agent's address space). The
fourth uses `HTTPS_PROXY` and the transparent listener (Tier 3 — zero
credential code, agent unmodified).

| Directory | Language | Tier | Notes |
|---|---|---|---|
| [`smart-mcp-server-ts/`](smart-mcp-server-ts/) | TypeScript | Native `/proxy` | Node 20+, `@modelcontextprotocol/sdk` |
| [`smart-mcp-server-py/`](smart-mcp-server-py/) | Python | Native `/proxy` | 3.10+, `mcp` SDK |
| [`smart-mcp-server-rs/`](smart-mcp-server-rs/) | Rust | Native `/proxy` | edition 2021, `rmcp` SDK |
| [`smart-mcp-server-transparent/`](smart-mcp-server-transparent/) | Python | Transparent `HTTPS_PROXY` | Demonstrates v1.1+ transparent listener; zero auth code in the server |

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
