# smart-mcp-server-ts

Minimal TypeScript smart MCP server. Exposes one tool, `ha_call_service`, that calls Home Assistant through vault-proxy.

## Setup

```bash
cd examples/smart-mcp-server-ts
npm install
npm run build
```

## Run standalone

```bash
export VAULT_PROXY_URL=http://127.0.0.1:3201
export VAULT_PROXY_CALLER_ID=ha-example-ts
node dist/index.js
```

The server reads MCP JSON-RPC from stdin and writes to stdout — pipe it from a host or use the MCP inspector.

## Run under `--launch`

See [`../README.md`](../README.md).

## What it demonstrates

- `VAULT_PROXY_URL` discovery (defaults to `http://127.0.0.1:3201` when unset)
- `VAULT_PROXY_CALLER_ID` forwarded as `X-Caller-Id` for per-caller rate limiting
- No Home Assistant Bearer token in this process — vault-proxy injects it
- Stdio MCP transport from `@modelcontextprotocol/sdk`
