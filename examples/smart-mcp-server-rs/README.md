# smart-mcp-server-rs

Minimal Rust smart MCP server. Exposes one tool, `ha_call_service`, that calls Home Assistant through vault-proxy.

## Setup

```bash
cd examples/smart-mcp-server-rs
cargo build --release
```

The binary lands at `target/release/smart-mcp-server`.

## Run standalone

```bash
export VAULT_PROXY_URL=http://127.0.0.1:3201
export VAULT_PROXY_CALLER_ID=ha-example-rs
./target/release/smart-mcp-server
```

## Run under `--launch`

See [`../README.md`](../README.md).

## What it demonstrates

- `VAULT_PROXY_URL` discovery (defaults to `http://127.0.0.1:3201` when unset)
- `VAULT_PROXY_CALLER_ID` forwarded as `X-Caller-Id` for per-caller rate limiting
- No Home Assistant Bearer token in this process — vault-proxy injects it
- Hand-rolled stdio JSON-RPC MCP transport (no SDK dep) so the example stays under 200 lines and one Cargo.toml file

A production server would use the official Rust SDK [`rmcp`](https://github.com/modelcontextprotocol/rust-sdk) instead — this example optimises for "easy to read top-to-bottom."
