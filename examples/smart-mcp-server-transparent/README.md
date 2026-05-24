# smart-mcp-server-transparent

A demonstration MCP server that calls Home Assistant **without
hardcoding a token** — every outbound HTTPS request is automatically
intercepted by vault-proxy's transparent listener, the agent's
(non-existent) `Authorization` header is replaced with a vault-resolved
Bearer token, and the upstream HA API sees a fully-authenticated
request.

The MCP server itself contains zero credential code. It just calls
`https://homeassistant.local:8123/api/states` and trusts the proxy.

## How it works

```
┌────────────────────────────┐
│ This MCP server            │
│   reqwest / fetch / urllib │
│   no Authorization header  │
└────────────┬───────────────┘
             │ HTTPS_PROXY=http://127.0.0.1:3203
             ▼
┌────────────────────────────┐
│ vault-proxy transparent    │
│   - intercepts CONNECT     │
│   - signs leaf cert        │
│   - strips agent auth      │
│   - injects Bearer from VW │
└────────────┬───────────────┘
             │ TLS to upstream
             ▼
   homeassistant.local:8123
```

## Prerequisites

1. vault-proxy v1.2+ running with the transparent listener bound on
   `127.0.0.1:3203` (default). The proxy must have a `[[service]]`
   block for `homeassistant.local:8123` with
   `transparent_mode = "host_inject"` and `auth = "bearer"`.
2. The proxy's CA cert installed (or trusted by the MCP server
   process via `REQUESTS_CA_BUNDLE` / `NODE_EXTRA_CA_CERTS` /
   `SSL_CERT_FILE`). See
   [`../../docs/operator/TRANSPARENT-CA.md`](../../docs/operator/TRANSPARENT-CA.md).
3. The Home Assistant token stored in Vaultwarden under
   `vault-proxy - Home Assistant`.

## services.toml

```toml
[[service]]
name             = "ha_home"
base_url         = "https://homeassistant.local:8123"
auth             = "bearer"
vault_item       = "vault-proxy - Home Assistant"
transparent_mode = "host_inject"
```

## Running the MCP server

This example uses Python for brevity. The same shape applies to TS /
Rust / Go / any language with an HTTPS client.

```bash
cd examples/smart-mcp-server-transparent
HTTPS_PROXY=http://127.0.0.1:3203 \
REQUESTS_CA_BUNDLE=/config/transparent-ca.crt \
python3 server.py
```

Then connect an MCP host (Claude Desktop, Claude Code, etc.) over
stdio. Calling `ha_get_states` issues a plain `requests.get(...)`
that becomes a fully-authenticated upstream call.

## Compare with the `/proxy` example

The sibling `smart-mcp-server-py/` example calls `POST /proxy` on
vault-proxy explicitly. That's the most secure path — the credential
never enters the MCP server's address space at all.

The transparent example is for cases where you cannot or do not want
to modify the MCP server to know about vault-proxy. The agent code
is unchanged from a normal HTTPS client; only the environment + CA
trust differ.
