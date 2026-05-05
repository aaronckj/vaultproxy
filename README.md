# vaultproxy

A secure credential sidecar for [MCP](https://modelcontextprotocol.io) servers.

Most MCP servers store credentials in env vars or `.env` files — readable by any process running as the same user, present in shell history, and scattered across every server you run. `vaultproxy` solves this: it reads credentials from your self-hosted [Vaultwarden](https://github.com/dani-garcia/vaultwarden) instance, injects the right auth header for each downstream service, and **never exposes plaintext secrets to the MCP layer**.

## How it works

```
Claude Code → MCP Server → vaultproxy (127.0.0.1:3201) → Your Service
                                     ↑
                               Vaultwarden (credentials stay here)
```

Your MCP server calls `POST http://127.0.0.1:3201/proxy` with:

```json
{
  "service": "unifi_home",
  "method": "GET",
  "path": "/api/s/default/stat/sta"
}
```

The proxy looks up the credential for `unifi_home` in Vaultwarden, injects the appropriate auth (API key, Bearer token, Basic auth, or session cookie), forwards the request, and returns the response — credential never leaves the proxy process.

## Supported auth patterns

| Pattern | Example services |
|---------|-----------------|
| `X-Api-Key` header | Sonarr, Radarr, Overseerr |
| `X-Plex-Token` header | Plex |
| `Authorization: Bearer` | Home Assistant |
| HTTP Basic | OPNsense |
| Session (POST login → token) | Nginx Proxy Manager, Duplicati |
| UniFi dual (API key → session fallback) | UniFi OS |
| Query param | Tautulli |

## Security model

- The proxy listens on `127.0.0.1:3201` only — network isolation is the primary guarantee
- DNS rebinding guard on all `/proxy` requests
- Rate limit: 60 req/60s on `/proxy`
- Credentials are decrypted in-process from an encrypted keystore; plaintext values never appear in logs
- Optional TPM sealing: keystore is hardware-bound to the host machine (`--features tpm`)
- Dashboard (optional, `--features dashboard`) listens on `127.0.0.1:3202` only

## Configuration

Services are registered in `services.toml` inside your `--config-dir` (default `/config/services.toml`). Copy `services.example.toml` from the repo as a starting point.

```toml
# Each [[service]] block registers one downstream service.
# `name` is what you pass as "service" in POST /proxy calls.
# `vault_item` is the name of the item in your Vaultwarden folder — 
#   the actual credential stays in Vaultwarden, never in this file.

[[service]]
name = "ha_home"
base_url = "http://homeassistant.local:8123"
auth = "bearer"
vault_item = "vault-proxy - Home Assistant"

[[service]]
name = "sonarr"
base_url = "http://sonarr.local:8989/api/v3"
auth = "header"
header_name = "X-Api-Key"
vault_item = "vault-proxy - Sonarr"

[[service]]
name = "unifi_home"
base_url = "https://unifi.local/proxy/network"
auth = "unifi_dual"
vault_item = "vault-proxy - UniFi"
login_path = "/api/auth/login"
```

### Auth types

| `auth` value | Required fields | Example use |
|-------------|-----------------|-------------|
| `bearer` | — | Home Assistant, any Bearer token API |
| `header` | `header_name` | Sonarr, Radarr, Plex (`X-Plex-Token`) |
| `query_param` | `param_name` | Tautulli |
| `basic` | `key_field`, `secret_field` | OPNsense (API key + secret) |
| `session` | `login_path`, `token_field` | Nginx Proxy Manager, Duplicati |
| `unifi_dual` | `login_path` | UniFi OS (API key → session fallback) |

Add `insecure_tls = true` for services with self-signed certificates (e.g. OPNsense on a local LAN).

> **Security warning:** `insecure_tls = true` disables all TLS certificate validation for that service. Credentials forwarded to the service are sent without certificate verification — a MITM attack on that service's IP cannot be detected. Only use this for LAN-local services with known self-signed certs. Never use it for internet-facing endpoints. A startup warning is logged for every service registered with this flag.

### Vault items

In Vaultwarden, create a folder named `vault-proxy` (or your `--vault-folder` value). Add one item per service named to match the `vault_item` field in `services.toml`:

```
vault-proxy - Home Assistant    ← password field = Bearer token
vault-proxy - UniFi             ← password field = API key
vault-proxy - OPNsense          ← custom fields: key, secret
vault-proxy - Sonarr            ← password field = API key
vault-proxy - Tautulli          ← password field = API key
vault-proxy - Plex              ← password field = X-Plex-Token
```

The `vault_item` string in `services.toml` is just a reference — credentials never leave Vaultwarden.

## Quickstart (Docker Compose)

**Step 1:** Create your config directory and place your `services.toml` inside it:

```bash
mkdir -p ./config
cp services.example.toml ./config/services.toml
# Edit ./config/services.toml to match your services and vault item names
```

**Step 2:** In Vaultwarden, create a folder named `vault-proxy` and add one item per service, named to match the `vault_item` field in `services.toml` (e.g. `vault-proxy - Home Assistant`).

**Step 3:** Start the setup wizard:

```yaml
services:
  vaultproxy:
    image: ghcr.io/aaronckj/vaultproxy:latest
    restart: unless-stopped
    network_mode: host
    volumes:
      - ./config:/config
    environment:
      VAULT_FOLDER: vault-proxy
    command: ["--setup"]   # Remove after first-run setup completes
```

```bash
docker compose up
```

The wizard prompts for your Vaultwarden URL, email, and master password. Credentials are stored encrypted in `/config/keystore.json`.

**Step 4:** Remove `command: ["--setup"]` from your compose file and restart:

```bash
docker compose up -d
```

The proxy is now running. Verify with:

```bash
curl http://127.0.0.1:3201/vault/health
```

**With TPM (bare metal):**
```bash
cargo build --release --features tpm
```

## CLI reference

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `--listen` | — | `127.0.0.1:3201` | Proxy listen address |
| `--config-dir` | `CONFIG_DIR` | `/config` | Keystore + config directory |
| `--vault-folder` | `VAULT_FOLDER` | `vault-proxy` | Vaultwarden folder name |
| `--setup` | — | — | Run interactive setup wizard |
| `--proxy-timeout` | `PROXY_TIMEOUT` | `120` | Upstream request timeout (seconds) |
| `--ntfy-url` | `NTFY_URL` | — | ntfy.sh topic URL for push alerts |
| `--litellm-url` | `LITELLM_URL` | — | LiteLLM base URL (browser rotation feature) |

## Building

```bash
# Headless — recommended for Docker/server deployments
cargo build --release

# With TPM sealing — bare metal, requires TSS2 system libraries
cargo build --release --features tpm

# With web dashboard — adds management UI on 127.0.0.1:3202
cargo build --release --features dashboard
```

## Launching MCP servers (wrapper mode)

For MCP servers that don't support vault-proxy natively, use launcher mode to inject credentials at spawn time:

```bash
vault-proxy --launch unifi-network
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

See `mcp-servers.example.toml` for all options. See `SECURITY.md` for the security tradeoffs between launcher mode and native `/proxy` integration.

## `/proxy` API

`POST http://127.0.0.1:3201/proxy`

Request body:
```json
{
  "service": "ha_home",
  "method": "POST",
  "path": "/api/services/light/turn_on",
  "body": { "entity_id": "light.living_room" },
  "headers": { "X-Custom-Header": "value" },
  "query": { "format": "json" }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `service` | string | yes | Registered service name (from `services.toml`) |
| `method` | string | no | HTTP method — defaults to `"GET"` |
| `path` | string | yes | Path appended to the service's `base_url`. Must not contain `.` or `..` segments. |
| `body` | object | no | JSON body forwarded verbatim to the downstream service |
| `headers` | object | no | Extra headers merged into the downstream request (string values only) |
| `query` | object | no | Extra query parameters appended to the URL |

The proxy injects the registered auth credential, forwards the request, and returns:
- On success: the upstream HTTP status code and JSON body
- On proxy error: a `{"error": "..."}` JSON body with a 4xx or 5xx status

**Smart MCP servers** should set `VAULT_PROXY_URL` (default `http://127.0.0.1:3201`) to locate the sidecar. All proxy calls go to `$VAULT_PROXY_URL/proxy`.

## Why not just use env vars?

Env vars are readable by any process running as the same OS user, show up in `ps auxe`, persist in shell history, and end up copy-pasted across multiple `.env` files. `vaultproxy` keeps credentials in a single encrypted keystore backed by Vaultwarden — one source of truth, never in plaintext outside the proxy process.

## License

MIT
