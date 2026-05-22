# Configuration

`services.toml` lives in `--config-dir` (default `/config/services.toml`). Copy `services.example.toml` from the repo as a starting point.

> **Note:** `services.toml` is read at startup and can also be reloaded at runtime via SIGHUP — see [RELOAD.md](RELOAD.md). `POST /vault/resync` only refreshes vault *credentials* from Vaultwarden — it does not reload `services.toml`.

## Service entries

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

## Auth types

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

## `POST /proxy` request format

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

## `--launch`-injected env vars (smart MCP servers)

When vault-proxy launches a smart MCP server via `--launch`, it injects two env vars before any `[[mcp_server.env]]` entries are applied:

| Variable | Value | Purpose |
|----------|-------|---------|
| `VAULT_PROXY_URL` | `http://127.0.0.1:3201` (or `VAULT_PROXY_PUBLIC_URL` if set) | URL of the vault-proxy sidecar |
| `VAULT_PROXY_CALLER_ID` | The server name from `mcp-servers.toml` | Per-caller rate-limit identity |

Smart servers should forward `VAULT_PROXY_CALLER_ID` as `X-Caller-Id` on every call to receive an isolated rate-limit bucket. See [SECURITY.md §Per-caller rate limiting](../../SECURITY.md#per-caller-rate-limiting-x-caller-id--vault_proxy_caller_id) for the trust model.

## `VAULT_PROXY_PUBLIC_URL`

Set this env var when vault-proxy sits behind a reverse proxy (nginx, Caddy, Traefik) that terminates TLS — e.g. `VAULT_PROXY_PUBLIC_URL=https://vault-proxy.example.com`. Must be a valid `http://` or `https://` URL without a trailing slash. Validated at startup and in `--check` mode. When unset, vault-proxy derives the URL from the `--listen` address.
