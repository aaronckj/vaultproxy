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

- The proxy listens on `127.0.0.1:3201` by default — network isolation is the primary guarantee. **Warning:** if you override `--listen` to bind a non-loopback address (e.g. `0.0.0.0:3201`), all proxy and vault endpoints become accessible to any host on that network. There is no authentication middleware — the only access control is the loopback bind. A startup warning is logged whenever a non-loopback address is used. Never expose this port beyond the local machine without a reverse proxy with mTLS or network-layer ACLs.
- DNS rebinding guard on all `/proxy` requests
- Rate limit: 60 req/60s on all endpoints
- Credentials are decrypted in-process from an encrypted keystore; plaintext values never appear in logs
- Optional TPM sealing: keystore is hardware-bound to the host machine (`--features tpm`)
- Dashboard (optional, `--features dashboard`) listens on `127.0.0.1:3202` by default; same `--listen` non-loopback warning applies

## Configuration

Services are registered in `services.toml` inside your `--config-dir` (default `/config/services.toml`). Copy `services.example.toml` from the repo as a starting point.

> **Note:** `services.toml` is read at startup and can also be reloaded at runtime via SIGHUP (see below). `POST /vault/resync` only refreshes vault *credentials* from Vaultwarden — it does not reload `services.toml`.

### Hot-reloading services.toml (SIGHUP)

To add, remove, or change a `[[service]]` block without restarting:

```bash
# In Docker
docker kill --signal=HUP <container_name>

# On bare metal
kill -HUP $(pidof vaultproxy)
```

vault-proxy will:
1. Re-parse `services.toml` and validate every entry (SSRF rules, required fields, PEM certs)
2. Rebuild per-service CA-cert HTTP clients
3. Atomically swap the new registry into place — in-flight requests see the old registry; new requests see the updated one

**Rollback safety:** if the reloaded file would produce zero services (parse error, all entries rejected), vault-proxy keeps the previous registry and logs a `SIGHUP: rolling back` warning. Fix the file and send SIGHUP again.

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

To verify that services.toml loaded correctly, use:

```bash
curl http://127.0.0.1:3201/vault/services
```

`GET /vault/services` returns the count and list of registered services — each entry includes the service `name`, `base_url`, `auth` type (`bearer`, `header`, `query_param`, `basic`, `session`, or `unifi_dual`), and auth-type-specific detail (header name, param name, token field, etc.). `vault_item` (the Vaultwarden credential name) is intentionally omitted. This endpoint requires no authentication token; it exposes no secrets.

> **Internal token:** vault-proxy generates a 64-character hex bearer token at startup and writes it to `$CONFIG_DIR/internal-token` (mode 0600). Internal endpoints (`/vault/connecterr-secrets`, `/vault/connecterr-secrets/upsert`, `/rotate`, `/browser/*`, `/vault/notes`) require `Authorization: Bearer <token>`. The Connecterr TypeScript side reads this file automatically. If you are integrating a custom client, read `CONFIG_DIR/internal-token` and include it as `Authorization: Bearer <value>` on calls to those endpoints.

> **`write_env` feature:** `POST /vault/write-env` (which decrypts a vault item and writes its credentials as env-var lines to a file) is disabled by default (`501 Not Implemented`). Enable it by setting `ENV_WRITE_ROOT` to a directory that the proxy is allowed to write into (e.g. `ENV_WRITE_ROOT=/envs`). The endpoint enforces that `target_path` begins with this prefix.

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
| `--check` | — | — | Validate services.toml (parse + SSRF rules) and exit. No Vaultwarden connection required. Exit 0 = ok. |
| `--proxy-timeout` | `PROXY_TIMEOUT` | `120` | Upstream request timeout (seconds) |
| `--ntfy-url` | `NTFY_URL` | — | ntfy.sh topic URL for push alerts |
| `--litellm-url` | `LITELLM_URL` | — | LiteLLM base URL (browser rotation feature) |
| `--allow-root` | — | — | Suppress the root-user security warning (see below) |
| `--env-write-root` | `ENV_WRITE_ROOT` | — | Root directory that `POST /vault/write-env` is allowed to write into (e.g. `/envs`). Unset = endpoint returns 501. |
| — | `UPSTREAM_BODY_LIMIT_MB` | `32` | Max upstream response body to buffer (MB) |

> **`--allow-root`**: vault-proxy logs a `SECURITY:` warning when it starts as
> uid 0 (root) because a credential broker running as root grants full system
> access if compromised. Pass `--allow-root` only when root is genuinely
> required — for example, when accessing `/dev/tpm0` on systems without udev
> rules that permit non-root TPM access. Prefer a dedicated non-root user in all
> other cases (e.g. `--user vaultproxy:vaultproxy` in Docker Compose).

## Audit log

vault-proxy writes an audit trail to `$CONFIG_DIR/audit-log.json` (default `/config/audit-log.json`). The file is a JSON array of objects (newest entry first), capped at 1 000 entries:

```json
[
  {
    "timestamp":      "2026-05-05T12:34:56.789Z",   // RFC 3339 UTC
    "tool_name":      "ha_home__get",                // <service>__<method>
    "args_summary":   "method=GET, path=/api/states", // truncated at 200 chars
    "result_summary": "states=[...]",                 // truncated; sensitive fields masked
    "permission":     "Log",                          // Allow | Log | Ask | Block
    "trigger":        "proxy"                         // always "proxy" for /proxy calls
  }
]
```

Sensitive field values (`password`, `token`, `api_key`, `secret`, `bearer`, `cookie`, and related names) are replaced with `***` before writing so raw credentials never appear in the log.

The file is written to disk every 10 entries or on process shutdown (whichever comes first). To ship it to a SIEM, tail the file or mount the config directory and read it directly — there is no syslog or stdout output of audit events.

## Credential audit (password health scan)

vault-proxy includes a built-in credential health scanner that detects weak, reused, and compromised passwords across vault items in your `vault_folder`. Three HTTP endpoints control it:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `POST /audit/credaudit/scan/start` | public | Start a new audit run. Returns `{"run_id": "..."}`. |
| `GET /audit/credaudit/review_pending/{run_id}` | public | Poll run status and retrieve flagged items awaiting review. Returns `{"status": "...", "items": [...]}`. |
| `POST /audit/credaudit/apply` | public | Apply approved rotation recommendations from the review. Body: `{"run_id": "...", "approvals": [...]}`. |

Results are persisted in `$CONFIG_DIR/credential_audit.sqlite`. The scanner runs pass-1 (local weak/reuse detection) immediately and schedules pass-2 (HaveIBeenPwned k-anonymity check) asynchronously. No plaintext passwords leave the proxy — only the first 5 characters of each SHA-1 hash are sent to the HIBP API per the k-anonymity protocol.

## Operator runbook

### vault-proxy won't start

Look for `STARTUP:` messages in the container log. Common causes:
- **`STARTUP: vault_folder 'X' was NOT FOUND in Vaultwarden`** — the folder name in `VAULT_FOLDER` doesn't match an existing Vaultwarden folder. Create the folder or correct the env var.
- **`failed to parse services.toml`** — TOML syntax error. Run `--check` to get a summary: `docker run --rm -v ./config:/config vaultproxy --check`
- **`keystore locked`** — run `--setup` or use the dashboard to unlock.

### `POST /proxy` returns 404 "unknown service"

The service name in your request doesn't match any entry in `services.toml`. Verify:
```bash
curl http://127.0.0.1:3201/vault/services
```
This returns the full list of registered services with their auth types and base URLs.

### Credentials stopped working (upstream returns 401/403)

The vault item may have changed in Vaultwarden. Force a re-sync:
```bash
curl -X POST http://127.0.0.1:3201/vault/resync
```
This re-fetches all vault items from Vaultwarden. For session-based services, the cached session token is invalidated on the next 401 and refreshed automatically.

### Added a service to services.toml but it's not found

Send SIGHUP to reload services.toml without restarting:
```bash
docker kill --signal=HUP <container_name>
```
Then check `vault/services` to confirm it loaded. If it's still missing, check the container log for a per-service rejection reason (SSRF violation, missing field, bad base_url, etc.).

### `--setup` hangs waiting for input

The setup wizard reads from stdin. If stdin is not a TTY (e.g. `docker run -d`), it will block forever. Run with `-it` to attach a TTY:
```bash
docker run --rm -it -v ./config:/config vaultproxy --setup
```

Or use the web dashboard (`--features dashboard`) to complete setup via browser.

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
