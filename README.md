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

### HTTP reload (alternative to SIGHUP)

If you prefer a synchronous HTTP trigger over sending a Unix signal, use:

```bash
TOKEN=$(cat ./config/internal-token)
curl -X POST http://127.0.0.1:3201/vault/reload-services \
  -H "Authorization: Bearer $TOKEN"
```

Returns JSON confirming the before/after service counts:

```json
{
  "ok": true,
  "prev_service_count": 3,
  "new_service_count": 4,
  "services": ["ha_home", "sonarr", "radarr", "plex"],
  "note": "services.toml reloaded synchronously; CA-cert clients rebuilt. ..."
}
```

Returns `409 Conflict` if the reload would drop to zero services (rollback safety, same as SIGHUP). Requires the internal bearer token (`Authorization: Bearer <token>` from `$CONFIG_DIR/internal-token`).

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
    # Build locally — see Dockerfile in the repo root.
    # A pre-built image (ghcr.io/aaronckj/vaultproxy:latest) is published
    # automatically on each version tag via the GitHub Actions CI workflow
    # (.github/workflows/docker-publish.yml).  If the image is not yet
    # available for your version, use `build: .` to build it from source.
    build: .
    # image: ghcr.io/aaronckj/vaultproxy:latest  # uncomment once CI has published
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

> **`/browser/rotate` — requires `playwright/agent.py`:** `POST /browser/rotate` drives a Playwright browser session to log into the target site and change the password. It requires `playwright/agent.py` to be present at `/app/playwright/agent.py`, `./playwright/agent.py` (relative to the working directory), or a custom path set via `PLAYWRIGHT_AGENT_PATH`. If the file is not found, the endpoint returns `501` with an actionable error message instead of silently succeeding and failing in the background. `LITELLM_URL` and `VISION_MODEL` must also be set — missing either returns a `400` before any browser is spawned.

> **`/rotate` endpoint — planned for a future release:** `POST /rotate` is defined and gated behind the internal token, but all rotation strategies (`sonarr`, `radarr`) currently return `501 Not Implemented`. The stub is present for API compatibility with planned v0.2 tooling. Do not build production workflows on this endpoint until a full strategy implementation is shipped.

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
| `--launch <name>` | — | — | Resolve credentials from Vaultwarden and exec the named MCP server (configured in `mcp-servers.toml`). Process is replaced — vault-proxy does not stay running. |
| `--proxy-timeout` | `PROXY_TIMEOUT` | `120` | Upstream request timeout (seconds) |
| `--dashboard-listen` | `DASHBOARD_LISTEN` | `127.0.0.1:3202` | Dashboard web UI listen address (only used with `--features dashboard`) |
| `--cloud-email` | `CLOUD_EMAIL` | — | Bitwarden cloud account email. When set, enables cloud sync (Bitwarden → Vaultwarden). |
| `--cloud-kdf-iterations` | `CLOUD_KDF_ITERATIONS` | — | Override KDF iterations for Bitwarden cloud prelogin (use only if the server returns the wrong value). |
| `--ntfy-url` | `NTFY_URL` | — | ntfy.sh topic URL for push alerts |
| `--notify-channel` | `NOTIFY_CHANNEL` | `disabled` | Notification channel: `"ntfy"`, `"email"`, or `"disabled"` |
| `--notify-email` | `NOTIFY_EMAIL` | — | Email address for notifications when `--notify-channel=email` (queued to `/config/notification-queue.json`). |
| `--litellm-url` | `LITELLM_URL` | — | LiteLLM base URL (browser rotation feature) |
| `--litellm-api-key` | `LITELLM_API_KEY` | — | LiteLLM Bearer API key. Prefer the env var over CLI — CLI args are visible in `/proc/<pid>/cmdline`. |
| `--vision-model` | `VISION_MODEL` | `""` | Vision model name served by LiteLLM (browser rotation feature). Must be set to the name of a vision-capable model in your LiteLLM deployment (e.g. `"gpt-4o"`). Empty = browser rotation disabled. |
| `--allow-root` | — | — | Suppress the root-user security warning (see below) |
| `--env-write-root` | `ENV_WRITE_ROOT` | — | Root directory that `POST /vault/write-env` is allowed to write into (e.g. `/envs`). Unset = endpoint returns 501. |
| `--vault-refresh-interval-secs` | `VAULT_REFRESH_INTERVAL_SECS` | `0` | Background vault refresh interval in seconds. When non-zero, spawns a task that calls `POST /vault/resync` semantics automatically every N seconds. Set to `300` for 5-minute auto-sync. `0` = disabled. Setting `VAULT_REFRESH_INTERVAL_SECS=""` (empty string) is an error and vault-proxy will exit with a parse error. |
| — | `VAULT_PROXY_PUBLIC_URL` | — | Public-facing URL injected as `VAULT_PROXY_URL` into MCP servers launched via `--launch`. Use this when vault-proxy sits behind a reverse proxy (nginx, Caddy, Traefik) that terminates TLS — e.g. `VAULT_PROXY_PUBLIC_URL=https://vault-proxy.example.com`. Must be a valid `http://` or `https://` URL without a trailing slash. Validated at startup and in `--check` mode. When unset, vault-proxy derives the URL from the `--listen` address. |
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

vault-proxy includes a built-in credential health scanner that detects weak, reused, and compromised passwords across vault items in your `vault_folder`. Four HTTP endpoints control it:

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /vault/audit/run` | internal bearer | In-process password health scan. Decrypts every vault password transiently, computes HMAC fingerprints with an ephemeral key, and returns weak/reused groupings. No plaintext passwords appear in the response. Rate-limited to 2 req/60 s (expensive — decrypts all vault passwords). |
| `POST /audit/credaudit/scan/start` | public | Start a new audit run against the engine sidecar. Returns `{"run_id": "..."}`. Returns `409` if a scan is already running; `503` if the engine sidecar is unreachable. |
| `GET /audit/credaudit/review_pending/{run_id}` | public | Poll run status and retrieve flagged items awaiting review. Returns `200 [...]` on success. Returns `404` with `{"error": "run_id '...' not found — no scan has been started with this ID"}` for an unknown `run_id`. |
| `POST /audit/credaudit/apply` | public | Apply approved rotation recommendations. Body: `{"run_id": "...", "dry_run": true, "item_ids": [...], "confirm_bulk": false}`. `dry_run` defaults to `true` — you must explicitly pass `"dry_run": false` to write changes. Returns `404` for an unknown `run_id`. Requires `confirm_bulk: true` when applying more than 50 items without explicit `item_ids`. |

Results from the engine-sidecar endpoints are persisted in `$CONFIG_DIR/credential_audit.sqlite`. The scanner runs pass-1 (local weak/reuse detection) immediately and schedules pass-2 (HaveIBeenPwned k-anonymity check) asynchronously. No plaintext passwords leave the proxy — only the first 5 characters of each SHA-1 hash are sent to the HIBP API per the k-anonymity protocol.

### In-process health scan (`GET /vault/audit/run`)

```bash
curl -H "Authorization: Bearer $(cat /config/internal-token)" \
     http://127.0.0.1:3201/vault/audit/run
```

Returns a JSON object:
```json
{
  "total_items": 42,
  "weak_passwords": [
    {"name": "My Service", "username": "admin", "item_type": "login", "password_strength": "weak"}
  ],
  "reused_passwords": [
    [
      {"name": "Site A", "username": "user@example.com", "item_type": "login", "password_strength": "fair"},
      {"name": "Site B", "username": "user@example.com", "item_type": "login", "password_strength": "fair"}
    ]
  ],
  "weak_threshold_len": 8
}
```

- `weak_passwords`: array of `AuditItem` objects whose password is shorter than `weak_threshold_len` characters (rule-based heuristic — not zxcvbn/HIBP). Each object has `name`, `username`, `item_type`, and `password_strength` (`"weak"`). Passwords scored `"fair"` (8–15 chars or lacking character-class diversity) are not surfaced here.
- `reused_passwords`: array of groups — each group is an array of two or more `AuditItem` objects that share the same password (detected via HMAC-SHA256 fingerprints with an ephemeral per-run key — no plaintext stored or returned).
- `weak_threshold_len`: the minimum password length (exclusive) used to classify passwords as "weak". Currently `8`. Included so callers can interpret results without reading source code — e.g. "27 weak passwords (threshold: len < 8)".
- All decryption is transient; the ephemeral HMAC key and all password buffers are zeroized immediately after use.
- Scoped to `vault_folder` — only items inside the configured folder are scanned.

> **Scan item cap and pagination:** `SCAN_ITEM_CAP = 1_000` — the scan is hard-capped at 1,000 items. If your `vault_folder` contains more than 1,000 items, only the first 1,000 (in vault list order) are scanned; items 1,001 onward are silently excluded. There is no pagination or offset support. A `WARN` log is emitted when the cap is hit. To audit all items beyond the cap, split credentials across multiple vault folders and point separate `--vault-folder` instances at each, or raise `SCAN_ITEM_CAP` in `src/credential_audit/vw_adapter.rs` and recompile.

### Complete credential audit workflow

**Step 1 — Start a scan:**
```bash
RUN_ID=$(curl -sX POST http://127.0.0.1:3201/audit/credaudit/scan/start | jq -r .run_id)
```

**Step 2 — Poll until items appear:**
```bash
curl http://127.0.0.1:3201/audit/credaudit/review_pending/$RUN_ID
```
Returns a JSON array of flagged items. Each entry includes `item_id`, `status` (e.g. `"dead"`, `"weak"`, `"duplicate"`), `reason`, and `pass` number. An empty array (`[]`) means the scan is still running or found nothing to flag — poll again in a few seconds if the scan was just started. A `404` means the `run_id` is unknown.

**Step 3 — Dry-run apply (preview only):**
```bash
curl -sX POST http://127.0.0.1:3201/audit/credaudit/apply \
  -H 'Content-Type: application/json' \
  -d '{"run_id": "'$RUN_ID'", "dry_run": true}'
```
Returns `{"applied": 0, "would_apply": N, "failed": 0}`. No vault changes are made.

**Step 4 — Apply to specific items (or all flagged items):**
```bash
# Apply to specific items only:
curl -sX POST http://127.0.0.1:3201/audit/credaudit/apply \
  -H 'Content-Type: application/json' \
  -d '{"run_id": "'$RUN_ID'", "dry_run": false, "item_ids": ["<id1>", "<id2>"]}'

# Apply to all flagged items (>50 items requires confirm_bulk: true):
curl -sX POST http://127.0.0.1:3201/audit/credaudit/apply \
  -H 'Content-Type: application/json' \
  -d '{"run_id": "'$RUN_ID'", "dry_run": false, "confirm_bulk": true}'
```
`apply` moves each flagged vault item into a Vaultwarden folder named `_review-delete` and appends an audit marker block to its notes field. The folder is created automatically if it does not exist. The `confirm_bulk: true` flag is required when applying to more than 50 items without specifying `item_ids`, as a safeguard against accidental bulk operations.

**Undo an apply:**
`apply` does not delete items — it only moves them. To undo, open Vaultwarden and move the items from `_review-delete` back to their original folder (or `No Folder`). The audit marker block in the notes field is inert and can be deleted manually if desired. There is no automated undo endpoint.

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

### MCP server launched with `--launch` exits immediately

Launcher mode (`--launch <name>`) resolves credentials from Vaultwarden and `exec`s the configured command, replacing the vault-proxy process. If the launched process exits immediately, check the logs for:

- **`WARN vault_proxy::launcher: command not found`** — the `command` in `mcp-servers.toml` is not on `PATH` or is misspelled. Verify with `which <command>` inside the container.
- **`WARN vault_proxy::launcher`** — any other launcher warning. Run with `RUST_LOG=debug` for detailed output.
- **`vault item '...' not found`** — the `vault_item` in `mcp-servers.toml` does not match an item name in Vaultwarden. Check for typos and confirm the item is in the correct `vault_folder`.
- **MCP server itself crashes** — the MCP server process exited non-zero. Its stdout/stderr appears in the container log immediately after the `vault-proxy` output. Check for missing dependencies (`pip install`, `npm install`, etc.).

```bash
# Check launcher logs
docker logs <container_name> 2>&1 | grep -E "launcher|WARN|ERROR"

# Validate mcp-servers.toml syntax (--check only validates services.toml; mcp-servers.toml has no --check flag)
docker run --rm -v ./config:/config vaultproxy --launch <name>  # run interactively to see errors
```

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

See `mcp-servers.example.toml` for all options. See `SECURITY.md` for the security tradeoffs between launcher mode and native `/proxy` integration.

### Smart servers and `--launch`

When a "smart" MCP server (one with native vault-proxy support) is launched via `--launch`, vault-proxy automatically injects `VAULT_PROXY_URL=http://127.0.0.1:3201` into the child's environment. The smart server uses this URL to call `POST $VAULT_PROXY_URL/proxy` — vault-proxy injects the credential internally and forwards the request. No vault items appear in the smart server's environment.

**Calling `/proxy` from a launched smart server:** This is the intended flow. The smart server calls `POST /proxy` with `{"service": "my_service", "method": "GET", "path": "/..."}` and vault-proxy resolves the credential, applies auth, and forwards to the downstream service. The corresponding `[[service]]` block must exist in `services.toml`.

**Calling `/vault/*` endpoints from a launched smart server:** Internal endpoints (`/vault/reload-services`, `/vault/connecterr-secrets`, `/rotate`, etc.) require the internal bearer token. If your smart server needs to call these endpoints, it must read `$CONFIG_DIR/internal-token` and include it as:

```
Authorization: Bearer <token>
```

The token file is written at vault-proxy startup (mode 0600, owner = vault-proxy process user). It is separate from all Vaultwarden credentials.

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
