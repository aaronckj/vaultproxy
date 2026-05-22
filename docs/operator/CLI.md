# CLI reference

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `--listen` | — | `127.0.0.1:3201` | Proxy listen address |
| `--config-dir` | `CONFIG_DIR` | `/config` | Keystore + config directory |
| `--vault-folder` | `VAULT_FOLDER` | `vault-proxy` | Vaultwarden folder name |
| `--setup` | — | — | Run interactive setup wizard |
| `--check` | — | — | Validate `services.toml` (parse + SSRF rules) and exit. No Vaultwarden connection required. Exit 0 = ok. |
| `--launch <name>` | — | — | Resolve credentials from Vaultwarden and exec the named MCP server (configured in `mcp-servers.toml`). Process is replaced — vault-proxy does not stay running. See [LAUNCHER.md](LAUNCHER.md). |
| `--proxy-timeout` | `PROXY_TIMEOUT` | `120` | Upstream request timeout (seconds) |
| `--dashboard-listen` | `DASHBOARD_LISTEN` | `127.0.0.1:3202` | Dashboard web UI listen address (only used with `--features dashboard`) |
| `--persist-dashboard-cert` | `PERSIST_DASHBOARD_CERT` | — | Write the dashboard TLS cert to `{config_dir}/dashboard.crt` + `dashboard.key` on first run; reload on subsequent runs so the browser warning disappears after restart. |
| `--cloud-email` | `CLOUD_EMAIL` | — | Bitwarden cloud account email. When set, enables cloud sync (Bitwarden → Vaultwarden). |
| `--cloud-kdf-iterations` | `CLOUD_KDF_ITERATIONS` | — | Override KDF iterations for Bitwarden cloud prelogin (use only if the server returns the wrong value). |
| `--ntfy-url` | `NTFY_URL` | — | ntfy.sh topic URL for push alerts |
| `--notify-channel` | `NOTIFY_CHANNEL` | `disabled` | Notification channel: `"ntfy"`, `"email"`, or `"disabled"` |
| `--notify-email` | `NOTIFY_EMAIL` | — | Email address for notifications when `--notify-channel=email` (queued to `/config/notification-queue.json`). |
| `--litellm-url` | `LITELLM_URL` | — | LiteLLM base URL (browser rotation feature) |
| `--litellm-api-key` | `LITELLM_API_KEY` | — | LiteLLM Bearer API key. **Prefer the env var over CLI** — CLI args are visible in `/proc/<pid>/cmdline`. |
| `--vision-model` | `VISION_MODEL` | `""` | Vision model name served by LiteLLM (browser rotation feature). Must be set to the name of a vision-capable model in your LiteLLM deployment (e.g. `"gpt-4o"`). Empty = browser rotation disabled. |
| `--allow-root` | — | — | Suppress the root-user security warning (see below) |
| `--env-write-root` | `ENV_WRITE_ROOT` | — | Root directory that `POST /vault/write-env` is allowed to write into (e.g. `/envs`). Unset = endpoint returns 501. |
| `--vault-refresh-interval-secs` | `VAULT_REFRESH_INTERVAL_SECS` | `0` | Background vault refresh interval in seconds. When non-zero, spawns a task that calls `POST /vault/resync` semantics automatically every N seconds. Set to `300` for 5-minute auto-sync. `0` = disabled. Setting `VAULT_REFRESH_INTERVAL_SECS=""` (empty string) is an error and vault-proxy will exit with a parse error. |
| `--audit-interval-secs` | `AUDIT_INTERVAL_SECS` | `0` | Background credential-health audit interval in seconds. When non-zero, spawns a task that runs the same HMAC-fingerprint audit as `GET /vault/audit/run` every N seconds and logs a summary. Logs at `WARN` when weak or reused passwords are found; logs at `DEBUG` when all passwords are healthy (avoids log noise on clean vaults). Minimum recommended value is `60`; values below `60` trigger a startup warning. Set to `3600` for hourly audits. `0` = disabled. |
| — | `VAULT_PROXY_PUBLIC_URL` | — | Public-facing URL injected as `VAULT_PROXY_URL` into MCP servers launched via `--launch`. Use this when vault-proxy sits behind a reverse proxy (nginx, Caddy, Traefik) that terminates TLS — e.g. `VAULT_PROXY_PUBLIC_URL=https://vault-proxy.example.com`. Must be a valid `http://` or `https://` URL without a trailing slash. Validated at startup and in `--check` mode. When unset, vault-proxy derives the URL from the `--listen` address. |
| — | `UPSTREAM_BODY_LIMIT_MB` | `32` | Max upstream response body to buffer (MB) |

## `--allow-root`

vault-proxy logs a `SECURITY:` warning when it starts as uid 0 (root) because a credential broker running as root grants full system access if compromised. Pass `--allow-root` only when root is genuinely required — for example, when accessing `/dev/tpm0` on systems without udev rules that permit non-root TPM access. Prefer a dedicated non-root user in all other cases (e.g. `--user vaultproxy:vaultproxy` in Docker Compose).
