# mcp-vault-proxy

A secure credential sidecar for [MCP](https://modelcontextprotocol.io) servers.

Most MCP servers store credentials in env vars or `.env` files — readable by any process running as the same user, present in shell history, and scattered across every server you run. `mcp-vault-proxy` solves this: it reads credentials from your self-hosted [Vaultwarden](https://github.com/dani-garcia/vaultwarden) instance, injects the right auth header for each downstream service, and **never exposes plaintext secrets to the MCP layer**.

## How it works

```
Claude Code → MCP Server → mcp-vault-proxy (127.0.0.1:3201) → Your Service
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
| `X-Api-Key` header | UniFi, Plex |
| `Authorization: Bearer` | Home Assistant |
| HTTP Basic | OPNsense |
| Session (POST login → cookie) | Nginx Proxy Manager, Duplicati |
| UniFi dual (API key → session fallback) | UniFi OS |
| Query param | Tautulli |

## Security model

- The proxy listens on `127.0.0.1:3201` only — network isolation is the primary guarantee
- DNS rebinding guard on all `/proxy` requests
- Rate limit: 60 req/60s on `/proxy`
- Credentials are decrypted in-process from an encrypted keystore; plaintext values never appear in logs
- Optional TPM sealing: keystore is hardware-bound to the host machine (`--features tpm`)
- Dashboard (optional, `--features dashboard`) listens on `127.0.0.1:3202` only

## Vault item naming

Create a folder in Vaultwarden named `vault-proxy` (or your `--vault-folder` value). Add items inside it named:

```
vault-proxy - Home Assistant       ← password field holds the Bearer token
vault-proxy - UniFi                ← password field holds the API key
vault-proxy - OPNsense             ← custom fields: key, secret
vault-proxy - Nginx Proxy Manager  ← username + password
vault-proxy - Tautulli             ← password field holds the API key
vault-proxy - Plex                 ← password field holds the X-Plex-Token
vault-proxy - Sonarr               ← password field holds the API key
vault-proxy - Radarr               ← password field holds the API key
vault-proxy - Overseerr            ← password field holds the API key
```

## Quickstart (Docker Compose)

```yaml
services:
  mcp-vault-proxy:
    image: ghcr.io/ajarratt/mcp-vault-proxy:latest
    restart: unless-stopped
    network_mode: host
    volumes:
      - ./config:/config
    environment:
      VAULT_FOLDER: vault-proxy
    command: ["--setup"]   # Remove after first-run setup completes
```

Run `docker compose up` with `--setup` to configure. The wizard prompts for your Vaultwarden URL, email, and master password. Credentials are stored encrypted in `/config/`. Restart without `--setup` for normal operation.

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

## `/proxy` API

`POST http://127.0.0.1:3201/proxy`

Request body:
```json
{
  "service": "ha_home",
  "method": "POST",
  "path": "/api/services/light/turn_on",
  "body": { "entity_id": "light.living_room" },
  "headers": {},
  "query": {}
}
```

The `service` name must match a registered service in your Vaultwarden folder. The proxy injects auth and returns the upstream HTTP status + body.

## Why not just use env vars?

Env vars are readable by any process running as the same OS user, show up in `ps auxe`, persist in shell history, and end up copy-pasted across multiple `.env` files. `mcp-vault-proxy` keeps credentials in a single encrypted keystore backed by Vaultwarden — one source of truth, never in plaintext outside the proxy process.

## License

MIT
