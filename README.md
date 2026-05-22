# vaultproxy

**Secure credential sidecar for MCP servers — backed by [Vaultwarden](https://github.com/dani-garcia/vaultwarden).**

Stop pasting API keys into `.env` files. `vaultproxy` reads credentials from your self-hosted Vaultwarden, injects the right auth header for each downstream service, and **never exposes plaintext secrets to the MCP layer or the AI agent**.

```
Claude Code → MCP Server → vaultproxy (127.0.0.1:3201) → Your Service
                                     ↑
                               Vaultwarden (credentials stay here)
```

---

## Why vaultproxy

Most MCP servers store credentials in env vars or `.env` files. These are readable by any process running as the same user, leak into shell history and `ps auxe`, and end up duplicated across every server you run. The AI agent driving your MCP server can also see them in tool responses.

vaultproxy fixes this with a small loopback HTTP service that:

- Reads every credential from one place — your Vaultwarden folder.
- Injects the correct auth pattern per service (`X-Api-Key`, Bearer, Basic, session cookie, UniFi dual-mode, query param).
- Keeps secrets out of the MCP server's address space entirely (native `/proxy` mode), or at worst out of disk (launcher mode).
- Detects weak / reused / pwned credentials, and (optionally) rotates them automatically via a Playwright + vision-LLM agent.

### How it compares

| | **vaultproxy** | [agent-vault](https://github.com/Infisical/agent-vault) | [wirken](https://github.com/gebruder/wirken) | [OneCLI](https://sesamedisk.com/onecli-vault-ai-agents-rust/) | [warden-mcp](https://github.com/icoretech/warden-mcp) etc. |
|---|---|---|---|---|---|
| Backend | **Vaultwarden** | Infisical | own vault + OS keychain | own encrypted file | Vaultwarden (as vault tool) |
| Hides credentials from AI | ✅ | ✅ | ✅ | ✅ | ❌ exposes vault to AI |
| Auth patterns built-in | bearer, header, basic, session, query, UniFi dual | bearer | bearer | bearer | n/a |
| Hot-reload (SIGHUP + HTTP) | ✅ | ❌ | ❌ | ❌ | ❌ |
| Credential audit (weak/reused/HIBP) | ✅ | ❌ | ❌ | ❌ | ❌ |
| Auto credential rotation | ✅ Playwright + vision LLM | ❌ | ❌ | ❌ | ❌ |
| TPM sealing | ✅ optional | ❌ | ❌ | ❌ | ❌ |
| Dual integration: smart `/proxy` + dumb `--launch` | ✅ | proxy only | proxy only | proxy only | n/a |
| Language / binary | Rust, single static binary | Go | Rust | Rust | TS / shells `bw` |

vaultproxy is opinionated for the **selfhost / homelab** crowd — *arr stack, Home Assistant, OPNsense, UniFi, Plex, Tautulli, Nginx Proxy Manager. Other brokers assume HashiCorp Vault / Infisical / Conjur backends and target generic API providers (Anthropic, GitHub, Stripe).

---

## Quickstart (Docker Compose)

**1. Create a `vault-proxy` folder in Vaultwarden** and add one item per downstream service. The password field holds the credential (API key, Bearer token, etc.).

**2. Create `services.toml`** in a local `./config/` directory:

```toml
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
```

Full example: [`services.example.toml`](services.example.toml).

**3. Run the setup wizard once** to unlock Vaultwarden:

```yaml
# docker-compose.yml
services:
  vaultproxy:
    image: ghcr.io/aaronckj/vaultproxy:latest   # or pin to a tag, e.g. :1.0.4
    restart: unless-stopped
    network_mode: host
    volumes:
      - ./config:/config
    environment:
      VAULT_FOLDER: vault-proxy
    command: ["--setup"]   # remove after first run
```

```bash
docker compose up                 # interactive setup
# remove `command: ["--setup"]`
docker compose up -d              # run for real
curl http://127.0.0.1:3201/vault/health
```

**4. Use it from an MCP server:**

```bash
curl -X POST http://127.0.0.1:3201/proxy \
  -H 'Content-Type: application/json' \
  -d '{"service":"ha_home","method":"GET","path":"/api/states"}'
```

The credential never appears in your shell, the MCP server, or the response.

Working MCP server examples (TypeScript, Python, Rust): [`examples/`](examples/).

---

## Auth patterns

| `auth` value | Required fields | Example service |
|---|---|---|
| `bearer` | — | Home Assistant |
| `header` | `header_name` | Sonarr / Radarr / Plex |
| `query_param` | `param_name` | Tautulli |
| `basic` | `key_field`, `secret_field` | OPNsense |
| `session` | `login_path`, `token_field` | Nginx Proxy Manager, Duplicati |
| `unifi_dual` | `login_path` | UniFi OS (API key → session fallback) |

Add `insecure_tls = true` for LAN services with self-signed certs (logs a startup warning).

---

## Two integration modes

1. **Native `/proxy` (Tier 1, recommended).** Your MCP server detects vault-proxy via `VAULT_PROXY_URL` env and calls `POST $VAULT_PROXY_URL/proxy`. The credential resolves inside vault-proxy and is injected into the outbound header. The MCP server never holds the secret. See [`examples/smart-mcp-server-*`](examples/).

2. **Launcher mode `--launch` (Tier 2).** For unmodified upstream MCP servers, vault-proxy resolves credentials from Vaultwarden and `exec`s the MCP server with credentials injected as env vars. No `.env` files on disk. Weaker than Tier 1 (env vars are readable from `/proc/<pid>/environ` by the same OS user) but stronger than file-based storage. Configure in [`mcp-servers.example.toml`](mcp-servers.example.toml).

---

## Feature highlights

| Feature | Status | Where |
|---|---|---|
| 6 built-in auth patterns | ✅ stable | this README |
| SIGHUP + `POST /vault/reload-services` hot-reload with atomic swap and rollback-to-empty guard | ✅ stable | [docs/operator/RELOAD.md](docs/operator/RELOAD.md) |
| Per-caller rate limiting via `X-Caller-Id` / `VAULT_PROXY_CALLER_ID` | ✅ stable | [SECURITY.md](SECURITY.md) |
| Credential audit (weak/reused + HIBP k-anonymity) | ✅ stable | [docs/operator/CRED-AUDIT.md](docs/operator/CRED-AUDIT.md) |
| Browser-driven credential rotation (Playwright + vision LLM) | ✅ `--features browser` | [docs/operator/BROWSER-ROTATION.md](docs/operator/BROWSER-ROTATION.md) |
| TPM-sealed keystore | ✅ `--features tpm` | [SECURITY.md](SECURITY.md) |
| Web dashboard | ✅ `--features dashboard` (127.0.0.1:3202) | [docs/operator/DASHBOARD.md](docs/operator/DASHBOARD.md) |
| Audit log (JSON, sensitive fields masked, 1000-entry cap) | ✅ stable | [docs/operator/AUDIT-LOG.md](docs/operator/AUDIT-LOG.md) |
| SMB mount provisioning via vault items | ✅ stable | [docs/SMB.md](docs/SMB.md) |

Planned for v1.1+: transparent `HTTPS_PROXY` mode, mTLS / Unix-socket listener, OAuth flows, response prompt-injection sanitisation, SIEM audit sinks, generic `/rotate` strategies. See [docs/ROADMAP.md](docs/ROADMAP.md).

---

## Security stance (one-paragraph version)

vaultproxy binds to `127.0.0.1:3201` only. The trust model is **OS-level process isolation** — any local process running as the same user can call `/proxy`. There is no mTLS or caller authentication on the proxy endpoint by design (network isolation is the primary defence; a startup warning fires on any non-loopback bind). Internal endpoints (`/vault/connecterr-secrets`, `/vault/reload-services`, `/browser/*`, `/vault/notes`) require an `Authorization: Bearer <internal-token>` from `$CONFIG_DIR/internal-token` (mode 0600, rotated on every restart). Credentials are decrypted in-process from an encrypted keystore; plaintext never appears in logs. Optional TPM sealing binds the keystore to the host machine. SSRF, log-injection, path-traversal, and arbitrary-command launcher guards are enforced at config load. Full threat model: [SECURITY.md](SECURITY.md). Report vulnerabilities privately via [GitHub Security Advisories](../../security/advisories/new).

---

## Install

### Docker (recommended)

```bash
docker build -t vaultproxy:latest .                                    # headless, default
docker build --build-arg FEATURES=dashboard -t vaultproxy:dashboard .  # + web UI
docker build --build-arg FEATURES=dashboard,browser,engine -t vaultproxy:full .
```

A pre-built image is published to `ghcr.io/aaronckj/vaultproxy` via the GitHub Actions workflow on every tagged release.

### Cargo (bare metal)

```bash
cargo build --release                          # headless
cargo build --release --features tpm           # + TPM sealing (needs libtss2-dev)
cargo build --release --features dashboard     # + web UI on 127.0.0.1:3202
cargo build --release --features browser       # + Playwright rotation (needs LiteLLM + Playwright)
```

---

## Deeper docs

- [SECURITY.md](SECURITY.md) — threat model, trust boundaries, rate limits, per-folder scope guards
- [docs/operator/QUICKSTART.md](docs/operator/QUICKSTART.md) — fuller setup walkthrough
- [docs/operator/CONFIG.md](docs/operator/CONFIG.md) — `services.toml` reference, vault items, internal token
- [docs/operator/CLI.md](docs/operator/CLI.md) — every CLI flag and env var
- [docs/operator/RELOAD.md](docs/operator/RELOAD.md) — SIGHUP and `POST /vault/reload-services` semantics
- [docs/operator/RUNBOOK.md](docs/operator/RUNBOOK.md) — diagnosing common failures
- [docs/operator/CRED-AUDIT.md](docs/operator/CRED-AUDIT.md) — weak/reused/HIBP scan + apply workflow
- [docs/operator/AUDIT-LOG.md](docs/operator/AUDIT-LOG.md) — audit log format and shipping
- [docs/operator/BROWSER-ROTATION.md](docs/operator/BROWSER-ROTATION.md) — rotation via Playwright + vision LLM
- [docs/operator/LAUNCHER.md](docs/operator/LAUNCHER.md) — `--launch` mode and `mcp-servers.toml`
- [docs/operator/DASHBOARD.md](docs/operator/DASHBOARD.md) — web UI, TLS cert persistence
- [docs/operator/UPGRADING.md](docs/operator/UPGRADING.md) — v0.2.x → v1.0.x breaking changes
- [docs/ROADMAP.md](docs/ROADMAP.md) — what's planned for v1.1+
- [GAPS.md](GAPS.md) — competitive landscape and pre-release tracking

---

## License

MIT. See [LICENSE](LICENSE).
