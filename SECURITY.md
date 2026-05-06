# Security Policy

## Threat model

`vaultproxy` sits between your MCP servers and your downstream services. Its job is to hold credentials so your MCP servers don't have to.

**What it protects against:**
- Credentials in env vars or `.env` files readable by any same-user process
- Credentials appearing in MCP tool responses visible to AI agents
- Credentials in shell history or log files
- Stolen-disk recovery of credentials (with `--features tpm` — keystore is hardware-bound)
- SSRF via `services.toml`: link-local (169.254.0.0/16, fe80::/10), cloud-metadata (169.254.169.254, fd00:ec2::254), and loopback targets are rejected at registry load time across all 9 validated SSRF vectors
- Log injection via service names: ASCII control characters (including `\n`, `\r`, `\t`) in service names are rejected at load time
- Path traversal in `login_path`: `..` and `.` path segments are rejected at load time
- Arbitrary command execution in launcher mode: shell interpreters (bash, sh, python, node, etc.) are blocked as launch targets

**What it does NOT protect against:**
- A compromised process running as the same OS user on the same host — it can reach `127.0.0.1:3201` directly
- A compromised Vaultwarden instance
- Physical access without TPM — the software keystore can be brute-forced if the master password is weak

**Trust boundary:** The proxy trusts any caller that can reach `127.0.0.1:3201`. Network isolation (localhost-only bind) is the primary defense. **Do not expose port 3201 externally.**

## Proxy endpoint (`127.0.0.1:3201`)

- Listens on localhost only by default; a startup warning is logged when `--listen` is set to a non-loopback address
- DNS rebinding guard rejects requests with non-localhost `Host` headers
- Rate-limited: 60 requests per 60-second window
- No credential-based auth on the endpoint itself — the trust model is OS-level process isolation
- Internal endpoints (`/vault/connecterr-secrets`, `/vault/reload-services`, `/rotate`, `/browser/*`, `/vault/notes`) require `Authorization: Bearer <internal-token>`. The token is written to `$CONFIG_DIR/internal-token` (mode 0600) at startup and rotated on each restart.
- Auth-override headers (`Authorization`, `X-Api-Key`, `X-Plex-Token`, `Cookie`, `Host`, etc.) supplied by callers in `POST /proxy` requests are blocked — auth is always injected from the vault, never from the caller
- Duplicate query parameters that shadow keys already present in the service `base_url` are rejected
- Upstream response bodies are capped at 32 MB (configurable via `UPSTREAM_BODY_LIMIT_MB`) to prevent heap exhaustion from malicious upstreams

## Dashboard (`--features dashboard`, `127.0.0.1:3202`)

- Listens on localhost only by default
- Session-based auth with bcrypt password hashing
- Rate-limited login: 5 attempts per 5 minutes
- Never returns plaintext credentials — passwords masked as `"********"` in all API responses
- If exposed via a reverse proxy, place it behind strong forward authentication (e.g., Authentik)

## Vault folder scope guards

All 17 vault item handlers enforce that looked-up items belong to the configured `vault_folder`. A compromised or crafted request cannot read credentials from outside the designated folder, even if the attacker knows exact Vaultwarden item IDs. This prevents privilege escalation across vault folders in multi-tenant Vaultwarden instances.

## Two-tier security model

### Tier 1: Native `/proxy` integration (recommended)

MCP servers that support vault-proxy call `POST http://127.0.0.1:3201/proxy` at runtime. The credential is resolved inside vault-proxy, injected into the outbound HTTP request header, and **never exposed to the MCP server process**. The MCP server only sees the downstream service's response.

To detect vault-proxy, smart servers check the `VAULT_PROXY_URL` environment variable (automatically set when vault-proxy is running or when a server is launched via `--launch`).

If a smart server launched via `--launch` also needs to call vault-proxy's internal `/vault/*` endpoints (not `/proxy`), it must present the internal bearer token from `$CONFIG_DIR/internal-token`. This is a deliberate two-layer design: `/proxy` is open to any local caller (rate-limited); internal endpoints require the token.

### Tier 2: Launcher mode (`--launch`)

For MCP servers with no vault-proxy support ("dumb" servers), use:

```bash
vaultproxy --launch unifi-network
```

vault-proxy resolves credentials from Vaultwarden and spawns the server via fork/exec with credentials injected as environment variables. **No credential file is written to disk.**

**Known limitation:** credentials injected via fork/exec exist in the child process's memory space. On Linux, `/proc/<pid>/environ` allows any process running as the same OS user to read these values. This is weaker than Tier 1 but stronger than storing credentials in `.env` files (which persist on disk). vault-proxy logs a warning on every `--launch` invocation.

**Additional launcher hardening:**
- Shell interpreters (bash, sh, python, node, etc.) are blocked as launch targets — use a purpose-built binary
- Dynamic-linker control variables (`LD_PRELOAD`, `LD_LIBRARY_PATH`, etc.) in the `env` block trigger a startup warning
- Env var names are validated against `[A-Za-z_][A-Za-z0-9_]*` — `=` signs and null bytes are rejected
- Duplicate server names in `mcp-servers.toml` are warned at load time
- A per-server fcntl advisory lock prevents duplicate launches of the same server

For maximum security on sensitive services, prefer Tier 1 (native integration or a fork that adds vault-proxy support).

## Reporting vulnerabilities

Report security issues **privately** via [GitHub Security Advisories](../../security/advisories/new) on this repository. Do not open public issues for security vulnerabilities.

Please include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

We aim to respond within 48 hours and ship a fix within 14 days for confirmed critical issues.
