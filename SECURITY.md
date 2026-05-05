# Security Policy

## Threat model

`mcp-vault-proxy` sits between your MCP servers and your downstream services. Its job is to hold credentials so your MCP servers don't have to.

**What it protects against:**
- Credentials in env vars or `.env` files readable by any same-user process
- Credentials appearing in MCP tool responses visible to AI agents
- Credentials in shell history or log files
- Stolen-disk recovery of credentials (with `--features tpm` — keystore is hardware-bound)

**What it does NOT protect against:**
- A compromised process running as the same OS user on the same host — it can reach `127.0.0.1:3201` directly
- A compromised Vaultwarden instance
- Physical access without TPM — the software keystore can be brute-forced if the master password is weak

**Trust boundary:** The proxy trusts any caller that can reach `127.0.0.1:3201`. Network isolation (localhost-only bind) is the primary defense. **Do not expose port 3201 externally.**

## Proxy endpoint (`127.0.0.1:3201`)

- Listens on localhost only by default
- DNS rebinding guard rejects requests with non-localhost `Host` headers
- Rate-limited: 60 requests per 60-second window
- No credential-based auth on the endpoint itself — the trust model is OS-level process isolation

## Dashboard (`--features dashboard`, `127.0.0.1:3202`)

- Listens on localhost only by default
- Session-based auth with bcrypt password hashing
- Rate-limited login: 5 attempts per 5 minutes
- Never returns plaintext credentials — passwords masked as `"********"` in all API responses
- If exposed via a reverse proxy, place it behind strong forward authentication (e.g., Authentik)

## Two-tier security model

### Tier 1: Native `/proxy` integration (recommended)

MCP servers that support vault-proxy call `POST http://127.0.0.1:3201/proxy` at runtime. The credential is resolved inside vault-proxy, injected into the outbound HTTP request header, and **never exposed to the MCP server process**. The MCP server only sees the downstream service's response.

To detect vault-proxy, smart servers check the `VAULT_PROXY_URL` environment variable (set to `http://127.0.0.1:3201` when vault-proxy is running).

### Tier 2: Launcher mode (`--launch`)

For MCP servers with no vault-proxy support ("dumb" servers), use:

```bash
vault-proxy --launch unifi-network
```

vault-proxy resolves credentials from Vaultwarden and spawns the server via fork/exec with credentials injected as environment variables. **No credential file is written to disk.**

**Known limitation:** credentials injected via fork/exec exist in the child process's memory space. On Linux, `/proc/<pid>/environ` allows any process running as the same OS user to read these values. This is weaker than Tier 1 but stronger than storing credentials in `.env` files (which persist on disk).

For maximum security on sensitive services, prefer Tier 1 (native integration or a fork that adds vault-proxy support).

## Reporting vulnerabilities

Report security issues **privately** via [GitHub Security Advisories](../../security/advisories/new) on this repository. Do not open public issues for security vulnerabilities.

Please include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

We aim to respond within 48 hours and ship a fix within 14 days for confirmed critical issues.
