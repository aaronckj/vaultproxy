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
- Prompt injection via browser vision pipeline: LLM responses from the vision model (MLbox/Qwen3-VL) are sanitised by `sanitize_output` before JSON parsing — adversarial text embedded in web page screenshots cannot reach downstream tool decisions

**What it does NOT protect against:**
- A compromised process running as the same OS user on the same host — it can reach `127.0.0.1:3201` directly
- A compromised Vaultwarden instance
- Physical access without TPM — the software keystore can be brute-forced if the master password is weak

**Trust boundary:** The proxy trusts any caller that can reach `127.0.0.1:3201`. Network isolation (localhost-only bind) is the primary defense. **Do not expose port 3201 externally.**

## Proxy endpoint (`127.0.0.1:3201`)

- Listens on localhost only by default; a startup warning is logged when `--listen` is set to a non-loopback address
- DNS rebinding guard rejects requests with non-localhost `Host` headers
- Rate-limited: 60 requests per 60-second window per caller (see per-caller rate limiting below)
- Destructive endpoints (`/vault/items/delete`, `/vault/items/update`, `/vault/folders/delete`) are tighter: 10 req/60 s per caller
- Credential audit endpoint (`/vault/audit/run`) decrypts every vault password for HMAC fingerprinting — capped at 2 req/60 s per caller to prevent decrypt-loop DoS
- No credential-based auth on the endpoint itself — the trust model is OS-level process isolation
- Internal endpoints (`/vault/connecterr-secrets`, `/vault/reload-services`, `/rotate`, `/browser/*`, `/vault/notes`) require `Authorization: Bearer <internal-token>`. The token is written to `$CONFIG_DIR/internal-token` (mode 0600) at startup and rotated on each restart.
- Auth-override headers (`Authorization`, `X-Api-Key`, `X-Plex-Token`, `Cookie`, `Host`, etc.) supplied by callers in `POST /proxy` requests are blocked — auth is always injected from the vault, never from the caller
- Duplicate query parameters that shadow keys already present in the service `base_url` are rejected
- Upstream response bodies are capped at 32 MB (configurable via `UPSTREAM_BODY_LIMIT_MB`) to prevent heap exhaustion from malicious upstreams
- HTTP/1 header-read timeout of 5 seconds is set on every connection to prevent slowloris-style resource exhaustion

## Per-caller rate limiting (`X-Caller-Id` / `VAULT_PROXY_CALLER_ID`)

All MCP servers sharing `127.0.0.1` would otherwise share a single rate-limit bucket. vault-proxy supports per-caller isolation:

- Callers set `X-Caller-Id: <name>` on every request. When present and valid ASCII, this header value is used as the bucket key — each MCP server gets its own independent budget.
- When `--launch <server-name>` is used, vault-proxy automatically injects `VAULT_PROXY_CALLER_ID=<server-name>` into the child process's environment. Smart servers forward this as `X-Caller-Id`.
- `X-Caller-Id` is **not authenticated** — it is a cooperative declaration. Any local process can set any value. This is intentional: in the loopback threat model, IP address and header value are equally controllable by any local process. If vault-proxy is ever exposed beyond `127.0.0.1` (strongly discouraged), `X-Caller-Id` would need to be derived from the authenticated bearer token.
- Values are truncated to 64 bytes and must be printable ASCII (0x20–0x7E). Values containing `=` are valid (server names like `"prod=main"` are a legitimate operator convention; `=` is the name/value delimiter only in the env entry, not in the value itself).

## Dashboard (`--features dashboard`, `127.0.0.1:3202`)

- Listens on localhost only by default
- Session-based auth with bcrypt password hashing
- Rate-limited login: 5 attempts per 5 minutes
- Never returns plaintext credentials — passwords masked as `"********"` in all API responses
- If exposed via a reverse proxy, place it behind strong forward authentication (e.g., Authentik)

## Browser rotation subsystem (`--features browser`)

- Routes: `POST /browser/rotate`, `POST /browser/rotate` (all gated behind internal bearer token)
- Vision model (LiteLLM/Qwen3-VL via MLbox) receives base64 PNG screenshots and returns JSON action descriptors
- LLM responses are sanitised by `sanitize_output` **before** JSON parsing — injection phrases, `<tool_call>` tags, and LLM control tokens are replaced with `[FILTERED]` before any field value can influence Playwright selectors or downstream tool calls
- Screenshots and LLM calls never leave the homelab network (all traffic goes to `LITELLM_URL`, which should be the local MLbox endpoint)

## Vault folder scope guards

All vault item handlers enforce that looked-up items belong to the configured `vault_folder`. A compromised or crafted request cannot read credentials from outside the designated folder, even if the attacker knows exact Vaultwarden item IDs. This prevents privilege escalation across vault folders in multi-tenant Vaultwarden instances.

The `vault_folder` → folder ID resolution is cached after the first successful lookup (double-checked locking in `resolve_vault_folder_id`). The cache is invalidated by `POST /vault/resync`. If the folder does not exist in the vault, `None` is returned without caching — every subsequent request re-scans until the folder is created, at which point the cache is populated automatically.

### Folder rename / not-found behavior

If `--vault-folder` no longer matches any folder in the vault (e.g. the folder was renamed in Vaultwarden without updating `--vault-folder`), `resolve_vault_folder_id` returns `None`. The consequence depends on the handler type:

- **`list_items`** — returns an **empty list** (iter-99). The previous permissive fallback (return-all) leaked cross-folder metadata (names, usernames, URIs from personal banking, SSH-key, and other personal folders) when `vault_folder` was configured but not found. An empty result is safe and the warn! log tells the operator what to do. Other read-only listing endpoints (`list_duplicates`, `list_untracked`) retain the permissive-with-warn behavior.
- **Read-only handlers** (`list_duplicates`, `generate_totp`, `decrypt_notes`, `inject_creds`, etc.) — fall through **permissively** (warn! emitted; request proceeds). First-run tooling on a fresh vault where the folder does not yet exist continues to work without operator intervention.
- **Write/destructive handlers** (`write_env`) — **block with 503 Service Unavailable** and emit `{"ok": false, "error": "..."}`. Writing plaintext credentials to disk without folder-scope verification would allow any vault item UUID (including personal entries outside `vault_folder`) to be exfiltrated to disk. Blocking is the correct posture here.
- **Self-protection guard** (`delete_folder`) — falls through **permissively** but emits warn! so operators see that the guard is disabled. The folder cannot be identified as the vault-proxy folder when `None` is returned, so the deletion proceeds unblocked — this is logged explicitly.

In all cases, the remediation is: verify `--vault-folder` matches the Vaultwarden folder name, then call `POST /vault/resync`.

The item membership check (`item_in_vault_folder`) is cache-aware: it calls `resolve_vault_folder_id` (O(1) after first lookup) and then checks the item's `folder_id` field directly — no per-call folder-name scan.

## Two-tier security model

### Tier 1: Native `/proxy` integration (recommended)

MCP servers that support vault-proxy call `POST http://127.0.0.1:3201/proxy` at runtime. The credential is resolved inside vault-proxy, injected into the outbound HTTP request header, and **never exposed to the MCP server process**. The MCP server only sees the downstream service's response.

To detect vault-proxy, smart servers check the `VAULT_PROXY_URL` environment variable (automatically set when vault-proxy is running or when a server is launched via `--launch`). They should also read `VAULT_PROXY_CALLER_ID` and forward it as `X-Caller-Id` to receive an isolated rate-limit budget.

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
- Env var names are validated against `[A-Za-z_][A-Za-z0-9_]*` — null bytes and newlines are rejected (null truncates the C-string value; newlines enable env-file injection). `=` signs in the server name (used as the `VAULT_PROXY_CALLER_ID` value, not the name) are allowed — a POSIX env entry `VAULT_PROXY_CALLER_ID=prod=main` is valid; the first `=` delimits name from value.
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
