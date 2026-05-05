# Changelog

All notable changes to vaultproxy are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased] — security hardening (iterations 1–14)

The v0.1.0 release tag reflects the initial public scaffold. Since that
tag, the codebase has gone through 14 focused security and reliability
audit passes totalling 118+ individual fixes. The items below are
representative; they are NOT all included in the v0.1.0 release artifact.

Users building from source or pulling a `latest` image get all fixes.
Users on the v0.1.0 tagged release should upgrade.

### Security fixes (iterations 11–14)

- **VaultManager HTTP client had no timeout (iter-14)**: `VaultManager::new()`
  built its reqwest client without a timeout, causing `--setup` validation and
  re-auth to hang indefinitely if Vaultwarden was unreachable (typo in URL, VW
  down). A 30-second connect+read timeout is now applied.

- **service name / vault_item whitespace not trimmed (iter-14)**: a services.toml
  entry like `name = "  ha_home  "` was registered with leading/trailing spaces,
  making the service silently unreachable (callers always send `{"service":"ha_home"}`
  without spaces). Both `name` and `vault_item` are now trimmed at load time and
  a warning is logged for config entries that needed trimming.

- **README security model claimed loopback-only listen without caveat (iter-14)**:
  the README stated "listens on 127.0.0.1:3201 only" without noting that `--listen`
  can override this to a non-loopback address, removing the primary access control.
  The security model section now prominently warns about non-loopback `--listen`
  usage and matches the runtime warning already logged by `main.rs`.

- **SSRF setup URL not validated (iter-13)**: the `validate_vaultwarden_creds`
  function in `setup.rs` called `VaultManager::new()` with the operator-supplied
  URL before checking it. A crafted setup URL could reach cloud-metadata endpoints.
  The URL now passes through `is_allowed_outbound_url()` before any network call.

- **Non-loopback --listen startup warning (iter-13)**: binding vault-proxy to
  `0.0.0.0` or any non-loopback address without authentication middleware exposes
  all endpoints to the local network. A prominent `SECURITY:` log entry is now
  emitted at startup in this case.

- **Scheme-less base_url emits actionable error (iter-13)**: a `base_url` without
  an `http://` or `https://` prefix (e.g. `homeassistant.local:8123`) was
  previously rejected with a generic SSRF error message. The message now
  explicitly suggests adding the scheme.

- **Duplicate mcp_server names logged at load time (iter-12)**: duplicate entries
  in `mcp-servers.toml` (where only the first match is used) now log a warning,
  making the silently-unreachable second entry visible.

- **`mcp_server` command not found emits actionable error (iter-12)**: an
  `ENOENT` (command not found) spawn failure now names the missing binary and
  shows the inherited `PATH`, distinguishing it from permission-denied failures.

- **Setup password minimum raised to 12 characters (iter-11)**: the previous
  8-character minimum was below the bcrypt offline-crack threshold. The new 12-char
  minimum with ≥2 character classes applies to both CLI and web setup flows.

- **Non-TTY stdin in `--setup` yields actionable error (iter-11)**: when stdin is
  not a TTY (Docker without `-t`, CI pipelines), `rpassword` returns a cryptic
  "not a tty" error. The error is now mapped to a clear message explaining how to
  allocate a pseudo-TTY or use the web setup flow instead.

- **Userinfo in base_url rejected (iter-11)**: a `base_url` containing embedded
  credentials (e.g. `http://user:pass@host/`) was accepted and the credentials
  would appear in logs. Such URLs are now rejected at registry load time.

### Security fixes (iterations 1–10)

- **SSRF via redirect following (iter-10)**: reqwest clients now set
  `redirect::Policy::none()`. Previously a malicious upstream could return
  a 301 to `http://127.0.0.1:3201/vault/items` and vault-proxy would follow
  it, bypassing the SSRF guard that only runs at registration time.

- **Log injection via control chars in service names (iter-10)**: service
  names containing ASCII control characters (tab, newline, CRLF) are now
  rejected at services.toml parse time, preventing log-injection attacks.

- **CONNECT/TRACE methods blocked (iter-5)**: only `GET`, `POST`, `PUT`,
  `PATCH`, `DELETE`, `HEAD`, `OPTIONS` are forwarded. `CONNECT` would allow
  arbitrary TCP tunnelling; `TRACE` would reflect auth headers in the body.

- **Path traversal in proxy paths (iter-5)**: paths containing `..` or `.`
  segments are rejected before URL construction.

- **Auth-override header injection (iter-7)**: caller-supplied headers that
  shadow `Authorization`, `X-Api-Key`, `Cookie`, etc. are blocked.

- **Query-key credential override (iter-4)**: caller-supplied query keys that
  conflict with keys already in the service base_url are rejected.

- **DNS rebinding guard (iter-4)**: all requests with non-localhost Host
  headers return 403.

- **SSRF via services.toml base_url (iter-5)**: `base_url` values pointing
  at cloud metadata endpoints (169.254.169.254, fd00:ec2::254, etc.) or
  link-local ranges are rejected at registry load time.

- **Empty session tokens cached (iter-4)**: empty `token_field` values from
  login responses are rejected; previously they cached an empty token and
  every subsequent call paid an extra login round-trip.

- **Duplicate service names (iter-4)**: duplicate `[[service]]` blocks in
  services.toml now log a warning (last-write-wins); previously the second
  registration silently replaced the first.

- **Null-byte / empty service names and vault_item names (iter-4/5)**: both
  are now rejected at parse time with clear error messages.

- **PROXY_TIMEOUT=0 silently accepted (iter-9)**: vault-proxy now refuses to
  start with a zero-second proxy timeout; a 1-second minimum is enforced.

- **Overwrite-confirmation for --setup on existing keystore (iter-3)**: the
  wizard now requires typing `overwrite` before destroying an existing
  keystore.

- **Graceful shutdown on SIGTERM (iter-5)**: axum drains in-flight requests
  before exiting, preventing credential mid-write corruption on Docker stop.

- **mTLS cert ephemeral by design (iter-5)**: dashboard TLS certs are
  regenerated every restart (no stale key material on disk).

- **Session token TTL (iter-4)**: cached session tokens expire after 15
  minutes to bound the replay window.

- **Session token cache cap (iter-4)**: the session_tokens cache is capped
  at 512 entries with LRU eviction to prevent unbounded memory growth.

- **Symlink rejection in safe_write_config (iter-3)**: atomic writes refuse
  to follow symlinks, preventing a TOCTOU symlink swap during setup.

- **Rate limiting on all endpoints (iter-6)**: 60 req/60s token-bucket per
  source IP covers all routes including `/vault/resync`.

### Reliability fixes

- **Vault item keyed by cipher id (iter-7)**: duplicate item names no longer
  collapse — both entries are preserved, mirroring actual Vaultwarden state.

- **Exponential backoff on WebSocket reconnect (iter-8)**: previously a flat
  5-second retry hammered the Bitwarden notifications service at 12/min
  during outages. Now backs off 5s → 300s with jitter.

- **Timeout distinguishable from other upstream errors (iter-5)**: reqwest
  timeout returns HTTP 504 (Gateway Timeout) instead of 502 (Bad Gateway).

- **Soft-delete vs. hard-delete (iter-9)**: `DELETE /vault/items/delete` now
  uses Vaultwarden's `PUT /api/ciphers/{id}/delete` (soft-delete, 30-day
  trash) instead of `DELETE /api/ciphers/{id}` (irrecoverable hard-delete).

- **login_path / token_field empty string (iter-8)**: both are rejected at
  parse time for session auth services; previously they produced confusing
  502/400 errors at first proxy call.

- **--config-dir auto-creation (iter-10)**: if the specified config directory
  does not exist, vault-proxy creates it on startup with a clear log message
  instead of failing with an obscure OS error deep in the setup flow.

### Known limitations

- **Vault cache staleness**: vault items are loaded once at startup and are
  only refreshed when `POST /vault/resync` is called. Updates made in
  Vaultwarden after startup are not automatically picked up.

- **/vault/resync rate limit**: the global 60 req/60s rate limiter covers
  this endpoint, but there is no per-endpoint cooldown. An MCP client could
  trigger up to 60 full vault syncs per minute.

- **RSA Marvin Attack (RUSTSEC-2023-0071)**: the `rsa` 0.9 crate used for
  Bitwarden type-4 cipher-string decryption is affected. Exploitation is
  extremely narrow for a localhost-only service. Awaiting a fixed upstream.

## [0.1.0] — 2025 (initial public tag)

Initial scaffold. Not recommended for new deployments — use the latest
commit, which includes all security fixes listed under [Unreleased].
