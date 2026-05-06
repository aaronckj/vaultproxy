# Changelog

All notable changes to vaultproxy are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.6] — iterations 53–54: VwAdapter scope bypass fix, audit/run endpoint, rate limit, localhost HTTPS warn

### Security fixes (iter-53 — CRITICAL)

- **`VwAdapter` vault_folder scope bypass (iter-53, CRITICAL)**: The
  credential-audit scan adapter (`src/credential_audit/vw_adapter.rs`) was not
  filtering items by `vault_folder`. `list_items_metadata()` called
  `vault.list_items()` and returned ALL vault items — including personal banking
  credentials, SSH keys, and any item outside the proxy-owned folder. The
  subsequent `apply` step could then call `marker.mark()` on any of those item
  IDs, moving personal credentials into `_review-delete`. Fixed: the adapter now
  calls `find_folder_id_by_name_async` on every `list_items_metadata()` call and
  filters the item list to only those in the resolved `folder_id`.

### Security fixes (iter-54)

- **`VwAdapter` permissive fallback changed to EMPTY (iter-54, HIGH)**: The
  iter-53 fix used a permissive fallback: when `vault_folder` is configured but
  the folder doesn't exist in Vaultwarden yet, the adapter returned ALL items so
  "the very first scan still works". This defeats the security goal — scanning
  personal credentials is exactly what the scope guard prevents. Fixed: when
  `vault_folder` is configured but the folder is absent, `list_items_metadata()`
  now returns an empty list and logs a prominent warning telling the operator to
  create the folder first. Only when `vault_folder` is entirely unconfigured
  (`None`) does the old all-items behaviour apply.

- **`GET /vault/audit/run` missing rate limit (iter-54, HIGH)**: The endpoint
  decrypts every vault password in sequence to compute HMAC fingerprints. It was
  added to `RATE_LIMITED_PATHS` with a 2 req/60 s per-IP cap (via the
  `per_route` override map). Without this, the global 60 req/60 s budget allowed
  60 concurrent audit runs per minute, each decrypting all vault passwords —
  a potential denial-of-service vector on large vaults.

### Features (iter-53)

- **`GET /vault/audit/run` endpoint (iter-53)**: The `run_audit()` function in
  `src/audit.rs` is now reachable via HTTP. The endpoint is gated behind the
  internal bearer token (`Authorization: Bearer <token>`), is read-only (no
  vault mutations), and returns a JSON report with `total_items`,
  `weak_passwords`, and `reused_passwords` groups. No plaintext passwords appear
  in the response — all reuse detection uses HMAC fingerprints with an ephemeral
  key that is zeroized after each run.

- **`validate_public_url` HTTPS warning for non-localhost http:// (iter-53)**:
  `VAULT_PROXY_PUBLIC_URL` with a non-loopback `http://` scheme now emits a
  `tracing::warn!` explaining that production reverse-proxy URLs should use
  `https://` to protect Bearer tokens and credentials in transit. Loopback
  addresses (`localhost`, `127.0.0.1`, `[::1]`) are explicitly exempted — HTTP
  over loopback is normal for local dev and Docker Compose setups where TLS
  terminates at the outer edge.

### Documentation (iter-53–54)

- **`GET /vault/audit/run` documented in README (iter-54)**: Added to the
  "Credential audit" section endpoint table with auth tier, rate limit, and
  response shape. Added a `### In-process health scan` sub-section with a `curl`
  example and JSON response skeleton documenting `total_items`, `weak_passwords`,
  and `reused_passwords` fields.

- **`GET /vault/audit/run` rate limit test (iter-54)**: New unit test
  `audit_run_uses_very_tight_limit` in `security/rate_limit.rs` verifies the 2
  req/60 s cap is enforced for the `/vault/audit/run` path.

### Findings — no code change required (iter-53–54)

- **`VwAdapter.vault_folder` construction vs. per-call** — the field is set at
  `VwAdapter::new()` time but `find_folder_id_by_name_async` is called on every
  `list_items_metadata()` invocation. This means the folder ID is re-resolved on
  every scan, which is correct and immune to SIGHUP folder-rename scenarios.

- **`run_audit()` holds no RwLock** — `vault.list_items()` acquires and releases
  the items read-lock before `decrypt_password()` calls begin. Each decrypt
  acquires only the ephemeral per-item lock. Concurrent audit runs do not block
  the vault sync path. The 2 req/60 s rate limit bounds the concurrent-decrypt
  cost without needing an application-level mutex.

- **`AuditResult` exposes item names** — `AuditItem.name` (`String`) is returned
  in `weak_passwords` and `reused_passwords`. This is intentional: the caller
  needs to know which items are weak/reused to act on them. The endpoint is
  gated behind the internal bearer token (same access tier as
  `/vault/connecterr-secrets`), so name exposure is confined to already-
  privileged callers. No password values or HMAC digests appear in the response.

- **v0.2.6 tag warranted** — the iter-53 scope bypass (CRITICAL) and iter-54
  empty-fallback fix (HIGH) affect users running the credential audit workflow
  on a multi-folder vault. Users on v0.2.5 should upgrade.

## [0.2.5] — iteration 52: credential audit workflow docs, audit.rs wiring notes

### Documentation

- **README credential audit section — complete workflow (iter-52)**: The
  `## Credential audit` section previously listed only the three endpoints
  with terse table rows. Added a `### Complete credential audit workflow`
  sub-section with: (1) step-by-step `curl` examples for scan start →
  poll → dry-run → apply, (2) explicit documentation of what `apply` does
  (moves items to `_review-delete`, appends marker to notes — never deletes),
  (3) the `confirm_bulk` threshold (>50 items without `item_ids`) explained
  inline, and (4) an **undo path**: move items back from `_review-delete` in
  Vaultwarden — there is no automated undo endpoint.

- **`src/audit.rs` — wiring requirements documented (iter-52)**: The
  existing comment block already explains the separation from
  `src/credential_audit/`; clarified that `run_audit` needs to be called from
  either (a) the audit-log dashboard endpoint or (b) a new scheduled endpoint
  to be wired in v1.0. No code changes required — the `#![allow(dead_code)]`
  suppression is intentional and correct until the v1.0 wiring is done.

### Findings documented (no code change required)

- **`marker.mark()` folder creation** — `ensure_folder_by_name()` in
  `VaultManager` already creates `_review-delete` on-demand before the first
  move. No failure path on missing folder.

- **`_review-delete` folder name** — hardcoded as `REVIEW_DELETE_FOLDER`
  constant in `src/credential_audit/marker.rs`. Could be made configurable
  via `--vault-folder-review` in a future release; acceptable for v0.x.

- **`BrowserAgent::new()` empty model** — `new()` accepts `""` without
  error; the runtime guard at `browser_rotate` (main.rs) fires before any
  workflow spawns and returns a clear 400. No initialization-time validation
  needed.

- **`sync/cloud.rs`** — `SyncManager` is fully implemented (auth, full sync,
  cipher re-encrypt, collection→folder mapping, semaphore dedup). No unit
  tests for `CloudClient` because it requires live Bitwarden credentials; the
  integration path is exercised by `SyncManager::full_sync`. Acceptable gap
  for v0.x — noted for v1.0 with mock HTTP testing.

- **Trailing whitespace** — 0 violations (`grep -rn ' $' src/ | grep '\.rs$'`).

## [0.2.4] — iterations 49–51: playwright guard, credential_audit 404, fmt, audit clarity

### Bugs fixed

- **`browser_rotate` missing playwright guard (iter-50, HIGH)**: `POST
  /browser/rotate` returned `{"status":"started"}` when `playwright/agent.py`
  was absent, then silently failed in the background task.  Fixed: the handler
  now checks `/app/playwright/agent.py`, `./playwright/agent.py`, and the new
  `PLAYWRIGHT_AGENT_PATH` env var before spawning; returns a clear 501 with an
  actionable message when none is found (iter-51 also adds `PLAYWRIGHT_AGENT_PATH`
  support to the check).

- **`credential_audit` endpoints returned 200 for unknown `run_id` (iter-50,
  MEDIUM)**: `GET /audit/credaudit/review_pending/{run_id}` returned `200 []`
  instead of 404 when the run_id was unknown, making it indistinguishable from a
  run with no pending items.  `POST /audit/credaudit/apply` similarly returned
  `200 {"applied":0,...}` for a non-existent run_id.  Fixed: `list_pending` and
  `apply` now call `run_exists()` via `Orchestrator` and the handlers map the
  "not found" error to `404 NOT_FOUND` with a descriptive JSON body.

- **`cargo fmt` failure on `src/sync/cloud.rs` (iter-51)**: An inline comment
  on a `#[allow(dead_code)]` attribute did not meet `rustfmt` style (comment
  must be on the next line, not trailing the attribute).  Would have failed CI
  `cargo fmt --check`.  Fixed by running `cargo fmt`.

### Tests added

- **`credential_audit::orchestrator` — run_exists and 404 paths (iter-51)**:
  Four new unit tests using an in-memory SQLite database:
  `run_exists_returns_false_for_unknown_run`,
  `run_exists_returns_true_after_insert`,
  `list_pending_unknown_run_id_returns_not_found_error`,
  `list_pending_known_run_id_returns_ok_empty`,
  `apply_unknown_run_id_returns_not_found_error`.

### Documentation / clarity

- **`audit.rs` — module distinction clarified (iter-51)**: Added a prominent
  comment explaining that `src/audit.rs` (in-process HMAC-based health analyser)
  is completely separate from `src/credential_audit/` (external engine sidecar
  system).  Previously the two could be confused.

- **`browser/mod.rs` and `credential_audit/mod.rs` — v1.0 TODO specifics
  (iter-51)**: The `#![allow(dead_code)]` TODO notes now list concrete
  completion criteria instead of the vague "v1.0 checklist" phrasing.

## [0.2.3] — iterations 46–48: O(n²) fix, vision-model guard, toolchain components

### Bugs fixed

- **Empty `--vision-model` with `--litellm-url` set sent `model: ""` to LiteLLM
  (iter-48, MEDIUM)**: When `LITELLM_URL` was configured but `VISION_MODEL` was
  left at its default empty string, `POST /browser/rotate` spawned a workflow
  that called LiteLLM with `"model": ""`. LiteLLM either returns a cryptic 422
  or routes to an unexpected model, and the error only appeared in the background
  task log — the HTTP caller received no useful message. Fixed: `browser_rotate`
  now checks `browser.model_name.is_empty()` immediately after the
  `litellm_url` check and returns a clear 400 with an actionable message before
  spawning anything.

### Performance

- **O(n²) `aggregate()` eliminated (iter-47)**: The `aggregate()` function in
  `connecterr_secrets.rs` previously called `list_field_names()` followed by
  `decrypt_field()` per field name — two vault-map locks and two linear scans
  over the field list per vault item, giving O(n²) in field count. Replaced with
  `list_field_pairs()`, a new `VaultManager` method that acquires the items map
  lock once and decrypts both field name and value in a single pass (O(n)). The
  nested JSON structure built by `build_secrets_json` is unchanged — only the
  data-collection path is rewritten. Field ordering is preserved (fields are
  returned in the same order they appear in the vault cipher's field list).

### Developer tooling

- **`rust-toolchain.toml` missing `components` (iter-48, LOW)**: The file only
  declared `channel = "stable"`. A fresh `rustup install` from the file gave the
  developer `rustc` and `cargo` but not `clippy` or `rustfmt`. CI uses
  `dtolnay/rust-toolchain@master` which reads the file; without `clippy` in
  `components`, any future CI step that runs `cargo clippy` would need a separate
  component install. Fixed: added `components = ["clippy", "rustfmt"]`.

### Documentation

- **`rust-toolchain.toml` `dtolnay/rust-toolchain@master` behaviour (iter-48)**:
  Confirmed that `dtolnay/rust-toolchain@master` reads `rust-toolchain.toml`
  automatically when the `toolchain:` input is omitted — the channel and
  component list are both honoured. No CI workflow changes are required.

### Verification

- **SecureBuffer zeroization in `list_field_pairs()` (iter-47/48)**: Audited
  end-to-end. `list_field_pairs()` returns `Vec<(String, SecureBuffer)>`. In
  `aggregate()` each `SecureBuffer` is consumed by `buf.as_str()?.to_string()`
  and then immediately drops as the `(fname, buf)` binding goes out of scope at
  the end of the `for` loop body. The `SecureBuffer::drop` impl calls
  `unlock_and_zero()` which zeroizes via the `Zeroize` trait and then
  `munlock`s. Plaintext field values never persist beyond the loop iteration
  that converts them to `String`s for JSON serialization.

- **`list_field_pairs()` concurrent access (iter-48)**: `list_field_pairs()`
  acquires `items.read().await` (an async `RwLock` read). A concurrent
  `vault.sync()` that holds `items.write().await` will block the
  `read().await` call until the write lock is released — correct behavior,
  no deadlock possible. The `.await` ensures Tokio can yield the task rather
  than spinning.

## [0.2.2] — iterations 43–45: IPv6 URL fix, session_login race, reverse-proxy URL, validation polish

### Bugs fixed

- **IPv6 listen address produced invalid VAULT_PROXY_URL (iter-43, HIGH)**:
  `--listen [::]:3201` (or `--listen [::1]:3201`) caused `VAULT_PROXY_URL` to
  be injected as `http://::1:3201` — an invalid URL because the colons in the
  IPv6 address are ambiguous with the port delimiter. RFC 3986 §3.2.2 requires
  square brackets: `http://[::1]:3201`. Smart MCP servers receiving the
  unbracketed form failed to parse the URL and fell back to direct credential
  env vars, defeating the proxy model. Fixed: IPv6 addresses are now bracketed
  when building the injected URL.

- **`session_login()` SIGHUP race produced opaque 502 (iter-44, LOW)**:
  When a SIGHUP reload removed a `session` service between `handle_proxy`
  dispatching the request and `session_login` looking up `base_url` in the
  registry, the registry scan returned `None` and the error propagated as a
  generic "cannot determine" message. Fixed: the `ok_or_else` now emits a
  clear message naming the vault item and explaining the SIGHUP race, making
  the 502 log actionable. The vault item name is included in the server-side
  error message (consistent with existing proxy error logging); it is never
  returned to the HTTP caller.

- **Per-service `timeout_secs` not applied in `session_login()` (iter-42, MEDIUM)**:
  The `session_login()` POST to `login_path` used the global `state.http`
  client (with `--proxy-timeout`, default 120 s), ignoring `ServiceEntry::
  timeout_secs`. A service with `timeout_secs = 5` would hang for up to 120 s
  on a failed login round-trip. Fixed: `session_login` now looks up the
  service's `timeout_secs` and applies it via `RequestBuilder::timeout()`.

- **UniFi dual-auth hardcoded 30 s timeout (iter-42, MEDIUM)**:
  Both the API-key probe and session-login clients in `unifi_session.rs` used
  `Duration::from_secs(30)` regardless of `ServiceEntry::timeout_secs`. Fixed:
  `UnifiRequestCtx` now carries `timeout_secs: Option<u64>`; both clients use
  `effective_timeout = timeout_secs.unwrap_or(30)`.

### Features

- **`VAULT_PROXY_PUBLIC_URL` env var (iter-44)**:
  Operators who run vault-proxy behind a TLS-terminating reverse proxy (nginx,
  Caddy, Traefik) can now set `VAULT_PROXY_PUBLIC_URL=https://vault-proxy.example.com`
  to control the `VAULT_PROXY_URL` value injected into smart MCP servers
  launched via `--launch`. Without this, vault-proxy always derived the URL
  from the (loopback) `--listen` address, forcing smart servers to use HTTP
  over the loopback rather than the HTTPS front-end.

- **`VAULT_PROXY_PUBLIC_URL` startup validation (iter-45)**:
  `VAULT_PROXY_PUBLIC_URL` is now validated at `--launch` time: the value must
  start with `http://` or `https://`, have a non-empty host, and must not end
  with a trailing slash (which would produce double-slash paths in downstream
  calls). `--check` also validates the env var when set, giving operators an
  early-warning before deployment.

### Documentation / quality

- **Stale `vault/mod.rs:143` TODO resolved (iter-45)**:
  The `items` field doc-comment said "implement a background refresh task
  (TODO)" — the feature was implemented in iter-37 via
  `--vault-refresh-interval-secs`. Updated to reference the implemented flag.

- **`VAULT_PROXY_PUBLIC_URL` added to README CLI reference table (iter-45)**:
  The env var introduced in iter-44 was missing from the operator CLI table.
  Added with description, valid values, and trailing-slash warning.

- **`VAULT_REFRESH_INTERVAL_SECS=0` log level raised to INFO (iter-42, LOW)**:
  When the background refresh is disabled (the default), the confirmation
  message was logged at DEBUG. Operators running with INFO filter had no
  positive confirmation that the background task was intentionally absent.
  Changed to INFO so it appears at the same level as the "task started" message.

- **`TIMEOUT_SECS_WARN_THRESHOLD` named constant (iter-42)**:
  The magic number `600` in per-service timeout validation is now a named
  constant `TIMEOUT_SECS_WARN_THRESHOLD` with inline rationale.

- **`services.example.toml` documents `timeout_secs` (iter-42)**:
  The new optional field was missing from the example file.

- **Wiremock timeout behavior test (iter-42)**:
  Added `per_service_timeout_fires_on_slow_upstream` to `registry.rs` tests.

## [0.2.1] — iteration-42: per-service timeout completeness

### Bugs fixed

- **`session_login()` used global client timeout (iter-42, MEDIUM)**: The
  `session_login()` function posted to the service's `login_path` using
  `state.http` directly — the global client with `--proxy-timeout` (default
  120 s) baked in. A service with `timeout_secs = 5` would hang for up to 120
  seconds on the login round-trip even though the operator intended a 5-second
  budget. Fixed: `session_login()` now looks up `ServiceEntry::timeout_secs`
  from the registry (same lock acquisition already needed for `base_url`) and
  applies it via `RequestBuilder::timeout()` on the login POST.

- **UniFi dual-auth used hardcoded 30 s timeout (iter-42, MEDIUM)**: Both the
  API-key probe client and the session login client in `unifi_session.rs` were
  built with `Duration::from_secs(30)` regardless of `ServiceEntry::timeout_secs`.
  `UnifiRequestCtx` now carries a `timeout_secs: Option<u64>` field. The
  `effective_timeout` (`timeout_secs.unwrap_or(30)`) is used for both the bare
  API-key client and the `login()` function so short-timeout UniFi services
  (e.g. `timeout_secs = 5`) no longer hang for 30 seconds on auth failures.

- **`vault background refresh: disabled` logged at DEBUG (iter-42, LOW)**: When
  `VAULT_REFRESH_INTERVAL_SECS=0` (the default), the "refresh disabled" message
  was emitted at `tracing::debug!`. Operators running with the default `INFO`
  filter had no positive confirmation that the background task was intentionally
  absent. Changed to `tracing::info!` so the "disabled" line appears in
  production logs at the same visibility level as the "task started" message.

### Documentation / quality

- **`TIMEOUT_SECS_WARN_THRESHOLD` named constant (iter-42)**: The magic number
  `600` in the per-service timeout validation in `registry.rs` is now a named
  constant `TIMEOUT_SECS_WARN_THRESHOLD` with inline rationale (homelab API
  scan budget, rate-limit starvation risk). The warning message now references
  the constant name and explains how to express "no timeout" (`None` / omit key).

- **`services.example.toml` documents `timeout_secs` (iter-42)**: The new
  optional field was missing from the example file. Added a documented comment
  in the Optional fields section and an inline commented example on the `plex`
  block (the canonical "slow service" use-case).

- **Wiremock timeout behavior test (iter-42)**: Added
  `per_service_timeout_fires_on_slow_upstream` to `registry.rs` tests. It mounts
  a wiremock handler with a 2-second delay, applies a 1-second
  `RequestBuilder::timeout()` override, and asserts the request fails with
  `is_timeout() == true` in under 1.8 s. This closes the gap identified in
  iter-41 where the 3 existing tests only verified registry parsing, not actual
  HTTP timeout behavior.

## [0.2.0] — iterations 36–37: concurrent reload guard, background vault refresh, hard service cap

### Security / correctness fixes (iteration 37)

- **`reload_mutex` acquisition timeout (iter-37)**: `POST /vault/reload-services`
  previously blocked indefinitely when another reload was already in progress
  (e.g. services.toml on a slow NFS mount, or many CA-cert clients building).
  Added a 5-second `tokio::time::timeout` around `reload_mutex.lock()`. Callers
  that time out receive `503 Service Unavailable` with `retry_after_s: 10` in
  the JSON body; the executing reload is unaffected.

- **Per-route tighter rate limits on destructive operations (iter-37)**:
  `/vault/items/delete` and `/vault/folders/delete` now enforce a 10 req/60 s
  limit (down from the global 60 req/60 s). Implemented via a
  `per_route: HashMap<&str, u64>` override map in `RateLimiter` so no second
  middleware instance is required. All other rate-limited routes retain 60/60.

- **Hard service cap at 512 (iter-37)**: `ServiceRegistry::from_toml_file` now
  enforces a `MAX_SERVICES = 512` hard cap. Entries beyond the cap are logged by
  name and dropped — the registry is still usable for the accepted entries.
  This bounds worst-case `reload_mutex` hold time to ~500 ms (512 CA-cert client
  builds at ~1 ms each). The 256-entry warning threshold is retained; entries
  between 257 and 512 warn, entries above 512 error and are dropped.

- **Forgejo token stripped from `.git/config` (iter-37)**: The Forgejo API token
  embedded in the `pushurl` in `.git/config` has been removed. The plaintext
  token `cba541e6543bcddcf59ed157a0355df08d26f4be` should be considered
  compromised and rotated.

### Features (iteration 37)

- **Background vault refresh (iter-37)**: New `--vault-refresh-interval-secs`
  flag (env: `VAULT_REFRESH_INTERVAL_SECS`, default `0` = disabled). When
  non-zero, a background task calls `vault.sync()` every N seconds, closing the
  staleness window when Vaultwarden credentials are rotated externally. Failures
  are logged as warnings; the last good credentials remain in use. Recommended
  value: `300` (5 minutes).

- **Rate limiter tests (iter-37)**: Added 5 unit tests for `RateLimiter` covering
  default limits, per-route overrides, independent IP buckets, and both delete
  endpoints.

### Operator notes (iteration 37)

- **Reload latency**: With `MAX_SERVICES = 512` and all services having
  `ca_cert_path`, `reload_services` holds the mutex for approximately 512 ms
  while building CA-cert clients. Callers that need to issue concurrent reloads
  (unusual) will queue for up to 5 seconds before receiving a 503. Normal
  single-operator reload calls are unaffected.

## [0.2.0-base] — iteration-36 concurrent reload guard and final gaps

### Security / correctness fixes (iteration 36)

- **Concurrent `reload-services` race condition fixed (iter-36, CRITICAL)**:
  Two simultaneous `POST /vault/reload-services` calls previously both built
  independent registries and CA-cert maps, then raced on three separate
  write-lock acquisitions (`registry` → `ca_cert_clients` → `cached_folder_id`).
  Because the three locks are taken sequentially, call A could win the
  `registry` write lock while call B won the `ca_cert_clients` write lock,
  leaving the process with a registry from A and a CA-cert map from B. For
  services with `ca_cert_path`, all subsequent proxy calls would find no
  matching entry in the stale client map and silently fall back to the default
  TLS client.

  Fixed by adding `reload_mutex: tokio::sync::Mutex<()>` to `AppState` and
  acquiring it at the top of `reload_services`. This serialises the reads and
  all three write-lock acquisitions into one critical section. SIGHUP is
  unaffected (it processes signals serially in its own task).

- **`proxy_timeout` stored in `AppState` (iter-36)**: `POST /vault/reload-services`
  previously re-read `PROXY_TIMEOUT` from the environment at reload time. This
  is now stored as `AppState::proxy_timeout` (captured and validated at startup)
  so reloads always use the startup value, consistent with the SIGHUP handler
  which already captured `args.proxy_timeout` via closure.

### Changes in this release

- `AppState` gains two new fields: `proxy_timeout: u64` and
  `reload_mutex: tokio::sync::Mutex<()>`. Any code constructing `AppState`
  directly (tests, embedders) must be updated.

## [0.1.9] — iteration-35 config_dir correctness and test coverage

### Correctness fixes (iteration 35)

- **`config_dir` stored in `AppState` (iter-35)**: `POST /vault/reload-services`
  previously read `CONFIG_DIR` from the environment at reload time. In container
  orchestrators that inject env var changes without restarting the process, this
  could cause the reload handler to read `services.toml` from a different path
  than the one used at startup. `config_dir` is now captured at startup and stored
  in `AppState`, ensuring all reload operations use the original path.

- **`cargo doc` warnings cleared (iter-35)**: Fixed 8 rustdoc warnings introduced
  in iter-33: unresolved intra-doc links (`from_toml_file`, `mcp_server`), unclosed
  HTML tags (`Vec<u8>`, `<id>`, `<vault-folder>`, `<Service>`), and a bare URL not
  wrapped in backticks.

### Tests (iteration 35)

- **`reload-services` integration tests (iter-35)**: Three HTTP-level tests covering
  the happy path (new services.toml → 200 + correct count), the rollback path
  (empty file with existing registry → 409 Conflict), and the auth path (no bearer
  token → 401 Unauthorized).

- **`credaudit/scan/start` 503 integration test (iter-35)**: Verifies that
  `POST /audit/credaudit/scan/start` returns 503 (not 500 or a panic) when the
  credential audit engine is unreachable.

## [0.1.8] — iteration-34 correctness and production hardening

### Features (iteration 34)

- **`POST /vault/reload-services` endpoint (iter-34)**: New internal endpoint
  that performs a synchronous hot-reload of `services.toml` and returns a JSON
  body confirming the before/after service count. Equivalent to sending SIGHUP
  but HTTP-accessible. Gated behind the internal bearer token. Includes the same
  rollback guard as SIGHUP (409 Conflict if reload produces zero services).

- **TPM status in `GET /vault/health` (iter-34)**: Health response now includes
  `tpm_feature_compiled` and `tpm_chip_available` fields so operators can confirm
  at a glance whether hardware sealing is possible on the running host.

- **Credential audit engine 503 fix (iter-34)**: `POST /audit/credaudit/scan/start`
  previously returned 500 when the audit engine was unreachable (the raw reqwest
  connection-refused error propagated). Now normalised to 503 SERVICE_UNAVAILABLE
  with a structured warning log and actionable hint (`CRED_AUDIT_ENGINE_URL`).

### Correctness fixes (iteration 35)

- **`config_dir` stored in `AppState` (iter-35)**: `POST /vault/reload-services`
  previously read `CONFIG_DIR` from the environment at reload time. In container
  orchestrators that inject env var changes without restarting the process, this
  could cause the reload handler to read `services.toml` from a different path
  than the one used at startup. `config_dir` is now captured at startup and stored
  in `AppState`, ensuring all reload operations use the original path.

- **`cargo doc` warnings cleared (iter-35)**: Fixed 8 rustdoc warnings introduced
  in iter-33: unresolved intra-doc links (`from_toml_file`, `mcp_server`), unclosed
  HTML tags (`Vec<u8>`, `<id>`, `<vault-folder>`, `<Service>`), and a bare URL not
  wrapped in backticks.

### Tests (iteration 35)

- **`reload-services` integration tests (iter-35)**: Three HTTP-level tests covering
  the happy path (new services.toml → 200 + correct count), the rollback path
  (empty file with existing registry → 409 Conflict), and the auth path (no bearer
  token → 401 Unauthorized).

- **`credaudit/scan/start` 503 integration test (iter-35)**: Verifies that
  `POST /audit/credaudit/scan/start` returns 503 (not 500 or a panic) when the
  credential audit engine is unreachable. Exercises the iter-34 error-normalisation
  path end-to-end through a real axum router with an in-memory SQLite DB.

## [0.1.7] — iterations 32–33 audit fixes

### Features (iteration 33)

- **`--version` flag (iter-33)**: `vault-proxy --version` now prints the binary
  version from `Cargo.toml` via clap's `#[command(version)]` derive. Previously
  operators had no way to confirm which release was running without inspecting the
  binary or reading `Cargo.toml`.

- **`GET /vault/health` version field (iter-33)**: The health response now includes
  a `"version"` field (`env!("CARGO_PKG_VERSION")`). Monitoring systems and
  operators can confirm the running version without shelling into the container.

- **Request tracing spans in `handle_proxy` (iter-33)**: `POST /proxy` now creates
  a `tracing::info_span!("proxy", service, method)` at the start of each request.
  All log lines emitted during a single request (permission check, vault decrypt,
  upstream send, audit entry) share the `service` and `method` fields, making
  correlated log analysis possible in structured-log tools.

- **`UnifiRequestCtx` struct — `too_many_arguments` refactor (iter-33)**:
  `unifi_session::handle_request` had 8 parameters, triggering
  `clippy::too_many_arguments`. Introduced `UnifiRequestCtx { base_url, method,
  path, body, query }` to group the per-request routing fields. The new signature
  is `handle_request(cache, service, req: &UnifiRequestCtx, auth_ctx:
  &UnifiDualAuthCtx)`. All call sites (proxy/mod.rs and all test helpers) updated.

- **SIGHUP vault_folder re-check (iter-33)**: After a successful `services.toml`
  reload, the SIGHUP handler now re-runs the vault_folder existence check and logs
  a confirmation or warning. Operators who create the vault folder and send SIGHUP
  now see an explicit `vault_folder confirmed` log line instead of silence.

- **Credential audit endpoints documented in README (iter-33)**: The three HTTP
  endpoints exposed by the `credential_audit` module (`/audit/credaudit/scan/start`,
  `/audit/credaudit/review_pending/{run_id}`, `/audit/credaudit/apply`) were live
  but undocumented. Added a "Credential audit" section to `README.md`.

- **`mcp-servers.example.toml` SIGHUP/restart clarification (iter-33)**:
  Added a comment at the top of `mcp-servers.example.toml` explaining that changes
  to this file require a process restart — they are NOT picked up by SIGHUP (which
  only reloads `services.toml`).

- **Vault scope guard integration test (iter-33)**: Added integration test
  `vault_folder_scope_guard_blocks_out_of_folder_delete` that wires a real axum
  router, registers a `vault_folder` in `AppState`, and verifies that
  `POST /vault/items/delete` with an item ID from outside the vault_folder returns
  403 FORBIDDEN. Catches regressions in the scope-guard code path.

### Correctness fixes (iteration 32)

- **Middleware integration tests (iter-32)**: Added integration tests for the
  rate-limiter middleware (`rate_limiter_returns_429_after_budget_exhausted`),
  DNS rebinding guard (`dns_rebinding_guard_blocks_external_host`), and the
  internal bearer token middleware (`internal_token_middleware_returns_401_without_header`).
  These tests exercise the full axum middleware stack via real HTTP requests.

- **`/rotate` returns 501 Not Implemented (iter-32)**: `POST /rotate` now returns
  `501 Not Implemented` with a JSON body explaining the feature status, rather than
  silently succeeding or returning an unrelated error. The internal token middleware
  still applies — callers must present a valid bearer token before reaching the
  handler.

- **`--check` integration test (iter-32)**: Added a subprocess-level test that
  runs `vault-proxy --check` against a temp `services.toml` and asserts the correct
  exit code and stdout content without standing up a live Vaultwarden connection.

- **`Cargo.toml` bumped to `0.1.7` (iter-33)**: Captures all iter-32/33 fixes.

## [0.1.6] — iterations 29–31 audit fixes

### Correctness fixes (iteration 31)

- **`security/permissions.rs:106,120` — collapsible nested `if` (iter-31)**:
  Two nested `if outer { if inner { ... } }` blocks in `get_default_permission`
  and `get_category` were flagged by `clippy::collapsible_if`. Collapsed to
  `if outer && inner` — no behaviour change, cleaner control flow.

- **`proxy/mod.rs:1017` — `manual_range_contains` (iter-31)**:
  `n < MIN_MB || n > MAX_MB` in `upstream_body_limit_bytes` replaced with
  `!(MIN_MB..=MAX_MB).contains(&n)` per clippy suggestion.

- **`vault/handlers.rs:974` — `unnecessary_lazy_evaluations` (iter-31)**:
  `get_or_insert_with(|| EncryptedLogin { ... })` replaced with
  `get_or_insert(EncryptedLogin { ... })` since the closure captured nothing.

- **`security/audit_log.rs:200` — `items_after_test_module` (iter-31)**:
  `truncate_str` was defined after the `#[cfg(test)] mod tests` block,
  triggering `clippy::items_after_test_module`. Moved before the test module.

- **`proxy/mod.rs:1262,1274` — `useless_vec!` in tests (iter-31)**:
  Two `vec![...]` literals in unit tests that were immediately iterated but
  never mutated replaced with array literals per clippy suggestion.

- **Integration test audit-log path collision (iter-31)**:
  `make_state` in the integration test module used `subsec_nanos()` as the
  unique suffix for the per-test audit log path. Two tests starting within the
  same nanosecond on a fast machine would produce the same path and race on the
  file. Replaced with a `static AtomicU64` counter that is strictly monotonic
  regardless of clock resolution.

### Documentation fixes (iteration 31)

- **`dashboard/mod.rs:495` — CSP `unsafe-inline` tradeoff documented (iter-31)**:
  The `Content-Security-Policy` header on the dashboard has permitted
  `unsafe-inline` for both `script-src` and `style-src` since the dashboard
  HTML files contain inline `<script>` and `<style>` blocks. This weakness
  was previously undocumented, risking it being "fixed" by removing the CSP
  header entirely. Added a comment explaining the tradeoff and the correct
  remediation path (extract inline JS/CSS to separate files, then tighten
  to `script-src 'self'`).

### Bug fixes (iteration 30)

- **Dashboard unlock redirect (iter-30)**: A fresh restart sent users to
  `/login` even when the keystore was locked. Entering credentials at `/login`
  failed silently because that page validates dashboard sessions, not the
  keystore password. The `require_session_redirect` middleware now routes based
  on system state: locked → `/unlock`; unlocked+no session → `/login`.

- **Audit log path race in parallel tests (iter-30)**: All 3 integration tests
  shared `/tmp/vault-proxy-test-audit.json`, causing file-level races on
  parallel `cargo test` runs. Each `make_state` call now generates a unique
  path using a monotonic suffix.

- **`credential_audit/mod.rs` dead-code re-exports (iter-30)**: Unused
  `pub use` re-exports of `ItemResult`, `Run`, and `RunStatus` removed.

### Bug fixes / improvements (iteration 29)

- **SIGHUP rollback guard (iter-29)**: `reload_services_toml` now refuses to
  swap in a 0-service registry when the previous registry was non-empty,
  preventing a silent outage when `services.toml` is temporarily unreadable or
  every entry is rejected. A warning naming the count mismatch is logged.

- **SIGHUP reload count logged (iter-29)**: The reload completion log now
  shows "N service(s) now registered (was M)" so operators can confirm the
  swap took effect.

- **`--check` stdout improvements (iter-29)**: Uses `from_toml_file_with_counts`
  to report attempted vs. accepted counts; names the rejected count; exits 1
  on partial acceptance so CI pipelines detect misconfigured entries without
  parsing structured tracing JSON.

- **`VaultManager::new_stub()` (iter-29)**: Test-only constructor for building
  `AppState` in integration tests without a live Vaultwarden connection.
  Crypto operations fail gracefully (wrong-key error, not panic), causing
  `handle_proxy` to return 502 rather than crashing.

- **Integration tests — real HTTP path (iter-29)**: Three new integration tests
  spin up a real `axum::serve` listener on `127.0.0.1:0` and make real
  `reqwest` HTTP requests, exercising the full middleware stack (bearer token
  check, rate limiter, DNS rebinding guard) rather than calling handler
  functions directly.

- **`Cargo.toml` bumped to `0.1.6` (iter-31)**: Captures all iter-29/30/31
  fixes listed above.

## [0.1.5] — iteration-28 audit fixes

### Security fixes (iteration 28)

- **`GET /vault/services` exposed `base_url` on open router (iter-28)**:
  The endpoint returned `base_url` for every registered service, leaking
  internal network topology (`http://homeassistant.local:8123`,
  `https://unifi.local/proxy/network`, etc.) to any unauthenticated caller
  with localhost access. An attacker who can reach port 3201 (e.g. from a
  compromised container on the same host) could enumerate all internal
  services and their addresses without any credentials. `base_url` is now
  omitted from the response. Service `name`, `auth` type, and wiring details
  (`header_name`, `param_name`, `key_field`, `secret_field`) are retained for
  debugging service registration — none of these enable topology discovery.

### Features (iteration 28)

- **SIGHUP hot-reload of `services.toml` (iter-28)**:
  Sending `SIGHUP` to a running `vault-proxy` now reloads `services.toml`
  from disk without restarting the process. The reload rebuilds the service
  registry and all per-service CA-cert clients, then atomically swaps them
  into `AppState` under write locks. In-flight requests complete against the
  old registry; new requests after the swap see the updated services. The
  folder-id cache (`cached_folder_id`) is cleared on reload so the next vault
  mutation re-resolves the folder.
  Implementation: `registry: Arc<RwLock<ServiceRegistry>>` and
  `ca_cert_clients: Arc<RwLock<HashMap<...>>>` in `AppState`; SIGHUP handler
  spawned in `start_server`.

### Bug fixes (iteration 28)

- **`--check` exit code: exit 1 on zero services loaded (iter-28)**:
  Previously `vault-proxy --check` always exited 0, even when `services.toml`
  existed but every entry was rejected by validation (parse error, SSRF
  block, missing required fields). A CI pipeline using `vault-proxy --check`
  as a gate could not distinguish "config is good, zero services" (first-run)
  from "config is broken, all entries rejected". Exit codes now:
  `0` = file missing (first-run hint emitted) or file parsed with ≥1 valid
  service; `1` = file exists but loaded zero services (parse error or all
  entries rejected).

### Documentation (iteration 28)

- **`mcp-servers.example.toml` documents shell-interpreter denylist and
  `/proc/<pid>/environ` warning (iter-28)**: The example file now includes an
  explicit security note about the `--launch` shell-interpreter denylist
  (refusing bash, sh, python, node, etc. as `command` targets), the runtime
  `/proc/<pid>/environ` exposure warning emitted on every launch, and the
  sensitive-env-var warning for LD_PRELOAD etc.

- **`services.example.toml` `ca_cert` path labeled as placeholder (iter-28)**:
  The commented-out `ca_cert = "/config/internal-ca.pem"` example now clearly
  states it must be changed to match the deployment (Docker Compose vs.
  bare-metal paths differ) and will cause a startup error if used verbatim.

- **`Cargo.toml` bumped to `0.1.5` (iter-28)**: Captures all iter-28 fixes.

## [0.1.4] — iteration-27 audit fixes

### Security fixes (iteration 27)

- **`GET /vault/services` exposed `login_path` on open router (iter-27)**:
  The endpoint added in iter-26 included `login_path` in the `auth_detail`
  object for `session` and `unifi_dual` auth patterns. Combined with the
  already-exposed `base_url`, an unauthenticated attacker enumerating this
  endpoint from a browser tab (no bearer token required) could build a map of
  `<base_url, login_path>` pairs for every registered service — enough to craft
  targeted credential-stuffing or SSRF probes. `login_path` is now omitted from
  the response. Token field names and `login_include_username` are retained as
  they don't aid path enumeration.

- **`totp.rs:28` — `unwrap()` on `SystemTime::duration_since` (iter-27)**:
  `seconds_remaining()` called `.unwrap()` on `SystemTime::now().duration_since(UNIX_EPOCH)`.
  `duration_since` returns `Err` when the system clock is set before the epoch — a
  real scenario on embedded or misconfigured systems. Changed to `.unwrap_or(Duration::ZERO)`
  so the function returns 30 (full TOTP period) rather than panicking.

- **`credential_audit/orchestrator.rs` — `Mutex::lock().unwrap()` with no
  panic message (iter-27)**: Seven `self.conn.lock().unwrap()` calls in the
  orchestrator had no context string — a mutex-poison panic would produce an
  opaque message. Changed all to `.expect("DB mutex poisoned")` for
  diagnosability.

### UX / tooling (iteration 27)

- **`--check` flag — validate services.toml without Vaultwarden (iter-27)**:
  `vault-proxy --check` parses `services.toml` and applies SSRF validation
  rules, then exits. No Vaultwarden credentials required, no ports bound.
  Exit 0 = config OK. Useful for CI pipelines and pre-deploy verification.

- **`GET /vault/services` documented in README (iter-27)**: The endpoint added
  in iter-26 was not referenced in the README API/CLI section. Added a
  description under the Quick Start "verify" step and added `--check` to the
  CLI reference table.

- **`Cargo.toml` bumped to `0.1.4` (iter-27)**: Captures all iter-25/26/27
  fixes. Previous versions are in the CHANGELOG below.

## [Unreleased] — iteration-26 audit fixes

### Security fixes (iteration 26)

- **Audit log coverage for all mutation handlers (iter-26)**: After 25 iterations
  of handler additions, only `POST /proxy` and `GET /vault/folders?include_all=true`
  emitted structured `AuditLog` entries. Every other mutation — `create_item`,
  `update_item`, `delete_item`, `delete_folder`, `move_item`,
  `upsert_connecterr_secrets`, and `POST /rotate` — was logged only to `tracing`
  (ephemeral, not persisted). Added `state.audit_log.log(AuditEntry { ... })` to
  each successful mutation path so operators have a persistent, queryable record
  of every write operation via the audit-log dashboard.

- **`services.toml` is a directory — clear error message (iter-26)**:
  `from_toml_file()` called `std::fs::read_to_string(path)`, which returns
  `EISDIR` (OS error 21) when the path is a directory. This fell through to
  the generic "could not read services.toml — check file permissions" branch,
  which is actively misleading: permissions on the directory are fine; the
  operator has created a directory instead of a file (e.g. via
  `mkdir /config/services.toml`). Added an explicit `IsADirectory` / errno-21
  branch that emits: "services.toml at <path> is a DIRECTORY, not a file —
  remove the directory and create the file instead."

### UX improvements (iteration 26)

- **`GET /vault/services` debugging endpoint (iter-26)**: There was no way for
  an MCP server developer to verify which services are registered without
  reading `services.toml` directly or inspecting startup logs. A new endpoint
  returns service names, `base_url`, auth type, and auth-type-specific detail
  (header name, param name, login path, etc.) for every registered service.
  `vault_item` (the Vaultwarden credential name) is intentionally omitted to
  avoid leaking credential naming conventions. The endpoint is on the open
  router (same access posture as `GET /vault/health`).

- **`GET /vault/health` enriched (iter-26)**: Added `vault_folder`, `service_count`,
  and a `cache_note` field to the health response. The `vault_folder` field
  lets callers confirm that the expected scope is active; `service_count`
  provides a quick sanity-check of whether services.toml loaded correctly.
  The `cache_note` makes explicit that `vault_item_count` is from the last
  in-memory sync, not a live Vaultwarden query.

## [Unreleased] — iteration-25 audit fixes

### Security fixes (iteration 25)

- **`Instant` overflow on absurdly large `expires_in` (iter-25)**: Vaultwarden
  instances (or self-hosted configurations) can return `expires_in = 9999999`
  or similar large values. Rust's `Instant::checked_add()` — not the panicking
  `Instant + Duration` — is now used everywhere in the token expiry path.
  Values above 7 days (604 800 s) are clamped and a warning is emitted; the
  reactive 401 refresh path remains fully operational for any token that
  outlives the cap window.

- **Startup `vault_folder` existence check (iter-25)**: `VAULT_FOLDER` was
  validated for format (non-empty, no slashes, no nulls) at parse time but not
  for existence. A typo like `VAULT_FOLDER=vault_prox` would pass format
  validation, yet every scoped handler would fall through to permissive mode
  (returning all vault items) with no operator-visible warning. vault-proxy now
  calls `find_folder_id_by_name_async` at startup and emits a prominent
  `STARTUP: SECURITY` warning when the folder is absent from Vaultwarden.

### Documentation fixes (iteration 25)

- **CA cert rotation note (iter-25)**: The CA-cert client build loop in
  `start_server` now logs explicitly that a process restart is required to
  pick up rotated CA certificates, preventing silent credential-verification
  failures when certs are rotated on disk while vault-proxy is running.

- **README updates (iter-25)**: CLI reference table updated to include
  `--env-write-root`, `--allow-root`, and `--launch`; security model section
  expanded with token-staleness and folder-scope notes.

## [Unreleased] — iteration-23 audit fixes

### Security fixes (iteration 23)

- **`POST /vault/notes` moved to internal router (iter-23 — TODO 3/3)**:
  `decrypt_notes` returns the full decrypted notes field (API tokens, SSH keys,
  recovery codes, etc.). It was previously on the open router — accessible to
  any localhost process without a bearer token. It is now on the internal router:
  callers must present `Authorization: Bearer <token>` from
  `$CONFIG_DIR/internal-token`. This closes the last open `TODO(public-release)`
  about notes exfiltration surface.

- **`require_internal_token` timing oracle via length short-circuit (iter-23)**:
  The iter-22 implementation compared `provided.len() == expected.len()` before
  the constant-time fold-XOR, leaking token length via response latency. An
  attacker with microsecond timing precision could binary-search the 64-character
  token length in O(log n) probes. Fixed: the accumulator now folds over exactly
  `expected.len()` iterations regardless of `provided.len()`, with a branchless
  length-difference flag OR'd into the same accumulator. No early return on
  length mismatch.

- **`resolve_vault_folder_id` thundering herd on resync (iter-23)**:
  After `vault_resync` clears `cached_folder_id` to `None`, all concurrent
  requests that observed `None` under the read lock would drop it and
  independently call `find_folder_id_by_name_async` — a thundering herd against
  the vault's folder-index read lock. Fixed with double-checked locking: the
  slow path now acquires the write lock and re-checks the cache before calling
  into the vault. Only the first writer resolves the folder ID; all others find
  the cache warm on the re-check.

- **`write_env` gated behind `--env-write-root` / `ENV_WRITE_ROOT` (iter-23 — TODO 2/3)**:
  `POST /vault/write-env` previously hardcoded `/envs/` as the only allowed
  target prefix — a homelab-specific convention that gave public users no
  actionable error. The endpoint now returns `501 Not Implemented` when
  `--env-write-root` is unset, explaining how to enable it. When the flag is
  set, the prefix is normalised to end with `/` to prevent path-prefix bypass
  (e.g. `/envs-evil/` matching a root of `/envs`).

### Reliability fixes (iteration 23)

- **Policy scheduler restart loop (iter-23 — TODO 1/3)**:
  The policy scheduler `tokio::spawn` would silently lose all rotation
  scheduling if the inner task panicked — the JoinHandle was dropped immediately
  and the panic swallowed. The spawn is now wrapped in an outer restart loop
  that `.await`s the inner JoinHandle, logs panics via `JoinError::is_panic()`,
  and re-spawns the inner task after a 5-second delay. This closes the
  `TODO(public-release)` in `main.rs`.

### Documentation fixes (iteration 23)

- **Dockerfile: `internal-token` cross-process permissions note (iter-23)**:
  Added an inline comment in the `Dockerfile` explaining that `0o600` permissions
  on `$CONFIG_DIR/internal-token` require vault-proxy and the TypeScript
  Connecterr layer to run as the same UID (1001 / vaultproxy). Documents
  Option A (same UID), Option B (shared group + 0o640), and Option C (shared
  volume) for multi-process deployments.

## [0.1.3] — iteration-22 security hardening

### Security fixes (iteration 22)

- **Internal bearer token for internal endpoints (iter-22 — TODO 1/3)**:
  `/handshake`, `/vault/connecterr-secrets`, `/vault/connecterr-secrets/upsert`,
  `/rotate`, `/browser/rotate`, `/browser/status`, `/browser/screenshot`, and
  `/browser/abort` are now gated by a shared-secret bearer token. At startup
  vault-proxy generates a 32-byte random hex token and writes it to
  `$CONFIG_DIR/internal-token` with `0o600` permissions. Callers must present
  `Authorization: Bearer <token>`. Previously any localhost process could call
  these endpoints without authentication. The TypeScript Connecterr side reads
  the token from the same file path.

- **HTTP/1 header-read timeout — Slowloris defence (iter-22 — TODO 2)**:
  The main API server now uses `axum_server::bind` instead of `axum::serve`,
  configuring `http1().timer(TokioTimer::new()).header_read_timeout(5s)` on the
  hyper-util connection builder. Without this, a Slowloris attack could hold
  connections open indefinitely by sending headers one byte at a time; the rate
  limiter only counts completed requests and would not have caught it. The 5-second
  timeout drops partial connections before they accumulate. Graceful shutdown is
  preserved via `axum_server::Handle::graceful_shutdown(10s)`.

- **Field-name control-character injection in `upsert_connecterr_secrets`
  (iter-22)**: The iter-21 fix added control-character rejection to item names
  (`validate_item_name`), but field names in the `fields: BTreeMap<String, String>`
  payload were not validated. A crafted field name with an embedded `\n` or `\0`
  could corrupt Vaultwarden storage or inject fake log lines. A new
  `validate_field_name` function is applied to all field keys before any vault
  mutations.

- **`list_folders?include_all=true` missing structured audit log (iter-22)**:
  The iter-21 implementation logged `tracing::info!` only — the persistent
  `AuditLog` was never written for the `include_all=true` path despite the
  CHANGELOG stating "Audit logging is applied." Fixed: `state.audit_log.log()`
  is now called for every `include_all=true` request.

### Performance improvements (iteration 22)

- **`find_folder_id_by_name_async` cached in AppState (iter-22)**: Every
  scoped vault handler previously called `find_folder_id_by_name_async` on
  every request — a read lock + linear scan over the folder map. Since
  `vault_folder` is static (set at startup), the resolved `folder_id` is now
  cached in `AppState::cached_folder_id`. The cache is invalidated by
  `POST /vault/resync`. A new `resolve_vault_folder_id` helper encapsulates
  the check-and-populate pattern for all handlers.

## [0.1.2] — iteration-21 audit fixes

### Security fixes (iteration 21)

- **API security response headers (iter-21)**: `GET /vault/*` and `POST /proxy`
  responses now include `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  and `Referrer-Policy: no-referrer`. Previously only the dashboard router applied
  these; the main API port returned bare responses, leaving browser-based clients
  vulnerable to MIME sniffing and framing attacks.

- **Control character injection in `upsert_connecterr_secrets` (iter-21)**: Item
  names containing newlines (`\n`, `\r`), null bytes (`\0`), tabs, or any other
  ASCII control character are now rejected with a 400 error. A crafted name with
  an embedded `\n` could corrupt Vaultwarden storage or inject fake log lines into
  structured output. `validate_item_name` now rejects all characters in the range
  U+0000–U+001F and U+007F.

### UX improvements (iteration 21)

- **`GET /vault/folders?include_all=true` (iter-21)**: `list_folders` now accepts
  an `include_all=true` query parameter that returns all vault folders. The default
  (no parameter) continues to return only `vault_folder`-scoped entries. The full
  listing is needed by `POST /vault/items/move` callers that want to specify a
  destination `folder_id` outside the proxy's own folder — without it, the
  `folder_id` path of `move_item` was unusable for cross-folder moves.

- **`services.toml` missing error message (iter-21)**: The startup warning when
  `services.toml` is absent now distinguishes "file not found" (first-run) from
  permission/I/O errors, and includes the correct Docker Compose mount path
  (`./config/services.toml`) in the first-run message.

## [Unreleased] — security hardening (iterations 1–20)

The v0.1.0 release tag reflects the initial public scaffold. Since that
tag, the codebase has gone through 20 focused security and reliability
audit passes totalling 160+ individual fixes. The items below are
representative; they are NOT all included in the v0.1.0 release artifact.

Users building from source or pulling a `latest` image get all fixes.
Users on the v0.1.0 tagged release should upgrade to v0.1.2 (or later).

### Security fixes (iterations 17–20) — vault_folder scope hardening

**Critical/high severity.** Iterations 17–19 added `vault_folder` scope
guards to every vault mutation and read-sensitive handler. Iteration 20
closed the remaining gaps. Without these guards, any local caller (MCP
client, localhost process) could read or modify vault items from outside
the proxy's designated folder, potentially accessing personal credentials
(banking, SSH keys, etc.) stored elsewhere in the same Vaultwarden vault.

- **`list_items` scoped to `vault_folder` (iter-18)**: `GET /vault/items`
  previously returned all items in the vault. Now filtered to items whose
  `folder_id` matches `vault_folder`. Personal items in other folders are
  never surfaced.

- **`list_duplicates` scoped to `vault_folder` (iter-19)**: the duplicate
  detection scan now operates only within `vault_folder`. Previously it
  fingerprinted passwords from every folder, which could reveal
  cross-folder password reuse patterns for personal accounts.

- **`create_item` locked to `vault_folder` (iter-19)**: `POST /vault/items`
  now rejects any `folder_name` that doesn't match `vault_folder`, and
  defaults to `vault_folder` when `folder_name` is omitted. Prevents
  callers from injecting items into arbitrary vault folders.

- **`update_item` scoped to `vault_folder` (iter-17)**: `PATCH /vault/items`
  verifies the target item is in `vault_folder` before modifying it.

- **`delete_item` scoped to `vault_folder` (iter-18)**: `DELETE /vault/items`
  verifies the target item is in `vault_folder` before soft-deleting it.

- **`clone_item` source scoped to `vault_folder` (iter-18)**: `POST
  /vault/clone` verifies the *source* item is in `vault_folder`. Without
  this guard a caller could clone a personal vault item's encrypted password
  blob into the proxy's folder and then decrypt it.

- **`test_credential` scoped to `vault_folder` (iter-19)**: `POST
  /vault/test-credential` verifies the vault item is in `vault_folder`
  before decrypting and forwarding credentials to the target URL.

- **`generate_totp` scoped to `vault_folder` (iter-19)**: `POST /vault/totp`
  verifies the item name is in `vault_folder` before decrypting and generating
  a live TOTP code. Prevents access to banking or email 2FA seeds.

- **`decrypt_notes` scoped to `vault_folder` (iter-19)**: `POST /vault/notes`
  verifies the item name is in `vault_folder` before returning the full
  decrypted notes field (which may contain API tokens, SSH keys, recovery codes).

- **`delete_folder` blocks deletion of `vault_folder` itself (iter-19)**:
  prevents an MCP caller from deleting the proxy's own folder, which would
  silently break all subsequent credential lookups.

- **`move_cipher` source scoped to `vault_folder` (iter-19)**: `POST
  /vault/move` verifies the source item is in `vault_folder` before moving it.

- **`write_env` scoped to `vault_folder` (iter-20)**: `POST /vault/write-env`
  now verifies the vault item is in `vault_folder` before decrypting credentials
  and writing them to disk. Previously any local caller could exfiltrate the
  plaintext of any vault item by passing its UUID to this endpoint.

- **`inject_creds` scoped to `vault_folder` (iter-20)**: `POST
  /vault/inject-creds` now checks both `vault_item` and `ha_token_item` against
  `vault_folder` before decrypting. Previously a caller could name any vault item
  and have its credentials submitted to an arbitrary HA config-flow URL.

- **`list_untracked_items` scoped to `vault_folder` (iter-20)**: `GET
  /vault/items/untracked` now returns only items inside `vault_folder` that are
  absent from the sync map. Previously it returned all untracked items across the
  entire vault, exposing names, usernames, and URIs of personal items.

- **`list_folders` scoped to `vault_folder` (iter-20)**: `GET /vault/folders`
  now returns only the folder(s) matching `vault_folder`. Previously it returned
  all vault folders, exposing personal folder names (e.g. "Banking", "Work")
  as metadata.

- **Duplicate folder name warning (iter-19)**: `sync()` now logs a prominent
  warning when two vault folders share the same decrypted name. Duplicate names
  cause `find_folder_id_by_name_async` to resolve non-deterministically, which
  could silently break scope guards. Operators are prompted to consolidate.

### Security fixes and features (iteration 16)

- **`ca_cert` per-request client creation (iter-16 fix)**: the iter-15
  implementation built a new `reqwest::Client` on every proxy call for services
  with a custom CA certificate. `reqwest::Client` maintains a connection pool;
  creating a new instance per request defeats connection reuse and forces a full
  TLS handshake on every call to that service. CA-cert clients are now built
  once at startup and stored in `AppState::ca_cert_clients`, keyed by service
  name, so the connection pool is preserved across concurrent requests.

- **`ca_cert` PEM validation at load time (iter-16 fix)**: the iter-15 check
  only confirmed that the `ca_cert` file was readable (`std::fs::read` success),
  but did not validate the PEM content. A file containing garbage or a DER-encoded
  cert (rather than PEM) passed the load-time check and would have failed at
  first request time with a cryptic TLS error. The registry now calls
  `reqwest::Certificate::from_pem()` at load time so malformed CA cert files
  are caught immediately with a clear error message.

- **`--allow-root` registered with clap (iter-16 fix)**: the `--allow-root` flag
  was parsed via `std::env::args().any()` (invisible to `--help`) rather than
  as a proper clap argument. It is now a first-class clap flag, appearing in
  `--help` output and the README CLI reference table.

- **`UPSTREAM_BODY_LIMIT_MB` env-var override (iter-16)**: the 32 MB upstream
  response body cap was a hardcoded constant. Operators with legitimate large
  responses (binary files, bulk exports) can now set `UPSTREAM_BODY_LIMIT_MB`
  to override the limit. Values below 1 MB or above 2048 MB fall back to the
  default with a warning.

### Security fixes and features (iteration 15)

- **Upstream response body cap (iter-15)**: `resp.bytes()` on an upstream response
  previously had no size limit — a malicious upstream returning a 10 GB body
  would exhaust the proxy's heap. A 32 MB cap (overridable via
  `UPSTREAM_BODY_LIMIT_MB`) is now applied via both `Content-Length` header
  pre-check and post-read byte-count check.

- **Custom CA certificate per service (iter-15)**: services.toml now accepts a
  `ca_cert = "/path/to/ca.pem"` field per `[[service]]` block. vault-proxy builds
  a dedicated reqwest client that trusts the specified CA, enabling services signed
  by a private/internal CA without disabling all TLS verification (`insecure_tls`).
  The file is validated at startup; missing or malformed cert files skip the service
  with an error log.

- **Root-user security warning (iter-15)**: vault-proxy now logs a prominent
  `SECURITY:` warning at startup when running as uid 0, with instructions to use
  a non-root user. Pass `--allow-root` to suppress the warning when root is
  genuinely required (e.g. TPM `/dev/tpm0` access without udev rules).

- **Proactive token refresh (iter-15)**: vault-proxy now proactively refreshes
  the Vaultwarden access token when it is within 5 minutes of expiry, before the
  token is used for the next request. This eliminates the reactive 401 → refresh →
  retry path that added ~200 ms latency on the first request after token expiry.
  Concurrent proactive refreshes are serialised via `reauth_mutex` with a
  short-circuit: if the token already changed while waiting, no re-auth is made.

- **Resync cooldown (iter-15)**: `POST /vault/resync` now enforces a 30-second
  per-endpoint cooldown (`last_resync_unix` in `AppState`) so an MCP client
  cannot trigger full-vault syncs at the global rate-limit cadence (60/min).

- **Startup configuration summary (iter-15)**: vault-proxy logs a single
  structured summary line at startup listing `listen`, `services`, `vault_folder`,
  `config_dir`, `tpm_active`, `cloud_sync`, `dashboard_listen`, and
  `proxy_timeout_s`. No sensitive values (email, passwords, paths with credentials)
  are included.

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
