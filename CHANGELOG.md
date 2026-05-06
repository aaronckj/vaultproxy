# Changelog

All notable changes to vaultproxy are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0-beta.4] — iteration 110: ok:true complete, list_items breaking-change docs

### BREAKING CHANGE (iter-109/110)

- **`GET /vault/items` response format changed** — `src/vault/handlers.rs:757`.
  **Before (≤ iter-108):** `[{"id":"...","name":"..."},...]` (bare JSON array)
  **After (iter-109+):** `{"ok": true, "items": [{"id":"...","name":"..."},...]}`

  **Migration:** Any caller treating the response body as a JSON array must be updated to read
  `body["items"]` instead. The Connecterr TypeScript client (`sidecar-client.ts:listVaultItems`)
  has been updated in iter-110. Raw `curl` scripts or other consumers that iterate the body
  directly must be updated to unwrap `body.items`.

### Bugs (iter-110) — collection/mutation handlers missing `"ok": true`

- **`list_duplicates` success missing `"ok": true` (iter-110)** — `src/vault/handlers.rs:768`. MEDIUM.
  Return type was `Json<Vec<DuplicateGroup>>` — a bare array with no `"ok"` sentinel.
  Every other collection success path wraps in an object with `"ok": true`. Fixed: return type
  changed to `Json<Value>`; response is now `{"ok": true, "groups": [...]}`.

- **`list_folders` success missing `"ok": true` — both paths (iter-110)** — `src/vault/handlers.rs:827`. MEDIUM.
  Both the default (scoped) path and the `?include_all=true` path returned bare `Vec<FolderInfo>`
  with no `"ok"` sentinel. Return type changed to `Json<Value>`; both paths now return
  `{"ok": true, "folders": [...]}`.

- **`list_untracked_items` success missing `"ok": true` (iter-110)** — `src/vault/handlers.rs:966`. MEDIUM.
  Response was `{"count": N, "items": [...]}` — the two data fields were present but `"ok": true`
  was absent. Added `"ok": true` to the top-level object. The `count` and `items` keys are unchanged.

### Bugs (iter-110) — Connecterr TS client uses pre-iter-109 array shape

- **`listVaultItems()` treats response as bare array (iter-110)** — `Connecterr/src/sidecar-client.ts:229`. HIGH.
  After iter-109 changed `GET /vault/items` from a bare array to `{"ok": true, "items": [...]}`,
  `listVaultItems()` still called `res.json() as unknown[]` — wrapping the entire object as if
  it were the array. All callers received an array of `[object Object]` tokens silently.
  Fixed: response is now parsed as `{ok, items}` and `body.items ?? []` is returned, preserving
  the `unknown[]` return type.

### Tests (iter-110)

- **`list_items_returns_ok_true_and_items_array` integration test (iter-110)** — `src/proxy/mod.rs`.
  `GET /vault/items` had no test asserting the post-iter-109 response shape. Without this, a
  regression to the bare-array format would go undetected. New test wires the handler against a
  stub vault and verifies `body["ok"] == true` and `body["items"]` is an array. Gate: no feature
  flag required.

### Quality gates (iter-110)

- `cargo build --features browser,engine,dashboard` — 0 errors, 0 warnings
- `cargo test --all-targets --features browser,engine,dashboard` — **290 passed**; 0 failed
- `cargo clippy --features browser,dashboard --all-targets -- -D warnings` — 0 errors, 0 warnings
- `cargo doc --no-deps --features browser,engine,dashboard` — 0 warnings

---

## [Unreleased] — iteration 107: browser_status ok:true, vault_folder_found test, README rotate note

### Bugs (iter-107)

- **`browser_status` idle path missing `"ok": true` (iter-107)** — `src/main.rs:2804`. MEDIUM.
  The idle branch returned `{"status": "idle"}` without `"ok": true`. Every other success path
  in the codebase carries the `ok` sentinel; callers using `body["ok"] == true` for success
  detection silently received `null` here. Fixed to `{"ok": true, "status": "idle"}`.

### Tests (iter-107)

- **`browser_status_idle_returns_200` now asserts `ok=true` (iter-107)** — `src/main.rs`.
  The iter-106 test only checked `status=idle`. Updated to also assert `body["ok"] == true`
  so the fix above has regression coverage.

- **`vault_folder_found` health-field shape tests (iter-107)** — `src/vault/handlers.rs`.
  Issue (iter-103) added `vault_folder_found: bool` to `GET /vault/health` but no unit test
  covered its two states. Added `vault_folder_found_tests` module with two tests:
  - `vault_folder_found_true_when_folder_resolves`: asserts `vault_folder_found=true` and
    `vault_item_count` is scoped to the configured folder (not the cross-folder total).
  - `vault_folder_found_false_when_folder_not_found`: asserts `vault_folder_found=false` and
    `vault_item_count=0` when the configured folder name is absent from the vault (e.g. renamed
    in Vaultwarden), distinguishing misconfiguration from a legitimately empty folder.

### Findings (iter-107) — no-change items

- **`post-v1.0:` annotation in `sanitize.rs` — already removed (iter-107 check)**.
  `src/security/sanitize.rs` has no `post-v1.0:` annotation. It was removed when iter-87 wired
  `sanitize_output` in `browser/vision.rs`. The comment in `vision.rs:11` only records the
  history ("was tagged post-v1.0: in iter-85"). No action needed.

- **`credaudit_apply` response structure — clean (iter-107 check)**.
  `src/dashboard/api.rs:1742`: `Ok(out) => Json(json!({"ok": true, "result": out}))`.
  The apply result is nested under `"result"`, not merged flat and not the raw bare `json!(out)`
  from before iter-106. Structure is intentional and consistent with `credaudit_run_detail`
  which also wraps under `"detail"`.

- **`credaudit_verify_start` success merges cleanly (iter-107 check)**.
  `src/dashboard/api.rs:1779`: `Ok(n) => Json(json!({"ok": true, "verify_started_for": n, "run_id": run_id}))`.
  `"ok": true` merges flat with the two result fields — no nesting conflict.

- **CHANGELOG archive reference present (iter-107 check)**.
  `CHANGELOG.md` footer already references `CHANGELOG-pre-1.0.md`. No fix needed.

- **README has no broken CHANGELOG links (iter-107 check)**.
  `README.md` does not link to specific CHANGELOG sections. The `v0.2 tooling` mention at
  line 218 is a stub note for the `/rotate` endpoint — not a broken link.

- **4 genuine `post-v1.0:` items remain (iter-107 count)**:
  1. `src/keystore.rs:333` — TPM auto-unlock path (requires TPM feature wiring)
  2. `src/proxy/unifi_session.rs:90` — rotation UI (browser rotation workflow)
  3. `src/sync/cloud.rs:40` — Bitwarden cloud password change
  4. `src/sync/cloud.rs:786` — dashboard cloud-account settings page
  None are newly tractable from recent changes.

### Quality gates (iter-107)

- `cargo build --features browser,engine,dashboard` — 0 errors, 0 warnings
- `cargo test --features browser` — **289 passed**; 0 failed
- `cargo clippy --features browser,dashboard --all-targets -- -D warnings` — 0 errors, 0 warnings
- `cargo doc --no-deps --features browser,engine,dashboard` — 0 warnings

---

## [Unreleased] — iteration 106: credaudit ok:false, browser_status test, clippy/doc clean

### Security (iter-106) — credaudit handlers missing `"ok": false`

- **`credaudit_unavailable()` missing `"ok": false` (iter-106)** — `src/dashboard/api.rs:1662`.
  The shared fallback returned `{"error": "credential audit unavailable: ..."}` without `"ok": false`.
  All 6 credaudit handlers that call this helper propagated the missing field. Fixed centrally.

- **`credaudit_runs_list` success + error bodies missing `"ok"` (iter-106)** — `src/dashboard/api.rs:1672`.
  Success returned `{"runs": [...]}` without `"ok": true`; error returned `{"error": "..."}` without
  `"ok": false`. Fixed to `{"ok": true, "runs": [...]}` and `{"ok": false, "error": "..."}`.

- **`credaudit_run_detail` success + error bodies missing `"ok"` (iter-106)** — `src/dashboard/api.rs:1686`.
  Same pattern. Fixed to `{"ok": true, "detail": {...}}` and `{"ok": false, "error": "..."}`.

- **`credaudit_scan_start` success + error bodies missing `"ok"` (iter-106)** — `src/dashboard/api.rs:1700`.
  Success returned `{"run_id": "..."}` without `"ok": true`. Error returned without `"ok": false`. Fixed.

- **`credaudit_apply` success + error bodies missing `"ok"` (iter-106)** — `src/dashboard/api.rs:1732`.
  Success returned bare `json!(out)` without `"ok": true`. Error missing `"ok": false`. Fixed.

- **`credaudit_telemetry` error body missing `"ok": false` (iter-106)** — `src/dashboard/api.rs:1751`.
  Error path returned `{"error": "..."}` without `"ok": false`. Fixed.

- **`credaudit_verify_start` run_id error + success + error missing `"ok"` (iter-106)** — `src/dashboard/api.rs:1768`.
  Three paths all missing `"ok"`. Fixed to standard shapes.

### Tests (iter-106)

- **`browser_status` 503 tests added (iter-106)** — `src/main.rs:browser_status_tests`.
  Iter-105 fixed `browser_status` to return 503 when browser is not configured, but no test was
  added. Two tests now verify the fix: `browser_status_none_returns_503` (HTTP 503 + `ok=false`)
  and `browser_status_idle_returns_200` (HTTP 200 + `status=idle`). Gate: `--features browser`.

### Quality gates (iter-106)

- **Unused `Path` import fixed (iter-106)** — `src/dashboard/api.rs:4`. The `Path` extractor was
  imported at the top-level but is only used by `cfg(feature = "engine")` credaudit handlers.
  Moved to a `#[cfg(feature = "engine")] use axum::extract::Path;` to suppress the
  `unused-imports` clippy warning when building with `--features dashboard` only.

- **`cred_audit_orch` dead-field warning fixed (iter-106)** — `src/dashboard/mod.rs:55`.
  The `#[cfg(not(feature = "engine"))]` placeholder field `pub cred_audit_orch: Option<()>`
  triggered `dead_code` with `--features dashboard`. Added `#[allow(dead_code)]` with a
  comment explaining the structural-symmetry intent.

- **Cargo doc `<Value>` HTML warnings fixed (iter-106)** — `src/vault/handlers.rs:3443,3508,3698`.
  Three doc comments contained `Json<Value>` with unescaped `<Value>` tags that rustdoc parsed
  as unclosed HTML. Wrapped all occurrences in backtick code spans (`` `Json<Value>` ``). Now
  `cargo doc --no-deps --features browser,engine,dashboard` produces **0 warnings**.

- `cargo build --features browser,engine,dashboard` — 0 errors, 0 warnings
- `cargo test --features browser` — **257 + browser_status_tests** passed; 0 failed
- `cargo clippy --features browser,dashboard --all-targets -- -D warnings` — 0 errors, 0 warnings
- `cargo doc --no-deps --features browser,engine,dashboard` — **0 warnings** (down from 6)

## [1.0.0-beta.3] — iterations 104–105: browser handler ok:false, dashboard body audit, vault_folder_found runbook

### Security (iter-105) — dashboard/api.rs `ok:false` body audit

- **`require_app` error body missing `"ok": false` (iter-105)** — `src/dashboard/api.rs:22`.
  The `require_app` helper returned `{"error": "vault not initialized..."}` without `"ok": false`.
  All 15 handlers that early-return on `Err(e)` from this helper propagated the missing field.
  Fixed in one place: callers gain the fix automatically.

- **`browser_screenshot` "not configured" missing `"ok": false` (iter-105)** — `src/dashboard/api.rs:423`.
  `None` (browser not configured) returned `{"error": "not configured"}` without `"ok": false`.
  Fixed to `{"ok": false, "error": "browser agent not configured"}`.

- **`browser_rotate` network-error path missing `"ok": false` (iter-105)** — `src/dashboard/api.rs:445`.
  The HTTP request failure path returned `{"error": "..."}` without `"ok": false`. Fixed.

- **`browser_abort` network-error path missing `"ok": false` (iter-105)** — `src/dashboard/api.rs:461`.
  Same pattern as `browser_rotate`. Fixed.

- **`respond_approval` "not found" missing `"ok": false` (iter-105)** — `src/dashboard/api.rs:292`.
  The "approval not found" path returned `{"error": "approval not found"}` without `"ok": false`.
  Fixed.

- **`save_policy` save-error missing `"ok": false` (iter-105)** — `src/dashboard/api.rs:210`.
  `Err` path from `save_policies` returned `{"error": "..."}` without `"ok": false`. Fixed.

- **`delete_policy_handler` delete-error missing `"ok": false` (iter-105)** — `src/dashboard/api.rs:229`.
  Same pattern as `save_policy`. Fixed.

- **`save_profiles_handler` parse and save errors missing `"ok": false` (iter-105)** — `src/dashboard/api.rs:1199`.
  Two error paths (JSON parse failure, file save failure) returned `{"error": "..."}` without
  `"ok": false`. Fixed.

- **`setup_cloud_via_dashboard` network-error missing `"ok": false` (iter-105)** — `src/dashboard/api.rs:1615`.
  The sidecar forward failure returned `{"error": "..."}` without `"ok": false`. Fixed.

### Security (iter-105) — main.rs `browser_status` silent HTTP 200

- **`browser_status` "not configured" returns HTTP 200 (iter-105)** — `src/main.rs:2779`. HIGH.
  Return type was `AxumJson<serde_json::Value>` — the "browser agent not configured" path
  returned HTTP 200 instead of 503. Iter-104 fixed `browser_rotate`, `browser_screenshot`,
  and `browser_abort` but missed `browser_status`. Changed return type to
  `axum::response::Response`; not-configured path now returns HTTP 503 with
  `{"ok": false, "error": "browser agent not configured"}`.

### Security (iter-104) — browser_rotate silent-200 paths

- **`browser_rotate` 6 silent-200 error paths (iter-104)** — `src/browser/rotate.rs` and
  `src/main.rs`. CRITICAL. Six error branches in `browser_rotate` returned HTTP 200 with
  error bodies due to `Json<Value>` return type. Changed to `impl IntoResponse`; all
  error paths now return appropriate non-200 status codes (503 not-configured, 400 bad
  request, 500 internal error) with `"ok": false`.

- **`rotate.rs` 501 Not Implemented stub (iter-104)** — `src/browser/rotate.rs`.
  Placeholder implementation returned `{"status": "not_implemented"}` at HTTP 200.
  Changed to HTTP 501 with `{"ok": false, "error": "not implemented"}`.

### Tests (iter-104)

- **8 new tests for `browser_rotate` error paths** — `src/main.rs:browser_rotate_guard_tests`.
  `not_configured_returns_503`, `empty_litellm_url_returns_error`, `invalid_site_returns_400`,
  `no_credential_returns_error`, and 4 additional guard tests. Gate: `--features browser`.

### Documentation (iter-105)

- **README Operator Runbook: `vault_folder_found` diagnosis** — `README.md`.
  Added a new runbook entry: "Services return 404 / `vault_item_count: 0` after a Vaultwarden
  folder rename". Explains how to use `GET /vault/health` → `vault_folder_found: bool` to
  distinguish a folder rename (actionable) from a legitimately empty vault (benign).
  Iter-103 added the field; iter-105 documents it in the runbook.

### Quality gates (iter-105)

- `cargo build --features browser,engine,dashboard` — 0 errors, 0 warnings
- `cargo test --all-targets --features browser,engine,dashboard` — **285 passed**; 0 failed
- `cargo clippy --all-targets --features browser,engine,dashboard -- -D warnings` — 0 errors, 0 warnings
- `cargo fmt --check` — 0 diffs

## [1.0.0-beta.2] — iterations 101–103: 503/409/207 body correctness, vault_folder_found, ok:false audit

### Security (iter-103)

- **`scan_start` return type trap (iter-103)** — `src/credential_audit/handlers.rs:28`. CRITICAL.
  Return type was `Result<Json<Value>, StatusCode>`. Bare `StatusCode` on the Err path produced
  a response with the correct HTTP status (409/503/500) but an **empty body** — no `"ok": false`,
  no `"error"` field. Any caller parsing the JSON body received an empty string. Changed to
  `axum::response::Response` so all branches emit a full JSON body. Addresses the TODO added in
  iter-34 which correctly identified the problem but could not fix it without a signature change.
  Severity: CRITICAL — this was the same `Json<Value>` return-type trap fixed in iter-102 for
  vault handlers, now propagated to the credential audit subsystem.

- **`review_pending` and `apply` missing `"ok": false` (iter-103)** — `src/credential_audit/handlers.rs:68,90`.
  Both handlers returned error tuples `(StatusCode, Json<Value>)` with correct status codes but
  bodies missing `"ok": false`. Every other non-200 response in the codebase includes `"ok": false`;
  callers using `body["ok"] == false` for status detection would not detect these errors.
  Added `"ok": false` to all error JSON bodies in `review_pending` (404, 500) and `apply` (404, 400).

- **`require_internal_token` 401 missing `"ok": false` (iter-103)** — `src/main.rs:2865`.
  The 401 body returned `{"error": "...", "hint": "..."}` without `"ok": false`. Added for
  consistency. All internal-endpoint callers (dashboard, Connecterr) use `ok` as the success signal.

- **`dns_rebinding_guard` 403 bodies missing `"ok": false` (iter-103)** — `src/main.rs:2936,2946`.
  Both 403 paths (missing Host, invalid Host) returned `{"error": "..."}` without `"ok": false`.
  Added for consistency with the 87 other `"ok": false` occurrences in the codebase.

- **Dashboard fallback 404 missing `"ok": false` (iter-103)** — `src/dashboard/mod.rs:204`.
  The `.fallback()` handler returned `{"error": "not found"}` without `"ok": false`. Fixed.

- **`require_session` 401 missing `"ok": false` (iter-103)** — `src/dashboard/mod.rs:614`.
  The dashboard API session-guard middleware returned `{"error": "authentication required"}`
  without `"ok": false`. Fixed. Dashboard JS checks `response.ok` via fetch, but API callers
  using the JSON body were getting an inconsistent shape.

- **`vault_folder_found: bool` added to `GET /vault/health` (iter-103)** — `src/vault/handlers.rs`.
  `vault_item_count: 0` was ambiguous: it could mean a legitimately empty folder or that the
  configured `vault_folder` name was not found in the vault (e.g. renamed in Vaultwarden UI).
  Monitoring that alerts on `vault_item_count == 0` would fire on a folder rename even though
  no data was lost. New field `vault_folder_found: bool` disambiguates:
  - `vault_folder_found: true, vault_item_count: 0` → folder exists but is empty (legitimate).
  - `vault_folder_found: false` → folder name not found → alert on misconfiguration, not data loss.

### Security (iter-102) — 7 critical `Json<Value>` return-type fixes

- **`handshake` 409 replay prevention (iter-102)** — `src/vault/handlers.rs:1328`. CRITICAL.
  `GET /handshake` returned HTTP 200 on replay (second call after handshake completed) with the
  *same cert material* rather than 409 Conflict. Return type changed from `Json<Value>` to
  `impl IntoResponse`; replay now returns 409 with `{"ok": false, "error": "..."}`. The 503 path
  (certs unavailable) was similarly silently returning 200 — now returns 503 with `"ok": false`.

- **`check_permission` 400 on missing tool param (iter-102)** — `src/vault/handlers.rs:3037`. CRITICAL.
  `GET /vault/check-permission?tool=` returned HTTP 200 with an error body when the required `tool`
  param was missing. Changed return type to `impl IntoResponse`; missing/empty param now returns
  HTTP 400 with `{"ok": false, "error": "tool query param required"}`.

- **`sync_trigger` 503/503 silent 200 (iter-102)** — `src/vault/handlers.rs:3443`. CRITICAL.
  `POST /sync/trigger` returned HTTP 200 for sync failures and for "cloud sync not configured".
  Return type changed from `Json<Value>` to `impl IntoResponse`; failure paths now return 503.

- **`sync_init` 409/503/502/207 silent 200 (iter-102)** — `src/vault/handlers.rs:3508`. CRITICAL.
  `POST /sync/init` returned HTTP 200 for all error paths: already-active (now 409), keystore
  unlock failure (now 503), auth failure (now 502), initial sync failure partial (now **207 Multi-Status**).
  HTTP 207 signals partial success: authenticated OK but initial sync failed — the cloud sync
  is initialized and subsequent `POST /sync/trigger` or the background scheduler will complete it.
  Callers receiving 207 should log a warning and retry sync; 207 is NOT a failure.

- **`provide_totp` 503/503/401/207 silent 200 (iter-102)** — `src/vault/handlers.rs:3698`. CRITICAL.
  `POST /sync/totp` returned HTTP 200 for all error paths: keystore unlock failure (now 503),
  no cloud credentials (now 503), TOTP auth failure (now 401), partial sync (now 207 Multi-Status).

- **`sync_check_password` 503 `"ok": false` missing (iter-102)** — `src/vault/handlers.rs:3683`.
  The 503 path in `sync_check_password` was missing `"ok": false` in the body, inconsistent
  with all other 503 paths. Added.

- **`sync_restart` 503 `"ok": false` missing (iter-102)** — `src/vault/handlers.rs:3871`.
  Same issue as `sync_check_password` — 503 body was missing `"ok": false`. Added.

### HTTP 207 Multi-Status — callers must handle partial success

`POST /sync/init` and `POST /sync/totp` may return **HTTP 207 Multi-Status** when:
- Authentication succeeded (cloud credentials validated, device token stored), AND
- The initial sync run failed (network error, vault timeout, etc.).

HTTP 207 is not an error; it signals that the cloud sync is **initialized but not yet synced**.
The scheduler or a manual `POST /sync/trigger` will complete the sync. Callers MUST NOT treat
207 as a success (200) or a failure (5xx). Check `body["result"] == "partial"` to confirm.

### Security (iter-101)

- **`generate_totp` 503 body consistency (iter-101)** — `src/vault/handlers.rs:2781`.
  When `item_in_vault_folder` returns `None` (vault_folder not found), `generate_totp`
  previously returned **HTTP 200** (not 503) with `{"error":"..."}` and no `"ok": false`,
  because the handler's return type was `Json<Value>`. Changed return type to
  `impl IntoResponse`; the `None` branch now returns **HTTP 503** with `{"ok": false, "error": "..."}`,
  consistent with `write_env`, `inject_creds`, and `reload_services`. The `Some(false)` scope-violation
  branch similarly upgraded to **HTTP 403** (was 200). CRITICAL: callers that checked the body
  `error` field would have blocked, but monitoring that inspects HTTP status codes would not
  have detected the scope-verification failure.

- **`decrypt_notes` 503 body consistency (iter-101)** — `src/vault/handlers.rs:2880`.
  Same root cause as `generate_totp`: `Json<Value>` return type silently downgraded 503 to 200.
  Changed to `impl IntoResponse`; `None` branch returns **HTTP 503** with `{"ok": false, "error": "..."}`.
  The `Some(false)` branch returns **HTTP 403**. The success path returns **HTTP 200** as before.

### Tests (iter-101)

- **`list_duplicates_returns_empty_when_vault_folder_not_found`** — new test in
  `folder_scope_guard_tests` verifying the iter-100 empty-list behaviour for `list_duplicates`.
  Covers the `None` branch: vault_folder_id not resolved, duplicate groups exist in other folders.

- **`list_untracked_returns_empty_when_vault_folder_not_found`** — new test in
  `folder_scope_guard_tests` verifying the iter-100 empty-list behaviour for `list_untracked_items`.
  Covers the `None` branch: vault_folder_id not resolved, untracked items exist across folders.

### Housekeeping (iter-101)

- **Labeled bare `#[allow(dead_code)]` suppressions** — `src/vault/handlers.rs:350,376,394,439`.
  `UpdateItemRequest`, `CloneItemRequest`, `TestCredentialRequest`, and `WriteEnvRequest` had
  bare `#[allow(dead_code)]` with no explanatory comment. Added `// fields read by serde deserialization`
  to match the convention used by adjacent structs (`DeleteItemRequest`, `MoveItemRequest`, etc.).

- **`vault_item_count: 0` when vault_folder not found** — documented in this CHANGELOG and
  inline in `src/vault/handlers.rs:504–520`. Operators monitoring `vault_item_count` from
  `GET /vault/health` should be aware that a drop to `0` reflects a folder rename (vault_folder
  configured but absent) rather than data loss. The startup log warns when vault_folder is
  not found; `POST /vault/resync` re-resolves after an operator corrects the folder name.
  See iter-103 fix: `vault_folder_found: bool` now makes this explicit in the health response.

### Quality gates (iter-103)

- `cargo build --features browser,engine,dashboard` — 0 errors, 0 warnings
- `cargo test --all-targets --features browser,engine,dashboard` — **280 passed** (278 lib + 2 integration); 0 failed
- `cargo clippy --all-targets --features browser,engine,dashboard -- -D warnings` — 0 errors, 0 warnings
- `cargo fmt --check` — 0 diffs

## [1.0.0-beta.1] — **MILESTONE: First Beta Release** — iterations 99–100: scope hardening complete

> **v1.0.0-beta.1 rationale:** The stable core is production-hardened across 100 audit iterations,
> 278 tests, 0 clippy warnings, 0 dead-code warnings, and complete vault-folder scope guards on
> all read, write, and credential-decrypting paths. The 4 remaining `post-v1.0:` items
> (TPM auto-unlock, Bitwarden cloud password change, dashboard cloud settings, session-rotation UI)
> all live in optional feature-gated code paths. The default feature set is production-ready.
> This tag begins the release-candidate process. Scope guard coverage is now uniform across every
> handler type (listing, credential-decryption, write, self-protection).

### Security (iter-100)

- **`list_duplicates` empty-on-vault-folder-not-found (iter-100)** — `src/vault/handlers.rs`.
  When `vault_folder` is configured but not found, `list_duplicates` previously passed `None`
  to `list_duplicates_in_folder` which scanned ALL vault items — exposing duplicate-credential
  groups from personal folders. Now returns an **empty list** with a `warn!` log. Consistent
  with the iter-99 precedent for `list_items`.

- **`list_untracked_items` empty-on-vault-folder-not-found (iter-100)** — `src/vault/handlers.rs`.
  When `vault_folder` is not found, `list_untracked_items` previously returned all untracked
  items regardless of folder — exposing names/IDs of items from every folder. Now returns
  `{"count": 0, "items": []}` with a `warn!` log.

- **`item_in_vault_folder` now returns `Option<bool>` — blocking on folder-not-found
  (iter-100)** — `src/vault/handlers.rs`. Previously returned `true` permissively when
  `vault_folder` was not found, allowing `inject_creds`, `generate_totp`, and `decrypt_notes`
  to proceed to credential decryption without any scope verification. Now returns `None`;
  all three handlers treat `None` as a blocking error and return 503 Service Unavailable.
  SECURITY.md updated.

- **`GET /vault/health` `vault_item_count` now scoped to `vault_folder` (iter-100)** —
  `src/vault/handlers.rs`. Previously called `state.vault.list_items()` — an unscoped count
  of all vault items — meaning a renamed `vault_folder` would inflate the count with personal
  items from other folders. Now filters by resolved folder ID; returns `0` when
  `vault_folder` is not found (consistent with `list_items`).

### Security (iter-99)

- **`list_items` empty-on-vault-folder-not-found (iter-99)** — `src/vault/handlers.rs`.
  When `vault_folder` is configured but not found in the vault (e.g. renamed in Vaultwarden
  without updating `--vault-folder`), `list_items` previously returned ALL vault items as a
  "fresh vault permissive fallback". This leaked cross-folder metadata — names, usernames, URIs
  from personal banking, SSH-key, and other personal folders — even though passwords are masked.
  Now returns an **empty list** with a `warn!` log entry. SECURITY.md updated.

- **`write_env` success response no longer echoes `target_path`** — `src/vault/handlers.rs`.
  The 200 OK success body previously included `"target_path": "/config/envs/sonarr.env"` — an
  absolute filesystem path that leaks the host's directory layout to any log consumer or MCP
  caller that captures the response. Removed: `"target_path"` field. Remaining fields:
  `"ok": true`, `"updated": [...]`, `"inserted": [...]`.

### Refactoring (iter-99)

- **`item_name_is_in_folder` moved to `#[cfg(test)]` impl block** — `src/vault/mod.rs`.
  After iter-96 switched all three production call sites to `item_in_vault_folder` (the
  cache-aware wrapper), `item_name_is_in_folder` had zero production callers and carried
  `#[allow(dead_code)]`. Moved into the `#[cfg(test)] impl VaultManager` block — excluded
  from production binaries.

### Tests

- **`list_items_returns_empty_when_vault_folder_not_found`** — new test in
  `folder_scope_guard_tests` verifying the iter-99 empty-list behavior.
- **`item_in_vault_folder` tests updated (iter-100)** — `returns_true_permissively_when_folder_not_found`
  renamed to `returns_none_when_folder_not_found`; assertions updated from `true` to `None` to
  match the new `Option<bool>` return type. `returns_true_when_item_is_in_vault_folder` /
  `returns_false_when_item_is_in_wrong_folder` updated to assert `Some(true)` / `Some(false)`.

### Quality gates (iter-100 — 100th audit milestone)

- `cargo build --features browser,engine,dashboard` — 0 errors, 0 warnings
- `cargo test --all-targets --features browser,engine,dashboard` — **278 passed**; 0 failed
- `cargo clippy --all-targets --features browser,engine,dashboard -- -D warnings` — 0 errors, 0 warnings
- `cargo fmt --check` — 0 diffs
- `cargo doc --no-deps --features browser,engine,dashboard` — 0 warnings

---

*Pre-v1.0 development history (iterations 1–103, versions 0.1.0 – 0.3.4) has been
archived to [`CHANGELOG-pre-1.0.md`](CHANGELOG-pre-1.0.md).*

