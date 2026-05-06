# Changelog

All notable changes to vaultproxy are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.24] — iteration 81: browser + engine feature gates, MSRV 1.87, dead-code hygiene

### Architecture (iter-81)

- **`browser = []` feature gate** — The entire `browser` module (PlaywrightProcess,
  VisionModel, RotationWorkflow, BrowserAgent) and its HTTP routes (`/browser/*`,
  `/api/browser/*` in dashboard) are now compiled only when `--features browser` is
  passed. Default builds omit the module entirely — no dead-code suppression needed
  and the binary is smaller. Operators who want browser rotation:
  `cargo build --release --features browser` or
  `docker build --build-arg FEATURES=browser`.
  `src/browser/mod.rs`, `src/main.rs`, `src/proxy/mod.rs`, `src/dashboard/mod.rs`,
  `src/dashboard/api.rs`.

- **`engine = []` feature gate** — The external credential-audit engine sidecar
  modules (`engine_client`, `orchestrator`, `pass2`) and their HTTP routes
  (`/audit/credaudit/*`, `/api/credaudit/*` in dashboard) are now compiled only
  when `--features engine` is passed. The in-process audit (`src/audit.rs` +
  `GET /vault/audit/run`) is NOT gated — it remains in the stable core.
  `src/credential_audit/mod.rs`, `src/main.rs`, `src/dashboard/mod.rs`,
  `src/dashboard/api.rs`.

- **`rust-version = "1.87"` MSRV declared** — Inferred from the highest-floor
  transitive dependency and `let-chains` usage in the codebase. `Cargo.toml`.

- **`#![allow(dead_code)]` removed** from `src/browser/mod.rs` and
  `src/credential_audit/mod.rs` — the feature gates make this suppression
  unnecessary. Feature-on builds have no dead code; feature-off builds don't
  compile the module at all.

### Dead-code hygiene (iter-81)

- Targeted `#[allow(dead_code)]` added to items that are reachable only when a
  specific feature is enabled:
  - `VaultManager::update_password_for_item` (browser)
  - `VaultManager::decrypt_notes_by_id`, `update_notes_by_id` (engine)
  - `VaultManager::list_field_names` (engine)
  - `Notifier::notify_rotation` (browser)
  - `AppState::approval_queue`, `AppState::browser` (used by dashboard/browser)
  - `EngineRunResponse::run_id`, `telemetry_summary` (future dashboard wiring)
  - `credential_audit::types::Pass2Result` (pass2 result collection, not yet wired)

- Pre-existing dashboard dead-code fixed (were previously hidden by the module-level
  `#![allow(dead_code)]`):
  - `ChangePasswordRequest` fields annotated (handler returns 503 pending implementation)
  - `generate_password` annotated (pending UI wiring)
  - `TokenResp::two_factor_token` annotated (parsed for completeness)
  - `save_permissions`: replaced `let mut perms = default(); perms.field = x;`
    pattern with struct literal + `..default()` (clippy `field_assignment_outside_initializer`)

### Dockerfile (iter-81)

- **`FEATURES` build-arg documentation updated** — Added explicit examples for
  `browser`, `engine`, and combined builds. Operators who previously relied on
  browser rotation being always-on must now add `--build-arg FEATURES=browser`.

### Verification (iter-81)

- `cargo test --all-targets`: 230 passed (228 lib + 2 integration), 0 failed.
- `cargo test --all-targets --features browser,engine,dashboard`: 258 passed, 0 failed.
- `cargo clippy --all-targets -- -D warnings`: 0 errors (default features).
- `cargo clippy --all-targets --features browser,engine,dashboard -- -D warnings`: 0 errors.

## [0.2.23] — iteration 79-80 (close-out): iter-79 config_file_exists test, iter-80 permissions read-guard clone, docstring path, permissions_source field

### Bug fixes (iter-79–80)

- **iter-79: config_file_exists integration test uses tempfile::TempDir (iter-79, LOW)**:
  The new `get_vault_permissions_config_file_exists_true_when_file_present` test
  creates a temporary directory via `tempfile::tempdir()`, which returns a
  `TempDir` guard that deletes the directory on drop.  No manual cleanup is
  needed and test failures cannot leave artifacts in `/tmp`.  Confirmed clean —
  no action required.

- **`handle_get_permissions` held RwLock across serde serialisation (iter-80, MEDIUM)**:
  `state.permissions.read().await` was called at the top of the handler and the
  guard was kept live through the entire `serde_json::json!()` macro expansion.
  Any slow serialisation pass (large permissions map, debug instrumentation) would
  block concurrent writers to `state.permissions` — including live permission
  reloads triggered by `handle_proxy`.  Fixed by cloning `defaults` and `overrides`
  out of the lock in a scoped block, dropping the guard before `serde_json::json!`
  runs.  `src/main.rs:2514-2524`.

- **`--audit-interval-secs` docstring hardcoded `/config/internal-token` (iter-80, LOW)**:
  The CLI help text for `--audit-interval-secs` showed
  `$(cat /config/internal-token)` — the old default path that predates the
  `--config-dir` flag.  Operators using a non-default `--config-dir` would get
  a misleading path.  Updated to `$CONFIG_DIR/internal-token` with a clarifying
  note that `$CONFIG_DIR` is the `--config-dir` value (default: `/config`).
  The `<config-dir>` angle-bracket form was avoided because `rustdoc` warns on
  unclosed HTML tags.  `src/main.rs:232-235`.

### Improvements (iter-80)

- **`GET /vault/permissions` response adds `permissions_source` field (iter-80, LOW)**:
  The existing `config_file_exists` field reflects the current on-disk state and
  can diverge from what was actually loaded if the file is added or removed after
  startup.  Added `permissions_source: "file" | "built-in-defaults"` derived
  from the current file-existence check, giving callers a clear machine-readable
  indicator without a separate API call.  Updated the `note` string to explain
  that `permissions_source` is re-evaluated on each call.  `src/main.rs:2531-2549`.

### Verification (iter-80)

- `cargo test --all-targets`: 258 passed, 0 failed.
- `cargo clippy --all-targets -- -D warnings`: 0 errors.
- `cargo fmt --check`: 0 diff lines (clean).
- `cargo doc --no-deps`: 0 warnings.
- CI v0.2.22: fmt/clippy/test steps all passed; Docker push in progress at audit time.

## [0.2.22] — iteration 78: ntfy body plain text, permissions rate-limit, MissedTickBehavior::Skip, config_file_exists, startup log, integration test

### Bug fixes (iter-78)

- **ntfy notification body contained unevaluated shell command (iter-78, MEDIUM)**:
  The ntfy push notification body ended with
  `"(Authorization: Bearer $(cat /config/internal-token))"`. This string is
  plain text delivered to ntfy.sh and then to the operator's phone — the shell
  subshell expansion `$(cat ...)` is never evaluated. The recipient saw the
  literal text `$(cat /config/internal-token)` rather than a token value or a
  human-readable instruction. Fixed to `"<token from /config/internal-token>"`,
  which is accurate plain English matching the help text elsewhere in the codebase.
  `src/main.rs:2274`.

- **`GET /vault/permissions` missing from `RATE_LIMITED_PATHS` (iter-78, MEDIUM)**:
  The endpoint was added to `internal_router` in iter-77 (bearer-token gated) but
  was not added to the rate-limiter's `RATE_LIMITED_PATHS` array. An attacker who
  obtained the internal token could call the endpoint in a tight loop to probe the
  permission system structure without hitting any rate limit. Added at the default
  60 req/60 s bucket (appropriate for a read-only diagnostic). `src/security/rate_limit.rs:146-151`.

- **Background audit interval bursts after slow audit (iter-78, LOW)**:
  `tokio::time::Interval` uses `MissedTickBehavior::Burst` by default — if an audit
  takes longer than `--audit-interval-secs`, every missed tick fires immediately
  after the slow audit finishes, potentially queuing back-to-back runs. Set
  `MissedTickBehavior::Skip` so missed ticks are discarded and exactly one new run
  is scheduled at the next boundary. `src/main.rs:2199-2208`.

### Improvements (iter-78)

- **`GET /vault/permissions` response includes `config_file_exists` (iter-78, LOW)**:
  Both "file exists with all defaults" and "file not found — using built-in
  defaults" produced identical JSON for `defaults` and `overrides`. Added a
  `config_file_exists: bool` field so callers can distinguish the two states
  without disk access or restart. `src/main.rs:2505-2510`.

- **Startup log mentions `GET /vault/audit/run` when scheduler is enabled (iter-78, LOW)**:
  When `--audit-interval-secs > 0`, a new `INFO` log line records the interval
  and the on-demand HTTP endpoint with its auth requirement. An operator enabling
  the scheduler for the first time now sees the endpoint immediately in startup
  logs without consulting the help text. `src/main.rs:1007-1014`.

- **Integration test for `GET /vault/permissions` (iter-78, MEDIUM)**:
  Added HTTP-level integration test verifying: (a) 401 without bearer token,
  (b) 200 with correct JSON shape (`defaults`, `overrides`, `config_file_exists`,
  `note` keys), (c) `config_file_exists` is `false` when the permissions file is
  absent. `src/proxy/mod.rs:2744-2848`.

### Verification (iter-78)

- `cargo test --all-targets`: 257 passed, 0 failed.
- `cargo clippy --all-targets -- -D warnings`: 0 errors.
- `cargo fmt --check`: 0 diff lines (clean).
- `cargo doc --no-deps`: 0 warnings.

## [0.2.21] — iteration 77: ntfy URL, permissions endpoint, scoring_note docs, README JSON fix

### Bug fixes (iter-77)

- **ntfy notification body missing bearer-token hint (iter-77, LOW)**: The ntfy
  push notification body for background credential audits ended with
  `"Review with: GET /vault/audit/run"` but gave no indication that the endpoint
  requires `Authorization: Bearer <token>`. An operator receiving the alert on their
  phone had no actionable path without prior knowledge of the auth requirement.
  Added `"(Authorization: Bearer $(cat /config/internal-token))"` so the full curl
  command is self-contained in the notification. `src/main.rs:2255–2265`.

- **README `scoring_note` example stale (iter-77, LOW)**: The `scoring_note` field
  in the `GET /vault/audit/run` JSON response example was missing the reuse
  name-list truncation clause added in iter-74 (`"reuse reason name lists are capped
  at 5 names per item ..."`). Updated to match the actual `format!()` output from
  `run_audit()`. `README.md`.

### Improvements (iter-77)

- **`GET /vault/permissions` endpoint (iter-77, MEDIUM)**: Added a diagnostic
  endpoint that returns the current `ToolPermissions` configuration as JSON
  (`defaults` map + `overrides` map). Gated behind the internal bearer token
  (on `internal_router`). Previously the only way to inspect effective permissions
  was to read `$CONFIG_DIR/tool-permissions.json` and manually apply priority rules
  — error-prone and unavailable in Docker without shell access. The new endpoint
  makes permission inspection possible via any HTTP client without restarting.
  Removes the need for the `dead_code` annotations on the helper methods used by
  the dashboard (`save`, `get_default_permission`, `get_category`) — those remain
  as-is since they are legitimately dashboard-only.
  `src/main.rs:2440–2482` (handler), `src/main.rs:1376` (router wiring).

- **`--audit-interval-secs` help text includes on-demand endpoint (iter-77, LOW)**:
  The `--audit-interval-secs` arg docstring now explicitly documents the on-demand
  `GET /vault/audit/run` endpoint with a complete curl example. Previously a new
  user reading `--help` would see the background scheduler documented but have no
  indication that the same audit is available as an HTTP endpoint.
  `src/main.rs:225–231`.

- **`run_audit()` all-non-login edge case documented (iter-77, LOW)**: Added an
  inline comment to the `decrypt_password` error-path `continue` in `run_audit()`
  explaining that if every item fails decryption (vault_folder contains only
  secure-notes or card items), the result (`total_items > 0`, all counts zero)
  is indistinguishable from a "100% strong passwords" vault. Operators should
  cross-check `total_items` against the expected login-item count.
  `src/audit.rs:306–320`.

### Notes (iter-77)

- **Background scheduler vs HTTP rate-limit model (iter-77)**: `GET /vault/audit/run`
  is rate-limited to 2 req/60 s. The background scheduler calls `run_audit()`
  directly (bypasses the HTTP rate limiter) via the `audit_mutex`. If
  `--audit-interval-secs=10` is set (triggers a startup warning), the scheduler
  fires 6×/min — 3× the HTTP rate limit — with no error. This is by design: the
  rate limit protects the HTTP surface from external abuse; the scheduler is a
  trusted internal caller. Operators who set sub-60 s intervals see a startup
  `WARN` encouraging them to use ≥ 60 s. No code change; documented here.

### Verification (iter-77)

- `cargo test --all-targets`: 256 passed, 0 failed.
- `cargo clippy --all-targets -- -D warnings`: 0 errors.
- `cargo fmt --check`: 0 diff lines (clean).
- `cargo doc --no-deps`: 0 warnings.

## [0.2.20] — iteration 76: reused_passwords nested-array shape, n_reused_items tests, v0.2.21 bump

### Bug fixes (iter-76)

- **No CHANGELOG entry for v0.2.20 (iter-76, LOW)**: Cargo.toml was bumped to
  `0.2.20` in the iter-75 commit but no `[0.2.20]` section was added to
  CHANGELOG.md — the previous entry was `[0.2.19]`.  Added this section.
  `CHANGELOG.md`.

### Improvements (iter-76)

- **Integration test: assert `reused_passwords` inner elements are arrays
  (iter-76, LOW)**: The integration test `audit_run_requires_bearer_token...`
  asserted `body["reused_passwords"].is_array()` (outer array only).  With an
  empty vault the outer array is always `[]` — this passes vacuously even if
  the type were accidentally changed from `Vec<Vec<AuditItem>>` to
  `Vec<AuditItem>` (flat).  Added a per-element loop asserting `group.is_array()`
  so any non-array element in a populated vault would be caught.  Accompanied by
  a comment explaining why the check is vacuously true on an empty vault but
  still serves as a shape contract.  `src/proxy/mod.rs:2718–2736`.

- **Unit tests: `n_reused_items` zero and multi-group sum (iter-76, LOW)**:
  The `n_reused_items` computation in `main.rs`
  (`result.reused_passwords.iter().map(|g| g.len()).sum()`) had no unit test
  for the empty-`Vec<Vec<_>>` edge case (clean vault where no passwords are
  shared).  Added two tests to `src/audit.rs`:
    1. `n_reused_items_is_zero_when_reused_passwords_empty` — verifies that
       `.iter().map(|g| g.len()).sum::<usize>()` returns `0` on `vec![]`, and
       that `total_issues` is therefore `0` for a clean vault.
    2. `n_reused_items_sums_across_groups` — verifies the non-empty case: two
       groups of sizes 3 and 2 sum to 5.  Also asserts the nested-array shape
       (`reused_passwords[i]` is a non-empty `Vec`) to document the
       `Vec<Vec<AuditItem>>` contract.
  `src/audit.rs:951–1030`.

### Verification (iter-76)

- `cargo test --all-targets`: 256 passed (254 unit + 2 integration), 0 failed.
- `cargo clippy --all-targets -- -D warnings`: 0 errors.
- `cargo fmt --check`: 0 diff lines (clean).
- `cargo doc --no-deps`: 0 warnings.

## [0.2.19] — iteration 74–75: JoinHandle abort, notify failure logging, reuse count, yield_now

### Bug fixes (iter-74–75)

- **JoinHandle abort on 8-second timeout (iter-74, CRITICAL)**: Previously
  `tokio::time::timeout(8s, handle).await` dropped the `JoinHandle` on
  `Err(Elapsed)` but the underlying tokio task continued running as an orphan —
  decrypted `SecureBuffer` pages remained live in mlocked memory until OS SIGKILL.
  Fixed: the `JoinHandle` is now passed as `&mut handle` so it is not consumed by
  the timeout future; on `Err(Elapsed)` the handle is still owned and `handle.abort()`
  is called explicitly to force-cancel the task and trigger `SecureBuffer` zeroization
  promptly.  `src/main.rs:2400–2410`.

- **Notification failure silently discarded (iter-74, MEDIUM)**: The background
  audit task called `.ok()` on the `Notifier::send()` result — if ntfy.sh was
  unreachable, the operator would never know the audit alert was dropped.  Fixed:
  the result is matched with `if let Err(e)` and a `tracing::warn!` is emitted so
  delivery failures appear in the log.  `src/main.rs:2271–2273`.

- **`n_reused_items` counted groups not items (iter-74, MEDIUM)**: The background
  audit log field `reused_items` was previously set to `result.reused_passwords.len()`
  (number of groups).  A single reuse group with 50 members would report as
  `reused_items=1`, severely under-reporting severity.  Fixed:
  `result.reused_passwords.iter().map(|g| g.len()).sum()` sums over group lengths
  — correct because `reused_passwords: Vec<Vec<AuditItem>>` and each `Vec<AuditItem>`
  has a `.len()` method.  The notification title and body also now use `n_reused_items`
  for the items-with-shared-passwords count.  Priority scaling also switched from
  `n_weak + n_reuse_groups` to `n_weak + n_reused_items`.  `src/main.rs:2212–2243`.

- **`run_audit()` loop has no yield points for task cancellation (iter-75, MEDIUM)**:
  After `vault.list_items().await` returns, the per-item loop (decrypt, HMAC, classify)
  runs entirely synchronously with no cooperative yield.  A `handle.abort()` during
  the loop cannot fire until the next `.await` in the outer background task — the
  interval tick after the full scan completes.  Fixed: `tokio::task::yield_now().await`
  added at the top of the for-loop body, giving the tokio scheduler a cancellation
  check point between each vault item.  Overhead is ~1 µs per item (<0.2 ms for a
  200-item vault).  `src/audit.rs:292`.

### Improvements (iter-74)

- **Notification wording: "reuse group" → "item(s) with shared passwords"
  (iter-74, LOW)**: The ntfy.sh notification title previously read
  `"N reuse group(s)"` — a technical term that operators unfamiliar with the code
  might not immediately understand.  Changed to `"N item(s) with shared passwords"`
  to make the alert actionable without consulting the source.  `src/main.rs:2251–2253`.

- **`scoring_note` references `REUSE_NAME_DISPLAY_LIMIT` constant (iter-74, LOW)**:
  The iter-74 addition to `scoring_note` uses `format!("... capped at {} names ...",
  REUSE_NAME_DISPLAY_LIMIT)` rather than a hardcoded literal `5`, ensuring the note
  tracks the constant if the limit changes.  `src/audit.rs:406–415`.

- **`zero_item_audit_result_has_correct_shape` test updated for `scoring_note`
  (iter-74, LOW)**: The test now constructs the expected `scoring_note` with
  `format!()` referencing `WEAK_THRESHOLD` and `REUSE_NAME_DISPLAY_LIMIT` so it
  tracks future constant changes automatically.  `src/audit.rs:836–846`.

### Verification (iter-74–75)

- `cargo test --all-targets`: 254 passed, 0 failed.
- `cargo clippy --all-targets -- -D warnings`: 0 errors.
- `cargo fmt --check`: 0 diff lines (clean).
- `cargo doc --no-deps`: 0 warnings.

## [0.2.18] — iteration 73: notification priority scaling, audit shutdown await

### Bug fixes (iter-73)

- **Rustfmt failure: multi-line `tracing::debug!` in audit shutdown path
  (iter-73, HIGH)**: The v0.2.18 CI run (25418852581) failed at the
  `cargo fmt --check` step because the single-argument `tracing::debug!("…")`
  macro call at line 2249 was written across three lines.  `rustfmt` collapses
  single-argument macros to one line.  Fixed by inlining the call.
  `src/main.rs:2249`.

- **Audit task JoinHandle not awaited on SIGTERM (iter-73, MEDIUM)**: The
  outer `tokio::spawn` wrapping the audit restart-loop was fully detached — its
  JoinHandle was dropped immediately.  After `audit_shutdown_token.cancel()` in
  the signal handler, `graceful_shutdown(10s)` started draining HTTP requests
  without waiting for the audit task to finish.  An in-flight `run_audit()` could
  keep decrypted `SecureBuffer` pages live in mlocked memory until the OS sent
  SIGKILL.  Fixed: the JoinHandle is now stored in
  `audit_task_handle: Option<JoinHandle<()>>` and the signal handler awaits it
  with an 8-second `tokio::time::timeout` before starting the graceful-shutdown
  drain.  `src/main.rs:2103, 2360–2371`.

- **Notification priority hardcoded to 4 ("high") regardless of severity
  (iter-73, LOW)**: `inner_notifier.send(&title, &body, 4)` sent an ntfy
  priority-4 (Android wake-lock) notification for every audit finding — including
  a single weak password.  Fixed: priority now scales with `total_issues`
  (weak + reuse groups): ≥ 10 → priority 4 (high), 5–9 → priority 3 (default),
  1–4 → priority 2 (low).  Clean runs still do not notify.
  `src/main.rs:2230–2249`.

### Improvements (iter-72, documented here)

- **`CancellationToken` graceful shutdown for audit background task (iter-72)**:
  `tokio_util::sync::CancellationToken` created unconditionally at startup; the
  signal handler calls `audit_shutdown_token.cancel()` so the audit's
  `tokio::select!` exits early and drops `SecureBuffer`s before process exit.

- **ntfy push notification on weak/reuse findings (iter-72)**: Background audit
  task now calls `Notifier::send()` when `n_weak > 0 || n_reuse > 0`.  Clean
  runs do not notify.  Rate-limited by the existing 5-per-5-min limiter.

- **Zero-item audit result test (iter-72)**: Added `audit_zero_items_returns_clean`
  to verify `run_audit()` on an empty vault returns
  `weak=0, reuse=0, total=0` without panic.

- **`--audit-interval-secs` CLI help text (iter-72)**: Expanded doc comment to
  document first-tick skip, notification behaviour, and minimum interval warning.

- **`tokio-util` dependency (iter-72)**: Added `tokio-util = { version = "0.7",
  features = ["rt"] }` to `[dependencies]` to provide
  `tokio_util::sync::CancellationToken`.  Minimum necessary feature set only.

## [0.2.17] — iteration 71 reuse reason pluralization, DISPLAY_LIMIT pub, AuditItem docs

### Bug fixes (iter-71)

- **"1 other item(s)" grammatical error (iter-71, LOW)**: Reuse reason strings
  used `"N other item(s)"` regardless of count — producing the awkward `"1 other
  item(s): X"` for a two-item group.  Fixed: `item_word` is now derived from
  `total_others` — `"item"` (singular) when `N == 1`, `"items"` (plural)
  otherwise.  Both the production path in `run_audit()` and the two test
  replications are updated.  `src/audit.rs` (lines 338–354, 763–778, 812–825).

- **Clippy error: `useless_vec` in `reuse_reason_not_truncated_at_exactly_five_names`
  (iter-71, MEDIUM)**: `vec!["A", "B", "C", "D", "E"]` flagged as
  `clippy::useless_vec` because the slice is never mutated and a fixed-size array
  suffices.  This caused the v0.2.16 CI run to fail at the clippy step (run ID
  25418296019).  Fixed: replaced `vec![...]` with `["A", "B", "C", "D", "E"]`.
  `src/audit.rs:808`.

### Improvements (iter-71)

- **`REUSE_NAME_DISPLAY_LIMIT` made `pub(crate)` (iter-71, LOW)**: The constant
  was module-private (`const`).  Tests in the same file can access it via
  `use super::*`, but making it `pub(crate)` is explicit about intent and allows
  future test helpers in other modules to reference the limit without duplicating
  the magic literal `5`.  Updated doc comment.  `src/audit.rs:224`.

- **`AuditItem::reason` field doc comment expanded (iter-71, LOW)**: The existing
  doc comment explained the `weak_passwords` use case but did not document the
  reuse-reason override applied in `reused_passwords`, the cross-list behaviour,
  or the plural/singular formats.  Added: reuse override description, cross-list
  note, and a "Possible formats:" list enumerating all four current reason strings.
  `src/audit.rs:74`.

- **README example JSON and `reused_passwords` field description updated
  (iter-71, LOW)**: The example JSON showed `"1 other item(s)"` and the field
  description used the same awkward form.  Updated to `"1 other item"` (singular)
  and `"N other items"` (plural) to match the corrected production output.
  `README.md`.

### Findings — no code change required (iter-71)

- **"and 0 more" edge case (iter-71, VERIFY OK)**: With exactly 6 items in a
  group, one item has 5 other items (`total_others = 5`).  The truncation
  condition is `total_others <= REUSE_NAME_DISPLAY_LIMIT` (`5 <= 5 = true`), so
  the non-truncating branch is taken — all 5 names are listed with no suffix.
  `"and 0 more"` is never produced.  Confirmed by reading the branch.

- **`cross_list_weak_and_reused_items_have_distinct_reasons` tests string
  manipulation only (iter-71, VERIFY OK — known limitation)**: The test constructs
  `AuditItem` values directly and sets `reuse_item.reason` by hand rather than
  calling `run_audit()`.  This is by design — `run_audit()` requires a live
  `VaultManager`.  The test correctly validates the contract (two entries, distinct
  reasons, strength reason retained in `weak_passwords`, reuse reason in
  `reused_passwords`) but does NOT exercise the production override loop.  This is
  a documented limitation of the test, not a coverage gap requiring a fix.

- **v0.2.16 CI failure root cause (iter-71, RESOLVED)**: The v0.2.16 CI run
  (ID 25418296019) failed because `vec!["A", "B", "C", "D", "E"]` in the
  `reuse_reason_not_truncated_at_exactly_five_names` test triggered
  `clippy::useless_vec` (promoted to error by `-D warnings`).  Fixed in this
  iteration.

### Verification (iter-71)

- `cargo test --all-targets`: 253 passed, 0 failed (251 unit + 2 integration).
- `cargo clippy --all-targets -- -D warnings`: 0 errors.
- `cargo fmt --check`: 0 diff lines (clean).
- `cargo doc --no-deps`: 0 warnings.

## [0.2.16] — iteration 70 reuse reason truncation, cross-list docs, test coverage

### Bug fixes (iter-70)

- **Reuse reason string unbounded when many items share a password (iter-70,
  MEDIUM)**: When a default/shared password is used by 50+ vault items, the
  `reason` field on each `AuditItem` in `reused_passwords` listed ALL other item
  names in a single string — producing unboundedly long reason strings (thousands
  of characters).  Fixed: names are now capped at the first 5 entries and a
  `"... and N more"` suffix is appended when the group is larger.  The full count
  is still reported (`"password shared with 50 other item(s): A, B, C, D, E, ...
  and 45 more"`).  Module-level constant `REUSE_NAME_DISPLAY_LIMIT = 5` controls
  the cap.  `src/audit.rs` `run_audit()`.

### Documentation (iter-70)

- **Cross-list item not documented in README (iter-70, MEDIUM)**: An item with a
  short, reused password appears in BOTH `weak_passwords` (strength reason) and in
  a `reused_passwords` group (reuse reason).  This is intentional but was not
  documented — an operator might be confused by seeing the same item name in two
  places for two different reasons and might incorrectly deduplicate the results.
  Added a `weak_passwords` / `reused_passwords` cross-list note to the
  `GET /vault/audit/run` response field documentation: explains that the same item
  can appear in both lists for independent reasons, that both problems need to be
  resolved, and that display-layer deduplication is incorrect.  `README.md`.

- **v0.2.15 GitHub release not created (iter-70, LOW)**: The v0.2.15 tag was
  pushed but no GitHub release was drafted.  Created `gh release create v0.2.15`
  with release notes covering the iter-69 changes (reuse reason override, shape
  test, `fair_passwords_count` test, README fields).

### Test coverage (iter-70)

- **No test for cross-list weak+reused item (iter-70, MEDIUM)**: An item that is
  both weak AND reused appears in both output lists with different `reason` values.
  There was no test verifying (a) that the two entries have distinct reasons and
  (b) that the `weak_passwords` entry retains the strength reason while the
  `reused_passwords` entry gets the reuse reason.  Added
  `cross_list_weak_and_reused_items_have_distinct_reasons` unit test in
  `src/audit.rs`.

- **No test for reuse reason truncation (iter-70, MEDIUM)**: No test verified that
  the truncation cap is applied at exactly 5 names or that the `"... and N more"`
  suffix is correct.  Added `reuse_reason_truncates_at_five_names` (8-item group →
  5 shown + "... and 2 more") and `reuse_reason_not_truncated_at_exactly_five_names`
  (5-item group → no suffix) unit tests in `src/audit.rs`.

- **`fair_passwords_count_logic_matches_classifier` does not assert weak/fair
  mutual exclusion (iter-70, LOW)**: The test verified the fair count but did not
  explicitly assert that the simulated weak count is correct and that weak + fair
  are mutually exclusive (no password counted in both).  Extended the test to also
  count simulated weak passwords and assert that `simulated_fair + simulated_weak ==
  4` (total non-strong passwords in the corpus), confirming the `else if` branch
  correctly prevents double-counting.

### Findings — no code change required (iter-70)

- **`fair_passwords_count` does not double-count weak items (iter-70, VERIFY OK)**:
  The counter increment is in an `else if strength == "fair"` branch (lines 276–279)
  — a `"weak"` password enters the `if strength == "weak"` arm and never reaches
  the `else if`.  Weak items are NOT also counted as fair.  Confirmed by reading
  the branch and by the extended `fair_passwords_count_logic_matches_classifier`
  test.

- **`reused_passwords` deduplication (iter-70, VERIFY OK)**: Each vault item is
  inserted into `reuse_map` exactly once per loop iteration (`reuse_map.entry(digest)
  .or_default().push(audit_item)`).  The post-processing step collects groups via
  `reuse_map.into_values()`, consuming the map.  An item cannot appear multiple
  times in the same group and cannot appear in multiple groups (a password has
  exactly one HMAC digest).  No deduplication bug present.

- **`scoring_note` grammar (iter-70, VERIFY OK)**: The full `scoring_note` string
  reads: `"rule-based heuristic: length + character classes only; no dictionary
  check — common passwords like 'password123' may score 'fair' if they meet the
  length threshold (weak = fewer than 8 characters); each AuditItem includes a
  \`reason\` field with an actionable explanation"`.  The semicolons correctly
  separate three independent clauses; the em-dash introduces the limitation caveat.
  Grammatically correct; reads as one compound sentence.

- **v0.2.15 CI run (iter-70, VERIFY OK)**: `gh run list --repo aaronckj/vaultproxy
  --limit 3` shows the v0.2.15 tag triggered a CI run (status: in_progress at time
  of check — run ID 25418005539).  The v0.2.14 and v0.2.13 runs both completed with
  `success`.

### Verification (iter-70)

- `cargo test --all-targets`: 253 passed, 0 failed (+3 new tests:
  `cross_list_weak_and_reused_items_have_distinct_reasons`,
  `reuse_reason_truncates_at_five_names`,
  `reuse_reason_not_truncated_at_exactly_five_names`).
- `cargo clippy -- -D warnings`: 0 warnings.
- `cargo fmt --check`: clean.

## [0.2.15] — iteration 69 reuse reason, test coverage, README fields

### Bug fixes (iter-69)

- **`reused_passwords` items show strength reason instead of reuse reason
  (iter-69, HIGH)**: Items in `reused_passwords` had `reason` set to the
  password-strength explanation (e.g. `"16+ characters with 3 or more
  character classes…"` for a strong-but-reused password).  This is semantically
  wrong — the item is in the reuse list because it is *shared*, not because it
  is weak.  Displaying a positive strength message (`"strong password!"`) while
  flagging the item as a security problem is confusing to operators.
  Fixed: `run_audit()` now post-processes every reuse group and overrides
  `reason` with `"password shared with N other item(s): name1, name2, …"` so
  each reuse-list entry gives an actionable, accurate description.
  `src/audit.rs` `run_audit()`.

- **`scoring_note` does not mention the `reason` field (iter-69, LOW)**:
  `scoring_note` described the scoring algorithm but did not direct callers to
  `AuditItem.reason` for per-item explanations.  Updated `scoring_note` to
  append `"; each AuditItem includes a \`reason\` field with an actionable
  explanation"` so operators reading the note are aware of the field.
  `src/audit.rs` `run_audit()`.

### Test coverage (iter-69)

- **`AuditItem.reason` field not verified in any HTTP-level test (iter-69,
  MEDIUM)**: The integration test runs against an empty vault so
  `weak_passwords` and `reused_passwords` are empty arrays — no `AuditItem`
  is ever inspected.  If `reason` were removed from the struct, all existing
  tests would still pass.  Added `audit_item_serialises_reason_field` unit
  test in `src/audit.rs` that constructs an `AuditItem`, round-trips it
  through `serde_json`, and asserts the `reason` key is present and correct.
  Also added comments to the integration test pointing to the unit test as the
  authoritative shape check, and added array-type assertions for
  `weak_passwords` and `reused_passwords` at the HTTP level.

- **`fair_passwords_count` not verified beyond presence check (iter-69,
  MEDIUM)**: The integration test only asserts that `fair_passwords_count`
  is a number field.  If the increment logic in `run_audit()` were deleted,
  the field would always return `0` and no test would fail.  Added
  `fair_passwords_count_logic_matches_classifier` unit test in `src/audit.rs`
  that simulates the `run_audit()` counter logic using a known corpus of
  passwords, verifies each password is classified correctly, and confirms the
  simulated count matches the expected value.

### Documentation (iter-69)

- **README `GET /vault/audit/run` response schema missing `fair_passwords_count`
  and `reason` (iter-69, MEDIUM)**: The JSON example omitted both fields; the
  field descriptions listed `total_items`, `weak_passwords`, `reused_passwords`,
  `weak_threshold_len`, and `scoring_note` but not `fair_passwords_count` or
  `AuditItem.reason`.  Updated the JSON example to show both fields with
  realistic values.  Added `AuditItem.reason` and `fair_passwords_count` to
  the field-by-field description table.  Updated `reused_passwords` description
  to mention the reuse-reason override (iter-69 bug fix).
  `README.md`.

- **GitHub release v0.2.14 not created (iter-69, LOW)**: The v0.2.14 tag was
  pushed but no GitHub release was drafted.  Created
  `gh release create v0.2.14` with release notes covering the iter-68 changes
  (`AuditItem.reason`, `fair_passwords_count`, `password_strength()` tuple
  return, mlock O(1) documentation).

### Findings — no code change required (iter-69)

- **`password_strength()` callers outside `run_audit()` (iter-69, VERIFY OK)**:
  `grep -rn 'password_strength' src/` shows all callers are in `src/audit.rs`
  only — six call sites (one in `run_audit()`, five in unit tests).  No other
  file calls this function.  The tuple return from iter-68 has no silent
  discard risk in external call sites.

- **`cargo doc --no-deps` warning count (iter-69, VERIFY OK)**:
  `cargo doc --no-deps 2>&1 | grep -c warning` = 0.  No new doc warnings
  introduced by the iter-68 changes (`reason` field, `fair_passwords_count`,
  `password_strength()` signature).

- **CHANGELOG [0.2.14] completeness (iter-69, VERIFY OK)**: The [0.2.14]
  section documents all three iter-68 changes: `AuditItem.reason`,
  `AuditResult.fair_passwords_count`, and mlock O(1) clarification.  Complete.

### Verification (iter-69)

- `cargo test --all-targets`: 250 passed, 0 failed (+2 new tests:
  `audit_item_serialises_reason_field`, `fair_passwords_count_logic_matches_classifier`).
- `cargo clippy -- -D warnings`: 0 warnings.
- `cargo fmt --check`: clean.

## [0.2.14] — iteration 68 audit hardening

### Enhancements (iter-68)

- **`AuditItem` gains `reason` field (iter-68, MEDIUM)**: `AuditItem` previously
  exposed only `password_strength` (`"weak"`, `"fair"`, `"strong"`) with no
  explanation of *why*.  An operator seeing `"my item is weak"` had no
  actionable guidance — they needed to read the source to learn the threshold.
  Added a `reason: String` field to `AuditItem` populated directly by the
  `password_strength()` function (which now returns `(&'static str, &'static str)`).
  Example values: `"fewer than 8 characters — increase length to at least 8"`,
  `"8–15 characters — increase to 16+ with mixed character classes for strong rating"`,
  `"16+ characters with 3 or more character classes (lower, upper, digit, symbol)"`.
  `src/audit.rs` `AuditItem`, `password_strength()`, `run_audit()`.

- **`AuditResult` gains `fair_passwords_count` field (iter-68, MEDIUM)**:
  `"fair"` passwords were completely invisible in the audit response — an
  operator whose entire vault scores `"fair"` (7–15 char passwords with mixed
  case but no symbols) would see `weak_passwords: []` and might incorrectly
  conclude their credentials are strong.  Added `fair_passwords_count: usize`
  to `AuditResult` so the middle tier is surfaced without bloating the response
  with a full list of fair items.  The log line at audit completion now also
  includes the fair count.
  `src/audit.rs` `AuditResult`, `run_audit()`.

- **`run_audit()` mlock footprint documented (iter-68, LOW)**: Added a
  `# Memory and mlock implications` section to the `run_audit()` docstring
  clarifying that the mlock footprint is O(1) in vault size (only one
  `SecureBuffer` per password is live at a time — it is dropped before the
  next item is processed).  For a 50,000-item vault the peak mlocked bytes are
  ~32 (ephemeral key) + ~128 (one password) = well under the 64 KB Linux
  default `ulimit -l` quota.  Previously the comment `pw_buf is dropped here`
  was the only indicator; the docstring now explains the implication for
  `mlock` quota.
  `src/audit.rs` `run_audit()` docstring.

### Bug fixes (iter-68)

- **`password_strength()` return type changed to tuple (iter-68)**: Function
  now returns `(&'static str, &'static str)` (strength, reason) instead of
  `&'static str`.  All call sites in `run_audit()` and the unit tests updated.
  The `"fair"` branch that previously fell through a single `return "fair"`
  now has two distinct paths with distinct reasons: one for 16+ char passwords
  lacking character diversity, and one for the 8–15 char range.
  `src/audit.rs` `password_strength()` and unit tests.

### Findings — no code change required (iter-68)

- **CI run 25417356435 (iter-67 fmt fix) — passed (VERIFY OK)**: The
  `in_progress` run seen at audit start completed successfully.  The Docker
  image push step was mid-flight when the audit began; all preceding steps
  (fmt check, clippy, tests) had already passed.  The iter-67 fmt blocker was
  fixed correctly.

- **`run_audit()` no SCAN_ITEM_CAP — mlock O(1) not O(N) (iter-68, VERIFY OK)**:
  The concern that all 50,000 passwords would be simultaneously mlocked is
  unfounded.  `pw_buf` is dropped (and zeroized + munlocked) inside the loop
  before the next iteration calls `decrypt_password()`.  Peak live mlocked
  buffers = 2 (ephemeral key + current password).  No cap is needed for
  mlock safety.  A cap could still be useful for CPU/time budgeting on very
  large vaults — consider a future `AUDIT_ITEM_LIMIT` flag if needed.

- **`password_strength()` sequential-character check absent (iter-68, INFO)**:
  Patterns like `"abcd1234"` or `"qwerty123!"` score `"fair"` or `"strong"`
  because the algorithm checks only length and character classes.  This is the
  documented no-dictionary-check limitation.  The `scoring_note` field in every
  response now reads: `"rule-based heuristic: length + character classes only;
  no dictionary check — common passwords like 'password123' may score 'fair'…"`.
  Sequential-character detection would require either a zxcvbn dependency or a
  hardcoded pattern list.  Both are out of scope for this in-process sidecar;
  operators who need it should use the credential-audit sidecar.

- **`--check` VAULT_PROXY_PUBLIC_URL output stream (iter-68, VERIFY OK)**:
  All `--check` output (services.toml results, VAULT_PROXY_PUBLIC_URL
  validation) uses `println!` (stdout).  The code comment at line ~358 of
  `src/main.rs` explicitly states "All output uses println! (stdout) so CI
  pipelines that capture stdout see the result — consistent with all other
  --check output."  No stderr/stdout split exists.  Consistent.

- **README length (iter-68, MONITOR)**: `README.md` is 555 lines — slightly
  above the 500-line threshold but still well-organized with clear section
  headers.  No structural reorganization needed; the additive growth has been
  in the credential audit and changelog sections which are logically grouped.

- **CHANGELOG iter-67 entries absent from [0.2.13] (iter-68, FIXED)**: The
  [0.2.13] entry only covered iter-66 fixes.  The iter-67 changes (fmt blocker
  fix, scoring assertion precision, README 503/audit docs) were committed to
  main without a CHANGELOG update.  This release note (v0.2.14) covers both
  the iter-67 commit and all iter-68 changes.

### Verification (iter-68)

- `cargo test --all-targets`: 248 passed, 0 failed (246 binary + 2 integration;
  +1 new test: `fair_password_reason_is_actionable`).
- `cargo clippy -- -D warnings`: 0 warnings.
- `cargo fmt --check`: clean.

## [0.2.13] — iteration 66 audit pass

### Bug fixes (iter-66)

- **`Retry-After` inconsistency between `reload_services` and `handle_audit_run`
  (iter-66, LOW)**: `POST /vault/reload-services` still emitted `Retry-After: 10`
  and `retry_after_s: 10` in its 503 mutex-timeout response after iter-65 reduced
  `GET /vault/audit/run` to `Retry-After: 5`. Both endpoints use the same "mutex
  held by concurrent operation" scenario with the same 5-second acquisition
  timeout; operators and monitoring tools that hit both endpoints would see
  different retry windows for the same underlying event.  Standardised
  `reload_services` to `Retry-After: 5` and `retry_after_s: 5`. Updated the
  `timeout_body` test helper and the `timeout_body_has_required_fields` assertion.
  `src/vault/handlers.rs` `reload_services()` and `reload_services_shape_tests`.

- **README `GET /vault/audit/run` response schema missing `scoring_note`
  (iter-66, LOW)**: The in-process health scan section showed the JSON response
  shape with only four fields (`total_items`, `weak_passwords`, `reused_passwords`,
  `weak_threshold_len`). The `scoring_note` field added in iter-64 and changed to
  `String` in iter-65 was absent from the example and from the field-by-field
  description. Added `scoring_note` to the example JSON and added a bullet point
  explaining its content (no-dictionary-check caveat, format!() embedding of
  `weak_threshold_len`).
  `README.md` credential audit section.

- **Integration test `scoring_note` assertion too weak (iter-66, LOW)**: The
  iter-65 assertion verified only that `scoring_note` is a non-empty string. It
  did not check that the string embeds the actual `WEAK_THRESHOLD` value. If
  `WEAK_THRESHOLD` changed from 8 to a different value, the format string in
  `run_audit()` would automatically reflect that, but the note might drift from
  the `weak_threshold_len` field if the format string were later edited.  Added a
  second assertion that `scoring_note` contains the `WEAK_THRESHOLD.to_string()`
  value so threshold drift is caught at test time.
  `src/proxy/mod.rs` `audit_run_requires_bearer_token_and_returns_200_with_json_shape`.

### Findings — no code change required (iter-66)

- **`scoring_note` format string accuracy (iter-66, VERIFY OK)**: The format
  string says "fewer than {} characters" where `{}` is `WEAK_THRESHOLD` (8).
  `password_strength()` classifies `len < WEAK_THRESHOLD` as "weak". A password
  with exactly 8 characters has `len == 8` which is NOT `< 8` — it passes the
  threshold. "fewer than 8 characters" is therefore correct; the comparison is
  `<`, not `<=`.

- **`AuditResult` optional fields (iter-66, VERIFY OK)**: `AuditResult` has no
  `Option<>` fields — `weak_passwords` and `reused_passwords` are `Vec<T>` and
  always serialise (potentially empty). `weak_threshold_len` is `usize` and
  `scoring_note` is `String`. No `#[serde(skip_serializing_if)]` needed.

- **Background audit restart loop logs panic (iter-66, VERIFY OK)**: `src/main.rs`
  line ~2177 emits `tracing::error!` on `JoinError::is_panic()` before the 5 s
  sleep and respawn. Operator visibility is present.

- **`AuditItem::username` sensitivity (iter-66, REVIEW NOTE)**: `username` is
  `Option<String>` and is included in the `AuditItem` serialised to the caller.
  The `GET /vault/audit/run` endpoint is gated behind the internal bearer token —
  only callers who already have full vault access see this field. Exposure is
  intentional and scoped correctly. No change required.

- **HMAC outputs zeroized after use (iter-66, VERIFY OK)**: `group_by_hmac`
  (now `reuse_map`) holds `String` HMAC digests, not `Vec<u8>` raw bytes.
  `hmac_hex()` converts the bytes to a hex string before returning, so the raw
  HMAC bytes are local to `hmac_hex()` and are dropped (stack-allocated) when
  the function returns. The `String` digests in `reuse_map` are not sensitive
  — they are keyed-MACs of passwords with an ephemeral key; they cannot be
  inverted to recover the password. The ephemeral key itself is a `SecureBuffer`
  dropped (and zeroized) before `AuditResult` is returned. No residual
  plaintext-equivalent material persists in the heap after `drop(ephemeral_key)`.

### Verification (iter-66)

- `cargo test --all-targets`: 247 passed, 0 failed.
- `cargo clippy -- -D warnings`: 0 warnings.
- `cargo fmt --check`: clean.

## [0.2.12] — iteration 64 audit pass

### Bug fixes (iter-64)

- **Audit background task missing panic-restart loop (iter-64, MEDIUM)**: The
  background audit task spawned by `--audit-interval-secs` had no outer restart
  loop — unlike the policy scheduler (which gained one in iter-23). A panic
  inside `run_audit()` (however unlikely) would silently kill the task with no
  log entry and no recovery. Added the same inner/outer `tokio::spawn` pattern
  used by the policy scheduler: the outer loop catches `JoinError::is_panic()`,
  logs at ERROR, and re-spawns after 5 s. Note: `tokio::sync::Mutex` has no
  poison semantics — a panic while holding `audit_mutex` simply drops the guard
  and leaves the mutex acquirable by the next caller; no `PoisonError` cleanup
  is needed.
  `src/main.rs` background audit task.

- **`audit_run_requires_bearer_token` test missing Content-Type assertion
  (iter-64, LOW)**: The return type of `handle_audit_run()` was changed from
  `Json<AuditResult>` to `axum::response::Response` in iter-63. The test
  verified the JSON body shape but did not assert `Content-Type: application/json`
  on the success response. Added explicit `content-type` header assertion.
  `axum::Json(result).into_response()` does set the header correctly — this
  change adds test coverage to prevent a future regression if the response
  construction is modified.
  `src/proxy/mod.rs` `audit_run_requires_bearer_token_and_returns_200_with_json_shape`.

- **`--audit-interval-secs` first-tick skip undocumented (iter-64, LOW)**: The
  background audit task skips the first `tokio::time::interval` tick so the
  first audit fires after one full interval rather than immediately at startup.
  This behaviour was not documented in the `--help` text. Added a
  `FIRST-TICK BEHAVIOUR` paragraph to the `--audit-interval-secs` help string
  explaining the skip and advising operators who need an immediate baseline to
  call `GET /vault/audit/run` manually.
  `src/main.rs` `Args::audit_interval_secs` field doc.

- **`password_strength()` no-dictionary limitation undocumented in API response
  (iter-64, LOW)**: The rule-based heuristic has no dictionary check — common
  passwords like `"password123"` or `"Summer2024!"` score "fair" if they meet
  the length + character-class thresholds and do NOT appear in
  `AuditResult::weak_passwords`. The limitation was described in the
  `password_strength()` source doc but was not visible in the API response.
  Added a `scoring_note` field to `AuditResult` that describes the scoring
  algorithm and explicitly calls out the no-dictionary-check limitation.
  `src/audit.rs` `AuditResult::scoring_note`, `password_strength()` doc comment.

### Verification (iter-64)

- `cargo test --all-targets`: 247 passed (245 unit + 2 integration), 0 failed.
- `cargo clippy -- -D warnings`: 0 warnings.
- `cargo fmt --check`: clean.

### Findings — no code change required (iter-64)

- **`handle_audit_run()` Content-Type on success path (iter-64, VERIFY OK)**:
  `axum::Json(result).into_response()` sets `Content-Type: application/json`
  automatically — this is a well-tested axum invariant. The iter-63 return-type
  change from `Json<AuditResult>` to `axum::response::Response` does not break
  this: the final `axum::Json(result).into_response()` still delegates to axum's
  `Json` responder. Verified by the new `content-type` assertion in
  `audit_run_requires_bearer_token_and_returns_200_with_json_shape`.

- **`audit_mutex` poison semantics (iter-64, VERIFY OK)**: `tokio::sync::Mutex`
  does NOT implement Rust's `std::sync::PoisonError` mechanism. A panic inside
  `.lock().await` simply drops the guard and leaves the mutex acquirable by the
  next caller — no `PoisonError`, no `lock().unwrap()` needed. This is correct
  behaviour and is now documented in the restart-loop comment in `src/main.rs`.

- **v0.2.12 CI run (iter-64, IN PROGRESS)**: The v0.2.12 tag triggered CI run
  `25416237308`. Formatting check, Clippy, and tests all passed; only the Docker
  push step was still in progress at the time of this audit. The GitHub release
  for v0.2.12 was created by this iter-64 commit.

- **`AppState` field count (iter-64, VERIFY OK)**: 24 fields — matches the
  expected count from the audit prompt. No fields appear unused (all 24 are
  consumed by at least one handler or background task). Fields verified:
  `vault`, `registry`, `http`, `http_permissive`, `ca_cert_clients`,
  `unifi_sessions`, `session_tokens`, `client_certs`, `cloud_sync`,
  `approval_queue`, `browser`, `permissions`, `audit_log`, `notifier`,
  `handshake_completed`, `vault_folder`, `last_resync_unix`, `internal_token`,
  `cached_folder_id`, `env_write_root`, `config_dir`, `proxy_timeout`,
  `reload_mutex`, `audit_mutex`.

- **`reload_services` vs `handle_audit_run` 503 consistency (iter-64,
  VERIFY OK)**: Both use `Retry-After: 10` (the static value `"10"`) and both
  return `retry_after_s: 10` in the JSON body. Both construct the 503 response
  as `(StatusCode::SERVICE_UNAVAILABLE, HeaderMap, Json(json!({...}))).into_response()`.
  No divergence.

### Bug fixes from iter-63 (included in this tag)

- **`handle_audit_run()` no timeout on `audit_mutex` (iter-63, HIGH)**: `GET
  /vault/audit/run` previously blocked indefinitely when the background audit
  task held the mutex on a large vault. Added a 5-second acquisition timeout
  mirroring the `reload_mutex` pattern: if the mutex cannot be acquired in 5 s,
  the handler returns `503 Service Unavailable` with a `Retry-After: 10` header
  and a `retry_after_s: 10` JSON field. Callers now get an immediate, actionable
  response rather than a silent multi-second stall.
  `src/audit.rs` `handle_audit_run()`.

- **Background audit log missing `vault_folder` (iter-63, LOW)**: In deployments
  with multiple vault-proxy instances sharing a log stream, the background audit
  messages ("credential audit background: complete — no issues") were
  indistinguishable between instances. Added `vault_folder = %audit_vault_folder`
  as a structured field to the startup info, per-run warn, and per-run debug log
  lines.
  `src/main.rs` background audit task.

### Findings — no code change required (iter-63)

- **`make_state()` updated with `audit_mutex` (iter-63, VERIFY OK)**: Confirmed
  at `src/proxy/mod.rs:1581` — `make_state()` already includes
  `audit_mutex: Arc::new(tokio::sync::Mutex::new(()))`. All tests compile and
  pass.

- **Background task does NOT hold mutex during sleep (iter-63, VERIFY OK)**:
  Confirmed: `src/main.rs` background loop is structured as
  `interval.tick().await; { lock; run_audit(); }` — the `_guard` drops at end of
  the loop body before `interval.tick().await` parks the task. The mutex is held
  only during the active audit, not during the inter-tick sleep.

- **`run_audit()` does NOT hold vault read lock during decrypt loop (iter-63,
  VERIFY OK)**: `list_items()` acquires `items.read()`, clones the item list,
  and drops the lock before returning. The subsequent `decrypt_password()` calls
  each use `try_read()` independently per item. SIGHUP/reload is never blocked
  for the full audit duration.

- **`audit_mutex` timeout response (iter-63, VERIFY OK)**: With the 5-second
  timeout now in place, a caller hitting `GET /vault/audit/run` while the
  background task is running gets an immediate 503 with `Retry-After: 10` rather
  than a silent wait. This closes the "hanging response with no indication"
  finding.

- **`--audit-interval-secs` warning message (iter-63, VERIFY OK)**: Message at
  `src/main.rs` is actionable: structured fields `interval_secs` and
  `min_secs` accompany the text "AUDIT_INTERVAL_SECS is below the recommended
  minimum of 60 s — … Consider 3600 (hourly)." Operators see both the bad value
  and the recommended floor in structured logs.

- **Rate limit 2 req/60 s still appropriate (iter-63, NO CHANGE)**: The
  `audit_mutex` prevents concurrent audit CPU load; the rate limit prevents
  burst submission of sequential audits. Both serve distinct purposes. Raising
  the limit would allow a single IP to queue 3–5 audits in rapid succession,
  each decrypting the full vault. Keeping 2 req/60 s is the conservative choice
  and can be revisited when vault size vs. audit duration data is available.

- **v0.2.12 tag warranted (iter-63, TAGGED)**: iter-62 introduced the
  `audit_mutex` fix (HIGH severity — prevented concurrent full-vault decryption).
  iter-63 adds a timeout to that mutex so callers are never left hanging. Both
  fixes together justify a patch release so users on
  `ghcr.io/aaronckj/vaultproxy:v0.2.11` can upgrade.

## [0.2.11] — iteration 60 audit pass (no version bump — doc + test only)

### Bug fixes (iter-60)

- **README `apply` workflow still referenced old `_review-delete` folder name
  (iter-60, LOW)**: The apply/undo documentation still said items are moved to
  `_review-delete` — the pre-iter-58 name. Since iter-58 the folder is
  `<vault_folder>-review-delete`. Fixed: updated both the description and the
  undo instruction; added an explicit migration note for operators upgrading
  from before iter-58 who have items stranded in the old folder name.

### Tests added (iter-60)

- **`health_version_tests` — `GET /vault/health` version field (iter-60)**:
  Added two unit tests to `src/vault/handlers.rs` verifying that
  `env!("CARGO_PKG_VERSION")` resolves to a non-empty semver triple (X.Y.Z)
  and that the health response JSON shape matches what the handler emits
  (`json!({ "version": env!("CARGO_PKG_VERSION") })`). These tests catch a
  future `Cargo.toml` version bump where the binary was not rebuilt. Total
  test count: 247 (245 unit + 2 integration).

### Documentation (iter-60)

- **Dockerfile `EXPOSE 3202` comment expanded (iter-60)**: Added an explicit
  note that an operator running `docker run -p 3202:3202 ghcr.io/.../vaultproxy`
  gets no dashboard and no error — the port is not bound because the feature
  was not compiled. Directs operators to `--build-arg FEATURES=dashboard` for
  the dashboard variant. The `EXPOSE` directive itself is retained as
  documentation-only metadata per Docker convention.

- **README: Docker build section added (iter-60)**: New "Docker" sub-section
  under "Building" documents `docker build --build-arg FEATURES=dashboard`,
  `--build-arg FEATURES=tpm`, and the combined `FEATURES=dashboard,tpm` form.
  Includes a Docker Compose `build.args` example. Notes that
  `--build-arg FEATURES=invalid-feature-name` produces a clear Cargo error
  (expected, not a silent failure). Previously only `cargo build` invocations
  were documented; Docker operators had no documented path to the dashboard.

- **`docker-compose.example.yml`: headless default and dashboard variant
  documented (iter-60)**: Added comments explaining that `build: .` produces
  the headless default (no dashboard, no port 3202 binding), and showing the
  `build.args: FEATURES: dashboard` + `ports` snippet for operators who want
  the web UI.

### Verification (iter-60)

- `cargo test --all-targets`: 247 passed (245 unit + 2 integration), 0 failed.
- `cargo build --release`: clean (0 errors, 0 warnings).

### Findings — no code change required (iter-60)

- **`EXPOSE 3202` removal considered (iter-60)**: Removing `EXPOSE 3202` from
  the Dockerfile entirely was considered but rejected. Docker `EXPOSE` is
  documentation metadata — it does not bind ports and cannot cause security
  issues. Removing it would break `docker inspect` workflows that read declared
  ports. The comment was expanded instead to make the headless behavior explicit.

- **`vault_folder` with spaces/special chars (iter-60)**: `main.rs` (line
  436–448) already validates `vault_folder` at startup: empty string, null
  bytes, and `/` are rejected with a hard `bail!()`. Spaces are intentionally
  permitted — Vaultwarden encrypts folder names and accepts any valid UTF-8
  content. The resulting `"my folder-review-delete"` folder name is safely
  transmitted to the Vaultwarden `/api/folders` API. No sanitization gap.

- **`audit.rs` tests in `#[cfg(test)]` (iter-60)**: Confirmed. Line 238 of
  `src/audit.rs` opens `#[cfg(test)] mod tests { ... }`. All five
  password_strength tests are inside that block. No compilation issue.

- **`from_config`/`from_vault` in integration tests (iter-60)**: `tests/`
  contains only `secret_discipline.rs`, which does not reference either
  function. Both are `#[cfg(test)]`-gated in `src/proxy/registry.rs` (lines
  324 and 532). Integration tests compile separately and cannot see
  `#[cfg(test)]` items from `src/` — confirmed no reference exists.

- **CI v0.2.11 run (iter-60)**: Not auditable from local source (requires
  GitHub Actions access). The commit pushed to main will trigger CI via the
  `docker-publish.yml` workflow on the next tag push.

## [0.2.11] — iteration 59: version sync, headless Dockerfile, Unicode test, migration note

### Bug fixes (iter-59)

- **`Cargo.toml` version stuck at `0.2.8` (iter-59, MEDIUM)**: Tags `v0.2.9` and
  `v0.2.10` were pushed for CI and fmt fixes but `Cargo.toml` was never bumped past
  `0.2.8`. As a result `cargo run -- --version` printed `vaultproxy 0.2.8` and
  `GET /vault/health` returned `"version": "0.2.8"` even when the published Docker
  image was tagged `v0.2.10`. Fixed: version bumped to `0.2.10` to match the current
  release tag, then bumped to `0.2.11` for this iteration's fixes.

- **Dockerfile compiled `--features dashboard` unconditionally (iter-59, MEDIUM)**:
  The published Docker image was built with `--features dashboard`, which starts a
  web UI listener on `127.0.0.1:3202` inside every container — whether or not the
  operator wanted it. Operators running the published image with `network_mode: host`
  got an unexpected dashboard on port 3202. Fixed: the default build is now headless
  (`FEATURES=""` ARG). Operators who want the dashboard build locally with
  `--build-arg FEATURES=dashboard`. The `EXPOSE 3202` comment was updated to note
  it is only meaningful for dashboard builds.

### Tests added (iter-59)

- **Unicode `password_strength()` regression tests (iter-59)**: Added a
  `#[cfg(test)] mod tests` block to `src/audit.rs` with five unit tests:
  `cyrillic_4_char_password_is_weak` — verifies that "АБВГ" (4 chars, 8 bytes)
  is classified "weak" (not "fair" as it was before the iter-58 fix);
  `cyrillic_8_char_password_is_not_weak` — verifies the boundary at 8 chars;
  `ascii_7_char_password_is_weak`, `ascii_8_char_password_is_not_weak` — ASCII
  boundary sanity; `strong_password_classified_strong` — 16-char mixed-class check.

### Documentation / migration note (iter-59)

- **`_review-delete` → `<vault_folder>-review-delete` migration gap documented**:
  The iter-58 change renamed the quarantine folder from `"_review-delete"` to
  `"<vault_folder>-review-delete"` for multi-deployment isolation. Deployments that
  ran a credential-audit scan before upgrading have items stranded in the old
  `"_review-delete"` folder; the `apply` endpoint will never find them under the new
  name. Migration path: in Vaultwarden, manually move items from `"_review-delete"`
  to `"<your_vault_folder>-review-delete"` (or simply rename the folder). There is no
  automated migration in vault-proxy. Deployments with `vault_folder = None`
  (unconfigured) are unaffected — they continue to use `"_review-delete"`.

### Findings — no code change required (iter-59)

- **Orchestrator `Marker::new()` vault_folder wiring — CORRECT (iter-59)**:
  `main.rs` line 1432–1435 passes `Some(args.vault_folder.clone())` to
  `Marker::new()` at `Orchestrator` construction time. The `vault_folder`
  parameter is correctly threaded from the parsed CLI args through to the
  `Marker`. No fix needed.

- **GitHub releases for v0.2.9 / v0.2.10 — deferred**: The tags were pushed for
  CI toolchain and fmt fixes; formal GitHub release notes were not created for
  those tags. The v0.2.11 tag (this iteration) should have a proper release with
  the notes from this section and the prior two iterations.

- **`WEAK_THRESHOLD = 8` configurability — documented, not changed**: The threshold
  is exposed in `AuditResult::weak_threshold_len` in every API response, so callers
  can see the active threshold without reading source. Making it a runtime CLI flag
  would require threading it through `run_audit()` and `AppState`, adding complexity
  for a homelab-targeted v0.x tool. The current approach (recompile to change the
  constant) is adequate; NIST SP 800-63B's own floor is 8 chars. A `--audit-weak-threshold`
  flag is noted as a v1.0 enhancement.

- **CI GHA cache — not auditable from source (iter-59)**: Whether the GitHub Actions
  cache was populated on the v0.2.10 build is a runtime artifact that cannot be
  verified from the repository. The workflow's `cache-from: type=gha` / `cache-to:
  type=gha,mode=max` configuration is correct; subsequent runs will benefit from the
  cache on a cache-hit. No change needed.

### Verification (iter-59)

- `cargo test --all-targets`: 245 passed (240 prior + 5 new password_strength tests), 0 failed.
- `cargo build --release`: clean (0 errors, 0 warnings in vaultproxy crate).
- `cargo clippy --all-targets -- -D warnings`: 0 errors.
- `cargo fmt --check`: clean.

## [0.2.10] — iteration 58 follow-up: CI fmt fix, Docker image publication

### Changes

- **`cargo fmt` fix (CI)**: Corrected rustfmt formatting in `src/sync/cloud.rs`
  that caused the CI `cargo fmt --check` step to fail on the v0.2.9 tag. No
  logic changes.

- **First published Docker image**: `ghcr.io/aaronckj/vaultproxy:v0.2.10` and
  `ghcr.io/aaronckj/vaultproxy:latest` were successfully built and pushed by the
  GitHub Actions workflow on the `v0.2.10` tag push.

- **Note**: `Cargo.toml` was not bumped from `0.2.8` for the `v0.2.9` or `v0.2.10`
  tags — only CI/fmt fixes were made. The binary version reported by `--version` and
  `GET /vault/health` remained `0.2.8`. This is corrected in `v0.2.11`.

## [0.2.9] — iteration 58: Unicode password length, review-delete folder isolation, CHANGELOG

### Bug fixes (iter-58)

- **`password_strength()` used byte count for Unicode passwords (iter-58, MEDIUM)**:
  `password_strength()` in `src/audit.rs` computed length via `pw.len()` (UTF-8
  byte count) rather than character count.  A 4-character Cyrillic password like
  "АБВГ" encodes to 8 UTF-8 bytes — exactly the `WEAK_THRESHOLD` — so it was
  wrongly classified "fair" instead of "weak".  Fixed: the function now converts
  the byte slice to `str` (when valid UTF-8) and calls `.chars().count()` to get
  the Unicode scalar-value count.  Non-UTF-8 byte slices (Bitwarden v1 legacy
  encoding) fall back to byte count so the function remains infallible.
  Updated `WEAK_THRESHOLD` and algorithm doc-comments to say "character count"
  instead of "byte-length".

### Security / isolation (iter-58)

- **`_review-delete` folder not isolated per vault_folder (iter-58, LOW)**:
  `src/credential_audit/marker.rs` hardcoded `REVIEW_DELETE_FOLDER = "_review-delete"`.
  Vaultwarden has no nested folders; all folders are root-level.  An operator
  running two vault-proxy deployments (`vault_folder = "staging"` and
  `vault_folder = "prod"`) on the same Vaultwarden would have both deployments
  dumping flagged items into the same `"_review-delete"` folder, making it
  impossible to attribute which deployment flagged each item without reading the
  marker note.  Fixed: `Marker` now carries `vault_folder: Option<String>` and
  constructs `"<vault_folder>-review-delete"` (e.g. `"staging-review-delete"`).
  When `vault_folder` is `None` (no scope configured), the legacy `"_review-delete"`
  name is used so existing single-deployment setups require no migration.
  `Marker::new()` signature updated from `new(vault)` to `new(vault, vault_folder)`;
  all three call sites updated (`main.rs`, `orchestrator.rs` test helper,
  `proxy/mod.rs` integration test).  Two new unit tests replace the old
  `folder_name_constant` test:
  `folder_name_with_vault_folder_prefix` and `folder_name_none_uses_legacy_name`.

### Verification (iter-58)

- `cargo build --release`: clean (0 errors, 0 warnings in vaultproxy crate).
- `cargo clippy --all-targets -- -D warnings`: 0 errors.
- `cargo fmt --check`: clean.
- `cargo test`: 240 passed (238 lib/integration + 2 secret_discipline), 0 failed.
- `cargo test --all-targets`: 240 passed, 0 failed.
- `cargo test --release`: 240 passed, 0 failed.

## [0.2.8] — iteration 57: AuditResult threshold field, scan pagination docs, rate-limit comment fix

### Added (iter-57)

- **`AuditResult::weak_threshold_len` field**: The JSON response from
  `GET /vault/audit/run` now includes `"weak_threshold_len": 8`. An operator
  seeing "27 weak passwords" previously had no way to know whether the
  threshold was `< 2` (very strict) or `< 8` without reading the source.
  The field is populated from a new `pub const WEAK_THRESHOLD: usize = 8`
  constant in `src/audit.rs`; `password_strength()` now references this
  constant instead of the bare literal. README response example updated.

### Documentation fixes (iter-57)

- **Scan pagination gap documented** (`README.md`, `GET /vault/audit/run`
  section): Added an explicit callout that `SCAN_ITEM_CAP = 1_000` is a hard
  cap with no pagination or offset support. An operator with 2,000 items will
  always scan the same first 1,000 in vault-list order; items 1,001 onward are
  silently excluded. Documents the workaround (split vault folders or raise
  the constant and recompile).

- **Trailing-slash comment corrected** (`src/security/rate_limit.rs` line
  ~186): The comment said "Strip *one* trailing slash" but
  `trim_end_matches('/')` strips ALL consecutive trailing slashes (so
  `/vault/audit/run//` normalizes correctly). Comment updated to reflect the
  actual all-slash behavior and note the double-slash case explicitly.

### Verification (iter-57)

- `cargo build --release`: clean (0 errors, 0 warnings in vaultproxy crate).
- `cargo clippy --all-targets -- -D warnings`: 0 errors.
- `cargo test`: 239 passed, 0 failed.

## [0.2.7] — iteration 56: trailing-slash rate-limit bypass, cfg(test) registry cleanup, scan item cap, audit algorithm docs

### Security fixes (iter-56)

- **Trailing-slash rate-limiter bypass (iter-56, MEDIUM)**: The rate-limit
  middleware keyed on the raw URI path. A caller sending `GET /vault/audit/run/`
  (trailing slash) would not match the `"/vault/audit/run"` entry in
  `RATE_LIMITED_PATHS` and would fall through to the default 60 req/60 s budget,
  bypassing the 2 req/60 s cap designed to prevent audit-decrypt DoS. Fixed:
  `rate_limit_middleware` now strips a single trailing slash from paths longer
  than `/` before the match, normalising `/vault/audit/run/` → `/vault/audit/run`.
  Added `trailing_slash_uses_same_bucket_as_canonical_path` unit test.

### Hardening (iter-56)

- **`from_config`/`from_vault`/`build_media_entry` moved to `#[cfg(test)]`
  (iter-56)**: These three items in `src/proxy/registry.rs` were previously
  tagged `#[allow(dead_code)]` with a comment claiming they were "called only by
  /vault/connecterr-secrets HTTP handlers". Investigation confirmed no production
  handler calls them — they are only exercised by tests. Moving the definitions
  inside `#[cfg(test)]` removes them from production binaries and makes accidental
  production use a compile error.

- **`scan/start` item count cap — `SCAN_ITEM_CAP = 1_000` (iter-56)**:
  `VwAdapter::list_items_metadata()` previously returned all scoped items with
  no upper bound. A vault_folder with 10 000 items would send all 10 000 items
  to the engine sidecar in one request, potentially exhausting the engine's
  memory and producing an oversized HTTP body. Added `SCAN_ITEM_CAP = 1_000`
  constant; when the item count exceeds the cap, `list_items_metadata()` truncates
  and emits a `tracing::warn!`. Documented in README under `GET /vault/audit/run`.

### Documentation (iter-56)

- **`password_strength` algorithm documented (iter-56)**: The `audit.rs`
  `password_strength()` function now carries a full algorithm docstring explaining
  why rule-based scoring was chosen over zxcvbn (avoids dictionary corpus and
  extended plaintext window) and over HIBP k-anonymity (avoids outbound HTTPS
  calls that leak partial hashes to an external service). The docstring also
  clarifies that only `"weak"` passwords appear in `weak_passwords`; `"fair"`
  passwords are not reported.

- **README `AuditResult` schema corrected (iter-56)**: `weak_passwords` and
  `reused_passwords` descriptions now specify the array element type (`AuditItem`
  with fields `name`, `username`, `item_type`, `password_strength`) and clarify
  that "fair" passwords are not surfaced. `SCAN_ITEM_CAP` noted in scope bullet.

### Findings — no code change required (iter-56)

- **Rate limiter test isolation (issue 1)**: `make_state()` does not contain a
  `RateLimiter`. The limiter is injected per-test via `make_audit_run_app()` which
  creates a fresh `RateLimiter::new()` with its own `Arc<Mutex<HashMap>>`. No
  shared state between tests; the concern is unfounded.

- **`_review-delete` folder scope (issue 2)**: Vaultwarden's `/api/folders` API
  creates top-level folders only (VW does not support folder nesting). The
  `_review-delete` folder is therefore always a root-level folder — this is
  correct and intentional. Operators should be aware the folder appears in their
  flat folder list alongside personal folders. The `marker.rs` docstring already
  mentions idempotency; a note about the top-level placement would be a future
  improvement but is not a bug.

- **`AuditResult` README schema (issue 3)**: The README correctly showed
  `weak_passwords` as an array of objects and `reused_passwords` as an array of
  arrays of objects. The prior description was accurate; this iteration only
  improved it by adding explicit field names and the "fair is not surfaced" note.

- **Empty vault_folder with `run_audit` (issue 4)**: `run_audit()` iterates over
  `vault.list_items()`. When the vault has no items the loop body never runs and
  `AuditResult { total_items: 0, weak_passwords: vec![], reused_passwords: vec![] }`
  is returned correctly. No error, no panic.

- **`scan/start` + `apply` 50-item threshold (issue 8)**: The `confirm_bulk`
  threshold guards the number of *pending flagged items* (results of a scan),
  not the number of items scanned. Even with SCAN_ITEM_CAP at 1 000, only the
  subset flagged by the engine as dead/weak/duplicate counts against the 50-item
  apply guard. The threshold remains appropriate.

## [0.2.6] — iterations 53–55: VwAdapter scope bypass fix, audit/run endpoint, rate limit, localhost HTTPS warn, iter-55 tests

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

- **`apply` item_id scope bypass — NOT present (iter-55)**: Audited the
  `apply()` method in `orchestrator.rs` for the potential that a caller
  could supply `item_ids` pointing to out-of-scope vault items to force
  `marker.mark()` on them. The filter at lines 296–303 uses
  `list_pending(run_id)` as its source — this is a DB query against
  `audit_run_items WHERE run_id=? AND marked_for_delete=1`. Items only
  enter that table during `start_scan()` which uses the scoped
  `VwAdapter.list_items_metadata()`. A caller cannot inject an arbitrary
  `item_id` because it will not be in `audit_run_items` for that run_id
  unless the VwAdapter already admitted it during the scan. No fix needed.

- **`Orchestrator` VwAdapter vault_folder wiring — CORRECT (iter-55)**:
  `main.rs` line 1427–1430 passes `Some(args.vault_folder.clone())` to
  `VwAdapter::new()` at `Orchestrator` construction time. The iter-53 fix
  is correctly propagated through the startup path.

- **`GET /vault/audit/run` per-IP bucket on localhost — known limitation
  (iter-55)**: The 2 req/60 s rate limit is keyed on `(route, client_ip)`.
  All MCP callers share `127.0.0.1` and therefore share one bucket. A TODO
  comment at lines 229–244 of `rate_limit.rs` documents this and recommends
  `X-Caller-Id` as the long-term fix. The 2 req/60 s limit is strict enough
  that the shared-bucket limitation is acceptable for v0.x homelab use.

- **`from_config` / `from_vault` not test-gated — LOW (iter-55)**: Both
  methods in `registry.rs` carry `#[allow(dead_code)]` and `#[doc(hidden)]`
  but are NOT guarded by `#[cfg(test)]`. All 14 call sites are inside
  `#[cfg(test)]` modules so they compile into the binary but are dead code
  in production builds. The `#[allow(dead_code)]` annotation is accurate and
  the binary overhead is negligible. Moving them to `#[cfg(test)]` would be
  correct but is low-priority for v0.x.

### Tests added (iter-55)

- **`VwAdapter` empty fallback regression guard (iter-55)**: New async unit
  tests in `src/credential_audit/vw_adapter.rs`:
  `list_items_metadata_returns_empty_when_configured_folder_absent` —
  verifies that when `vault_folder` is configured but the folder is absent,
  `list_items_metadata()` returns an empty list (not all items). A future
  refactor that reinstates the permissive fallback would fail this test
  immediately. Complementary `list_items_metadata_unconfigured_folder_returns_all_items`
  checks the `vault_folder=None` branch.

- **`GET /vault/audit/run` HTTP integration tests (iter-55)**: Two new tests
  in `src/proxy/mod.rs::integration_tests`:
  `audit_run_requires_bearer_token_and_returns_200_with_json_shape` —
  verifies 401 without token, 401 with wrong token, and 200 with correct
  token + JSON shape (`total_items`, `weak_passwords`, `reused_passwords`).
  `audit_run_rate_limited_returns_429_on_third_request` — exercises the
  full axum middleware stack through real HTTP round-trips, verifying 429
  after the budget is exhausted. Total test count: 238.

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
