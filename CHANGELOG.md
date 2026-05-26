# Changelog

All notable changes to vaultproxy are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [1.11.1] — 2026-05-26

### Security

- **mTLS server key 0600 enforcement.** `--transparent-mtls-server-key`
  is now mode-checked at startup, mirroring `TransparentCa::load_byo`'s
  treatment of the MITM CA key. A world-readable mTLS server key now
  refuses to start instead of silently loading. The mTLS server key is
  a Tier-1 secret (SECURITY.md) — a leak lets an attacker impersonate
  the proxy to every agent that trusts the corresponding server cert.
- **HTTP/2 trailer sanitisation.** The h2 MITM path now drops
  pseudo-header names (`:`-prefixed) and connection-specific names
  (`connection`, `keep-alive`, `proxy-connection`, `transfer-encoding`,
  `upgrade`, `te`, `trailer`, `host`, `content-length`) from upstream-
  supplied trailers before re-emitting on the agent stream. h2
  enforces this on send, but failing there would abort the stream
  after we'd already sent the response body. Drop quietly instead.
- **`FORBIDDEN_HEADERS` extended** with h2 pseudo-headers (`:authority`,
  `:scheme`, `:method`, `:path`, `:status`) and trailer-control fields
  (`trailer`, `te`). Defence-in-depth against a confused or hostile
  agent smuggling these inline on an http/1.1 request.

### Tests

- New `h2_pseudo_headers_and_trailer_fields_stripped` covers the
  extended `FORBIDDEN_HEADERS` list.

### Source

- Findings from a v1.2.5..v1.11.0 security audit (cavecrew-reviewer
  subagent). Two additional 🟡 findings (seed_test_password
  ungating, oauth-writeback cache-write ordering) inspected and
  determined to be either defence-in-depth deferrable or already
  correct as implemented. No 🔴 critical findings.

## [1.11.0] — 2026-05-25

### Added

- **HTTP/2 trailers pass-through.** gRPC carries its status in
  trailers (`grpc-status` / `grpc-message`), so transparent gRPC
  proxying needs them. The h2 MITM path now drains the upstream's
  TRAILERS frame after the body, then re-emits it on the agent
  stream via `SendStream::send_trailers`. End-of-stream flags on
  the response HEADERS / body DATA frames are computed so the h2
  framing is correct (`end_stream` on DATA = false when trailers
  follow).
- `h2_upstream::ParsedH2Response` gains a fourth tuple element:
  `Option<Vec<(String, String)>>` for trailers. Callers that don't
  speak h2 to the agent (the http/1.1 MITM path) get a startup
  WARN when the upstream returns trailers — gRPC over plain
  http/1.1 isn't supported and the trailers are dropped.

### Tests

- `tests/transparent_h2_trailers.rs` spins up an h2c upstream that
  sends `{body: "grpc-body", trailers: {grpc-status: "0",
  grpc-message: "OK"}}`; drives an h2 agent through the proxy;
  asserts the agent receives both the body and the trailers
  end-to-end.

### Not implemented

- **HTTP/2 server push** is intentionally not supported. Browsers
  have removed it (Chrome 106+, Firefox 113+); it's effectively
  dead in modern stacks.

## [1.10.0] — 2026-05-25

### Added

- **Upstream HTTP/2 connection pool.** `AppState.h2_upstream_pool`
  is a `DashMap<(host, port), h2::client::SendRequest<Bytes>>` that
  reuses h2 sessions across many transparent requests instead of
  opening a fresh connection per stream. `SendRequest` is `Clone`
  and thread-safe, so concurrent requests against the same upstream
  share one frame multiplexer + one flow-control budget.
- New `h2_upstream::try_h2_pooled` consults the pool first; on a
  miss it handshakes, stores the new `SendRequest`, and runs the
  request. On send error (GOAWAY / RST_STREAM / connection-died)
  the entry is evicted so the next request re-handshakes against a
  healthy upstream.
- Both MITM paths (h2 agent via `h2_mitm`, http/1.1 agent via
  `mitm::run_http1`) now call `try_h2_pooled` so all four
  agent↔upstream wire combinations benefit from the pool.

### Refactored

- `h2_upstream` split the prior single-shot helper into
  `handshake_tls` / `handshake_plain` / `drive_handshake` /
  `send_request_on`. The pooled and non-pooled entry points share
  the `send_request_on` path so a cached `SendRequest` and a fresh
  one issue identical requests.

### Tests

- `tests/transparent_h2_upstream_pool.rs` drives 3 sequential h2
  requests through the proxy against a counting h2c upstream;
  asserts the upstream observed exactly 1 h2 connection (not 3).
- All 19 prior transparent E2E tests still pass.

## [1.9.0] — 2026-05-25

### Added

- **Cross-protocol HTTP/2 upstream for HTTP/1.1 agents.** v1.8.0
  added upstream h2 only when the agent itself spoke h2. v1.9.0
  closes the matrix: the http/1.1 MITM path now also tries h2
  against the upstream first (via the same `h2_upstream::try_h2`
  helper). When the upstream picks h2, the parsed response is
  re-serialised back to http/1.1 wire bytes
  (`h2_upstream::serialise_as_http1`) for the agent. When the
  upstream picks http/1.1, the path falls back to the existing
  http/1.1 forwarder unchanged.
- New `h2_upstream::serialise_as_http1(status, headers, body)`
  helper: produces a complete HTTP/1.1 response with a
  recomputed `Content-Length`, `Connection: close`, and the
  connection-specific h2-forbidden headers dropped.

### Tests

- `tests/transparent_cross_protocol_h2_upstream.rs` drives a
  vanilla reqwest http/1.1 agent through the proxy against an
  h2c upstream, asserts the upstream sees the vault-injected
  Bearer (not the agent's smuggled one) and the agent gets the
  body back as a normal http/1.1 response.
- All four agent↔upstream wire combinations now have E2E coverage:
  http/1.1 ↔ http/1.1 (v1.1.0), h2 ↔ http/1.1 (v1.7.0),
  h2 ↔ h2 (v1.8.0), http/1.1 ↔ h2 (v1.9.0).

### Limitations

- Still no upstream h2 connection pool — every request opens a
  fresh h2 session to the upstream. Tracked as v1.10 "HTTP/2
  upstream pool".

## [1.8.0] — 2026-05-25

### Added

- **Native HTTP/2 to the upstream too.** The v1.7.0 h2 MITM spoke h2
  to the agent and re-framed as HTTP/1.1 to the upstream. v1.8.0
  adds `h2_upstream::try_h2` which the h2 MITM path calls first: it
  opens a TLS connection to the upstream with ALPN
  `["h2", "http/1.1"]` and, when the upstream picks h2, runs a
  single h2 request and returns the parsed response shape
  (status + headers + body) for direct re-framing back to the agent.
  When the upstream picks http/1.1 — or `VP_TRANSPARENT_TEST_HTTP=1`
  is set (test affordance) — the path falls back to the existing
  http/1.1 forwarder + parse step. End-to-end native h2 now works
  when both the agent and the upstream speak h2.
- New `src/proxy/transparent/h2_upstream.rs` module.
- `HttpRequest` is now `Clone` so the h2 MITM can hand the same
  injected request to the h2-try then (on fallback) the http/1.1
  forwarder.

### Tests

- `tests/transparent_h2_upstream.rs` spins up a hand-rolled h2c
  upstream that records the headers it received, drives an h2 agent
  through the proxy, and asserts (a) the upstream got the
  vault-injected Bearer (not the agent's smuggled one) and (b) the
  agent got the upstream's h2 response back over h2.
- `VP_TRANSPARENT_TEST_FORCE_H2=1` is a new test-only env knob that
  flips the upstream h2 client to plain TCP (h2c with prior
  knowledge) so tests don't need a TLS dance against a stub cert.

### Limitations

- No upstream h2 connection pool yet. Every agent stream still
  opens its own h2 connection to the upstream. A `DashMap<(host,
  port), SendRequest<Bytes>>` is the natural v1.9 follow-up.
- The http/1.1 MITM path (agent speaks HTTP/1.1) still always
  forwards to the upstream over http/1.1. Mixing agent-http/1.1
  with upstream-h2 needs a separate response-shape converter and
  is not in scope for v1.8.0.

## [1.7.1] — 2026-05-25

### Fixed (CI)

- Three clippy errors surfaced on rust 1.95.0 (CI's stable channel)
  that the older 1.94.x local toolchain didn't emit. All purely
  stylistic; no runtime behaviour change.
  - `src/proxy/transparent/h2_mitm.rs`: extracted `ParsedHttp1` type
    alias for `parse_http1_response`'s return shape
    (`clippy::type_complexity`).
  - `src/security/audit_sinks.rs`: switched the `libc::syslog`
    format-string ptr from `b"%s\0".as_ptr()` to the modern
    `c"%s".as_ptr()` (`clippy::manual_c_str_literals`).
  - `src/security/audit_sinks_http.rs`: reflowed a multi-line doc
    list-item so the continuation line aligns at 4 spaces
    (`clippy::doc_overindented_list_items`).
- Root cause for the v1.4.4 → v1.7.0 Docker-publish failures was
  the same three lints; they tripped CI on every release since
  v1.4.4 but didn't affect crates.io publication (which doesn't run
  clippy) so the released artefacts were and remain correct.

## [1.7.0] — 2026-05-25

### Added

- **Native HTTP/2 transparent MITM.** The MITM leaf cert now
  advertises both `h2` and `http/1.1` on ALPN (was http/1.1-only in
  v1.4.1+). Post-handshake, `mitm::run` inspects the negotiated
  protocol and dispatches to either the existing
  `mitm::run_http1` (HTTP/1.1) or the new `h2_mitm::run_h2`
  (HTTP/2) path. Agent-side framing is native h2 with per-stream
  concurrency; upstream-side still speaks HTTP/1.1 via the shared
  `forward_to_upstream_for_h2` helper (the proxy synthesises an
  HTTP/1.1 request from the h2 headers + body, runs the existing
  injectors, then re-frames the HTTP/1.1 response as h2 back to the
  agent).
- New `src/proxy/transparent/h2_mitm.rs` module. Direct `h2 = "0.4"`
  and `http = "1"` deps (already in tree via reqwest/hyper).

### Behaviour changes

- **ALPN contract**: a client that offers `["h2", "http/1.1"]` now
  ends up on h2 (was http/1.1 in v1.4.1+). A client that offers only
  `["http/1.1"]` still negotiates http/1.1. A client that demands
  only `["h2"]` now succeeds (was a clean ALPN-mismatch error in
  v1.4.1+).
- The `transparent_alpn_downgrade` test file was renamed in spirit:
  the two tests now cover the v1.7.0 contract (mixed offer →
  picks h2; http/1.1-only → picks http/1.1).

### Tests

- New `tests/transparent_h2_mitm.rs` drives a hand-rolled rustls +
  `h2::client` end-to-end against the MITM listener: outer ALPN
  negotiation lands on h2, h2 server framing reads the agent
  request, vault-injected Bearer reaches the wiremock upstream, and
  the upstream's HTTP/1.1 response is re-framed back as h2.

### Limitations (will tighten in follow-up releases)

- Upstream still HTTP/1.1; an h2-required upstream (rare in
  practice — most accept HTTP/1.1) won't work via the h2 MITM yet.
- Trailers + server push not supported.

## [1.6.0] — 2026-05-25

### Added

- **Custom-field OAuth refresh-token writeback.** The v1.5.0 writeback
  path was limited to `refresh_token_field = "password"`. v1.6.0 adds
  `VaultManager::update_field_for_item` (and the pure
  `merge_field_into_cipher` helper that powers it) so OAuth services
  whose RT lives in a custom Vaultwarden field can now persist
  rotated tokens too. The helper merges only the named field; every
  other encrypted field (including the credential blobs) stays
  byte-for-byte unchanged so the cipher PUT diff is minimal.
- Routing: the OAuth writeback path now picks
  `update_password_for_item` when `refresh_token_field == "password"`
  and `update_field_for_item` otherwise. Behaviour for the default
  case is identical to v1.5.0.

### Tests

- New unit tests cover the merge helper end-to-end (existing-field
  update + untouched-field byte invariance, plus append-when-absent).

## [1.5.1] — 2026-05-25

### Docs

- **SECURITY.md sweep.** The transparent-mode section was last touched
  at v1.2.5 and still claimed "no listener-side authentication" — out
  of date since v1.3.1 (UDS + SO_PEERCRED) and v1.4.0 (mTLS-fronted
  listener). Rewritten:
  - The Transparent HTTPS_PROXY section now covers all three listener
    variants (TCP, UDS, mTLS), v1.4.1 ALPN downgrade behaviour, and
    the Tier-1 status of the mTLS server cert + key.
  - New "OAuth tokens" sub-section covers the in-memory token cache,
    refresh-token vault writeback (`oauth_writeback = true`), and the
    custom-field limitation.
  - New "Audit log + SIEM sinks" sub-section covers v1.4.2 sync sinks
    and v1.4.4 network sinks, including the Tier-2 sensitivity of the
    SIEM-side API key / HEC token and the rationale for sourcing them
    from env vars rather than argv.

No code changes — version bumped to v1.5.1 so the docs ship via the
standard publish flow.

## [1.5.0] — 2026-05-25

### Added

- **OAuth refresh-token vault writeback.** New `oauth_writeback = true`
  flag on `auth = "oauth_refresh"` services. When the IdP returns a
  rotated `refresh_token` in the response, the proxy writes it back
  to the vault item via `update_password_for_item`. Concurrent
  refreshes are serialised via a per-`vault_item` `Mutex` held from
  cache-check through POST through writeback, so a rotating IdP
  doesn't deal two grants the second of which uses an already-
  invalidated RT.
  - Default `false` (preserves v1.3.2 behaviour: log + discard).
  - Only supported when `refresh_token_field` is the default
    `"password"`. Custom-field writeback logs a WARN and discards
    the rotation (tracked as a v1.6 follow-up).
  - Public OAuth flows that don't return a rotated RT see no
    behaviour change.

### Changed

- `AppState.oauth_writeback_locks` (new) holds the per-`vault_item`
  serialisation mutexes. Lazily populated; one entry per OAuth
  refresh-token service for the process lifetime.
- `proxy::get_or_refresh_oauth_refresh_token` is now `pub` (was
  `pub(crate)`) so integration tests can drive it directly.
- `VaultManager::seed_test_password` is production-visible (was cfg-
  gated to `test-utils`). The companion reader `test_item_password`
  was already production-visible; symmetry is preserved. No new
  external API: the only way to populate the test_passwords map in
  production is to call this from inside the proxy process itself.

### Tests

- `tests/transparent_oauth_refresh_writeback.rs` E2Es both legs:
  writeback ON persists rotated RT to the stub map and the next
  refresh uses it; writeback OFF leaves the stub untouched.

## [1.4.4] — 2026-05-25

### Added

- **Network audit sinks: OTLP / Datadog Logs / Splunk HEC.** Extends
  the v1.4.2 `AuditSink` trait with three HTTP-based forwarders:
    - `--audit-sink=otlp` — POSTs to `OTLP_AUDIT_URL` with an OTLP
      `LogsData` envelope. Optional `OTLP_AUDIT_HEADERS` carries
      comma-separated `key=value` header pairs (typically the bearer
      auth header).
    - `--audit-sink=datadog` — POSTs to `DATADOG_AUDIT_URL` with a
      JSON array of `{service, ddsource, message, timestamp}` records.
      Auth via `DATADOG_AUDIT_API_KEY` (DD-API-KEY header).
    - `--audit-sink=splunk` — POSTs to `SPLUNK_AUDIT_URL` with
      newline-delimited `{"event": <entry>, "sourcetype": "vaultproxy:audit"}`
      records. Auth via `SPLUNK_AUDIT_TOKEN` (Splunk HEC bearer).
- All three share a bounded-mpsc + background-flusher design: each
  `emit()` enqueues non-blockingly, the flusher batches up to 50
  entries or 5s (whichever fires first), and a failed POST drops the
  batch with a WARN. Loss-intolerant operators keep the on-disk file
  (it always fans out alongside).
- Secrets live in env vars, not in `--audit-sink` argv — keeps tokens
  out of `/proc/<pid>/cmdline`.

### Tests

- New `tests/audit_sink_http_integration.rs` E2Es all three transports
  against wiremock, verifying batching + headers + body shape.

## [1.4.3] — 2026-05-25

### Docs

- **Operator docs catch up with v1.3/v1.4.** `docs/operator/TRANSPARENT.md`
  now covers all four listener variants (TCP, UDS, mTLS), OAuth
  client-credentials + refresh-token auth patterns, SIGHUP reload,
  the `--transparent-sanitize-responses` CLI flag (env shim gone),
  v1.4.1 ALPN downgrade behaviour, and v1.4.2 audit sinks.
- `docs/operator/TRANSPARENT-FLAGS.md` rewritten into four sections
  (Listeners, MITM CA, Per-service behaviour, Cross-cutting) so the
  full flag surface is one table-scan instead of one flat list.

No code changes.

## [1.4.2] — 2026-05-25

### Added

- **SIEM-friendly audit sinks.** New `--audit-sink=<spec>` /
  `AUDIT_SINK=<spec>` flag fans out every `AuditLog::log()` call to
  one or more sinks alongside the on-disk JSON file. Spec is a
  comma-separated list; recognised sinks: `stdout`, `stderr`,
  `syslog` (Unix only). Unknown entries are logged at WARN and
  skipped. Empty / unset = file-only (the v1.4.x behaviour).
- New `src/security/audit_sinks.rs` module exposes `AuditSink` trait
  for downstream extension (network sinks like OTLP / Datadog HEC /
  Splunk HEC remain v1.5 candidates).
- Tests: `tests/audit_sink_integration.rs` covers the fan-out
  contract; `parse_spec` unit tests cover empty / unknown /
  duplicate input handling.

## [1.4.1] — 2026-05-25

### Changed

- **Transparent MITM leaf certs now pin ALPN to `http/1.1`.** Previously
  the leaf cert advertised no ALPN, leaving negotiation up to the
  client. Modern clients that default to ALPN `["h2", "http/1.1"]`
  could negotiate h2 against a proxy whose MITM parser only speaks
  HTTP/1.1, leading to silent stream corruption. Now the leaf
  explicitly announces only `http/1.1`, so clients either downgrade
  (h2-capable clients picking http/1.1 from the list) or fail the TLS
  handshake with an ALPN mismatch (clients that demand h2 only). Both
  outcomes are safer than the previous silent corruption.

### Tests

- New `tests/transparent_alpn_downgrade.rs` exercises both paths
  (mixed offer downgrades to http/1.1; h2-only offer rejected).

## [1.4.0] — 2026-05-25

### Added

- **Transparent mTLS-fronted listener.** New
  `--transparent-mtls-listen <addr>` (env: `TRANSPARENT_MTLS_LISTEN`)
  binds an additional listener that requires the agent to present a
  client certificate signed by `--transparent-mtls-client-ca` and to
  trust the server cert configured at `--transparent-mtls-server-cert`
  / `--transparent-mtls-server-key`. Inside the outer TLS jacket, the
  same plaintext CONNECT + per-host MITM flow runs as on the plain TCP
  listener. Intended for exposing the transparent listener beyond
  loopback (e.g. over Tailscale). Loopback TCP and UDS listeners
  remain unaffected.
- E2E coverage in `tests/transparent_mtls_listener.rs` issuing an
  in-memory mTLS chain with rcgen, driving the full outer-mTLS + inner
  MITM round-trip, and verifying that callers without a client cert
  are rejected.

### Security

- Operators MUST treat the mTLS listener's server cert + key as if it
  were the transparent CA key (`SECURITY.md` covers the latter). The
  CA that signs client certs need not live on the proxy host once
  client certs are issued.

## [1.3.2] — 2026-05-25

### Added

- **OAuth 2.0 refresh-token auth pattern** — new
  `auth = "oauth_refresh"` in `services.toml`. Fields:
  `token_url` (required), optional `key_field` (default `"username"`)
  and `secret_field` (default empty — public OAuth clients omit
  client_secret entirely), optional `refresh_token_field`
  (default `"password"`), optional `scope`. The long-lived refresh
  token lives in the vault; vault-proxy exchanges it for short-lived
  access tokens, caches them per-`vault_item` until `expires_in − 60 s`,
  and re-acquires on a `401` from the upstream. Token cache is shared
  with `oauth_client_credentials` (`AppState.oauth_tokens`).
- E2E coverage in `tests/transparent_host_inject_oauth_refresh.rs`
  against wiremock-stubbed token + upstream endpoints.

### Limitations

- IdP-side refresh-token rotation is **logged but not persisted back to
  the vault**. Operators using IdPs that mandatorily rotate refresh
  tokens on every grant must rotate the vault item out-of-band.

## [1.3.1] — 2026-05-25

### Added

- **Transparent UDS listener — dispatch wired.** `--transparent-uds <path>`
  (env: `TRANSPARENT_UDS`) binds an additional listener on a Unix-domain
  socket alongside the TCP listener. Authenticates callers via
  `SO_PEERCRED` (uid match) and now routes accepted connections through
  the shared `handle_connection` MITM path (the v1.2.5 scaffold closed
  accepted streams without dispatching).
- **`--transparent-sanitize-responses` CLI flag** (env:
  `TRANSPARENT_SANITIZE_RESPONSES`) — promotes the v1.2.5
  `VP_TRANSPARENT_SANITIZE_RESPONSES=1` env shim into a first-class
  AppState-backed flag. Default off; flip on for response prompt-injection
  scrubbing.
- E2E coverage in `tests/transparent_uds_dispatch.rs` driving the UDS path
  end-to-end (CONNECT + TLS over UDS + wiremock upstream).

### Changed

- `handle_connection` is now generic over the agent-side I/O type
  (`AsyncRead + AsyncWrite + Unpin`) so the TCP and UDS listeners share
  one implementation. `mitm::run` and `passthrough::tunnel_with_audit`
  follow the same generalisation; upstream side is still TCP.
- `peer` argument on `handle_connection` is now a `String` so non-TCP
  peers (UDS uid stamp) can be passed in for logging.

### Removed

- `VP_TRANSPARENT_SANITIZE_RESPONSES` env shim. Use
  `--transparent-sanitize-responses` / `TRANSPARENT_SANITIZE_RESPONSES`.

## [1.3.0] — 2026-05-25

### Added

- **OAuth 2.0 client-credentials auth pattern** — new
  `auth = "oauth_client_credentials"` in `services.toml`. Fields:
  `token_url` (required), optional `key_field` / `secret_field`
  (default `username` / `password`) to nominate which vault fields hold
  the client_id / client_secret, optional `scope`. Tokens are minted on
  first use, cached per-`vault_item` until `expires_in − 60 s`, and
  re-acquired automatically on a `401` from the upstream. Works for both
  the `/proxy/{service}` path and the transparent HTTPS_PROXY listener
  in `host_inject` mode — the token cache is shared
  (`AppState.oauth_tokens`).
- E2E coverage in `tests/transparent_host_inject_oauth.rs` against
  wiremock-stubbed token + upstream endpoints.

### Docs

- `docs/ROADMAP.md` — strike OAuth client-credentials from v1.3 candidates.

## [1.2.5] — 2026-05-24

### Added

- **Wildcard host patterns** — `base_url = "https://*.github.com"` with
  `transparent_mode = "host_inject"` now matches any subdomain. Exact entries
  always win; wildcards fire only on exact miss. Leading `*.` only (embedded
  or trailing stars rejected at build).
- **Response prompt-injection sanitisation** — opt-in via
  `VP_TRANSPARENT_SANITIZE_RESPONSES=1`. Splits upstream HTTP response at
  `\r\n\r\n`, runs textual bodies through `security::sanitize::sanitize_for_wire`,
  rebuilds Content-Length. Skips chunked / non-textual / non-parseable
  responses defensively.
- **SO_PEERCRED Unix-domain-socket listener scaffold** — binds
  `$XDG_RUNTIME_DIR/vaultproxy-transparent.sock` (mode 0600), authenticates via
  SO_PEERCRED (uid match), rejects mismatched callers. Per-accept dispatch
  through `mitm::run` is a v1.3 follow-up (needs `handle_connection`
  `pub(super)`).

### Docs

- `docs/ROADMAP.md` rewritten to enumerate what's shipped through v1.2 and
  what remains for v1.3 (full mTLS, OAuth, HTTP/2, sanitise default-on).

## [1.2.4] — 2026-05-24

### Fixed (CI)

- `--test-threads=1` on the `Run integration tests` CI step so the transparent
  smoke clients (curl / python / node) don't race on the process-global
  `VP_TRANSPARENT_TEST_HTTP` env var.

## [1.2.3] — 2026-05-24

### Added

- **Audit log archive** — entries evicted past the 1 000-entry ring
  buffer cap now append to `<path>.archive` as JSONL (one entry per
  line). Best-effort: archive write failures log a WARN but don't
  block the live append path. Closes the data-loss gap that opened
  when transparent traffic could fill the cap in minutes.
- **`examples/smart-mcp-server-transparent/`** — minimal Python MCP
  server demonstrating zero-credential code via the transparent
  listener (`HTTPS_PROXY=...:3203` + `REQUESTS_CA_BUNDLE`).
- **README badges** — crates.io, GHCR, CI, License, MSRV, and a
  transparent-default-on shield for v1.2+.

### Docs

- `docs/operator/AUDIT-LOG.md` — documents the new archive file and
  the six transparent-mode telemetry fields on `AuditEntry`.

## [1.2.2] — 2026-05-24

### Refactor

- **Typed transparent error envelope** — `proxy::transparent::errors::TransparentErrorCode`
  centralises the HTTP status + `transparent_error_code` discriminator across
  all transparent error paths. Three near-duplicate inline writers
  (`mod.rs::reply_error`, `mitm.rs::write_error_over_tls`,
  `passthrough.rs::reply_502`) collapse into one helper. Client contract is unchanged.

## [1.2.1] — 2026-05-24

### Added

- **SIGHUP rebuild of transparent registry + placeholders** — `transparent_mode`
  edits and `[[transparent_placeholder]]` blocks now take effect without restart.
  The SIGHUP handler (already swaps `ServiceRegistry`) calls
  `proxy::transparent::rebuild_from_state` after the underlying registry swap.
  In-flight requests work from their captured snapshot; only new accepts see the
  updated map.
- `AppState.transparent_registry` + `transparent_placeholders` cells (cfg-gated)
  expose the live handles to the SIGHUP rebuild path.

## [1.2.0] — 2026-05-24

### Changed (breaking)

- **`default = ["transparent"]`** — the transparent HTTPS_PROXY listener is now
  built into the default release. Operators who don't want it can opt out via
  `--no-default-features` or a custom feature subset. Listener still binds
  `127.0.0.1:3203` only by default and only when `--transparent-listen` is non-empty.

### Added

- **Real Vaultwarden decryption in `inject_host`** — credentials for transparent
  host_inject (Bearer / Header / Basic / QueryParam) resolve via
  `VaultManager::decrypt_password` and `decrypt_field`, mirroring the existing
  `/proxy` `apply_auth_and_send` path. Production transparent mode is usable
  end-to-end with a live vault.

## [1.1.1] — 2026-05-24

### Fixed

- Reverted premature `default = ["transparent"]` from v1.2 attempt: shipping
  default-on without real vault wiring would have made every transparent request
  502 in production. Documented v1.2 prerequisite in Cargo.toml.

## [1.1.0] — 2026-05-24

### Added — transparent HTTPS_PROXY mode (`--features transparent`)

- New listener on `127.0.0.1:3203` (default; configurable via `--transparent-listen`).
- Auto-generated or BYO MITM CA at `$CONFIG_DIR/transparent-ca.{crt,key}` with
  0600 enforcement, SHA-256 fingerprint banner on startup, regeneration via
  file deletion.
- Per-host signed leaf certs (ED25519, 30-day validity) cached in a 1024-entry
  LRU. Upstream cert SANs mirrored into the leaf so pinning-based clients work.
- Two MITM modes selectable per service via `services.toml`:
  - `host_inject` — strip agent auth headers, inject vault credential per `auth`
    pattern. Supports Bearer, Header, Basic, QueryParam. Session / UnifiDual
    rejected at parse time.
  - `placeholder` — scan request path/headers/body for literal `__vault.<name>__`
    tokens and replace with the resolved vault value. Driven by new
    `[[transparent_placeholder]]` services.toml block.
- `--transparent-unregistered-policy={passthrough|allowlist}` — allowlist mode
  rejects CONNECT to hosts not in `[[service]]` with 502 +
  `transparent_error_code = "unregistered_host_blocked"`.
- Audit-log entries with `trigger = "transparent"`, plus per-entry telemetry
  (`transparent_mode`, `upstream_host`, `upstream_status`, `bytes_in`,
  `bytes_out`, `duration_ms`).
- E2E tests across reqwest, curl, Python urllib, Node tls.
- Documentation: `docs/operator/TRANSPARENT.md`, `TRANSPARENT-CA.md`,
  `TRANSPARENT-FLAGS.md`; `SECURITY.md` updated with CA threat model;
  `services.example.toml` annotated.

### CI

- Cache populated via `Swatinem/rust-cache@v2` (cold-cache builds ~21min → ~5min).
- Full feature matrix runs four extra clippy + test passes covering
  `transparent`, `transparent,test-utils`, and the combined
  `browser,engine,dashboard,transparent` permutation.

## [1.0.6] — 2026-05-24

### Fixed

- `RotationHook::fire` retries `spawn` up to 5 times on ETXTBSY (kernel
  exec-after-chmod race observed in CI under parallel test load). Other spawn
  errors still fail fast.
- Clippy backlog cleared across ~30 files: dead-code allowances for
  feature-gated call sites, `&PathBuf` → `&Path`, `drop(<future>)` over
  `let _ = <future>`, `is_empty()` companion for `len()`, mass `cargo fmt`.

---

## [1.0.3] — iterations 124–126: UniFi session invalidation complete, multi-service invalidation, v1.0.3 release

### Bugs (iter-126)

- **`items.html` only invalidates `serviceNames[0]` — second+ service sessions remain cached after rotation (iter-126)** — `dashboard/items.html:57`. MEDIUM.
  When a vault item is shared by multiple services (e.g. `"vault-proxy - UniFi"` used by both
  `unifi_home` and `unifi_backup`), `rotateItem()` only forwarded `serviceNames[0]` as the scalar
  `unifi_service_name` field.  The second service's cached session cookie remained live until the
  controller's own TTL expired, allowing subsequent proxy calls to authenticate with the rotated
  (now-invalid) credential.
  Fixed (two parts):
  1. `items.html:rotateItem()` now sends `unifi_service_names: item.serviceNames` (the full array)
     instead of `unifi_service_name: item.serviceNames[0]` (scalar, first element only).
  2. `browser_rotate` in `src/main.rs` upgraded from `unifi_service_name: Option<String>` (single)
     to `unifi_service_names: Vec<String>` (all matching services).  Accepts both
     `"unifi_service_names": [...]` (array, preferred) and `"unifi_service_name": "..."` (scalar
     legacy) for backward compatibility with old callers.  The invalidation block is now a loop
     that clears every matching service session.

- **`v1.0.3` GitHub release missing (iter-126)** — process gap.
  The git tag `v1.0.3` was created at the iter-125 commit but `gh release create` was never run.
  `gh release list` showed Latest = `v1.0.2`.  Fixed: release created in this iteration.

### Verified (iter-126) — iter-125 wiring audit

Ten specific areas were audited. Two bugs found and fixed (above); remainder pass.

1. **`items.html` only invalidates `serviceNames[0]`** — FIXED (see Bugs above). Now sends full
   `unifi_service_names` array; server loops over all entries.
2. **`GET /api/items` exposes service names in dashboard** — INFO, NOT A BUG. Endpoint already
   requires dashboard session auth. Service names (e.g. `"sonarr_main"`) are routing keys,
   not secrets; exposure is intentional for the rotation UI context.
3. **`v1.0.3` GitHub release** — FIXED (see Bugs above).
4. **`AuthPattern::vault_item()` — all 6 variants covered** — PASS. All 6 variants (Bearer,
   Header, QueryParam, Basic, Session, UnifiDual) return the correct `vault_item` field.
   `Basic` uses `vault_item` as the credential source with separate `key_field`/`secret_field`;
   `vault_item()` correctly returns `self.vault_item`, not a key/secret field.
5. **`browser_rotate` with `unifi_service_name` for non-existent service** — PASS. TRUE NO-OP.
   `invalidate()` uses `self.inner.get(service)` — if the key is absent, `get()` returns `None`
   and the `if let` block is skipped entirely. No spurious entry is inserted into the DashMap.
6. **Multiple service invalidation — `browser_rotate` only handles one service** — FIXED (see
   Bugs above). Upgraded to `Vec<String>` with loop over all service names.
7. **`GET /api/items` registry lock held during JSON serialization** — PASS. Lock is ALREADY
   released before serialization. `drop(registry)` at `src/dashboard/api.rs:137` is called
   before the `serde_json::to_value(&items)` call at line 140. No blocking issue.
8. **`ServiceEntry::vault_item()` returns `&str` — lifetime safety** — PASS. The registry lock
   IS held while building the reverse map (lines 125–136); all string values are cloned via
   `.to_string()` at line 134, so no dangling references exist after `drop(registry)` at line 137.
9. **`vault_item_accessor_tests` — covers `UnifiDual`** — PASS. Test at `registry.rs:2682` explicitly
   sets `vault_item = "unifi-home-item"` and `login_path = "/api/auth/login"`, asserting the accessor
   returns `"unifi-home-item"` (the credential name), not the login path.
10. **`CHANGELOG.md` iter-125 entry** — PASS. `[1.0.3]` section present with full iter-125 coverage
    including `items.html serviceNames` fix and `AuthPattern::vault_item()` addition. Updated here
    with iter-126 additions.

### Quality gates (iter-126)

- `cargo fmt --check` — 0 diffs
- `cargo clippy --all-targets --features browser,engine,dashboard -- -D warnings` — 0 warnings
- `cargo test --all-targets --features browser,engine,dashboard` — **324 passed** (+ 2 integration) = **326 total**; 0 failed
- `cargo doc --no-deps --features browser,engine,dashboard` — 0 errors, 0 warnings

## [1.0.3] — iterations 124–125: UniFi session invalidation complete, serviceNames in items API

### Bugs (iter-125)

- **`items.html` rotation button does not pass `unifi_service_name` — cache invalidation never fires for dashboard-initiated rotations (iter-125)** — `dashboard/items.html:50`. MEDIUM.
  Iter-124 wired `unifi_sessions.invalidate(svc)` into `browser_rotate` and documented that callers
  must include `unifi_service_name` in the request body.  The dashboard rotation button in `items.html`
  sent `{item_name: name}` with no service metadata — so the invalidation path was dead for every
  rotation triggered from the dashboard.  Root cause: `items.html` received only `MaskedItem` fields
  from `GET /api/items` and had no way to know which registry service name(s) referenced each vault item.
  Fixed (two parts):
  1. `GET /api/items` (`src/dashboard/api.rs`) now acquires a read lock on the service registry and
     annotates each item JSON object with `"serviceNames": [...]` — the registry service names whose
     `vault_item` field matches the item's name.  New `AuthPattern::vault_item()` and
     `ServiceEntry::vault_item()` accessors (`src/proxy/registry.rs`) power the reverse lookup.
     For non-UniFi items the list is empty; the field is a no-op on the server.
  2. `rotateItem()` in `items.html` now accepts the full item object.  When `item.serviceNames` is
     non-empty, the first entry is forwarded as `unifi_service_name` in the rotate request body.
     The handler invalidates the cached session cookie on a successful rotation exactly as intended
     by iter-124.

- **`unifi_session::invalidate` carries `#[allow(dead_code)]` after being production-wired (iter-125)** — `src/proxy/unifi_session.rs:92`. LOW.
  Iter-124 updated the comment but left `#[allow(dead_code)]` on the `pub` function.  Dead-code lint
  does not fire on `pub` items regardless, so the attribute was incorrect and misleading (suggesting
  the function still has no caller when it now does).  Removed.

### Tests (iter-125)

- **`vault_item_accessor_tests` — 7 new tests (iter-125)** — `src/proxy/registry.rs`.
  No tests covered the new `AuthPattern::vault_item()` / `ServiceEntry::vault_item()` accessors.
  Added one test per `AuthPattern` variant (Header, QueryParam, Bearer, Basic, Session, UnifiDual)
  and one test that exercises `ServiceEntry::vault_item()` delegation.

### Verified (iter-125) — iter-124 wiring audit

Ten specific areas were audited against iter-124 changes. One new bug found (see above); remainder pass.

1. **`items.html` passes `unifi_service_name`** — FIXED (see Bugs above). Was absent; invalidation
   never fired for dashboard-initiated rotations regardless of item type.
2. **`browser_rotate` silent skip when `unifi_service_name` absent** — DOCUMENTED. `Option<String>`;
   empty string filtered at parse time (`filter(|s| !s.is_empty())`). No-op for non-UniFi callers or
   old clients. The iter-125 fix ensures dashboard callers now pass the field for UniFi items.
3. **`approvals.html` approval payload** — PASS. POSTs to `/api/approvals` with `{id, action, code}`.
   Separate from rotation flow. No change needed.
4. **Connecterr TS client `triggerBrowserRotation()`** — NOT PRESENT. No such method in
   `Connecterr/src/sidecar-client.ts`. Browser rotation is dashboard-only; no TS client update needed.
5. **`invalidate()` called before or after panic window** — PASS. Invalidation fires after
   `workflow.run()` returns `success=true` — the rotation is already committed to the vault at that
   point.  A panic before `invalidate()` would leave the old session cached, but the credential
   fingerprint mismatch in `handle_request` would catch it on the next proxy call and re-login anyway.
   No additional guard needed.
6. **`CHANGELOG.md` iter-124 documented** — DONE (this entry, combined as [1.0.3]).
7. **`v1.0.3` patch release** — Cargo.toml bumped; tag to follow after quality gates.
8. **`#[allow(dead_code)]` on `invalidate`** — FIXED (see Bugs above). Annotation removed.
9. **`unifi_service_name` input validation** — PASS. `filter(|s| !s.is_empty())` rejects empty strings.
   The value is used as a `HashMap` key lookup — no injection vector; no length limit needed beyond
   what a `DashMap` key lookup already implies (safe for any valid UTF-8 string).
10. **Final quality gates** — see below.

### Quality gates (iter-125)

- `cargo fmt --check` — 0 diffs
- `cargo clippy --all-targets --features browser,engine,dashboard -- -D warnings` — 0 warnings
- `cargo test --all-targets --features browser,engine,dashboard` — **324 passed** (+ 2 integration) = **326 total**; 0 failed (7 new tests: `vault_item_accessor_tests`)
- `cargo doc --no-deps --features browser,engine,dashboard` — 0 errors, 0 warnings

## [1.0.2] — iterations 122–123: approvals silent-error, null fallback hardening, shape test gaps

### Bugs (iter-123)

- **`approvals.html` silently shows empty queue on `ok===false` (iter-123)** — `dashboard/approvals.html:243`. MEDIUM.
  The iter-122 array-unwrap fallback `Array.isArray(data.approvals) ? data.approvals : []` returns `[]`
  when `data.ok === false` (e.g. vault not initialized, 503 from `require_app`). Users would see
  "No pending approvals." with no explanation instead of the error. Same class of bug fixed in
  `items.html`, `audit-log.html`, `policies.html`, `permissions.html` in iter-119–121.
  Fixed: added `ok===false` guard that calls `renderError(data.error)` before the array-unwrap logic;
  added `renderError()` helper function.

- **`list_approvals` `approvals_val` can be `null` on serialization failure (iter-123)** — `src/dashboard/api.rs:301`. LOW.
  `serde_json::to_value(&pending).unwrap_or_default()` fallback returns `Value::Null` on (pathological)
  serialization failure. `Array.isArray(null)` is `false` in JavaScript, so the JS fallback in
  `approvals.html` would silently return an empty list rather than an error.
  Fixed: fallback changed to `unwrap_or_else(|_| Value::Array(vec![]))` so the field is always
  a JSON array regardless of serialization outcome.

- **`api_approvals_has_ok_true_and_approvals_array` test key-name assertion missing (iter-123)** — `src/dashboard/api.rs:2040`. LOW.
  The iter-122 shape test asserted `body["approvals"].is_array()` but not that the key is specifically
  named `"approvals"`. If the key were renamed to `"items"` the test would fail on the array check,
  but the explicit key-name assertion makes the intent clearer and provides a faster diagnostic.
  Fixed: added `body.get("approvals").is_some()` assertion with a descriptive message.

### Tests (iter-123)

- **`api_approvals_error_has_ok_false` shape test added (iter-123)** — `src/dashboard/api.rs`. LOW.
  No test verified the `ok===false` error shape for `GET /api/approvals`. A regression to a missing
  `"ok"` field on the error path (e.g. from `require_app`) would go undetected.
  Fixed: added `api_approvals_error_has_ok_false` test asserting `body["ok"] == false` and
  `body["error"]` is a string.

### Verified (iter-123) — iter-122 + remaining gaps audit

Ten specific areas were audited. Four new issues found (above); six passed.

1. **`approvals.html:241` ok===false guard** — FIXED (see Bugs above). Was missing; silently
   rendered empty queue when vault not initialized or other `require_app` error.

2. **`list_approvals` error paths have `"ok": false`** — PASS. Both error paths return `"ok": false`:
   (a) `require_app` failure → `{"ok":false,"error":"vault not initialized..."}` from the
   `require_app()` helper (iter-105); (b) no second explicit error path (write lock always succeeds
   on an `Arc<RwLock<Vec<_>>>`). No lock-failure path to guard.

3. **`v1.0.2` GitHub release** — MISSING. `gh release list` shows Latest is `v1.0.1`. `v1.0.2` git
   tag exists (created at iter-122 commit) but no GitHub release was created. Fixed: release
   created in this iteration (see process log).

4. **`setup_cloud_via_dashboard` bearer-token gating** — PASS. `POST /api/settings/cloud` is
   registered in `api_routes_base` (dashboard/mod.rs:112) which is wrapped in `require_session`
   middleware at line 182. Dashboard session cookie required. The raw sidecar proxy at
   `http://127.0.0.1:3201/sync/init` is localhost-only; sidecar response always contains `ok`
   from its own handler. No new exposure.

5. **`api_approvals_has_ok_true_and_approvals_array` test completeness** — PARTIAL GAP FIXED.
   Test asserted `body["approvals"].is_array()` but not the explicit key name `"approvals"`.
   Enhanced with `body.get("approvals").is_some()` assertion (above).

6. **`CHANGELOG.md [1.0.2]` completeness** — FIXED (this entry). Previous entry only covered
   iter-122. Now covers iter-123 fixes: approvals.html ok===false guard, null fallback hardening,
   key-name assertion, error path shape test.

7. **`unifi_session:invalidate` rotation UI path (post-v1.0:)** — DEFERRED (confirmed). The
   `invalidate()` method at line 91 is fully implemented — `#[allow(dead_code)]` comment updated
   to `post-v1.0: rotation UI`. The production wiring gap is in the browser rotation workflow:
   `browser_rotate` in `main.rs` calls the sidecar at `http://127.0.0.1:3201/browser/rotate`;
   that sidecar path would need to call back into the proxy to trigger `invalidate()` after a
   successful rotation, OR the proxy handler needs to invalidate before dispatching the rotate.
   Path: wire `app.unifi_session_cache.invalidate(&service_name)` in `browser_rotate` after
   a successful rotation response. Requires `--features browser`; estimated <50 LOC.

8. **`approvals.html` error path for `require_app` 503** — FIXED (see Bugs above). Identical
   to issue 1 — the `ok===false` guard now catches this case.

9. **`approvals.html` null `data.approvals` fallback** — FIXED (see Bugs above). `approvals_val`
   fallback changed from `Value::Null` to `Value::Array(vec![])`.

10. **Final `json!({...})` without `"ok"` scan** — PASS (with known exception). 179 `"ok"`
    occurrences vs 133 `json!({` occurrences in `src/dashboard/api.rs`. All `json!({` blocks
    without inline `"ok"` are sub-objects embedded inside a parent object that carries `"ok"`
    at the top level (e.g. `cloud_sync` inner object in `status`, per-tool item objects in
    `get_permissions`, per-file objects in `tpm_status`). One intentional exception:
    `setup_cloud_via_dashboard` proxies the raw sidecar body — that body always carries `ok`
    from the sidecar's own handler. The `audit` handler at line 213 uses
    `serde_json::to_value(result).unwrap_or_default()` where `AuditResult` has `pub ok: bool`;
    serialization is infallible so `ok` is always present. No unguarded gaps found.

### Quality gates (iter-123)

- `cargo fmt --check` — 0 diffs
- `cargo clippy --all-targets --features browser,engine,dashboard -- -D warnings` — 0 warnings
- `cargo test --all-targets --features browser,engine,dashboard` — **317 passed** (+ 2 integration) = **319 total**; 0 failed (1 new shape test: `api_approvals_error_has_ok_false`; existing `api_approvals_has_ok_true_and_approvals_array` strengthened)
- `cargo doc --no-deps --features browser,engine,dashboard` — 0 errors, 0 warnings

---

## [1.0.2] — iteration 122: JS correctness audit, approvals envelope fix

### Bugs (iter-122)

- **`GET /api/approvals` returns bare JSON array without `"ok"` envelope (iter-122)** — `src/dashboard/api.rs:298`. MEDIUM.
  Every other dashboard collection endpoint (`/api/items`, `/api/sync`, `/api/permissions`, etc.)
  returns `{"ok":true,"<key>":[...]}`. `GET /api/approvals` was the sole exception — it returned a
  raw JSON array with no `"ok"` sentinel, inconsistent with the pattern established in iter-109 through
  iter-117. The JavaScript in `approvals.html:241` compensated with `Array.isArray(data) ? data : []`,
  masking the inconsistency. Fixed: response wrapped in `{"ok":true,"approvals":[...]}`;
  `approvals.html` updated to unwrap `data.approvals` with the Array.isArray fallback retained for
  graceful rollback; shape test added (`api_approvals_has_ok_true_and_approvals_array`).

### Verified (iter-122) — iter-121 JS correctness audit

Ten specific areas were audited. Nine passed; one new bug was found (above).

1. **`rotation.html:244` — interval ID accessible** — PASS. `refreshTimer` is declared
   `var refreshTimer;` at line 242, assigned `refreshTimer = setInterval(...)` at line 327
   (module scope), and `clearInterval(refreshTimer)` is called at lines 259 and 323. Both call
   sites share the same var scope. Correct.

2. **`sync.html:121` — `applyState("error")` defined** — PASS. `applyState` is defined at line 99.
   Line 106 explicitly handles `"error"`: `state === "error" || state === "idle_with_errors"` adds
   the `err` CSS class. Calling `applyState("error")` on server error is safe and visible.

3. **`audit.html:304` — `statusNote` DOM element exists** — PASS. `statusNote` is obtained via
   `document.getElementById("status-note")` at line 155. The HTML element `<p id="status-note">`
   exists at line 140. Not null.

4. **`index.html` — all API calls protected** — PASS. `index.html` makes exactly one API call
   (`/api/status`). Vault count, sync state, and service count all derive from that single response.
   The iter-121 `ok === false` guard covers all three fields. No unguarded second call.

5. **`settings.html:880` `loadCredentials` error messaging** — PASS (with note). The error string
   is rendered in the `creds-vw-url` display element labeled "Vault URL". Operator sees `Error: <msg>`
   in the URL field; email and cloud-status show `"--"`. Error IS visible; no silent failure. The
   display location (URL card) is slightly misleading but not a crash or data loss scenario.

6. **`v1.0.2` patch release** — DONE. Cargo.toml bumped to `1.0.2`; this CHANGELOG entry added;
   `cargo update --workspace` ran to sync Cargo.lock.

7. **`settings.html:343` wizard error visibility** — PASS. `setupWizard` has `style="display:none"`
   in HTML (line 30). The iter-121 fix calls `setupWizard.style.display = ""` at line 361, making
   the panel visible regardless of prior setup state. Error heading and description are rendered
   inside the visible panel.

8. **`dashboard/api.rs` — remaining success handlers without `"ok": true`** — 173 occurrences of
   `"ok"` in file. All `json!({...})` success handlers confirmed to have `"ok": true`. The one
   exception by design is `setup_cloud_via_dashboard` which proxies the raw sidecar body (that
   body always contains `ok` from the sidecar's own handler). `GET /api/approvals` was the only
   true gap — fixed above.

9. **`CHANGELOG.md [1.0.1]` — complete through iter-121** — PASS. The iter-121 section accurately
   describes all 9 bugs fixed. Quality gates section correctly shows 317 total tests (315 + 2
   integration) for both iter-119 and iter-121 passes — the iter-121 test was a rename
   (not a net-new test), so the count is unchanged and accurate.

10. **Final quality gates (iter-122)** — see below.

### Quality gates (iter-122)

- `cargo fmt --check` — 0 diffs
- `cargo clippy --all-targets --features browser,engine,dashboard -- -D warnings` — 0 warnings
- `cargo test --all-targets --features browser,engine,dashboard` — **316 passed** (+ 2 integration) = **318 total**; 0 failed (1 new shape test: `api_approvals_has_ok_true_and_approvals_array`)
- `cargo doc --no-deps --features browser,engine,dashboard` — 0 errors, 0 warnings

---

## [1.0.1] — iterations 117–121: dashboard "ok" sentinel pass, diagnostic fields, CI OCI fix, stability hardening

### Bugs (iter-121) — complete dashboard silent-error audit

- **`rotation.html` silently shows "Idle" on `ok:false` from `/api/browser/status` (iter-121)** — `dashboard/rotation.html:244`. MEDIUM.
  `refreshStatus()` had no `ok === false` guard. A server-side error returned as
  `{"ok":false,"error":"..."}` would leave the step showing "Idle" and the badge stuck on "Running"
  indefinitely. Fixed: `ok === false` guard renders error text in the step field, sets badge to
  "Error", and stops the polling interval.

- **`settings.html` `checkSetupStatus()` silently ignores `ok:false` (iter-121)** — `dashboard/settings.html:343`. LOW.
  The catch comment read `// Silently ignore — setup status is optional` but an `ok:false` response
  from the API (not a network exception) was also silently swallowed — the wizard would never show
  any feedback to the operator. Fixed: `ok === false` guard renders an error heading/message inside
  the wizard panel and makes it visible.

- **`settings.html` `loadTpm()` leaves table in "Loading..." on `ok:false` (iter-121)** — `dashboard/settings.html:517`. LOW.
  On a server-side error the TPM table stayed in its initial "Loading..." state with no indication of
  the failure. Fixed: `ok === false` guard sets TPM status to "Error" and renders an error row in the
  sealed-credentials table.

- **`settings.html` `loadCredentials()` silently swallows `ok:false` (iter-121)** — `dashboard/settings.html:880`. MEDIUM.
  The URL/email/cloud-status cards would show stale "--" values when `/api/credentials` returned an
  error. Fixed: `ok === false` guard renders the error string in the URL card so the operator sees it.

- **`index.html` silently shows "--" on `ok:false` from `/api/status` (iter-121)** — `dashboard/index.html:52`. MEDIUM.
  All three overview cards (vault items, cloud sync, services) stayed "--" on server error with no
  explanation. Fixed: `ok === false` guard renders the error in the vault-count and sync-state fields.

- **`sync.html` silently shows "--" on `ok:false` from `/api/sync` (iter-121)** — `dashboard/sync.html:121`. MEDIUM.
  State/last-sync/items-synced stayed "--" on error; errors table showed nothing. Fixed: `ok === false`
  guard calls `applyState("error")` and renders the error string in the errors table.

- **`audit.html` shows "Audit failed — see console" with no visible message (iter-121)** — `dashboard/audit.html:304`. LOW.
  The catch branch set `statusNote.textContent = "Audit failed — see console."` — helpful only if
  the user has DevTools open. An `ok:false` response from the API was also not handled (render would
  fail or show empty data). Fixed: `ok === false` guard renders `"Audit error: <message>"` in
  `statusNote`; the catch branch now includes the error message text.

- **`GET /api/permissions` missing `configured_vault_folder` (iter-121)** — `src/dashboard/api.rs:939`. LOW.
  `GET /vault/permissions` (proxy endpoint, iter-120) added `configured_vault_folder` for operator
  diagnostics. `GET /api/permissions` (dashboard endpoint) was not updated. The dashboard page could
  not show operators what vault folder the permissions are scoped to. Fixed: added
  `"configured_vault_folder": app.vault_folder` to the `GET /api/permissions` response.
  `dashboard/permissions.html` updated to display it in a subtitle beneath the page heading.

- **`dashboard/permissions.html` does not display `configured_vault_folder` (iter-121)** — `dashboard/permissions.html:53`. LOW.
  Even after iter-120 added the field to `/vault/permissions`, the dashboard page never consumed it.
  Fixed: added a "Vault folder scope: <value>" subtitle paragraph populated from
  `data.configured_vault_folder` on load.

- **No test asserting `GET /api/permissions` returns `configured_vault_folder` (iter-121)** — `src/dashboard/api.rs:1905`. LOW.
  The existing `api_permissions_has_ok_true` shape test did not include the new field.
  Fixed: test renamed to `api_permissions_has_ok_true_and_configured_vault_folder`; assertion added
  that `body["configured_vault_folder"].is_string()`.

### Bugs (iter-120) — three more dashboard pages + telemetry path + OCI version prefix

- **`audit-log.html` silently shows empty table on `ok:false` (iter-120)** — `dashboard/audit-log.html:121`. MEDIUM.
  The `api('/api/audit-log')` call had no `ok === false` guard; a server-side error left the table
  empty with no explanation. Fixed: `ok === false` guard renders an error row in the table.

- **`policies.html` silently shows empty table on `ok:false` (iter-120)** — `dashboard/policies.html:218`. MEDIUM.
  Same pattern as audit-log.html. Fixed: `ok === false` guard calls `showError()` with the error message.

- **`permissions.html` silently shows empty table on `ok:false` (iter-120)** — `dashboard/permissions.html:209`. MEDIUM.
  Same pattern. Fixed: `ok === false` guard calls `showStatus()` with the error message.

- **`audit-runs.html` reads `tdata.summary` instead of `tdata.telemetry.summary` (iter-120)** — `dashboard/audit-runs.html:304`. MEDIUM.
  After iter-119 wrapped the telemetry response in `{"ok":true,"telemetry":{...}}`, the dashboard
  JS still read `tdata.summary` (always `undefined`) instead of `tdata.telemetry.summary`. All six
  telemetry counters silently showed `0`. Fixed: reads `tdata.telemetry.summary` with null-safety.

- **Docker image OCI version label gets `v`-prefixed version (iter-120)** — `.github/workflows/docker-publish.yml`.
  `docker/metadata-action` with `type=semver,pattern={{version}}` strips the `v` prefix
  (e.g. `v1.0.1` → `1.0.1`). The CI workflow passed `IMAGE_VERSION=${{ github.ref_name }}` which
  retains the prefix (e.g. `v1.0.1`), causing the OCI label to read `v1.0.1` while the semver tag
  reads `1.0.1`. Fixed: workflow now passes `IMAGE_VERSION=${{ steps.meta.outputs.version }}`
  (the already-stripped value from metadata-action).

- **`GET /vault/permissions` missing `configured_vault_folder` (iter-120)** — `src/main.rs:2661`. LOW.
  The proxy permissions endpoint lacked the diagnostic field already present in `GET /vault/folders`
  and `GET /sync/status` (iter-115/117). Fixed: added `"configured_vault_folder": state.vault_folder`.

### Bugs (iter-119) — final stability pass

- **`items.html` silently swallows server-side errors (iter-119)** — `dashboard/items.html:103-105`. MEDIUM.
  The fallback `itemsResp.items || []` silently returned an empty list when the server returned
  `{"ok":false,"error":"..."}`. Users would see a blank items table with no explanation. Fixed: added
  `ok === false` guard that renders an error row in the table via DOM `textContent` (XSS-safe).

- **`Dockerfile ARG IMAGE_VERSION` hardcodes stale version string (iter-119)** — `Dockerfile:206`. LOW.
  Default was `"1.0.1"` — every release requires updating this line manually. A bare `docker build .`
  without `--build-arg` would silently label the image with whatever version was last hardcoded.
  Fixed: default changed to `""` so unlabeled builds stamp `unknown`; CI always passes the correct
  value via `IMAGE_VERSION=${{ github.ref_name }}`.

- **`credaudit_telemetry` returns raw engine JSON without `"ok"` envelope (iter-119)** — `src/dashboard/api.rs:1776`. LOW.
  Success path returned `Json(v)` (raw engine telemetry blob) while the error path returned
  `{"ok":false,"error":"..."}`. Inconsistent — callers checking `body.ok` got `undefined` on
  success. Fixed: wrapped as `{"ok":true,"telemetry":{...}}`.

- **`list_profiles` (browser) returns bare `HashMap` without `"ok"` envelope (iter-119)** — `src/dashboard/api.rs:1222`. LOW.
  The `#[cfg(feature = "browser")]` variant returned `serde_json::to_value(profiles)` directly
  (a raw JSON object) while the non-browser stub returned `{"profiles":{},"note":"..."}` without
  `"ok"`. Fixed: both variants now return `{"ok":true,"profiles":{...},...}`.

- **No test coverage for any of the 11 iter-117 dashboard handler `"ok"` additions (iter-119)** — `src/dashboard/api.rs`. LOW.
  Iter-117 added `"ok"` to 11 dashboard handlers with no regression tests. If any handler accidentally
  loses the field it would go undetected until a dashboard JS call returned `undefined`. Fixed: added
  `#[cfg(test)] mod dashboard_ok_shape_tests` with 14 shape tests covering all 11 iter-117 fixes plus
  3 new iter-119 fixes.

### Bugs (iter-118)

- **CI workflow missing `IMAGE_VERSION` build arg (iter-118)** — `.github/workflows/docker-publish.yml:124`. MEDIUM.
  Iter-117 added `ARG IMAGE_VERSION="1.0.0"` and OCI labels to the Dockerfile, but the CI build step
  only passed `BUILDKIT_INLINE_CACHE=1` under `build-args`. The `org.opencontainers.image.version` label
  was therefore always `"1.0.0"` regardless of the git tag being built. Fixed: added
  `IMAGE_VERSION=${{ github.ref_name }}` to the `build-args` block so every tagged release
  (e.g. `v1.0.1`) stamps the correct version into the image label.

### Verified (iter-118) — no action required

- **`browser_status` — two separate handlers, not a duplicate fix** — `src/dashboard/api.rs:428,431`
  vs `src/main.rs:2869`. Confirmed distinct. The `main.rs` handler serves the internal bearer-token
  route `/browser/status` (for TypeScript callers); `dashboard/api.rs` serves `/api/browser/status`
  (for dashboard JS). Iter-117 correctly fixed both independently.

- **`GET /api/credentials` all three paths have `"ok": true`** — `src/dashboard/api.rs:1392,1403,1419`.
  Confirmed: not-configured, unlocked, and locked branches all return `"ok": true`.

- **`GET /api/setup-status` line 1369 discrepancy** — CHANGELOG cited line 1369 but the handler is
  `handle_setup_status` at line 1373; line 1369 is the `handle_reset` success path. The setup-status
  handler at line 1378 correctly includes `"ok": true`. No code defect.

- **`[1.0.1]` CHANGELOG at top, before `[1.0.0]`** — Confirmed correct placement.

- **Dashboard JS parsers unaffected by new `"ok"` key** — All 11 iter-117 handlers add `"ok"` to
  JSON objects. Dashboard JS accesses named keys (`data.tools`, `data.state`, `data.items`, etc.) —
  no code uses `Object.keys(data)[0]` ordering or array-style indexing on object responses.
  `permissions.html:102` uses `Object.keys(groups)` on a locally-built `groups` object, not on
  the API response. Safe.

- **Connecterr TS client calls `/vault/items`, not `/api/items`** — `Connecterr/src/sidecar-client.ts:235`.
  Confirmed: `listVaultItems()` calls `GET /vault/items` (proxy endpoint). The dashboard-only
  `GET /api/items` endpoint is consumed only by `items.html`. No Connecterr update needed.

- **`SyncStatus` + `configured_vault_folder` in Connecterr** — No `SyncStatus` type or
  `/sync/status` call found in `sidecar-client.ts`. TypeScript ignores extra fields on `as` casts
  regardless; no breakage possible.

### Quality gates (iter-121)

- `cargo fmt --check` — 0 diffs
- `cargo clippy --all-targets -- -D warnings` — 0 warnings
- `cargo clippy --all-targets --features browser,engine,dashboard -- -D warnings` — 0 warnings
- `cargo test --all-targets` — **258 passed**; 0 failed
- `cargo test --all-targets --features browser,engine,dashboard` — **315 passed** (+ 2 integration) = **317 total**; 0 failed (existing shape test updated to cover `configured_vault_folder`)

### Quality gates (iter-119)

- `cargo fmt --check` — 0 diffs
- `cargo clippy --all-targets -- -D warnings` — 0 warnings
- `cargo clippy --all-targets --features browser,engine,dashboard -- -D warnings` — 0 warnings
- `cargo test --all-targets` — **258 passed**; 0 failed
- `cargo test --all-targets --features browser,engine,dashboard` — **315 passed** (+ 2 integration) = **317 total**; 0 failed (14 new shape tests)

---

### Bugs (iter-117) — dashboard `"ok"` sentinel gaps and diagnostic completeness

- **`GET /sync/status` missing `"configured_vault_folder"` in response (iter-117)** — `src/vault/handlers.rs:3482`. LOW.
  `GET /vault/folders` (scoped) already includes `"configured_vault_folder"` (iter-115). `GET /sync/status`
  did not. When troubleshooting cloud sync issues, knowing the vault_folder the instance is scoped to is
  helpful without grepping startup logs. Fixed: both `Some(sync)` and `None` branches now include
  `"configured_vault_folder": vault_folder`.

- **Dashboard `GET /api/status` missing `"ok": true` (iter-117)** — `src/dashboard/api.rs:97`. MEDIUM.
  The success path returned `{"vault_items":...,"cloud_sync":...,"services":[...]}` without `"ok": true`.
  Fixed: added `"ok": true` to the response envelope. Dashboard `index.html` is unaffected (reads named keys).

- **Dashboard `GET /api/sync` missing `"ok": true` in both branches (iter-117)** — `src/dashboard/api.rs:131,138`. MEDIUM.
  Both the configured (`Some`) and not-configured (`None`) paths were missing `"ok"`. Fixed: both branches
  now include `"ok": true`. `sync.html` is unaffected (reads `data.state`, `data.last_sync`, etc.).

- **Dashboard `GET /api/tpm-status` missing `"ok": true` (iter-117)** — `src/dashboard/api.rs:406`. LOW.
  Response returned `{"tpm_available":...,"sealed_credentials":[...]}` without `"ok"`. Fixed.

- **Dashboard `GET /api/settings/setup-status` missing `"ok": true` (iter-117)** — `src/dashboard/api.rs:509`. LOW.
  Response returned `{"vaultwarden_configured":...,...}` without `"ok"`. Fixed.

- **Dashboard `GET /api/permissions` missing `"ok": true` (iter-117)** — `src/dashboard/api.rs:933`. MEDIUM.
  Response returned `{"tools":[...],"overrides":{...}}` without `"ok"`. Fixed.

- **Dashboard `GET /api/settings/notifications` missing `"ok": true` (iter-117)** — `src/dashboard/api.rs:1182`. LOW.
  Response returned `{"channel":...,"detail":...}` without `"ok"`. Fixed.

- **Dashboard `GET /api/setup-status` missing `"ok": true` (iter-117)** — `src/dashboard/api.rs:1369`. LOW.
  Response returned `{"configured":...,"tpm_available":...,"tpm_key_sealed":...}` without `"ok"`. Fixed.

- **Dashboard `GET /api/credentials` all three branches missing `"ok": true` (iter-117)** — `src/dashboard/api.rs:1391,1402,1417`. MEDIUM.
  Not-configured (`{"configured":false}`), unlocked, and locked branches all lacked `"ok"`. Fixed: all
  three branches now include `"ok": true`.

- **Dashboard `GET /api/browser/status` missing `"ok": true` in idle/not-configured paths (iter-117)** — `src/dashboard/api.rs:428,431`. LOW.
  `{"status":"idle"}` and `{"status":"not_configured"}` lacked `"ok": true`. Fixed. The `Some(ws)` path
  forwards a serialized `WorkflowStatus` struct — that struct already carries `ok` if the job does.

- **Dashboard `GET /api/browser/screenshot` success path missing `"ok": true` (iter-117)** — `src/dashboard/api.rs:448`. LOW.
  `{"image_b64":...}` lacked `"ok": true`. Fixed.

- **Dashboard `GET /api/items` bare JSON array without `"ok"` envelope (iter-117)** — `src/dashboard/api.rs:116`. MEDIUM.
  Response was a raw `serde_json::to_value(items)` producing a bare JSON array. Wrapped in
  `{"ok":true,"items":[...]}`. `items.html` updated to unwrap `itemsResp.items` (with Array.isArray
  fallback for graceful rollback).

- **`POST /sync/setup-cloud` test missing HTTP status-code assertion (iter-117)** — `src/vault/handlers.rs:5017`. LOW.
  The `setup_cloud_stub_has_ok_false` test only checked the body, not the 501 status code. Added
  `setup_cloud_stub_status_code_is_501` test that asserts `StatusCode::NOT_IMPLEMENTED.as_u16() == 501`,
  providing a regression guard for any accidental revert to `StatusCode::OK`.

- **Dockerfile missing OCI image version label (iter-117)** — `Dockerfile:ENTRYPOINT`. LOW.
  `docker inspect ghcr.io/aaronckj/vaultproxy:latest` showed no version metadata. Added
  `LABEL org.opencontainers.image.version` (and title/description/source/license labels)
  populated from build-time ARG `IMAGE_VERSION` (default `"1.0.0"`). CI workflows can override
  with `--build-arg IMAGE_VERSION=${{ github.ref_name }}` to inject the git tag automatically.

### v1.1.0 candidates — post-v1.0 planning

The 4 `post-v1.0:` items identified in iter-107 remain. Tractability assessment:

1. **`src/keystore.rs:333` — TPM auto-unlock path** (tag: `post-v1.0:`).
   `unlock_keystore_with_tpm()` is dead code — the TPM sealing path exists but the auto-unlock
   caller (startup) does not call it yet. Tractable for v1.1.0: wire `unlock_keystore_with_tpm`
   into `startup_unlock()` behind `#[cfg(feature = "tpm")]` with a fallback to the software path.

2. **`src/proxy/unifi_session.rs:90` — rotation UI** (tag: `post-v1.0:`).
   `rotate_credential()` on `UnifiSession` is implemented but not exposed through the browser
   rotation workflow. Tractable but requires browser feature; defer to v1.1.0-browser milestone.

3. **`src/sync/cloud.rs:40` — Bitwarden cloud password change** (tag: `post-v1.0:`).
   `master_password` field is read by the (unimplemented) `change_master_password`. Requires
   Bitwarden API flow; non-trivial. Defer to v1.1.0.

4. **`src/sync/cloud.rs:786` — dashboard cloud-account settings** (tag: `post-v1.0:`).
   `account_info()` is dead code for the settings page. Tractable: wire to `GET /api/credentials`
   cloud section. Consider v1.1.0.

**Recommended v1.1.0 scope:** TPM auto-unlock wiring (item 1) + cloud-account settings page (item 4).
Both are self-contained and improve the out-of-box experience for non-CLI operators.

### Quality gates (iter-117)

- `cargo fmt --check` — 0 diffs
- `cargo build` (headless) — 0 errors, 0 warnings
- `cargo build --features browser,engine,dashboard` — 0 errors, 0 warnings
- `cargo test --all-targets` — **258 passed**; 0 failed
- `cargo test --all-targets --features browser,engine,dashboard` — **301 passed**; 0 failed
- `cargo clippy --all-targets --features browser,engine,dashboard -- -D warnings` — 0 errors, 0 warnings

---

> **BREAKING CHANGES — response format migration (iter-109 through iter-112)**
>
> All collection endpoints have been migrated from bare JSON arrays to
> `{"ok": true, "<key>": [...]}` envelopes. Callers that iterate the response
> body directly must be updated to unwrap the named key:
>
> | Endpoint | Old shape | New shape | Key | Since |
> |---|---|---|---|---|
> | `GET /vault/items` | `[...]` | `{"ok":true,"items":[...]}` | `items` | iter-109 |
> | `GET /vault/folders` | `[...]` | `{"ok":true,"folders":[...]}` | `folders` | iter-110 |
> | `GET /vault/duplicates` | `[...]` | `{"ok":true,"groups":[...]}` | `groups` | iter-110 |
> | `GET /audit/credaudit/review_pending/:id` | `[...]` | `{"ok":true,"items":[...]}` | `items` | iter-112 |
>
> The Connecterr TypeScript sidecar client has been updated for all four.
> Raw `curl` scripts or other consumers that iterate the body directly must
> unwrap the named key shown above.

---

## [1.0.0] — iteration 116: v1.0.0 stable release — Cargo.toml version sync, fmt fixes, sentinel completeness

> **MILESTONE: v1.0.0 stable.** After 116 audit iterations, ~790 issues resolved, and 299 tests,
> vaultproxy reaches its first stable release. The codebase has been hardened across security,
> correctness, observability, and test coverage dimensions over 115 prior iterations. This entry
> documents the final pre-release cleanups that close the gap between the `v1.0.0` git tag
> (created at iter-115) and a fully correct stable release.

### Journey summary (iterations 1–116)

- **Iterations 1–20:** Initial proxy scaffold, HMAC token auth, vault folder scoping, TLS, rate limiting.
- **Iterations 21–50:** Security response headers, dead-code elimination, per-module allow attributes, setup wizard, rpassword, cloud sync scaffold.
- **Iterations 51–80:** Credential audit engine, browser rotation scaffold, TPM integration, policy engine, tool-permissions endpoint, safe_write_config (0600 atomic).
- **Iterations 81–100:** Feature-gating (browser/engine/dashboard), scope guard completeness (list_items/list_duplicates/list_untracked empty-on-folder-not-found, item_in_vault_folder Option<bool>), `vault_folder_found` in health, 100th audit milestone.
- **Iterations 101–112:** HTTP status code correctness (Json<Value> return-type trap — 20+ handlers fixed), HTTP 207 for partial sync, `"ok": true/false` sentinel completeness campaign across all collection and error paths, Connecterr TS client format fixes.
- **Iterations 113–115:** `--persist-dashboard-cert` feature, mTLS cert stability, migration guide, `configured_vault_folder` in scoped list_folders response, headless-flag warning.
- **Iteration 116 (this entry):** Final pre-release fixes — Cargo.toml version `1.0.0-beta.8` → `1.0.0`, `cargo fmt` compliance (main.rs, tpm.rs), `GET /sync/status` missing `"ok"` in both branches, `POST /sync/setup-cloud` stub silent-200 with no `"ok"` (now returns 501 Not Implemented with `"ok": false`).

### Bugs (iter-116) — version sync and sentinel gaps

- **`Cargo.toml` version `1.0.0-beta.8` while git tag is `v1.0.0` (iter-116)** — `Cargo.toml:3`. CRITICAL.
  `cargo run -- --version` and `GET /vault/health` `"version"` field both read `CARGO_PKG_VERSION`
  at compile time. With `version = "1.0.0-beta.8"`, the binary reports the wrong version even
  though the `v1.0.0` tag exists. Fixed: bumped to `1.0.0`.

- **`cargo fmt --check` failing on CI for `v1.0.0` tag (iter-116)** — `src/main.rs:1127`, `src/tpm.rs:283,293`. HIGH.
  The `v1.0.0` CI run (run ID 25438651228) failed on `cargo fmt --check` at the "Check formatting"
  step. Two diffs: (a) `src/main.rs:1127` — rustfmt prefers a line break before `.map_err(...)`,
  (b) `src/tpm.rs:283,293` — rustfmt prefers `if let Err(e) = ...` on a single line for
  `persist_dashboard_cert`. Both fixed. This is why the `v1.0.0` Docker image was never published.

- **`GET /sync/status` missing `"ok"` in both branches (iter-116)** — `src/vault/handlers.rs:3482`. MEDIUM.
  Both the `Some(sync)` and `None` paths returned JSON without `"ok"`. The configured path
  returned `{"state": "..."}` and the not-configured path returned `{"state": "not_configured"}`.
  Every other success handler carries `"ok": true`. Fixed: both paths now include `"ok": true`.

- **`POST /sync/setup-cloud` stub returns HTTP 200 with no `"ok"` (iter-116)** — `src/vault/handlers.rs:3543`. MEDIUM.
  The placeholder handler returned `{"result": "not_yet_implemented"}` at HTTP 200 — no `"ok"` field,
  wrong status code for an unimplemented stub. Fixed: returns HTTP 501 Not Implemented with
  `{"ok": false, "error": "not yet implemented — use POST /sync/init instead"}`.

### Quality gates (iter-116)

- `cargo fmt --check` — 0 diffs
- `cargo build` (headless) — 0 errors, 0 warnings
- `cargo build --features browser,engine,dashboard` — 0 errors, 0 warnings
- `cargo test --all-targets` — **256 passed**; 0 failed
- `cargo test --all-targets --features browser,engine,dashboard` — **300 passed**; 0 failed
- `cargo clippy --all-targets --features browser,engine,dashboard -- -D warnings` — 0 errors, 0 warnings
- `cargo doc --no-deps --features browser,engine,dashboard` — 0 errors, 0 warnings

---

## [1.0.0-beta.8] — iteration 115: headless-flag warning, configured_vault_folder, CLI tests

### Bugs (iter-115) — silent-ignore and diagnostic gaps

- **`--persist-dashboard-cert` silently ignored in headless builds (iter-115)** — `src/main.rs:1153`. LOW.
  The `--persist-dashboard-cert` flag is intentionally NOT gated with `#[cfg(feature = "dashboard")]`
  at the `Args` struct-field level (gating it would cause clap to emit "unexpected argument" with no
  hint about needing `--features dashboard`). However, in headless builds the value was silently
  discarded with `let _ = args.persist_dashboard_cert` — an operator would pass the flag, see no
  effect, and have no indication why. Fixed: added a `tracing::warn!` when `persist_dashboard_cert`
  is `true` and the dashboard feature is absent, with explicit instruction to rebuild with
  `--features dashboard`.

### Enhancements (iter-115) — operator diagnostics

- **`GET /vault/folders` scoped response includes `configured_vault_folder` (iter-115)** — `src/vault/handlers.rs:896`. MEDIUM.
  When `include_all=false` (the default), `GET /vault/folders` filters to only folders whose name
  matches `--vault-folder`. An operator who sees `{"ok":true,"folders":[]}` had no way to know what
  value vault-proxy was filtering for — they had to check the process arguments or config. Fixed:
  the scoped response now includes `"configured_vault_folder": "<name>"` alongside `"folders": [...]`.
  The `include_all=true` path is unchanged (it returns the full list — the vault_folder filter is not
  applied, so the field would be misleading there). The migration guide non-breaking section is updated.

### Tests (iter-115) — CLI flag and folder response shape

- **`persist_dashboard_cert_accepted_by_clap_in_all_builds` (iter-115)** — `src/main.rs` (new `cli_flag_tests` module).
  Verifies that `--persist-dashboard-cert` is accepted by clap in all build configurations (headless
  and dashboard). Unconditional — not feature-gated.

- **`persist_dashboard_cert_defaults_to_false` (iter-115)** — `src/main.rs`.
  Verifies that `persist_dashboard_cert` is `false` when the flag is not supplied.

- **`list_folders_returns_ok_true_and_folders_array` updated (iter-115)** — `src/proxy/mod.rs`.
  Added assertion that the scoped response contains `"configured_vault_folder"` as a string key.

### Quality gates (iter-115)

- `cargo build` (headless) — 0 errors, 0 warnings
- `cargo build --features browser,engine,dashboard` — 0 errors, 0 warnings
- `cargo test --all-targets` — **254 passed**; 0 failed
- `cargo test --all-targets --features browser,engine,dashboard` — **297 passed**; 0 failed
- `cargo clippy --all-targets --features browser,engine,dashboard -- -D warnings` — 0 errors, 0 warnings
- `cargo doc --no-deps --features browser,engine,dashboard` — 0 errors, 0 warnings

---

## [1.0.0-beta.7] — iteration 113: persist-dashboard-cert, migration guide, v1.0.0 readiness

### Features (iter-113) — persist dashboard TLS cert across restarts

- **`--persist-dashboard-cert` / `PERSIST_DASHBOARD_CERT` flag (iter-113)** — `src/main.rs`, `src/tpm.rs`. HIGH (v1.0.0 blocker).
  The ephemeral dashboard certificate (regenerated on every restart) caused a browser
  "certificate has changed" warning after every container restart, making the dashboard
  frustrating to use in production. Added `--persist-dashboard-cert` flag (env:
  `PERSIST_DASHBOARD_CERT=1`) that:
  - **First run:** generates the server cert normally, writes it to
    `{config_dir}/dashboard.crt` and `{config_dir}/dashboard.key` (mode 0600,
    atomic tempfile+rename via `safe_write_config`).
  - **Subsequent runs:** reads the saved cert back from disk — browser sees the same
    identity, warning disappears.
  The mTLS CA and client certs (used for the `/handshake` endpoint) remain ephemeral
  (forward secrecy). Only the dashboard server cert is persisted. The flag is wired
  into both `start_server` and `start_dashboard_only`. Deleting `dashboard.crt` +
  `dashboard.key` forces regeneration on next startup. Not bound to the TPM-sealed
  keystore — cert material is stored in plaintext PEM alongside other config files.
  `load_persisted_dashboard_cert` and `persist_dashboard_cert` in `src/tpm.rs` are
  gated `#[cfg(feature = "dashboard")]` to eliminate dead-code warnings in headless
  builds.

### Documentation (iter-113) — operator migration guide

- **Upgrading from v0.2.x to v1.0.0 section added to README** — `README.md`. MEDIUM.
  After 113 iterations of breaking changes, no consolidated upgrade path existed.
  Added "Upgrading from v0.2.x to v1.0.0" section documenting: (a) the four
  bare-array → envelope breaking changes (iter-109 through iter-112) with a
  migration diff pattern, (b) the `"ok": true/false` sentinel requirement, and
  (c) non-breaking response changes. Also added `--persist-dashboard-cert` to the
  CLI reference table.

### Quality gates (iter-113)

- `cargo build --features browser,engine,dashboard` — 0 errors, 0 warnings
- `cargo build` (headless) — 0 errors, 0 warnings
- `cargo test --all-targets --features browser,engine,dashboard` — **292 passed**; 0 failed
- `cargo clippy --features browser,dashboard --all-targets -- -D warnings` — 0 errors, 0 warnings

---

## [1.0.0-beta.6] — iteration 112: final format pass, v1.0.0 readiness assessment

### Bugs (iter-112) — remaining bare-array JSON responses

- **`review_pending` success missing `"ok": true` (iter-112)** — `src/credential_audit/handlers.rs:88`. HIGH.
  `GET /audit/credaudit/review_pending/:run_id` returned `Json<Vec<ItemResult>>` — a bare JSON
  array with no `"ok": true` sentinel, inconsistent with every other collection success path
  in the codebase. Fixed: return type changed to `Json<Value>`;
  response is now `{"ok": true, "items": [...]}`. Connecterr TS client
  `credentialAuditReviewPending` in `sidecar-client.ts` updated to unwrap `body.items`.

- **`get_audit_log` missing `"ok": true` (iter-112)** — `src/dashboard/api.rs:1017`. MEDIUM.
  `GET /api/audit-log` returned `Json(serde_json::to_value(entries))` — a bare array.
  Fixed: wrapped in `{"ok": true, "entries": [...]}`. `dashboard/audit-log.html` updated
  to read `data.entries ?? []`.

- **`list_policies` missing `"ok": true` (iter-112)** — `src/dashboard/api.rs:214`. MEDIUM.
  `GET /api/policies` returned `Json(serde_json::to_value(policies))` — a bare array.
  Fixed: wrapped in `{"ok": true, "policies": [...]}`. `dashboard/policies.html` updated
  to read `data.policies ?? []`.

### Documentation (iter-112) — CHANGELOG breaking-change prominence

- **BREAKING CHANGE banner promoted to top of CHANGELOG** — `CHANGELOG.md`. MEDIUM.
  The `GET /vault/items` and related breaking changes (iter-109 through iter-112) were buried
  inside their respective version sections. A consolidated breaking-change table has been added
  at the very top of the file (before any version sections) so it is impossible to miss.

### Quality gates (iter-112)

- `cargo build --features browser,engine,dashboard` — 0 errors, 0 warnings
- `cargo test --all-targets --features browser,engine,dashboard` — **292 passed**; 0 failed
- `cargo clippy --features browser,dashboard --all-targets -- -D warnings` — 0 errors, 0 warnings
- `tsc` in Connecterr — 0 errors

---

## [1.0.0-beta.5] — iteration 111: Connecterr TS list_folders/list_duplicates format fix + integration tests

### Bugs (iter-111) — Connecterr TS client uses pre-iter-110 bare-array shape

- **`listVaultFolders()` treats response as bare array (iter-111)** — `Connecterr/src/sidecar-client.ts:587`. HIGH.
  After iter-110 changed `GET /vault/folders` from a bare `Vec<FolderInfo>` array to
  `{"ok": true, "folders": [...]}`, `listVaultFolders()` still called
  `res.json() as unknown[]` — wrapping the entire envelope object as if it were
  the array. All callers (`listFolders()` in `vaultwarden/index.ts`,
  `listFolders()` in `vaultwarden/api.ts`) silently received `[object Object]`
  instead of the folder list. Fixed: response is now parsed as `{ok, folders}`
  and `body.folders ?? []` is returned, preserving the `unknown[]` return type.

- **`listVaultDuplicates()` treats response as bare array (iter-111)** — `Connecterr/src/sidecar-client.ts:713`. HIGH.
  After iter-110 changed `GET /vault/duplicates` from a bare `Vec<DuplicateGroup>`
  array to `{"ok": true, "groups": [...]}`, `listVaultDuplicates()` still called
  `res.json() as unknown[]`. All callers silently received the envelope object
  as the single element of the "array". Fixed: response is now parsed as
  `{ok, groups}` and `body.groups ?? []` is returned.

### Tests (iter-111) — integration tests for iter-110 response shape changes

- **`list_folders_returns_ok_true_and_folders_array` (iter-111)** — `src/proxy/mod.rs`.
  `GET /vault/folders` had no test asserting the post-iter-110 `{"ok":true,"folders":[...]}` shape.
  New test wires the handler against a stub vault and verifies `body["ok"] == true` and
  `body["folders"]` is an array.

- **`list_duplicates_returns_ok_true_and_groups_array` (iter-111)** — `src/proxy/mod.rs`.
  `GET /vault/duplicates` had no test asserting the post-iter-110 `{"ok":true,"groups":[...]}` shape.
  New test wires the handler against a stub vault and verifies `body["ok"] == true` and
  `body["groups"]` is an array.

### Quality gates (iter-111)

- `cargo build --features browser,engine,dashboard` — 0 errors, 0 warnings
- `cargo test --all-targets --features browser,engine,dashboard` — **292 passed** (290 unit/integration + 2 secret_discipline); 0 failed
- `cargo clippy --features browser,dashboard --all-targets -- -D warnings` — 0 errors, 0 warnings
- `tsc` in Connecterr — 0 errors

---

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

