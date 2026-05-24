# Transparent HTTPS_PROXY mode — design spec

**Status:** approved, awaiting implementation plan
**Author:** brainstormed with Claude Opus 4.7 on 2026-05-24
**Target release:** vaultproxy v1.1.0 (feature off by default; flips on by default in v1.2.0)
**Bucket:** B1 of three architectural buckets (B2 = listener auth / mTLS; B3 = OAuth flows). See `docs/ROADMAP.md`.

---

## 1 — Problem and motivation

Today `vaultproxy` brokers credentials in two modes:

1. **Native `/proxy`** — smart MCP servers POST `{"service":..., "method":..., "path":...}` to `127.0.0.1:3201/proxy`. Credentials never enter the MCP server's address space.
2. **Launcher `--launch`** — vault-proxy exec's a "dumb" MCP server with credentials injected as env vars. Credentials reach the child process memory + `/proc/<pid>/environ`.

Neither covers an unmodified third-party agent or HTTP client that wants to call an arbitrary upstream HTTPS API. Competitors fill this gap:

- **Infisical/agent-vault** intercepts via `HTTPS_PROXY=...` and swaps dummy placeholders for real credentials before forwarding upstream.
- **OneCLI** does the same with its own encrypted vault backend.

This spec adds a **transparent HTTPS proxy mode** to vaultproxy that lets zero-modification clients use Vaultwarden-backed credentials with no application changes. It is the single biggest adoption-driving feature gap identified in `GAPS.md` §4.1 (item G1).

---

## 2 — Goals and non-goals

### Goals

- Unmodified HTTPS clients (curl, requests, fetch, third-party MCP servers, agent frameworks) can use vault credentials by setting `HTTPS_PROXY=http://127.0.0.1:3203` and trusting one CA cert.
- Two injection modes co-exist: **host-based** (auth header injected automatically when the upstream host matches a `[[service]]` block) and **placeholder** (literal `__vault.X__` tokens in the request body/headers are swapped for the vault value).
- Operators can opt unregistered hosts into passthrough (default) or allowlist-blocking (`--transparent-unregistered-policy=allowlist`).
- Existing `services.toml` files keep working unchanged. New `transparent_mode` field is optional and defaults to `"off"`.
- Existing `/proxy` and `--launch` integrations are unaffected.
- All transparent traffic is recorded in the existing `audit-log.json` with a `trigger = "transparent"` discriminator.

### Non-goals (deferred)

- HTTP/2, HTTP/3, QUIC, gRPC-aware injection
- Wildcard host patterns in `services.toml` (e.g. `*.github.com`)
- WebSocket payload substitution (passthrough after 101)
- Plain HTTP (non-TLS) injection — use `/proxy` instead
- Listener authentication beyond loopback (mTLS / SO_PEERCRED) — that's bucket B2
- Listener exposure beyond loopback (blocked until B2 lands)
- Dashboard UI panels for transparent mode — extends after B1 GA

---

## 3 — Architecture and data flow

```
Agent (env: HTTPS_PROXY=http://127.0.0.1:3203)
   │
   │  CONNECT api.github.com:443 HTTP/1.1
   ▼
┌──────────────────────────────────────────────────────────────┐
│  vault-proxy: transparent listener on 127.0.0.1:3203         │
│                                                               │
│  1. Parse CONNECT → host:port                                 │
│  2. Lookup registry: services.toml entry for host?            │
│       ├─ YES + transparent_mode = "host_inject"  ─► MITM      │
│       ├─ YES + transparent_mode = "placeholder"  ─► MITM      │
│       ├─ YES + transparent_mode = "passthrough"  ─► tunnel    │
│       └─ NO  ─► passthrough (or block in allowlist mode)      │
│                                                               │
│  MITM path:                                                   │
│  3. Open TLS to upstream, fetch real cert                     │
│  4. Sign leaf cert with our CA, present to agent              │
│  5. Read plaintext request                                    │
│  6a. host_inject: strip agent auth header, inject vault cred  │
│  6b. placeholder: scan body/headers for __vault.X__, swap     │
│  7. Forward to upstream over the real TLS conn                │
│  8. Stream response back (with response body audit if opted)  │
│                                                               │
│  Passthrough path: raw TCP relay both directions              │
└──────────────────────────────────────────────────────────────┘
   │
   ▼
api.github.com:443  (sees vault-proxy IP, real Bearer token)
```

### Scope summary

- New module `src/proxy/transparent/` (listener, CONNECT handler, MITM engine, cert factory, placeholder swapper)
- New `src/tls/ca.rs` for CA gen + leaf signing (uses `rcgen`, already a transitive dep)
- New CLI flags: `--transparent-listen` (default `127.0.0.1:3203`, set empty to disable), `--transparent-default-mode` (`off` | `host_inject` | `placeholder` | `passthrough`), `--transparent-unregistered-policy` (`passthrough` | `allowlist`, default `passthrough`), `--transparent-ca-cert`, `--transparent-ca-key` (BYO override)
- New `services.toml` field: `transparent_mode` per `[[service]]`
- New top-level config block (optional): `[[transparent_placeholder]]` for tokens not tied to a single service
- Audit log: every transparent request emits an entry with `trigger = "transparent"`
- Cargo feature flag: `transparent` (default off through all of v1.1; flips on by default in v1.2)

---

## 4 — TLS and CA management

### CA generation (default)

- On first start with `--transparent-listen` set, generate an ED25519 keypair and self-signed CA cert via `rcgen`.
- 10-year validity. `CN = "vault-proxy MITM CA (<hostname>)"`. SAN empty.
- Constraints: `basicConstraints = CA:TRUE, pathLen:0`, `keyUsage = keyCertSign, cRLSign`, `extendedKeyUsage = serverAuth`.
- Stored as `$CONFIG_DIR/transparent-ca.crt` (mode 0644) and `$CONFIG_DIR/transparent-ca.key` (mode 0600, atomic write).
- On subsequent starts: load from disk. Corrupt or unreadable files → fail-fast with operator-actionable error.

### CA fingerprint banner (every startup with transparent listener active)

```
TRANSPARENT PROXY CA  SHA-256: 5a:3b:c1:...:9e
                      File:    /config/transparent-ca.crt
                      Install on every agent host that uses HTTPS_PROXY=…3203.
                      Setup guide: docs/operator/TRANSPARENT-CA.md
```

### Leaf cert factory

- On CONNECT, open a TLS connection to upstream to grab the real cert chain.
- Cache upstream cert metadata for 24h per host.
- Copy SAN + CN from upstream cert into a fresh leaf signed by our CA. ED25519 key per host (~50µs).
- Leaf validity: 30 days. In-memory LRU cache keyed on `host:port`, max 1024 entries, LRU eviction.
- Cache invalidation on upstream cert change (detected by daily background refresh).

### BYO CA mode

- `--transparent-ca-cert <path>` + `--transparent-ca-key <path>` (or `TRANSPARENT_CA_CERT` / `TRANSPARENT_CA_KEY` env).
- Validated at startup: cert must have `CA:TRUE`, key must match cert public key, key file must be mode 0600. Refuse to start otherwise.
- BYO disables auto-generation. Operator owns rotation.

### Cert install docs

Ship `docs/operator/TRANSPARENT-CA.md` with platform-specific install paths:

- Linux system: `sudo cp transparent-ca.crt /usr/local/share/ca-certificates/vault-proxy.crt && sudo update-ca-certificates`
- Per-language overrides (no system install required):
  - Node: `NODE_EXTRA_CA_CERTS`
  - Python `requests`: `REQUESTS_CA_BUNDLE`
  - Python stdlib + httpx: `SSL_CERT_FILE` / `ssl_context.load_verify_locations()`
  - curl: `--cacert` or `CURL_CA_BUNDLE`
  - Go: `SSL_CERT_FILE`
  - Rust reqwest: `Certificate::from_pem()` + `.add_root_certificate()`
- macOS: Keychain Access → import → Always Trust (operator decision)
- Windows: `certutil -addstore -f Root transparent-ca.crt` (admin)

### Threat model addition

The transparent CA can sign for any hostname. If `transparent-ca.key` leaks, the attacker can MITM all traffic from any host that trusted it.

Mitigations:

- `0600` key file; refuse to start if perms drift.
- Document never to copy off the proxy host.
- Document in `SECURITY.md` as a Tier-1 secret alongside the keystore master key.

### Rotation procedure

`vault-proxy --regenerate-transparent-ca` (new CLI subcommand) deletes both files, regenerates, prints new fingerprint. Operator re-installs cert on every agent host. No grace period — old cert dies immediately.

---

## 5 — services.toml schema and host matching

### New per-service field

```toml
[[service]]
name = "github_api"
base_url = "https://api.github.com"
auth = "bearer"
vault_item = "vault-proxy - GitHub PAT"

# NEW: opt service into transparent-proxy injection. Default = "off"
# (preserves existing services.toml behaviour 100%).
#   "off"          — transparent listener ignores this host (passthrough)
#   "host_inject"  — MITM + replace auth header on requests to this host
#   "placeholder"  — MITM + scan body/headers for __vault.<name>__ tokens, swap
#   "passthrough"  — explicit passthrough (same as "off" but registered)
transparent_mode = "host_inject"
```

### Default and override resolution

- Per-service `transparent_mode` wins.
- If unset, falls back to global `--transparent-default-mode` flag (default `"off"`).
- Global `--transparent-unregistered-policy=allowlist` means hosts without any `[[service]]` block get blocked at CONNECT (`HTTP/1.1 502 Bad Gateway` with JSON body, `transparent_error_code = "unregistered_host_blocked"`). Hosts with a `[[service]]` block use that block's `transparent_mode`.

### Host matching

- Match key = lowercase `host:port` from `base_url`. Missing port → `:443` (only HTTPS is MITM'd).
- Exact match only. No wildcards in v1.1.
- Multiple `[[service]]` blocks pointing at the same `host:port` → reject at load time with a clear error naming both entries.
- IP addresses allowed. IPv6 in brackets: `base_url = "https://[2001:db8::1]:8443"`.
- Existing SSRF guard still applies (link-local, metadata, loopback blocked unless explicit-loopback service).

### New top-level placeholder block

```toml
[[transparent_placeholder]]
token = "__vault.github_pat__"
vault_item = "vault-proxy - GitHub PAT"
field = "password"
```

- Token syntax: must start with `__vault.`, end with `__`, contain only `[A-Za-z0-9_-]+` between. Validated at load.
- Substitution scope: request body (when `Content-Type` is `application/json`, `text/*`, or `application/x-www-form-urlencoded`) and header values. Binary bodies pass through untouched.
- Substitution is literal-string match — no JSON-aware rewriting. Tokens must be valid JSON strings when used inside JSON bodies (documented constraint).
- Max body size: existing `UPSTREAM_BODY_LIMIT_MB` (default 32 MB). Larger bodies stream through without substitution and emit `WARN`.

### SIGHUP hot-reload

- Transparent listener reads the same `services.toml`. SIGHUP rebuilds registry, swaps atomically. In-flight transparent connections continue with the old registry; new CONNECTs see the new one.
- `[[transparent_placeholder]]` blocks reload with the same SIGHUP.

### `--check` mode additions

- Validate every `transparent_mode` is in the allowed enum.
- Validate every `[[transparent_placeholder]].token` matches the syntax regex.
- Detect `host:port` collisions across services with `transparent_mode != "off"`.
- Warn if `transparent_mode = "host_inject"` is set on a service whose `auth = "session"` or `auth = "unifi_dual"` (v1.1 `host_inject` only supports `bearer`, `header`, `basic`, `query_param`).

### Backwards compatibility

Every existing `services.toml` works unchanged. Field is optional, default `"off"`. No migration step.

---

## 6 — Internals and error handling

### Module layout

```
src/proxy/transparent/
  mod.rs                — listener, axum-less raw TCP accept loop
  connect.rs            — parse `CONNECT host:port HTTP/1.1`, registry lookup
  mitm.rs               — leaf-cert handshake + plaintext req/resp loop
  passthrough.rs        — copy_bidirectional TCP relay
  inject_host.rs        — Bearer/Header/Basic/QueryParam injection on req
  inject_placeholder.rs — body+header token scan/swap
  cert_factory.rs       — upstream cert fetch + leaf signing + LRU cache
  registry.rs           — host→[[service]] index, hot-reload aware
src/tls/ca.rs           — generate_ca, load_ca, validate_byo_ca
```

### Per-request state machine

```
ACCEPT TCP → READ_CONNECT
  ├─ malformed/non-CONNECT → 400 Bad Request → close
  └─ ok → REGISTRY_LOOKUP
       ├─ allowlist mode + unknown host → 502 + JSON → close + audit
       ├─ off/passthrough → TUNNEL (raw bidi copy)
       │     ├─ on close → audit entry (host:port, bytes_in/out, duration)
       │     └─ no plaintext logged
       └─ host_inject/placeholder → MITM
            1. Reply `HTTP/1.1 200 Connection established\r\n\r\n`
            2. cert_factory.leaf_for(host:port) → present in TLS handshake
            3. parallel: open real TLS conn to upstream
            4. read agent's HTTP/1.1 request (timeout 30s)
            5a. host_inject: drop forbidden auth headers, inject vault cred
            5b. placeholder: scan body+headers, swap __vault.X__ tokens
            6. forward to upstream, stream response back to agent
            7. on response complete → audit entry
```

### Error responses to agent

All proxy-side error responses use semantically-correct HTTP codes plus a discriminator in the JSON body. Clients should branch on `transparent_error_code`, not on the status code alone.

| Status | `transparent_error_code` | Cause |
|---|---|---|
| `400` | `malformed_connect` | malformed CONNECT line, oversized headers, unsupported HTTP version |
| `502` | `upstream_unreachable` | upstream TCP connect or TLS handshake failed |
| `502` | `unregistered_host_blocked` | allowlist mode + host has no `[[service]]` block |
| `502` | `vault_resolution_failed` | vault item missing, or required field missing on the item |
| `502` | `placeholder_unresolved` | request contained `__vault.X__` with no matching `[[transparent_placeholder]]`. Fail-closed: never forward a request with unsubstituted placeholders |
| `504` | `agent_read_timeout` | agent did not send a full request within 30 s (or `--proxy-timeout`) |

All error bodies are JSON: `{"ok": false, "error": "<human-readable>", "transparent_error_code": "<discriminator>"}`.

### Audit log additions (`audit-log.json`)

- New `trigger` value: `"transparent"`.
- New fields per entry: `transparent_mode`, `upstream_host`, `upstream_status`, `bytes_in`, `bytes_out`, `duration_ms`.
- Existing sensitive-field masking still applies. Credentials never appear in `args_summary` or `result_summary`.
- Per-request size: ~250 bytes. 1000-entry on-disk cap unchanged.

### Logging strategy

- `INFO` per successful request: `transparent: host=api.github.com mode=host_inject status=200 duration=234ms`
- `WARN` on cert refresh, allowlist block, oversized body skip, BYO CA permission drift
- `ERROR` on TLS handshake failure, upstream connect failure, vault resolution failure
- No plaintext request bodies logged at any level. URL paths logged at `DEBUG` only.

### Body buffering rules

- Default: stream pass-through (no buffering) for `passthrough` mode and for `host_inject` mode on responses.
- Required buffering: `placeholder` mode requests + responses (full body needed to scan). Capped at `UPSTREAM_BODY_LIMIT_MB`; oversize requests are rejected with `413`; oversize responses fall through unscanned with `WARN`.

### HTTP version

- HTTP/1.1 only in v1.1.
- HTTP/2 via ALPN negotiation is a follow-up.
- WebSocket upgrade (`Connection: upgrade`, `Upgrade: websocket`) → switch to passthrough after the 101. Substitution does not apply to `ws`/`wss` frames.

### Timeouts

- CONNECT line read: 5s (slowloris guard, matches existing)
- Agent → request body read: 30s default, `--proxy-timeout` override
- Upstream connect: 10s
- Upstream first byte: 30s
- Idle TLS connection: 120s, then close

### Performance targets

- Passthrough mode: ≥95% of raw socket throughput
- host_inject mode: ~100µs added latency per request
- placeholder mode: ~1ms per 100KB scanned (literal string search, not regex)
- Leaf cert generation: ~50µs cached, ~5ms cold

---

## 7 — Testing strategy

### Unit tests (per module)

- `tls/ca.rs` — generate_ca produces valid CA (basicConstraints+keyUsage+pathLen), load_ca round-trip, validate_byo rejects non-CA / mismatched key / world-readable key file
- `cert_factory.rs` — leaf signing copies SAN, ED25519 key gen, LRU eviction, upstream cert fetch (wiremock TLS), cache invalidation on upstream cert change
- `connect.rs` — parse valid CONNECT, reject malformed verb / missing port / HTTP/2 prelude / oversize line, host:port canonicalisation
- `registry.rs` — host:port lookup, port-default-443, IPv6 brackets, collision detection, hot-reload swap, allowlist-mode unknown-host miss
- `inject_host.rs` — Bearer/Header/Basic/QueryParam each overwrite agent-supplied auth headers, forbidden-header strip list complete, query_param merges with existing query
- `inject_placeholder.rs` — literal-string swap, multi-token in one body, token in header value, oversize body skips with WARN, JSON-string-embedded token works, no-match returns 508
- `mitm.rs` — error response shapes for 400/502/504/507/508, audit entry emission, response streaming preserves Content-Length and Transfer-Encoding

### Integration tests (`tests/transparent_*.rs`)

- `tests/transparent_passthrough.rs` — wiremock upstream, agent uses HTTPS_PROXY, raw byte equality through tunnel
- `tests/transparent_host_inject.rs` — wiremock asserts received `Authorization: Bearer <secret>` even though agent sent no auth (or sent a wrong one)
- `tests/transparent_placeholder.rs` — agent posts JSON containing `__vault.github_pat__`, wiremock asserts swapped value arrived
- `tests/transparent_allowlist.rs` — unknown host returns 502 with correct JSON envelope
- `tests/transparent_cert.rs` — rustls test client through proxy, validates leaf chains back to our CA, SAN matches upstream host
- `tests/transparent_hot_reload.rs` — SIGHUP swaps registry mid-flight, in-flight uses old, new CONNECT sees new
- `tests/transparent_audit.rs` — entries emitted with `trigger=transparent`, sensitive fields masked, bytes_in/out + duration_ms present

### E2E smoke (in CI, behind `transparent` feature flag)

- spawn vault-proxy
- `curl --cacert transparent-ca.crt -x http://127.0.0.1:3203 https://httpbin.local/headers` against wiremock httpbin → assert injected header
- python `requests` with `REQUESTS_CA_BUNDLE` env + proxies dict → same wiremock target → same assertion
- node `https` with `NODE_EXTRA_CA_CERTS` → same
- One per language so CA-trust-store integration bugs surface in CI

### CI matrix additions (`.github/workflows/docker-publish.yml`)

- New step: `cargo clippy --all-targets --features transparent -- -D warnings`
- New step: `cargo test --all-targets --features transparent`
- Existing `cargo clippy --all-targets --features browser,engine,dashboard` extends to include `transparent`
- Docker build `--build-arg FEATURES=transparent` smoke (verify TLS deps don't bloat image past ~50MB)

### Security review checkpoints (gate before merge)

- [ ] CA private key never read into a logged buffer (manual code review)
- [ ] Leaf cert cache cannot be poisoned by malicious upstream
- [ ] Forbidden-header strip list matches existing `/proxy` list (single source of truth)
- [ ] No path in `mitm.rs` where vault credential is written to a tracing macro at any level
- [ ] `--check` catches all new misconfigurations
- [ ] Threat model in `SECURITY.md` updated: new CA key as Tier-1 secret, BYO mode threat differences

---

## 8 — Rollout plan

| Version | Scope | Default | Audience |
|---|---|---|---|
| v1.1.0-alpha.1 | Module skeleton + passthrough mode only | feature off | Internal |
| v1.1.0-alpha.2 | + host_inject for `bearer` + `header` auth | feature off | Internal + author homelab |
| v1.1.0-beta.1 | + placeholder mode + remaining auth types + full test suite | feature off | Public preview |
| v1.1.0-beta.2 | + audit log + SECURITY.md + docs/operator/TRANSPARENT-CA.md | feature off | Public preview, soak ≥7d |
| v1.1.0 | No code changes from beta.2 | feature off | GA |
| v1.2.0 | Default `transparent` feature ON in Docker image | feature on | Mass adoption |

### Documentation deliverables (land with v1.1.0-beta.1)

- `docs/operator/TRANSPARENT.md` — what it is, when to use it, when to prefer `/proxy`
- `docs/operator/TRANSPARENT-CA.md` — install CA on each agent host, per-language overrides, rotation
- `SECURITY.md` — new sub-section on transparent CA threat model
- `README.md` — features-table blurb + comparison table updated for parity with agent-vault / OneCLI
- `services.example.toml` — annotated example with `transparent_mode` field

---

## 9 — Timeline and dependencies

### Effort estimate (focused)

| Phase | Effort | Cumulative |
|---|---|---|
| Module scaffolding + listener + CONNECT parser + passthrough | 3 days | 3d |
| TLS CA gen + leaf factory + cache + BYO validation | 4 days | 7d |
| host_inject (all 4 auth types) + forbidden-header strip | 3 days | 10d |
| placeholder substitution + body buffering + size limits | 3 days | 13d |
| services.toml schema + registry + hot-reload integration | 2 days | 15d |
| Audit log integration + error JSON envelopes | 2 days | 17d |
| Unit + integration test suite (~25 new tests) | 4 days | 21d |
| E2E smoke (curl + python + node) | 2 days | 23d |
| CI matrix + feature-flag wiring + Docker build-arg | 1 day | 24d |
| Docs + services.example.toml | 2 days | 26d |
| Soak + bugfix buffer (beta.1 → beta.2 → 1.1.0) | 5 days | 31d |

~6 calendar weeks at one focused day per calendar day; 8-10 calendar weeks realistic with day-job context.

### External dependencies (crates)

- `rcgen` — promote from transitive to direct dep
- `rustls`, `tokio-rustls` — already direct
- `lru` — new direct dep for leaf cert cache (~3KB compiled)

### Internal dependencies (must land first)

- v1.0.6 release (ETXTBSY fix already on `main` HEAD) — needs only a tag
- CI cache (Swatinem/rust-cache@v2) — strongly recommended; transparent feature CI runs would otherwise add 16min cold compile per push

---

## 10 — Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| CA install instructions wrong on some platform → silent agent failures | High | Med | E2E smoke covers curl/python/node; platform-specific runbooks; community confirms during beta |
| MITM breaks an upstream that pins certs (banks/govs) | Med | Low | Documented limitation; passthrough mode is the escape hatch per service |
| Leaf cert cache poisoning via crafted upstream cert | Low | High | Validate SAN against requested host before signing leaf; security-review checklist item |
| `placeholder` mode + binary protocols silently corrupt requests | Med | Med | Content-Type allowlist; binary bodies skip substitution + emit WARN; documented |
| Performance regression on passthrough mode | Low | Med | Benchmark in CI vs raw socat; gate on ≥90% throughput |
| Operator confusion: which mode to use (host_inject vs placeholder vs /proxy) | High | Low | Decision tree in `docs/operator/TRANSPARENT.md`; comparison table in README |
| BYO CA with mode != 0600 → operator skips startup check via escape flag → key leaks | Med | High | Don't add an escape flag. Fail-fast, period. |

---

## 11 — Hard cutoffs (will NOT change in v1.1)

- HTTP/1.1 only
- TLS only (no plain-HTTP injection — operators keep using `/proxy` for plain HTTP)
- Loopback-bound listener by default
- Feature flag opt-in (not default-on until v1.2)

## 12 — Backwards compatibility guarantee

- Every existing `/proxy` integration keeps working unchanged.
- Every existing `services.toml` parses unchanged.
- No CLI flag removed or renamed.
- Default Docker image without `--build-arg FEATURES=transparent` has zero new behaviour.

---

## 13 — Open questions for implementation planning

These were not blockers for the design but the implementation plan must resolve them:

1. Concrete `lru` crate version + feature set (sync, async, no-std?).
2. Whether `cert_factory` benefits from a separate background task that pre-warms upstream cert cache for hot hosts vs lazy on-demand only.
3. Audit-log batch flush interval for high-traffic transparent mode (current default flushes every 10 entries — may want lower for transparent).
4. Whether to plumb `tracing::Span` per-connection for correlation (helpful for debugging; small perf cost).
5. Exact set of forbidden inbound headers — does the existing `/proxy` block list need any additions for transparent context (e.g. `Proxy-Authorization`, `X-Forwarded-For` from agent)?
