# Transparent HTTPS_PROXY mode

A third integration tier for vault-proxy, alongside native `/proxy`
and `--launch`. Unmodified HTTPS clients (curl, requests, fetch,
third-party MCP servers, agent frameworks) use vault-credentials by
setting `HTTPS_PROXY=http://127.0.0.1:3203` and trusting one CA cert
that vault-proxy generates at first start.

**Status:** GA since v1.1.0; default-on since v1.2.0. Current
operator-facing surface as of v1.4.2 covers four listener variants,
seven auth patterns including OAuth client-credentials and
refresh-token, SIEM audit sinks, response-body sanitisation, and a
typed error envelope.

```
Agent (env: HTTPS_PROXY=http://127.0.0.1:3203)
   │
   │  CONNECT api.github.com:443 HTTP/1.1
   ▼
┌──────────────────────────────────────────────────────────────┐
│  vault-proxy: transparent listener on 127.0.0.1:3203         │
│  (or UDS, or mTLS — see "Listener variants" below)            │
│                                                               │
│  1. Parse CONNECT → host:port                                 │
│  2. Lookup registry: services.toml entry for host?            │
│       ├─ YES + transparent_mode = "host_inject"  ─► MITM      │
│       ├─ YES + transparent_mode = "placeholder"  ─► MITM      │
│       ├─ YES + transparent_mode = "passthrough"  ─► tunnel    │
│       └─ NO  ─► passthrough (or block in allowlist mode)      │
└──────────────────────────────────────────────────────────────┘
   │
   ▼
api.github.com:443  (sees vault-proxy IP, real Bearer/OAuth/etc.)
```

## Which mode for which use case?

| Use case | Mode |
|---|---|
| Smart MCP server you control | Native `POST /proxy` (Tier 1). No CA install. Plaintext request never crosses TLS. |
| Unmodified third-party MCP server (no `/proxy` support) | `--launch` (Tier 2) for `.env`-style credentials, or transparent `host_inject` if it makes HTTPS calls to a registered service |
| Random Anthropic API caller / LLM agent script / `curl` | Transparent `host_inject` — the only mode that requires zero code change in the client |
| Old code with a placeholder convention already in it (`__SECRET__`-style) | Transparent `placeholder` |
| Off-loopback access (other hosts on a tailnet) | Transparent `mTLS` listener — same MITM under an outer TLS+client-cert jacket |

`/proxy` is still the most secure option (no MITM, no plaintext on
the proxy). Transparent mode is for clients you can't or won't
modify.

## Enabling the feature

The `transparent` Cargo feature has been on by default since v1.2.0,
so the stock build / Docker image already ships everything here. To
build without it (smaller binary, zero transparent footprint), pass
`--no-default-features`.

The TCP listener binds `127.0.0.1:3203` by default. Disable via
`TRANSPARENT_LISTEN=""` or change the address with
`--transparent-listen 127.0.0.1:3210` etc.

On startup vault-proxy generates a CA cert in `$CONFIG_DIR/transparent-ca.{crt,key}`
and prints the fingerprint. See [`TRANSPARENT-CA.md`](TRANSPARENT-CA.md)
for the per-platform CA install runbook.

## Listener variants

| Variant | Bind | Auth | Use case |
|---|---|---|---|
| TCP (default) | `--transparent-listen`, default `127.0.0.1:3203` | none (relies on loopback) | local agents on the same host |
| UDS | `--transparent-uds <path>` | `SO_PEERCRED` uid match | local agents that prefer Unix sockets / containers sharing the runtime dir |
| mTLS-fronted TCP | `--transparent-mtls-listen <addr>` plus `--transparent-mtls-server-cert`, `--transparent-mtls-server-key`, `--transparent-mtls-client-ca` | outer TLS handshake requires a client cert signed by the configured CA | off-loopback exposure (Tailscale, etc.) |

All three variants run the same `handle_connection` MITM/passthrough
flow internally — the only difference is the agent-facing transport.
They can be enabled simultaneously (e.g. UDS for local + mTLS for
remote callers).

## services.toml

Add `transparent_mode` to any service you want the transparent
listener to participate in. Default is `"off"` — existing
`services.toml` files parse unchanged.

```toml
[[service]]
name             = "github_api"
base_url         = "https://api.github.com"
auth             = "bearer"
vault_item       = "vault-proxy - GitHub PAT"
transparent_mode = "host_inject"
```

Valid `transparent_mode` values:

| Value | Behaviour |
|---|---|
| `off` (default) | Service participates in `/proxy` only. Transparent listener ignores it. |
| `host_inject` | MITM. vault-proxy strips agent's auth headers, injects the credential per `auth` pattern. Supports `bearer`, `header`, `basic`, `query_param`, `oauth_client_credentials`, `oauth_refresh`. `session` and `unifi_dual` are rejected at parse time. |
| `placeholder` | MITM. vault-proxy scans body + headers for `__vault.<name>__` literal tokens and swaps each for the resolved value. |
| `passthrough` | Explicit TCP relay. Same as `off` but signals intentional registration (useful with `--transparent-unregistered-policy=allowlist`). |

`base_url` may contain a leading-`*.` wildcard (v1.2.5+) such as
`https://*.github.com` to match any subdomain on a single service
entry. Exact entries always win; wildcards only fire on miss.

### OAuth flows

Two OAuth auth patterns ship in v1.3 and slot into `host_inject` mode
just like Bearer/Header:

```toml
[[service]]
name             = "github_app"
base_url         = "https://api.github.com"
auth             = "oauth_client_credentials"
vault_item       = "vault-proxy - GitHub App"
token_url        = "https://github.com/login/oauth/access_token"
# key_field      = "client_id"        # default "username"
# secret_field   = "client_secret"    # default "password"
# scope          = "repo read:org"
transparent_mode = "host_inject"

[[service]]
name                  = "google_drive"
base_url              = "https://www.googleapis.com"
auth                  = "oauth_refresh"
vault_item            = "vault-proxy - Google OAuth"
token_url             = "https://oauth2.googleapis.com/token"
# key_field           = "username"             # holds client_id
# secret_field        = "client_secret"        # optional; omit for public clients
# refresh_token_field = "password"             # holds the long-lived refresh token
# scope               = "https://www.googleapis.com/auth/drive.readonly"
transparent_mode      = "host_inject"
```

Tokens are cached per-`vault_item` until `expires_in − 60 s` and
re-acquired automatically on a `401` from the upstream. The cache is
shared between `/proxy/{service}` calls and the transparent listener.

IdP-side refresh-token rotation: set `oauth_writeback = true` on an
`oauth_refresh` service (v1.5.0+) to write rotated RTs back to the
vault item. Concurrent refreshes are serialised via a per-`vault_item`
mutex held from cache-check through writeback, so a rotating IdP
doesn't deal two grants the second of which uses an already-invalidated
RT. Writeback works against any `refresh_token_field` (v1.6.0+);
`"password"` uses the login-block updater, other fields use a generic
custom-field merge that leaves every other encrypted field byte-for-byte
unchanged. Default remains `false` — operators must opt in.

### Placeholder map

For credentials not tied to a single host, declare them in their own
block:

```toml
[[transparent_placeholder]]
token      = "__vault.github_pat__"
vault_item = "vault-proxy - GitHub PAT"
# field    = "password"   # default
```

Token syntax: `__vault.<name>__` where `<name>` matches `[A-Za-z0-9_-]+`.
Invalid tokens are rejected at load time with a clear error.

A request that references an undeclared token gets back a 502 with
`transparent_error_code = "placeholder_unresolved"` — vault-proxy
never forwards a request with unresolved placeholders.

## SIGHUP reload (v1.2.1+)

Sending `SIGHUP` to the proxy rebuilds the transparent registry and
the placeholder list in place — no restart needed. In-flight requests
work from their captured snapshot; only new accepts see the swap.

## Response sanitisation (v1.2.5+ env, v1.3.1+ CLI)

`--transparent-sanitize-responses` / `TRANSPARENT_SANITIZE_RESPONSES`
runs upstream HTTP response bodies through the prompt-injection
sanitiser before returning them to the agent. Off by default; opt in
when you want extra hardening against upstream content that may
contain hostile prompts. Skips chunked / non-textual responses
defensively. The v1.2.5 env shim `VP_TRANSPARENT_SANITIZE_RESPONSES`
was removed in v1.3.1.

## ALPN behaviour (v1.7.0+)

The MITM leaf cert advertises both `h2` and `http/1.1` on ALPN.
Post-handshake, the proxy inspects the negotiated protocol and
dispatches to either the HTTP/1.1 MITM path (v1.1.0) or the native
HTTP/2 MITM path (`h2_mitm::run_h2`, v1.7.0). h2-capable clients get
native h2 framing; http/1.1-only clients keep their existing path;
clients that demand `h2` only now succeed (v1.4.1–v1.6.x rejected
them with an ALPN-mismatch).

Upstream-side h2 (v1.8.0+): the h2 MITM path tries h2 against the
upstream first (TLS + ALPN `["h2", "http/1.1"]`). When the upstream
picks h2 the response stays on the h2 wire end-to-end — no http/1.1
re-frame. When the upstream picks http/1.1 the path falls back to
the existing http/1.1 forwarder.

Cross-protocol upstream h2 for http/1.1 agents (v1.9.0+): the
http/1.1 MITM path now tries h2 against the upstream too. On
success the parsed h2 response is re-serialised back to http/1.1
wire bytes for the agent; on failure (or upstream picking http/1.1)
the existing http/1.1 forwarder runs. All four agent↔upstream wire
combinations work — http/1.1↔http/1.1, h2↔http/1.1, h2↔h2,
http/1.1↔h2.

Limitations: no upstream h2 connection pool yet — every agent stream
opens its own h2 session to the upstream. A pool keyed by
`(host, port)` is tracked as v1.9 follow-up "HTTP/2 upstream pool".

## SIEM audit sinks (v1.4.2 sync, v1.4.4 network)

`--audit-sink=<spec>` / `AUDIT_SINK=<spec>` fans out the audit log to
SIEM-friendly sinks in addition to the on-disk JSON file. Spec is a
comma-separated list of sink names. Unknown entries are logged at
WARN and skipped. Empty / unset = file-only (the v1.4.x behaviour).

Synchronous sinks (v1.4.2):
- `stdout` — newline-delimited JSON to stdout; pair with `systemd StandardOutput=journal`
- `stderr` — same to stderr
- `syslog` — Unix syslog at LOG_INFO with ident `vaultproxy`

Network sinks (v1.4.4) — batched (50 entries or 5 s) and best-effort.
Secrets live in env vars, not argv:

| Sink | URL env | Auth env | Wire shape |
|---|---|---|---|
| `otlp` | `OTLP_AUDIT_URL` (required) | `OTLP_AUDIT_HEADERS` (optional, comma-separated `key=value`) | OTLP HTTP `LogsData` envelope |
| `datadog` | `DATADOG_AUDIT_URL` | `DATADOG_AUDIT_API_KEY` (DD-API-KEY header) | JSON array of `{service, ddsource, message, timestamp}` |
| `splunk` | `SPLUNK_AUDIT_URL` | `SPLUNK_AUDIT_TOKEN` (Splunk HEC bearer) | Newline-delimited `{"event": …, "sourcetype": "vaultproxy:audit"}` |

Examples:
- `--audit-sink=stdout` — pair with `systemd StandardOutput=journal`
- `--audit-sink=syslog` — local rsyslog / journald
- `--audit-sink=stdout,syslog,splunk` — three at once
- `--audit-sink=datadog` plus `DATADOG_AUDIT_URL=https://http-intake.logs.datadoghq.com/api/v2/logs` + `DATADOG_AUDIT_API_KEY=<key>` in env

## CLI reference

See [`TRANSPARENT-FLAGS.md`](TRANSPARENT-FLAGS.md) for the full flag /
env-var matrix across listeners, MITM CA, per-service behaviour, and
cross-cutting concerns.

## Error responses to the agent

All proxy-side error responses use semantically-correct HTTP codes
plus a discriminator in the JSON body. Clients should branch on
`transparent_error_code`, not on the status code alone.

| Status | `transparent_error_code` | Cause |
|---|---|---|
| `400` | `malformed_connect` | malformed CONNECT line, oversized headers, unsupported HTTP version |
| `502` | `upstream_unreachable` | upstream TCP connect or TLS handshake failed |
| `502` | `unregistered_host_blocked` | allowlist mode + host has no `[[service]]` block |
| `502` | `placeholder_unresolved` | request contained `__vault.X__` with no matching `[[transparent_placeholder]]` |
| `502` | `vault_resolution_failed` | vault item or field missing on resolved item |

All error bodies: `{"ok": false, "error": "<human-readable>", "transparent_error_code": "<discriminator>"}`.

## Security notes

- Loopback bind by default. Non-loopback `--transparent-listen`
  produces a startup `SECURITY:` warning. For off-loopback exposure
  use the mTLS-fronted listener instead — see
  [`TRANSPARENT-FLAGS.md`](TRANSPARENT-FLAGS.md) for the flag set.
- The MITM CA private key is a Tier-1 secret. See
  [`../../SECURITY.md`](../../SECURITY.md) for the full threat model
  and [`TRANSPARENT-CA.md`](TRANSPARENT-CA.md) for rotation steps.
- The mTLS listener's server cert + key are equivalent in sensitivity
  to the MITM CA key — compromise of either lets an attacker MITM
  every transparent request originating on the affected host.
- Agent's pre-existing `Authorization` / `X-Api-Key` / `X-Plex-Token`
  / `Cookie` / `Proxy-Authorization` headers are **always stripped**
  before the credential is injected. The vault is the single source
  of truth.
- Existing `/proxy` SSRF guard (loopback, link-local, cloud-metadata
  blocking) applies to `services.toml` regardless of `transparent_mode`.

## Limitations

- HTTP/1.1 only on the wire. h2-capable clients are forced to
  downgrade (v1.4.1); native h2 framing is a v1.5 follow-up.
- TLS-only upstream by default. Plain-HTTP upstreams should use
  `/proxy` instead. The `VP_TRANSPARENT_TEST_HTTP=1` affordance is
  for integration tests only — do not set in production.
- WebSocket upgrades fall back to passthrough after the 101 response;
  ws/wss frames are not inspected for placeholders.
- OAuth refresh-token rotation by the IdP is logged but not persisted
  back to the vault — operators using IdPs that mandatorily rotate
  must rotate the vault item out-of-band.

## See also

- [`TRANSPARENT-FLAGS.md`](TRANSPARENT-FLAGS.md) — every flag / env
  for transparent mode in one place
- [`TRANSPARENT-CA.md`](TRANSPARENT-CA.md) — install the MITM CA on
  every host that uses `HTTPS_PROXY=...:3203`
- [`../../SECURITY.md`](../../SECURITY.md) — threat model for the
  whole proxy, including the transparent CA private key and mTLS
  listener material
- [`../ROADMAP.md`](../ROADMAP.md) — what's shipped, what's next
