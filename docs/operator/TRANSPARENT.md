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
IdP-side refresh-token rotation is logged at WARN but **not** persisted
back to the vault — see the v1.5 roadmap if your IdP mandates
rotation.

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

## ALPN behaviour (v1.4.1+)

The MITM leaf cert advertises only `http/1.1` on ALPN. h2-capable
clients that also offer `http/1.1` downgrade cleanly; clients that
demand `h2` only fail the outer TLS handshake with an ALPN-mismatch
error. Both outcomes are safer than the pre-v1.4.1 behaviour where
silent stream corruption was possible. Native HTTP/2 framing is
tracked in `docs/ROADMAP.md`.

## SIEM audit sinks (v1.4.2+)

`--audit-sink=<spec>` / `AUDIT_SINK=<spec>` fans out the audit log to
SIEM-friendly sinks in addition to the on-disk JSON file. Spec is a
comma-separated list; recognised: `stdout`, `stderr`, `syslog` (Unix
only). Unknown entries are logged at WARN and skipped. Empty / unset
= file-only (the v1.4.x behaviour).

Each emitted line is a single-line JSON object — the same `AuditEntry`
shape that the on-disk file uses, so any SIEM that parses JSON can
ingest the stream verbatim.

Examples:
- `--audit-sink=stdout` — pair with `systemd StandardOutput=journal`
- `--audit-sink=syslog` — local rsyslog / journald
- `--audit-sink=stdout,syslog` — both at once

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
