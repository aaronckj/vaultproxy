# Transparent HTTPS_PROXY mode

A third integration tier for vault-proxy, alongside native `/proxy`
and `--launch`. Unmodified HTTPS clients (curl, requests, fetch,
third-party MCP servers, agent frameworks) use vault-credentials by
setting `HTTPS_PROXY=http://127.0.0.1:3203` and trusting one CA cert
that vault-proxy generates at first start.

**Status: v1.1.0 beta** — requires `--features transparent` at build
time. Default off through all of v1.1.x; flips on in v1.2.

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
└──────────────────────────────────────────────────────────────┘
   │
   ▼
api.github.com:443  (sees vault-proxy IP, real Bearer token)
```

## Which mode for which use case?

| Use case | Mode |
|---|---|
| Smart MCP server you control | Native `POST /proxy` (Tier 1). No CA install. Plaintext request never crosses TLS. |
| Unmodified third-party MCP server (no `/proxy` support) | `--launch` (Tier 2) for `.env`-style credentials, or transparent `host_inject` if it makes HTTPS calls to a registered service |
| Random Anthropic API caller / LLM agent script / `curl` | Transparent `host_inject` — the only mode that requires zero code change in the client |
| Old code with a placeholder convention already in it (`__SECRET__`-style) | Transparent `placeholder` |

`/proxy` is still the most secure option (no MITM, no plaintext on
the proxy). Transparent mode is for clients you can't or won't
modify.

## Enabling the feature

Build with the `transparent` Cargo feature:

```bash
cargo build --release --features transparent
# or
docker build --build-arg FEATURES=transparent -t vaultproxy:transparent .
```

The listener binds `127.0.0.1:3203` by default. Disable via
`TRANSPARENT_LISTEN=""` or change the address with
`--transparent-listen 127.0.0.1:3210` etc.

On startup vault-proxy generates a CA cert in `$CONFIG_DIR/transparent-ca.{crt,key}`
and prints the fingerprint. See [`TRANSPARENT-CA.md`](TRANSPARENT-CA.md)
for the per-platform CA install runbook.

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
| `host_inject` | MITM. vault-proxy strips agent's auth headers, injects the credential per `auth` pattern. Supports `bearer`, `header`, `basic`, `query_param`. `session` and `unifi_dual` are rejected at parse time. |
| `placeholder` | MITM. vault-proxy scans body + headers for `__vault.<name>__` literal tokens and swaps each for the resolved value. |
| `passthrough` | Explicit TCP relay. Same as `off` but signals intentional registration (useful with `--transparent-unregistered-policy=allowlist`). |

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

## CLI reference

| Flag | Env | Default | Description |
|---|---|---|---|
| `--transparent-listen` | `TRANSPARENT_LISTEN` | `127.0.0.1:3203` | Listen address. Empty disables. |
| `--transparent-ca-cert` | `TRANSPARENT_CA_CERT` | (auto) | BYO CA cert (PEM). Pairs with `--transparent-ca-key`. |
| `--transparent-ca-key` | `TRANSPARENT_CA_KEY` | (auto) | BYO CA key (PEM, mode 0600). |
| `--transparent-default-mode` | `TRANSPARENT_DEFAULT_MODE` | `off` | Reserved; per-service field always wins. |
| `--transparent-unregistered-policy` | `TRANSPARENT_UNREGISTERED_POLICY` | `passthrough` | `passthrough` or `allowlist`. Allowlist mode blocks hosts with no `[[service]]` block. |

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
  produces a startup `SECURITY:` warning. The proxy currently has
  no listener-side auth (mTLS / SO_PEERCRED) — exposing the
  transparent port beyond `127.0.0.1` is not recommended in v1.1.
- The MITM CA private key is a Tier-1 secret. See `SECURITY.md` for
  the full threat model and `TRANSPARENT-CA.md` for rotation steps.
- Agent's pre-existing `Authorization` / `X-Api-Key` / `X-Plex-Token`
  / `Cookie` / `Proxy-Authorization` headers are **always stripped**
  before the credential is injected. The vault is the single source
  of truth.
- Existing `/proxy` SSRF guard (loopback, link-local, cloud-metadata
  blocking) applies to `services.toml` regardless of `transparent_mode`.

## Limitations (v1.1)

- HTTP/1.1 only. HTTP/2 over the transparent listener is a future
  enhancement.
- TLS-only upstream (the proxy speaks TLS to upstream). Plain-HTTP
  upstreams should use `/proxy` instead.
- WebSocket upgrades fall back to passthrough after the 101 response;
  ws/wss frames are not inspected for placeholders.
- SIGHUP does NOT yet rebuild the transparent registry — operators
  need to restart vault-proxy after editing `transparent_mode` or
  `[[transparent_placeholder]]` blocks. The existing `/proxy`
  SIGHUP path swaps `ServiceRegistry` without restart; transparent
  SIGHUP support is a beta.2 deliverable.
- No audit-log entries for transparent traffic yet (beta.2).

## See also

- [`TRANSPARENT-CA.md`](TRANSPARENT-CA.md) — install the MITM CA on
  every host that uses `HTTPS_PROXY=...:3203`
- [`../../SECURITY.md`](../../SECURITY.md) — threat model for the
  whole proxy, including the transparent CA private key
- [`../../docs/superpowers/specs/2026-05-24-transparent-https-proxy-design.md`](../superpowers/specs/2026-05-24-transparent-https-proxy-design.md)
  — design spec
