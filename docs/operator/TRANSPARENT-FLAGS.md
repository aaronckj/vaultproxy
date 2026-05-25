# Transparent-mode CLI quick reference

> **Build-time prerequisite.** The default build of vault-proxy has shipped
> with `--features transparent` enabled since v1.2.0. Operators building
> without default features must re-enable it explicitly. None of the flags
> below appear in `--help` when the feature is off.

## Listeners

| Flag | Env | Default | Description |
|---|---|---|---|
| `--transparent-listen` | `TRANSPARENT_LISTEN` | `127.0.0.1:3203` | TCP listener bind address. Empty disables. Non-loopback triggers a SECURITY: startup warning. |
| `--transparent-uds` | `TRANSPARENT_UDS` | (unset) | Additional UDS listener path (e.g. `$XDG_RUNTIME_DIR/vaultproxy-transparent.sock`). Authenticated via `SO_PEERCRED` uid match. Same MITM dispatch as the TCP listener. v1.3.1+. |
| `--transparent-mtls-listen` | `TRANSPARENT_MTLS_LISTEN` | (unset) | Additional TLS-fronted TCP listener address. Requires the agent to present a client cert signed by `--transparent-mtls-client-ca` and to trust `--transparent-mtls-server-cert`. Use for off-loopback exposure. v1.4.0+. |
| `--transparent-mtls-server-cert` | `TRANSPARENT_MTLS_SERVER_CERT` | (unset) | PEM cert the mTLS listener presents. Required when `--transparent-mtls-listen` is set. v1.4.0+. |
| `--transparent-mtls-server-key` | `TRANSPARENT_MTLS_SERVER_KEY` | (unset) | PEM key paired with the mTLS server cert. Must be mode 0600. v1.4.0+. |
| `--transparent-mtls-client-ca` | `TRANSPARENT_MTLS_CLIENT_CA` | (unset) | PEM CA bundle that signs agent client certs. v1.4.0+. |

## MITM CA (used by every listener variant above)

| Flag | Env | Default | Description |
|---|---|---|---|
| `--transparent-ca-cert` | `TRANSPARENT_CA_CERT` | (auto-generated) | BYO CA cert (PEM). Pairs with `--transparent-ca-key`; mutually exclusive with auto-generation. |
| `--transparent-ca-key` | `TRANSPARENT_CA_KEY` | (auto-generated) | BYO CA key (PEM). Must be mode 0600 — startup refuses to proceed otherwise. |

## Per-service behaviour

| Flag | Env | Default | Description |
|---|---|---|---|
| `--transparent-default-mode` | `TRANSPARENT_DEFAULT_MODE` | `off` | Default `transparent_mode` for services that omit the field. Reserved; the per-service field always wins. Valid: `off` \| `host_inject` \| `placeholder` \| `passthrough`. |
| `--transparent-unregistered-policy` | `TRANSPARENT_UNREGISTERED_POLICY` | `passthrough` | Behaviour for hosts with no `[[service]]` block. `passthrough` = TCP tunnel unchanged; `allowlist` = reject with 502 + `transparent_error_code = "unregistered_host_blocked"`. |
| `--transparent-sanitize-responses` | `TRANSPARENT_SANITIZE_RESPONSES` | `false` | Run upstream HTTP response bodies through the prompt-injection sanitiser before returning them to the agent. Skips chunked and non-textual responses. Small per-request CPU cost. v1.3.1+ (env shim removed; was `VP_TRANSPARENT_SANITIZE_RESPONSES=1` in v1.2.5). |

## Cross-cutting

| Flag | Env | Default | Description |
|---|---|---|---|
| `--audit-sink` | `AUDIT_SINK` | (empty) | Comma-separated list of SIEM-friendly audit sinks fanned out alongside the on-disk audit log. Recognised: `stdout`, `stderr`, `syslog`. Unknown entries are logged at WARN and skipped. v1.4.2+. |

## ALPN behaviour (v1.4.1+)

The MITM leaf cert advertises only `http/1.1` on ALPN. h2-capable clients
that also offer `http/1.1` downgrade cleanly; clients that demand `h2`
only fail the outer TLS handshake with an ALPN-mismatch error. Native
HTTP/2 framing on the upstream side is tracked in `docs/ROADMAP.md`.

## See also

- [`TRANSPARENT.md`](TRANSPARENT.md) — conceptual guide
- [`TRANSPARENT-CA.md`](TRANSPARENT-CA.md) — CA install + rotation
- [`../ROADMAP.md`](../ROADMAP.md) — what's shipped vs. v1.5 candidates
- [`../../SECURITY.md`](../../SECURITY.md) — threat model + key-handling rules
