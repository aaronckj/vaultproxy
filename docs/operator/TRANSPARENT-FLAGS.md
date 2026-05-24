# Transparent-mode CLI quick reference

| Flag | Env | Default | Description |
|---|---|---|---|
| `--transparent-listen` | `TRANSPARENT_LISTEN` | `127.0.0.1:3203` | Listener bind address. Empty disables. Non-loopback triggers a SECURITY: startup warning. |
| `--transparent-ca-cert` | `TRANSPARENT_CA_CERT` | (auto-generated) | BYO CA cert (PEM). Pairs with `--transparent-ca-key`; mutually exclusive with auto-generation. |
| `--transparent-ca-key` | `TRANSPARENT_CA_KEY` | (auto-generated) | BYO CA key (PEM). Must be mode 0600 — startup refuses to proceed otherwise. |
| `--transparent-default-mode` | `TRANSPARENT_DEFAULT_MODE` | `off` | Default `transparent_mode` for services that omit the field. Reserved; the per-service field always wins in v1.1. Valid: `off` \| `host_inject` \| `placeholder` \| `passthrough`. |
| `--transparent-unregistered-policy` | `TRANSPARENT_UNREGISTERED_POLICY` | `passthrough` | Behaviour for hosts with no `[[service]]` block. `passthrough` = TCP tunnel unchanged; `allowlist` = reject with 502 + `transparent_error_code = "unregistered_host_blocked"`. |

All flags require `--features transparent` at build time. The default
build has zero transparent footprint (no listener, no CA, no flags
in `--help`).

See [`TRANSPARENT.md`](TRANSPARENT.md) for the conceptual guide and
[`TRANSPARENT-CA.md`](TRANSPARENT-CA.md) for CA install + rotation.
