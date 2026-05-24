# Roadmap

## Shipped through v1.2.4

| ID | Item | Version |
|---|---|---|
| G1 | Transparent HTTPS_PROXY mode (host_inject + placeholder) | v1.1.0 |
| G1.1 | Default-on (`default = ["transparent"]`) + real vault decryption in `inject_host` | v1.2.0 |
| G2 partial | SO_PEERCRED Unix-socket listener scaffold | v1.2.5 |
| G4 | Response prompt-injection sanitisation (opt-in via `VP_TRANSPARENT_SANITIZE_RESPONSES=1`) | v1.2.5 |
| Wildcards | `*.host.com:port` patterns in `services.toml` for transparent_mode | v1.2.5 |
| SIGHUP | Rebuild of transparent registry + placeholders without restart | v1.2.1 |
| Audit | `<path>.archive` JSONL eviction trail | v1.2.3 |
| Errors | Typed `TransparentErrorCode` envelope across all transparent error paths | v1.2.2 |

## v1.3 candidates

| ID | Item | Notes |
|---|---|---|
| G2 full | **mTLS listener** | Wire UDS dispatch through the existing MITM handler (current `uds_listener` scaffold accepts + rejects on uid mismatch but doesn't yet route to `mitm::run`). Add optional client-cert auth for the TCP listener so it can be safely exposed beyond loopback. |
| G3 | **OAuth flows** | `auth = "oauth_client_credentials"` and `auth = "oauth_refresh"` patterns for upstream services that require OAuth. Significant scope: 1 week per flow + refresh handling + state storage. |
| G4-default | **`sanitize_responses` default-on** | Currently env-flag-gated. Bake into a CLI flag and document the perf cost in `docs/operator/TRANSPARENT.md`. |
| HTTP/2 | **HTTP/2 transparent support** | Current MITM only speaks HTTP/1.1. Modern API clients increasingly default to h2 over ALPN. Significant: needs hyper-style h2 framing or rustls ALPN downgrade fallback. |

## v1.1 candidates (deferred or superseded)

| ID | Item | Notes |
|---|---|---|
| G1 | **Transparent `HTTPS_PROXY` mode** | Allow unmodified third-party agents to be proxied via `HTTPS_PROXY=http://127.0.0.1:3201`, using placeholder-token substitution as agent-vault / OneCLI do. Feature-flagged. |
| G2 | **mTLS / Unix-socket listener** | Optional listener that authenticates callers via mTLS or `SO_PEERCRED` uid match, replacing the current loopback-only trust model. |
| G3 | **OAuth flows** | `auth = "oauth_client_credentials"` and `auth = "oauth_refresh"` patterns for upstream services that require OAuth. |
| G4 | **Response prompt-injection sanitisation** | Optional `sanitize_responses` flag that runs upstream JSON responses through the same `sanitize_output` helper used by the browser-rotation pipeline before they are returned to the MCP layer. |
| G11 | **SIEM audit sinks** | `--audit-sink=stdout`, `--audit-sink=syslog`, and OTLP/Datadog/Splunk forwarders for the audit log. Currently the log is JSON-on-disk only — see [operator/AUDIT-LOG.md](operator/AUDIT-LOG.md). |
| G12 | **HIBP scan pagination** | The credential audit caps at 1 000 items (see [operator/CRED-AUDIT.md](operator/CRED-AUDIT.md)). v1.1 will add pagination or chunked async scan. |
| G13 | **Generic `/rotate` strategies** | The internal `POST /rotate` endpoint is defined and gated behind the internal token, but all built-in rotation strategies (`sonarr`, `radarr`) currently return `501 Not Implemented`. The stub exists for API compatibility with planned tooling — **do not build production workflows on `/rotate` in v1.0.** v1.1 will ship at least one working strategy (`vaultwarden_password` or `bearer_regenerate_via_admin_api`). For browser-driven rotation that already works today, see [operator/BROWSER-ROTATION.md](operator/BROWSER-ROTATION.md). |

## v1.2+ candidates

- Kubernetes deployment reference (Helm chart, sidecar injector)
- Native client SDKs (Rust crate, Python pip, npm package)
- Windows binary artefact in releases
- Additional auth patterns: SCRAM, mutual-cert for upstream

## Out of scope (declined)

- Multi-tenant vault folders in a single process — use one vault-proxy container per tenant
- Replacing Vaultwarden with a different backend — Vaultwarden is the explicit positioning
- Acting as a general-purpose MCP gateway / aggregator — that is a different category (see `wirken`, `stephenlacy/mcp-proxy`)
