# Roadmap

## Shipped through v1.9.0

| ID | Item | Version |
|---|---|---|
| G1 | Transparent HTTPS_PROXY mode (host_inject + placeholder) | v1.1.0 |
| G1.1 | Default-on (`default = ["transparent"]`) + real vault decryption in `inject_host` | v1.2.0 |
| G2 partial | SO_PEERCRED Unix-socket listener scaffold | v1.2.5 |
| G2 dispatch | UDS listener wired through `handle_connection` (TLS MITM + passthrough on UDS) + `--transparent-uds` CLI flag | v1.3.1 |
| G2 mTLS | mTLS-fronted TCP listener with client-cert auth (`--transparent-mtls-listen`) | v1.4.0 |
| G3 client | OAuth 2.0 `client_credentials` auth pattern (token cache + 401 refresh, works in both `/proxy/{service}` and transparent host_inject) | v1.3.0 |
| G3 refresh | OAuth 2.0 `refresh_token` auth pattern (long-lived RT in vault, short-lived access token cached; IdP-side RT rotation logged but not written back to vault) | v1.3.2 |
| G4 | Response prompt-injection sanitisation (opt-in via `VP_TRANSPARENT_SANITIZE_RESPONSES=1`) | v1.2.5 |
| G4 CLI | `--transparent-sanitize-responses` CLI flag (env shim removed) | v1.3.1 |
| HTTP/2 ALPN | MITM leaf cert pins ALPN to `http/1.1` (h2-capable clients downgrade; h2-only clients fail with ALPN mismatch) | v1.4.1 |
| HTTP/2 native | Native h2 MITM path via `h2_mitm::run_h2`. Agent-side native h2 framing; upstream-side still HTTP/1.1 (re-framed on the way back). ALPN advertises `["h2", "http/1.1"]`. | v1.7.0 |
| HTTP/2 upstream | Native h2 to the upstream too (`h2_upstream::try_h2`). End-to-end h2 when both sides speak it; falls back to http/1.1 on upstream ALPN miss. | v1.8.0 |
| HTTP/2 cross-protocol | Upstream h2 reachable from http/1.1 agents too (`h2_upstream::serialise_as_http1` re-serialises the parsed h2 response). | v1.9.0 |
| SIEM stdout/syslog | `--audit-sink=<stdout\|stderr\|syslog>` fans out the audit log to SIEM-friendly sinks | v1.4.2 |
| SIEM network | `--audit-sink=<otlp\|datadog\|splunk>` HTTP-based forwarders (batched, env-configured) | v1.4.4 |
| G3 RT-writeback | OAuth refresh-token vault writeback via `oauth_writeback = true` on `oauth_refresh` services. Per-`vault_item` mutex serialises rotations. | v1.5.0 |
| G3 RT-writeback custom-field | RT writeback now supports custom `refresh_token_field` (not only the default `"password"`). | v1.6.0 |
| Wildcards | `*.host.com:port` patterns in `services.toml` for transparent_mode | v1.2.5 |
| SIGHUP | Rebuild of transparent registry + placeholders without restart | v1.2.1 |
| Audit | `<path>.archive` JSONL eviction trail | v1.2.3 |
| Errors | Typed `TransparentErrorCode` envelope across all transparent error paths | v1.2.2 |

## v1.10 candidates

| ID | Item | Notes |
|---|---|---|
| HTTP/2 upstream pool | **h2 client pool** | Every request still opens a fresh h2 connection to the upstream. A `DashMap<(host, port), SendRequest<Bytes>>` would reuse upstream h2 sessions across many agent requests. Needs careful eviction on RST_STREAM / GOAWAY. |
| HTTP/2 trailers / push | h2 trailers + server push on both sides. Rare; defer until a real workload asks. |

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
