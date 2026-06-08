# vault-proxy — Competitive Gap Analysis

Pre-release positioning vs adjacent OSS projects. Goal: identify what to highlight, what to fix, and what to deprioritise before broader AI-community release of `vaultproxy` v1.0.3.

---

## 1. Positioning summary

`vaultproxy` is an HTTP credential broker (sidecar) that resolves credentials from **Vaultwarden** at request time and forwards authenticated calls to downstream services on behalf of MCP servers. Credentials never enter the MCP server's address space (Tier 1 native `/proxy`) or, at worst, only enter via fork/exec env vars (Tier 2 `--launch`).

Three distinct OSS categories overlap with this:

| Category | Pattern | Relationship to vault-proxy |
|---|---|---|
| **A. HTTP credential brokers for AI agents** | Placeholder→real substitution, proxy hides secrets from agent | Direct competitors |
| **B. MCP servers that wrap a password manager** | Exposes vault CRUD as tools the AI calls directly | Inverse — opposite threat model |
| **C. Generic secrets sidecars / agent injectors** | k8s/TCP brokers (Vault Agent, Secretless, vault-creds) | Adjacent — different protocol scope |
| **D. OS keychain wrappers for MCP** | get/set against OS keychain | Tangent — primitive, not a broker |

vault-proxy sits in **A**, with a **Vaultwarden-specific** backend (the others use HashiCorp Vault, Infisical, CyberArk Conjur, or a bespoke encrypted file).

---

## 2. Direct competitors (Category A)

| Project | Lang | Backend | Status | Notes |
|---|---|---|---|---|
| **Infisical/agent-vault** | Go | Infisical | preview, active | MITM via `HTTPS_PROXY`, dummy-placeholder substitution. Targets API providers (Anthropic, GitHub, Stripe). |
| **gebruder/wirken** | Rust | XChaCha20-Poly1305 vault + OS keychain | active, v1.7.x, 1802 tests, signed releases | Broader scope: also routes messaging adapters (Telegram/Slack/Discord/…) + LLM providers. Per-channel Ed25519 isolation, hash-chained audit, prompt-injection detection. |
| **OneCLI** | Rust | Encrypted file vault | trending, HN launch | Placeholder substitution + policy engine (agent identity, allowed hosts/paths). HTTP only. |

### Indirect / different category

| Project | Why not direct | Notes |
|---|---|---|
| cyberark/secretless-broker | TCP/SQL/SSH not HTTP-MCP; Conjur backend | Mature reference architecture |
| bitwarden/mcp-server, warden-mcp, mcp-vaultwarden, rbw-mcp, giuliolibrando/bitwarden-mcp-server | **Inverse** — exposes vault tools to the AI | Opposite threat model |
| rccyx/vault-mcp (HashiCorp Vault MCP) | Inverse, **archived 2026-02** | dead |
| Keeper PAM MCP | Inverse | commercial |
| amirshk/mcp-secrets-plugin, ai-mcp-garage/mcp-secrets | OS keychain wrapper, no broker | primitive layer |
| hashicorp/vault-k8s + vault agent injector | k8s sidecar, Vault backend, env-var/file injection | different deploy target |

---

## 3. Where vault-proxy LEADS (highlight in launch)

| Feature | vault-proxy | agent-vault | wirken | OneCLI | secretless |
|---|---|---|---|---|---|
| Vaultwarden backend (self-hosted, open-source vault) | ✅ native | ❌ Infisical | ⚠️ own vault | ❌ own vault | ❌ Conjur/etc |
| Per-service auth pattern library (bearer/header/basic/session/`unifi_dual`/query) | ✅ 6 patterns + UniFi dual fallback | ⚠️ token only | ⚠️ token only | ⚠️ HTTP only | ✅ many TCP |
| SIGHUP + HTTP hot-reload of `services.toml` with atomic swap + rollback-to-empty guard | ✅ | ❌ | ❌ | ❌ | partial |
| TPM sealing (hardware-bound keystore) | ✅ `--features tpm` | ❌ | ❌ | ❌ | ❌ |
| Built-in credential audit (weak/reused detection via HMAC-SHA256 fingerprints — all local, no password hashes ever leave your LAN; HIBP explicitly out of scope by design) | ✅ in-process + engine-sidecar workflow | ❌ | ❌ | ❌ | ❌ |
| Playwright + LLM-vision browser rotation (`POST /browser/rotate`) | 🚧 partial — browser-vision (experimental, off by default) + UniFi key-bootstrap; generic *arr API rotation not supported (`--features browser`, gated, sanitised) | ❌ | ❌ | ❌ | ❌ |
| Per-caller rate buckets via `X-Caller-Id` / `VAULT_PROXY_CALLER_ID` | ✅ | ❌ | per-channel via Ed25519 | ⚠️ policy match | ❌ |
| Dual integration modes (`/proxy` for smart servers + `--launch` for dumb ones) | ✅ | ⚠️ proxy only | proxy only | proxy only | proxy only |
| SSRF defence-in-depth — blocks loopback, link-local, and cloud-metadata endpoints (IPv4 + IPv6) at registry-load time + path-traversal rejection | ✅ | ⚠️ rule-based | ⚠️ | ⚠️ | ⚠️ |
| Vault-folder scope guard (cross-folder metadata leak prevention) | ✅ iter-99/100/103 | n/a | n/a | n/a | n/a |
| Audit log with sensitive-field masking + 1000-entry cap | ✅ | ✅ request log | ✅ hash-chained | ⚠️ | ⚠️ |
| Self-signed TLS (`insecure_tls`) for homelab services (with startup warning) | ✅ | ❌ | ❌ | ❌ | ❌ |
| MIT licence + single static Rust binary (no runtime deps) | ✅ | ✅ Go binary | ✅ | ✅ | ✅ |

**Unique selling propositions:**
1. **Only broker built around Vaultwarden** — every other tool assumes HashiCorp Vault, Infisical, Conjur, or a custom vault. Homelab + selfhosted operators already running Vaultwarden have zero-friction adoption.
2. **Only broker shipping browser-vision credential rotation** — closes the loop from "detect weak password" → "automatically change it on the upstream site."
3. **Native local HMAC audit (weak/reused detection — no password hashes ever leave your LAN; HIBP is explicitly out of scope by design)** — agent-vault/OneCLI/wirken all rely on the user noticing weak credentials externally.
4. **`unifi_dual` and other homelab-specific auth patterns** — opinionated for the *arr / Home Assistant / OPNsense / UniFi audience.

---

## 4. Where vault-proxy GAPS (fix or call out)

### 4.1 High-priority gaps (block release momentum)

| # | Gap | What competitors do | Recommendation |
|---|---|---|---|
| G1 | **No `HTTPS_PROXY` MITM mode.** Smart MCP servers must explicitly POST `/proxy` — dumb servers can use `--launch` but credentials hit env vars. | agent-vault & OneCLI intercept *any* outbound HTTPS via `HTTPS_PROXY` + placeholder swap, so zero-modification third-party agents work. | Document as a deliberate tradeoff (Tier 1 / Tier 2 model is already clear) OR add a Tier 1.5 transparent-proxy mode behind a feature flag. |
| G2 | **No mTLS / no listener auth.** Trust model is "loopback + cooperative `X-Caller-Id`." Anyone on `127.0.0.1` can call `/proxy`. | wirken: per-adapter Ed25519 handshake over Unix socket. agent-vault: token-based caller auth. | Already documented honestly in `SECURITY.md`. For v1.1 add optional Unix-domain-socket listener + SO_PEERCRED uid match. |
| G3 | **No OAuth/OIDC** (only API key / bearer / basic / session). | agent-vault handles GitHub OAuth. Truefoundry / Doppler position around OAuth for MCP. | Add `auth = "oauth_client_credentials"` and `auth = "oauth_refresh"` patterns. Significant scope; defer to v1.2. |
| G4 | **No prompt-injection detector on responses.** Upstream returns are forwarded verbatim back through the MCP server to the LLM. | wirken: prompt-injection detection on inbound LLM-bound text. | Out of scope OR add an opt-in `sanitize_responses` flag using the same `sanitize_output` helper used in `/browser/rotate`. |
| G5 | **No published GHCR image yet** (README says "uncomment once CI has published"). | All competitors ship pre-built containers. | Tag v1.0.3, let `docker-publish.yml` run, then update README to switch from `build: .` to the published image. **Block release on this.** |
| G6 | **No `cargo install vaultproxy` workflow documented.** | `cargo install` is idiomatic Rust. | Add `cargo install vaultproxy` to README quickstart; verify `crates.io` publish works (currently the crate is on crates.io per `Cargo.toml` — confirm). |

### 4.2 Mid-priority gaps (would strengthen v1.0 messaging)

| # | Gap | Recommendation |
|---|---|---|
| G7 | **No K8s deploy reference** (helm chart, secret CRD, sidecar injector). agent-vault, secretless, vault-k8s all ship k8s manifests. | Add a `deploy/k8s/` sample with sidecar pattern. Optional — homelab-first audience may not need. |
| G8 | **No client SDK other than Connecterr-internal TS.** Brokering on `/proxy` requires every consumer to roll its own HTTP client. | Publish a tiny `vaultproxy-client` crate + Python pip package + npm `@vaultproxy/client` wrapping `POST /proxy` with caller-id auto-injection. |
| G9 | **No examples folder** for the "smart MCP server" pattern. README says `VAULT_PROXY_URL` is the detection mechanism but there is no minimal example MCP server to clone. | Add `examples/smart-mcp-server/` with a 50-line Python or TS MCP server that calls `/proxy`. |
| G10 | **Browser rotation depends on local LiteLLM + vision model.** Sets a high bar. | Stub out a `mock` rotation strategy for tutorials; document a `gpt-4o`-via-OpenAI path for users without MLbox. |
| G11 | **Audit log is JSON file only** (no syslog, no stdout option, no SIEM push). wirken has Datadog/Splunk/Sentinel/OTLP. | Add `--audit-sink=stdout` and `--audit-sink=syslog`; OTLP is v1.2 material. |
| G12 | **Credential audit scan caps at 1000 items.** Operators with >1000 vault items need to split folders — friction. | Pagination or chunked async scan in v1.1. |
| G13 | **No generic API rotation for *arr-style services.** `POST /rotate` returns a typed `unsupported` result for them (they need config-file access, not an API call). Working strategies today: browser-vision (experimental) and UniFi key-bootstrap. | Ship more first-class rotation strategies over time; keep generic *arr API rotation out of scope until a workable path exists. |
| G14 | **No multi-tenant story.** Single Vaultwarden folder per process. | Document a "one container per agent" pattern. Don't expand scope. |
| G15 | **No Windows binary** in releases (Cargo builds, but no published artefact). wirken ships Win11 binaries. | Add Windows job to CI matrix; low effort. |

### 4.3 Lower-priority / cosmetic

| # | Gap | Recommendation |
|---|---|---|
| G16 | README is 700 lines and front-loads operational detail. New users hit "Quickstart" only after wall of auth/security text. | Reshape README: top-of-fold = 5-line elevator pitch + a 3-step quickstart with the GHCR image. Move security/threat model to `SECURITY.md` and runbook to `docs/RUNBOOK.md`. |
| G17 | No demo GIF / screencast / asciinema. agent-vault has one. | Record 60s asciinema of `--setup` → `/proxy` call → `/vault/audit/run`. |
| G18 | No "comparison table" in README. Users will ask "why not warden-mcp / agent-vault / OneCLI." | Lift this gap-analysis table 2 into README. |
| G19 | No badges (build status, crates.io version, MSRV). | Add shields.io badges. |
| G20 | `CHANGELOG.md` + `CHANGELOG-pre-1.0.md` split is unusual; many AI-tool users won't notice the pre-1.0 file. | Either merge them with a section header or link prominently from the top. |
| G21 | Bin names are inconsistent (`mcp-bearer-bridge`, `mcp-rpc-bridge`, `vaultproxy-mount-helper`). | Decide on one prefix (`vaultproxy-bearer-bridge`, …) before v1.1; rename now while users are few. |

---

## 5. Differentiation pitch (suggested launch copy)

> `vaultproxy` is the credential broker for self-hosted MCP setups. Unlike agent-vault, wirken, or OneCLI — which assume Infisical, their own vault, or HashiCorp Vault — `vaultproxy` plugs straight into the Vaultwarden you're already running. It speaks every weird homelab auth pattern (API key, Bearer, Basic, session-cookie, UniFi dual-mode, query-param), hot-reloads its config on SIGHUP, optionally binds the keystore to your TPM, and — uniquely — ships an experimental (off-by-default) Playwright/vision-LLM agent that can rotate some weak credentials on the upstream site, not just flag them.

---

## 6. Recommended pre-release punch list

Order of operations before posting to /r/selfhosted, /r/homelab, Hacker News, MCP community:

1. **G5** — tag v1.0.3, let GHCR publish run, switch README to `image:` line. Hard blocker.
2. **G13** — `/rotate` now returns a typed `unsupported` for generic *arr services; keep public docs honest that working strategies today are browser-vision (experimental) + UniFi key-bootstrap.
3. **G16** — restructure README. First impression matters most for AI-community discoverability.
4. **G17** — record asciinema demo.
5. **G18** — add comparison table from §2 of this doc.
6. **G9** — add `examples/smart-mcp-server/` minimal client.
7. **G6/G15** — confirm `cargo install` path and add Windows CI artefact.
8. **G8** — publish thin client SDK in at least one of Python/TypeScript.

Items G1–G4 (transparent-proxy, mTLS, OAuth, response sanitisation) are roadmap items for v1.1+; document the gap honestly rather than blocking v1.0.

---

## Sources

- [Infisical/agent-vault](https://github.com/Infisical/agent-vault)
- [gebruder/wirken](https://github.com/gebruder/wirken)
- [OneCLI launch writeup](https://sesamedisk.com/onecli-vault-ai-agents-rust/)
- [cyberark/secretless-broker](https://github.com/cyberark/secretless-broker)
- [bitwarden/mcp-server](https://github.com/bitwarden/mcp-server)
- [icoretech/warden-mcp](https://github.com/icoretech/warden-mcp)
- [rccyx/vault-mcp (archived)](https://github.com/rccyx/vault-mcp)
- [amirshk/mcp-secrets-plugin](https://github.com/amirshk/mcp-secrets-plugin)
- [ai-mcp-garage/mcp-secrets](https://github.com/ai-mcp-garage/mcp-secrets)
- [hashicorp/vault-k8s (sidecar injector)](https://github.com/hashicorp/vault-k8s)
- [microsoft/playwright-mcp issue #922 — placeholder resolution](https://github.com/microsoft/playwright-mcp/issues/922)
- [Doppler — MCP credential security best practices](https://www.doppler.com/blog/mcp-server-credential-security-best-practices)
- [TrueFoundry — OAuth 2.0 for MCP](https://www.truefoundry.com/blog/oauth-mcp-enterprise-token-management)
