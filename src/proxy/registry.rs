//! Service auth registry — maps service names to their auth patterns and base URLs.
//!
//! Public API: [`ServiceRegistry::from_toml_file`] — reads user-defined services.toml.
//! Internal legacy: [`ServiceRegistry::from_config`] / [`ServiceRegistry::from_vault`] —
//! used by the /vault/connecterr-secrets HTTP handlers only. Contains homelab-specific
//! service type mappings and should not be extended.

use std::collections::HashMap;
use std::path::Path;

// -------------------------------------------------------------------------- //
// services.toml deserialization types                                          //
// -------------------------------------------------------------------------- //

#[derive(serde::Deserialize)]
struct ServicesFile {
    #[serde(default)]
    service: Vec<ServiceConfig>,
}

#[derive(serde::Deserialize)]
struct ServiceConfig {
    name: String,
    base_url: String,
    auth: String,
    vault_item: String,
    // auth-type-specific fields
    header_name: Option<String>,
    param_name: Option<String>,
    key_field: Option<String>,
    secret_field: Option<String>,
    login_path: Option<String>,
    token_field: Option<String>,
    #[serde(default = "default_true")]
    login_include_username: bool,
    #[serde(default)]
    insecure_tls: bool,
    /// Optional path to a PEM-encoded CA certificate bundle to use when
    /// connecting to this service. Intended for services signed by a private
    /// / internal CA where `insecure_tls = true` is too broad. If both
    /// `ca_cert` and `insecure_tls` are set, `insecure_tls` wins (no cert
    /// verification at all). A missing or unreadable file is a startup error
    /// for the affected service (the service is skipped with an error log).
    ca_cert: Option<String>,
}

fn default_true() -> bool {
    true
}

// -------------------------------------------------------------------------- //
// AuthPattern                                                                  //
// -------------------------------------------------------------------------- //

/// Describes how a downstream service authenticates requests.
#[derive(Debug, Clone)]
pub enum AuthPattern {
    /// Inject a static token into a named request header.
    /// e.g. `X-Api-Key`, `X-Plex-Token`
    Header {
        header_name: String,
        vault_item: String,
    },

    /// Append a credential as a URL query parameter.
    /// e.g. Tautulli's `?apikey=xxx`
    QueryParam {
        param_name: String,
        vault_item: String,
    },

    /// `Authorization: Bearer <token>` header.
    /// e.g. Home Assistant long-lived access token.
    Bearer { vault_item: String },

    /// HTTP Basic authentication derived from two custom vault fields.
    /// e.g. OPNsense API key + secret.
    Basic {
        vault_item: String,
        key_field: String,
        secret_field: String,
    },

    /// Session-based login: first POST credentials to `login_path`, extract a
    /// token from the JSON response field `token_field`, then attach it as a
    /// `Bearer` header (or service-specific header) on the real request.
    ///
    /// When `login_include_username` is `false`, the login body contains only the
    /// password field (no username). Configure this in `services.toml` for services
    /// like Duplicati whose login API does not accept a username field.
    Session {
        vault_item: String,
        login_path: String,
        token_field: String,
        login_include_username: bool,
    },

    /// UniFi dual auth: try `X-API-Key` from `vault_item.password`, and on
    /// auth failure fall back to POST `login_path` with
    /// `{"username","password","remember":true}` using the same vault item.
    /// Session cookies + CSRF are managed by the `unifi_session` module.
    UnifiDual {
        vault_item: String,
        login_path: String,
    },
}

// -------------------------------------------------------------------------- //
// ServiceEntry                                                                 //
// -------------------------------------------------------------------------- //

/// A registered downstream service.
#[derive(Debug, Clone)]
pub struct ServiceEntry {
    /// Logical name used as the lookup key (e.g. "sonarr", "ha/home").
    pub name: String,
    /// Full base URL including any path prefix (e.g. "http://192.0.2.1:8989/api/v3").
    pub base_url: String,
    /// How to authenticate requests to this service.
    pub auth: AuthPattern,
    /// Set when the service presents a self-signed TLS cert (typically
    /// LAN-local appliances like OPNsense, Duplicati-UI-over-HTTPS, etc.).
    /// Dispatched via `state.http_permissive` instead of the strict `state.http`.
    /// iter-29 added this — previously iter-1's TLS-strict `state.http`
    /// silently broke OPNsense (502 "error sending request").
    pub insecure_tls: bool,
    /// Optional path to a PEM CA certificate bundle for this service. When set,
    /// a per-service reqwest client is built that trusts this CA in addition to
    /// the system root store — the correct option for internal-CA-signed services
    /// where `insecure_tls = true` would disable all TLS verification.
    pub ca_cert_path: Option<String>,
}

// -------------------------------------------------------------------------- //
// ServiceRegistry                                                              //
// -------------------------------------------------------------------------- //

/// In-memory registry of all downstream services vault-proxy knows how to
/// authenticate.
pub struct ServiceRegistry {
    entries: HashMap<String, ServiceEntry>,
}

impl ServiceRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Register a service entry.
    ///
    /// If a service with the same name is already registered, the new entry
    /// overwrites it (last-write-wins) and a warning is emitted.  This is
    /// intentional for dynamic re-registration from vault data, but operators
    /// should not have duplicate names in `services.toml` — the warning makes
    /// the silent overwrite visible in logs.
    pub fn register(&mut self, entry: ServiceEntry) {
        if let Some(existing) = self.entries.get(&entry.name) {
            tracing::warn!(
                "service '{}': duplicate registration — '{}' will be overwritten by '{}'",
                entry.name,
                existing.base_url,
                entry.base_url,
            );
        }
        self.entries.insert(entry.name.clone(), entry);
    }

    /// Look up a service by name.
    pub fn get(&self, name: &str) -> Option<&ServiceEntry> {
        self.entries.get(name)
    }

    /// List all registered service names.
    pub fn list(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.entries.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }

    // ---------------------------------------------------------------------- //
    // Config-driven construction                                               //
    // ---------------------------------------------------------------------- //

    /// Internal legacy path — used only by the /vault/connecterr-secrets HTTP handlers.
    /// Public users register services via services.toml and from_toml_file().
    /// DO NOT add new service-specific logic here.
    ///
    /// Reads `modules.media.services`, `modules.ha.instances`,
    /// `modules.opnsense.instances`, `modules.npm.instances`, and
    /// `modules.duplicati.instances`.
    #[doc(hidden)]
    pub fn from_config(config: &serde_json::Value) -> Self {
        let mut registry = Self::new();

        let modules = match config.get("modules") {
            Some(m) => m,
            None => return registry,
        };

        // ---- media services ------------------------------------------------
        if let Some(services) = modules
            .get("media")
            .and_then(|m| m.get("services"))
            .and_then(|s| s.as_array())
        {
            for svc in services {
                let name = match svc.get("name").and_then(|v| v.as_str()) {
                    Some(n) => n.to_string(),
                    None => continue,
                };
                let svc_type = svc.get("type").and_then(|v| v.as_str()).unwrap_or(&name).to_string();
                let svc_type = svc_type.as_str();
                let url = match svc.get("url").and_then(|v| v.as_str()) {
                    Some(u) => u.trim_end_matches('/').to_string(),
                    None => continue,
                };

                let entry = build_media_entry(name, svc_type, url, "Connecterr");
                if let Some(e) = entry {
                    registry.register(e);
                }
            }
        }

        // ---- Home Assistant ------------------------------------------------
        if let Some(instances) = modules
            .get("ha")
            .and_then(|m| m.get("instances"))
            .and_then(|i| i.as_array())
        {
            for inst in instances {
                let inst_name = inst.get("name").and_then(|v| v.as_str()).unwrap_or("main");
                let url = match inst.get("url").and_then(|v| v.as_str()) {
                    Some(u) => u.trim_end_matches('/').to_string(),
                    None => continue,
                };

                registry.register(ServiceEntry {
                    name: format!("ha_{}", inst_name),
                    base_url: url,
                    auth: AuthPattern::Bearer {
                        vault_item: "Connecterr - Home Assistant".to_string(),
                    },
                    insecure_tls: false,
                    ca_cert_path: None,
                });
            }
        }

        // ---- OPNsense -------------------------------------------------------
        if let Some(instances) = modules
            .get("opnsense")
            .and_then(|m| m.get("instances"))
            .and_then(|i| i.as_array())
        {
            for inst in instances {
                let inst_name = inst.get("name").and_then(|v| v.as_str()).unwrap_or("main");
                let url = match inst.get("url").and_then(|v| v.as_str()) {
                    Some(u) => u.trim_end_matches('/').to_string(),
                    None => continue,
                };

                registry.register(ServiceEntry {
                    name: format!("opnsense_{}", inst_name),
                    base_url: format!("{}/api", url),
                    auth: AuthPattern::Basic {
                        vault_item: "Connecterr - OPNsense".to_string(),
                        key_field: "key".to_string(),
                        secret_field: "secret".to_string(),
                    },
                    insecure_tls: true,
                    ca_cert_path: None,
                });
            }
        }

        // ---- Nginx Proxy Manager -------------------------------------------
        if let Some(instances) = modules
            .get("npm")
            .and_then(|m| m.get("instances"))
            .and_then(|i| i.as_array())
        {
            for inst in instances {
                let inst_name = inst.get("name").and_then(|v| v.as_str()).unwrap_or("main");
                let url = match inst.get("url").and_then(|v| v.as_str()) {
                    Some(u) => u.trim_end_matches('/').to_string(),
                    None => continue,
                };

                registry.register(ServiceEntry {
                    name: format!("npm_{}", inst_name),
                    base_url: format!("{}/api", url),
                    auth: AuthPattern::Session {
                        vault_item: "Connecterr - Nginx Proxy Manager".to_string(),
                        login_path: "/tokens".to_string(),
                        token_field: "token".to_string(),
                        login_include_username: true,
                    },
                    insecure_tls: false,
                    ca_cert_path: None,
                });
            }
        }

        // ---- UniFi controllers ------------------------------------------------
        if let Some(controllers) = modules
            .get("unifi")
            .and_then(|m| m.get("controllers"))
            .and_then(|c| c.as_array())
        {
            for ctrl in controllers {
                let ctrl_name = ctrl.get("name").and_then(|v| v.as_str()).unwrap_or("main");
                let url = match ctrl.get("url").and_then(|v| v.as_str()) {
                    Some(u) => u.trim_end_matches('/').to_string(),
                    None => continue,
                };

                // UDM/UDR controllers use /proxy/network as the API base path
                registry.register(ServiceEntry {
                    name: format!("unifi_{}", ctrl_name),
                    base_url: format!("{}/proxy/network", url),
                    auth: AuthPattern::UnifiDual {
                        vault_item: "Connecterr - UniFi".to_string(),
                        login_path: "/api/auth/login".to_string(),
                    },
                    insecure_tls: false,
                    ca_cert_path: None,
                });
            }
        }

        // ---- Duplicati ------------------------------------------------------
        if let Some(instances) = modules
            .get("duplicati")
            .and_then(|m| m.get("instances"))
            .and_then(|i| i.as_array())
        {
            for inst in instances {
                let inst_name = inst.get("name").and_then(|v| v.as_str()).unwrap_or("main");
                let url = match inst.get("url").and_then(|v| v.as_str()) {
                    Some(u) => u.trim_end_matches('/').to_string(),
                    None => continue,
                };

                registry.register(ServiceEntry {
                    name: format!("duplicati_{}", inst_name),
                    base_url: format!("{}/api/v1", url),
                    auth: AuthPattern::Session {
                        vault_item: "Duplicati UI".to_string(),
                        login_path: "/auth/login".to_string(),
                        token_field: "AccessToken".to_string(),
                        login_include_username: false,
                    },
                    insecure_tls: false,
                    ca_cert_path: None,
                });
            }
        }

        registry
    }

    // ---------------------------------------------------------------------- //
    // Vault-driven construction                                                //
    // ---------------------------------------------------------------------- //

    /// Internal legacy path — used only by the /vault/connecterr-secrets HTTP handlers.
    /// Public users register services via services.toml and from_toml_file().
    /// DO NOT add new service-specific logic here.
    ///
    /// Build a `ServiceRegistry` from the aggregated JSON served by
    /// `GET /vault/connecterr-secrets`.
    ///
    /// The expected shape mirrors the TS-side `ConnecterrSecrets` schema:
    /// ```json
    /// {
    ///   "ha":        { "<instance>": { "url": "..." }, ... },
    ///   "opnsense":  { "<instance>": { "url": "..." }, ... },
    ///   "npm":       { "<instance>": { "url": "..." }, ... },
    ///   "unifi":     { "<instance>": { "url": "...", "site": "..." }, ... },
    ///   "duplicati": { "<instance>": { "url": "..." }, ... },
    ///   "media":     { "<name>": { "type": "<type>", "url": "..." }, ... }
    /// }
    /// ```
    ///
    /// Keys `ssh`, `docker`, `vaultwarden`, and `apiKey` are silently ignored —
    /// they don't need proxy-side registrations.
    #[doc(hidden)]
    pub fn from_vault(aggregated: &serde_json::Value, vault_prefix: &str) -> Self {
        let mut registry = Self::new();

        let obj = match aggregated.as_object() {
            Some(o) => o,
            None => return registry,
        };

        // ---- Home Assistant ------------------------------------------------
        if let Some(instances) = obj.get("ha").and_then(|v| v.as_object()) {
            for (inst_name, inst) in instances {
                let url = match inst.get("url").and_then(|v| v.as_str()) {
                    Some(u) => u.trim_end_matches('/').to_string(),
                    None => continue,
                };
                registry.register(ServiceEntry {
                    name: format!("ha_{}", inst_name),
                    base_url: url,
                    auth: AuthPattern::Bearer {
                        vault_item: format!("{} - Home Assistant", vault_prefix),
                    },
                    insecure_tls: false,
                    ca_cert_path: None,
                });
            }
        }

        // ---- OPNsense -------------------------------------------------------
        if let Some(instances) = obj.get("opnsense").and_then(|v| v.as_object()) {
            for (inst_name, inst) in instances {
                let url = match inst.get("url").and_then(|v| v.as_str()) {
                    Some(u) => u.trim_end_matches('/').to_string(),
                    None => continue,
                };
                registry.register(ServiceEntry {
                    name: format!("opnsense_{}", inst_name),
                    base_url: format!("{}/api", url),
                    auth: AuthPattern::Basic {
                        vault_item: format!("{} - OPNsense", vault_prefix),
                        key_field: "key".to_string(),
                        secret_field: "secret".to_string(),
                    },
                    insecure_tls: true,
                    ca_cert_path: None,
                });
            }
        }

        // ---- Nginx Proxy Manager -------------------------------------------
        if let Some(instances) = obj.get("npm").and_then(|v| v.as_object()) {
            for (inst_name, inst) in instances {
                let url = match inst.get("url").and_then(|v| v.as_str()) {
                    Some(u) => u.trim_end_matches('/').to_string(),
                    None => continue,
                };
                registry.register(ServiceEntry {
                    name: format!("npm_{}", inst_name),
                    base_url: format!("{}/api", url),
                    auth: AuthPattern::Session {
                        vault_item: format!("{} - Nginx Proxy Manager", vault_prefix),
                        login_path: "/tokens".to_string(),
                        token_field: "token".to_string(),
                        login_include_username: true,
                    },
                    insecure_tls: false,
                    ca_cert_path: None,
                });
            }
        }

        // ---- UniFi controllers ------------------------------------------------
        if let Some(instances) = obj.get("unifi").and_then(|v| v.as_object()) {
            for (ctrl_name, ctrl) in instances {
                let url = match ctrl.get("url").and_then(|v| v.as_str()) {
                    Some(u) => u.trim_end_matches('/').to_string(),
                    None => continue,
                };
                registry.register(ServiceEntry {
                    name: format!("unifi_{}", ctrl_name),
                    base_url: format!("{}/proxy/network", url),
                    auth: AuthPattern::UnifiDual {
                        vault_item: format!("{} - UniFi", vault_prefix),
                        login_path: "/api/auth/login".to_string(),
                    },
                    insecure_tls: false,
                    ca_cert_path: None,
                });
            }
        }

        // ---- Duplicati ------------------------------------------------------
        if let Some(instances) = obj.get("duplicati").and_then(|v| v.as_object()) {
            for (inst_name, inst) in instances {
                let url = match inst.get("url").and_then(|v| v.as_str()) {
                    Some(u) => u.trim_end_matches('/').to_string(),
                    None => continue,
                };
                registry.register(ServiceEntry {
                    name: format!("duplicati_{}", inst_name),
                    base_url: format!("{}/api/v1", url),
                    auth: AuthPattern::Session {
                        vault_item: "Duplicati UI".to_string(),
                        login_path: "/auth/login".to_string(),
                        token_field: "AccessToken".to_string(),
                        login_include_username: false,
                    },
                    insecure_tls: false,
                    ca_cert_path: None,
                });
            }
        }

        // ---- media services ------------------------------------------------
        if let Some(services) = obj.get("media").and_then(|v| v.as_object()) {
            for (svc_name, svc) in services {
                let svc_type = svc
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or(svc_name.as_str())
                    .to_string();
                let url = match svc.get("url").and_then(|v| v.as_str()) {
                    Some(u) => u.trim_end_matches('/').to_string(),
                    None => continue,
                };
                if let Some(entry) = build_media_entry(svc_name.clone(), &svc_type, url, vault_prefix) {
                    registry.register(entry);
                }
            }
        }

        registry
    }

    // ---------------------------------------------------------------------- //
    // TOML-file-driven construction                                            //
    // ---------------------------------------------------------------------- //

    /// Build a `ServiceRegistry` from a `services.toml` file in `--config-dir`.
    ///
    /// # Hot-reload: NOT supported
    ///
    /// Issue (iter-17): `services.toml` is read **once at startup** and is NOT
    /// watched for changes.  If an operator adds, removes, or modifies a
    /// `[[service]]` block at runtime, the change will not take effect until the
    /// vault-proxy process is restarted.  Calling `POST /vault/resync` does NOT
    /// reload `services.toml` — it only re-fetches vault *items* (credentials)
    /// from Vaultwarden.  The startup log and `/vault/resync` response body both
    /// explicitly state this to avoid operator confusion.
    ///
    /// # Shared vault_item across services
    ///
    /// Issue (iter-17): Two `[[service]]` entries may share the same `vault_item`
    /// value (e.g. two UniFi controllers pointing at `vault-proxy - UniFi`).
    /// This is **valid and intentional** — both services read the same single
    /// credential.  There is no deduplication or conflict: each service entry is
    /// stored independently; the shared vault_item string is simply a lookup key
    /// that resolves to the same vault credential at request time.  The
    /// `test_credential` handler also accepts a vault_item ID (not a service
    /// name), so testing one service's vault item implicitly tests all services
    /// that share it.  Document this in your services.toml with a comment if the
    /// sharing is intentional.
    ///
    /// A missing file returns an empty registry with a warning (not an error).
    /// This is **intentionally different** from `launcher::launch()`, which
    /// returns a hard error when `mcp-servers.toml` is missing:
    ///
    /// - `services.toml` is *optional* — the proxy can serve vault/health and
    ///   the dashboard even without any registered downstream services. An
    ///   operator who only uses `--launch` mode never creates this file.
    /// - `mcp-servers.toml` is *required* for the `--launch` flag, so a
    ///   missing file is always a configuration error that must stop the process.
    ///
    /// Parse errors also return an empty registry with an error log, giving
    /// operators a chance to fix the TOML without taking down an already-running
    /// proxy (e.g. during a hot-reload). Both cases emit a visible log entry.
    ///
    /// # Service count limit
    ///
    /// There is no hard upper bound on the number of `[[service]]` entries.
    /// Each entry becomes one `HashMap` entry in the registry and one vault
    /// item lookup at credential-use time (not at startup). A very large file
    /// (e.g. 10 000 services) imposes no startup cost beyond parsing, but
    /// would make the `service_tokens` cache unbounded and log output very
    /// noisy. A warning is emitted above 256 services as an operator hint.
    ///
    /// TODO: Consider adding a hard cap (e.g. 1024) guarded by an override env
    /// var for operators who genuinely need large registries.
    pub fn from_toml_file(path: &Path) -> Self {
        let mut registry = Self::new();

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                // Issue (iter-21): Distinguish "file does not exist" (first-run)
                // from other I/O errors (permissions, corrupted FS) so operators
                // get an actionable message in each case.
                //
                // First-run: services.toml has not yet been created. The operator
                // needs to copy services.example.toml from the repo into the config
                // directory before any /proxy calls will work. The Docker Compose
                // mount is `./config:/config`, so the destination is /config/services.toml.
                //
                // Other error: the file exists but can't be read — permission or FS
                // issue that needs operator attention before services will work.
                if e.kind() == std::io::ErrorKind::NotFound {
                    tracing::warn!(
                        "services.toml not found at {:?} — starting with empty registry. \
                         First run? Copy services.example.toml to {:?} and add [[service]] \
                         blocks for each downstream API you want vault-proxy to proxy. \
                         In Docker Compose the config mount is ./config:/config, so the \
                         file belongs at ./config/services.toml on the host.",
                        path, path
                    );
                } else {
                    tracing::warn!(
                        "could not read services.toml at {:?}: {} — starting with empty registry. \
                         Check file permissions (needs read access for the vault-proxy user).",
                        path, e
                    );
                }
                return registry;
            }
        };

        let parsed: ServicesFile = match toml::from_str(&content) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("failed to parse services.toml: {}", e);
                return registry;
            }
        };

        for mut svc in parsed.service {
            // Issue (iter-14): Trim leading/trailing whitespace from the service
            // name and vault_item at load time.  A TOML entry like
            //   name = "  ha_home  "
            // would register under the key "  ha_home  " (with spaces), but
            // callers always send {"service": "ha_home"} (without spaces),
            // making the service silently unreachable.  The same applies to
            // vault_item: "  vault-proxy - HA  " would never match the Vaultwarden
            // item name, causing every credential lookup to return "not found".
            //
            // We trim here (before any other validation) so that the subsequent
            // empty-name / all-whitespace checks correctly reject a name that
            // becomes empty after trimming.
            let trimmed_name = svc.name.trim().to_string();
            if trimmed_name != svc.name {
                tracing::warn!(
                    "services.toml: service name '{}' has leading/trailing whitespace — \
                     trimmed to '{}'. Update the config to remove the spaces.",
                    svc.name, trimmed_name
                );
            }
            svc.name = trimmed_name;

            let trimmed_vault_item = svc.vault_item.trim().to_string();
            if trimmed_vault_item != svc.vault_item {
                tracing::warn!(
                    "services.toml: vault_item '{}' for service '{}' has leading/trailing \
                     whitespace — trimmed to '{}'. Update the config to remove the spaces.",
                    svc.vault_item, svc.name, trimmed_vault_item
                );
            }
            svc.vault_item = trimmed_vault_item;

            // Issue-1 (iter-4): Validate service name. An empty name would
            // register a "" key in the lookup map, making `/proxy` calls with
            // `service = ""` reach a real service. Names with null bytes, path
            // separators, or only whitespace are rejected to keep routing and
            // logging unambiguous.
            if svc.name.is_empty() {
                tracing::error!("services.toml: skipping service with empty name");
                continue;
            }
            if svc.name.contains('\0') {
                tracing::error!(
                    "services.toml: service name '{}' contains null byte — skipping",
                    svc.name
                );
                continue;
            }
            if svc.name.chars().all(|c| c.is_whitespace()) {
                tracing::error!(
                    "services.toml: service name '{}' is all-whitespace — skipping",
                    svc.name
                );
                continue;
            }

            // Issue (iter-10): Reject service names that contain ASCII control
            // characters (U+0001..U+001F and U+007F, including tab \t, newline
            // \n, and carriage return \r). These characters:
            //
            //   1. Log injection: a name like "foo\nERROR: vault unlocked"
            //      injects fake log lines into structured text logs, which can
            //      confuse log-aggregation pipelines (Loki, Splunk, CloudWatch)
            //      and trigger false alerts.
            //
            //   2. HTTP header injection: if the service name appears in a
            //      response header or audit entry that is forwarded as an HTTP
            //      header, CRLF injection (\r\n) can split the response and
            //      inject arbitrary headers.
            //
            // Unicode multi-byte names (CJK, Arabic, etc.) are intentionally
            // ALLOWED because they have no security impact and blocking them
            // would exclude valid non-ASCII service names. The null-byte check
            // above already covers the most dangerous single-byte case.
            if svc.name.chars().any(|c| (c as u32) < 0x20 || c == '\x7f') {
                tracing::error!(
                    "services.toml: service name contains ASCII control character (tab, newline, etc.) — skipping"
                );
                continue;
            }

            // Issue-7 (iter-5): Validate vault_item name.
            //
            // The vault_item string is used as an exact-match key against the
            // in-memory vault cache (linear scan by decrypted item name — no
            // HTTP search call is made, so there is no search-API injection
            // risk). However, a null-byte or empty vault_item would cause every
            // `decrypt_password` / `decrypt_field` call for this service to
            // return "item not found" at runtime, which is confusing to diagnose
            // from logs. Rejecting them here gives an immediate, actionable error
            // at startup rather than a mysterious 502 on first proxy call.
            if svc.vault_item.is_empty() {
                tracing::error!(
                    "service '{}': vault_item is empty — every credential lookup will fail. \
                     Set vault_item to the exact Vaultwarden item name (e.g. \
                     'vault-proxy - Home Assistant'). Skipping.",
                    svc.name
                );
                continue;
            }
            if svc.vault_item.contains('\0') {
                tracing::error!(
                    "service '{}': vault_item '{}' contains a null byte — \
                     this is never a valid Vaultwarden item name. Skipping.",
                    svc.name, svc.vault_item
                );
                continue;
            }

            let base_url = svc.base_url.trim_end_matches('/').to_string();

            // Issue (iter-13): Emit a specific diagnostic for scheme-less base_url values
            // before the general SSRF check.  `url::Url::parse("host:port")` succeeds
            // but treats "host" as the scheme — so `is_allowed_outbound_url` rejects it
            // with a generic "not allowed" message that gives no hint the problem is a
            // missing "http://" or "https://" prefix (e.g. "homeassistant.local:8123").
            // Catching this case first emits a targeted, actionable error.
            {
                let looks_schemeless = !base_url.starts_with("http://")
                    && !base_url.starts_with("https://");
                if looks_schemeless {
                    // Still run the full SSRF check to catch edge cases, but
                    // the error message below already covers this branch.
                    tracing::error!(
                        "service '{}': base_url '{}' has no http/https scheme — \
                         did you mean 'http://{}' or 'https://{}'? Skipping.",
                        svc.name, base_url, base_url, base_url
                    );
                    continue;
                }
            }

            // Validate base_url against SSRF policy. This prevents a
            // compromised/tricked services.toml from pointing the proxy at
            // cloud-metadata endpoints (169.254.169.254, fd00:ec2::254, etc.)
            // or link-local addresses. The check mirrors the one used by
            // `inject_creds` and `browser_rotate` in vault/handlers.rs.
            if !crate::vault::handlers::is_allowed_outbound_url(&base_url) {
                tracing::error!(
                    "service '{}': base_url '{}' is not allowed — \
                     must be http/https with a non-loopback, non-link-local, \
                     non-cloud-metadata host. Skipping.",
                    svc.name, base_url
                );
                continue;
            }

            let auth = match svc.auth.as_str() {
                "bearer" => AuthPattern::Bearer {
                    vault_item: svc.vault_item,
                },
                "header" => {
                    let header_name = match svc.header_name {
                        Some(h) => h,
                        None => {
                            tracing::warn!("service '{}': auth=header requires header_name — skipping", svc.name);
                            continue;
                        }
                    };
                    AuthPattern::Header {
                        header_name,
                        vault_item: svc.vault_item,
                    }
                }
                "query_param" => {
                    let param_name = match svc.param_name {
                        Some(p) => p,
                        None => {
                            tracing::warn!("service '{}': auth=query_param requires param_name — skipping", svc.name);
                            continue;
                        }
                    };
                    AuthPattern::QueryParam {
                        param_name,
                        vault_item: svc.vault_item,
                    }
                }
                "basic" => {
                    let key_field = match svc.key_field {
                        Some(k) => k,
                        None => {
                            tracing::warn!("service '{}': auth=basic requires key_field — skipping", svc.name);
                            continue;
                        }
                    };
                    let secret_field = match svc.secret_field {
                        Some(s) => s,
                        None => {
                            tracing::warn!("service '{}': auth=basic requires secret_field — skipping", svc.name);
                            continue;
                        }
                    };
                    AuthPattern::Basic {
                        vault_item: svc.vault_item,
                        key_field,
                        secret_field,
                    }
                }
                "session" => {
                    let login_path = match svc.login_path {
                        Some(p) => p,
                        None => {
                            tracing::warn!("service '{}': auth=session requires login_path — skipping", svc.name);
                            continue;
                        }
                    };
                    // Issue (iter-8): Reject empty login_path. An empty string
                    // passes the Option check above but would construct a login
                    // URL of just `base_url` (e.g. "http://host/api") — the
                    // login POST hits the API root, not the login endpoint.
                    if login_path.is_empty() {
                        tracing::error!(
                            "service '{}': login_path is empty — skipping. \
                             Set login_path to the login endpoint path (e.g. login_path = \"/tokens\")",
                            svc.name
                        );
                        continue;
                    }
                    // Reject login_path values that contain path traversal
                    // segments. `login_path` is concatenated with `base_url` to
                    // form the login URL (e.g. "http://host/api" + "/tokens" →
                    // "http://host/api/tokens"). A crafted value like
                    // "/../admin/delete" would cause the login POST to target an
                    // unintended endpoint on the upstream service.
                    if login_path_has_traversal(&login_path) {
                        tracing::error!(
                            "service '{}': login_path '{}' contains path traversal segments — skipping",
                            svc.name, login_path
                        );
                        continue;
                    }
                    let token_field = match svc.token_field {
                        Some(t) => t,
                        None => {
                            tracing::warn!("service '{}': auth=session requires token_field — skipping", svc.name);
                            continue;
                        }
                    };
                    // Issue (iter-8): Reject empty token_field. An empty string
                    // would cause `resp.get("")` to always return None and then
                    // produce "token field '' not found in login response" — a
                    // confusing error that gives no hint the config is missing.
                    if token_field.is_empty() {
                        tracing::error!(
                            "service '{}': token_field is empty — skipping. \
                             Set token_field to the JSON key in the login response (e.g. token_field = \"token\")",
                            svc.name
                        );
                        continue;
                    }
                    AuthPattern::Session {
                        vault_item: svc.vault_item,
                        login_path,
                        token_field,
                        login_include_username: svc.login_include_username,
                    }
                }
                "unifi_dual" => {
                    let login_path = match svc.login_path {
                        Some(p) => p,
                        None => {
                            tracing::warn!("service '{}': auth=unifi_dual requires login_path — skipping", svc.name);
                            continue;
                        }
                    };
                    // Same traversal check as session auth above.
                    if login_path_has_traversal(&login_path) {
                        tracing::error!(
                            "service '{}': login_path '{}' contains path traversal segments — skipping",
                            svc.name, login_path
                        );
                        continue;
                    }
                    AuthPattern::UnifiDual {
                        vault_item: svc.vault_item,
                        login_path,
                    }
                }
                other => {
                    tracing::warn!("service '{}': unknown auth type '{}' — skipping", svc.name, other);
                    continue;
                }
            };

            // Issue (iter-15 + iter-16 fix): Validate ca_cert at startup.
            //
            // iter-15: reject missing / unreadable file at startup rather than
            // at first proxy call (which may be hours later in production).
            //
            // iter-16 fix: the iter-15 check called `std::fs::read()` only to
            // confirm the file existed, but did NOT parse the PEM content. A
            // file that exists but contains garbage (e.g. "not a cert", or a
            // DER-encoded cert instead of PEM) would pass the load-time check
            // and fail at first request time with a cryptic reqwest TLS error.
            // We now parse it with `reqwest::Certificate::from_pem()` at load
            // time to surface malformed PEM early with a clear error message.
            //
            // We also warn if BOTH ca_cert and insecure_tls are set — in that
            // case insecure_tls wins (disables all verification), making ca_cert
            // pointless; the operator probably meant one or the other.
            let ca_cert_path: Option<String> = match svc.ca_cert {
                Some(ref path) if !path.is_empty() => {
                    if svc.insecure_tls {
                        tracing::warn!(
                            "service '{}': both ca_cert and insecure_tls = true are set. \
                             insecure_tls disables ALL certificate verification, making ca_cert \
                             redundant. Remove ca_cert if you want no verification, or remove \
                             insecure_tls to use the CA cert instead.",
                            svc.name
                        );
                        None // insecure_tls wins; don't store ca_cert_path
                    } else {
                        // Read and parse the PEM at startup so a missing, empty,
                        // or malformed cert file is caught immediately rather
                        // than at first request time.
                        //
                        // Note: `reqwest::Certificate::from_pem` defers real
                        // PEM parsing to when the client is built (rustls path:
                        // the bytes are stored raw and parsed later). We therefore
                        // validate by actually building a test reqwest client with
                        // the certificate — this is the only way to confirm the
                        // PEM is well-formed before the first proxy call.
                        match std::fs::read(path) {
                            Ok(pem_bytes) => {
                                // Validate the PEM content. reqwest's rustls backend
                                // uses a lenient PEM parser that silently skips
                                // unrecognized blocks rather than erroring on
                                // garbage input — `from_pem()` + `build()` both
                                // succeed even for completely invalid files,
                                // silently adding zero root certs. We apply two
                                // checks:
                                //
                                // 1. Structural: require at least one
                                //    "BEGIN CERTIFICATE" header in the file.
                                //    Catches empty files, DER blobs, and random
                                //    text that contains no PEM blocks.
                                //
                                // 2. Build test: actually construct a reqwest
                                //    client to surface encoding errors (e.g.
                                //    truncated DER inside a PEM envelope).
                                let pem_str = String::from_utf8_lossy(&pem_bytes);
                                if !pem_str.contains("BEGIN CERTIFICATE") {
                                    tracing::error!(
                                        "service '{}': ca_cert '{}' contains no PEM certificate \
                                         blocks (no '-----BEGIN CERTIFICATE-----' header found) — \
                                         skipping service. Ensure the file is a PEM-encoded \
                                         certificate, not DER or another format.",
                                        svc.name, path
                                    );
                                    continue;
                                }

                                // Build test — catches DER-inside-PEM encoding errors.
                                let build_ok = reqwest::Certificate::from_pem(&pem_bytes)
                                    .and_then(|cert| {
                                        reqwest::Client::builder()
                                            .add_root_certificate(cert)
                                            .build()
                                    });
                                match build_ok {
                                    Ok(_) => {
                                        tracing::info!(
                                            "service '{}': using custom CA certificate from '{}' \
                                             (PEM validated at load time)",
                                            svc.name, path
                                        );
                                        Some(path.clone())
                                    }
                                    Err(e) => {
                                        tracing::error!(
                                            "service '{}': ca_cert '{}' failed client build test: \
                                             {} — skipping service.",
                                            svc.name, path, e
                                        );
                                        continue;
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::error!(
                                    "service '{}': ca_cert '{}' is not readable: {} — skipping service",
                                    svc.name, path, e
                                );
                                continue;
                            }
                        }
                    }
                }
                _ => None,
            };

            // Issue-3 (iter-5): Warn prominently when a service is registered
            // with insecure_tls = true. Silently accepting invalid certs means
            // the proxy will not detect MITM attacks or certificate substitution
            // on that service — all auth credentials destined for it are at risk.
            // The warning is emitted here (at registry load time) so it appears
            // in container startup logs even if the service is never called.
            // Operators who need this for LAN self-signed certs should understand
            // the tradeoff; operators who copy services.example.toml without
            // reading it should see this warning before anything goes wrong.
            if svc.insecure_tls {
                tracing::warn!(
                    "service '{}': insecure_tls = true — TLS certificate validation is \
                     DISABLED for this service. All credentials forwarded to '{}' are \
                     sent without cert verification. Suitable only for LAN services with \
                     known self-signed certs; never use for internet-facing endpoints.",
                    svc.name, base_url
                );
            }
            registry.register(ServiceEntry {
                name: svc.name,
                base_url,
                auth,
                insecure_tls: svc.insecure_tls,
                ca_cert_path,
            });
        }

        // Warn on unusually large registries. The registry HashMap and the
        // session_tokens cache both scale with the number of services; past
        // 256 entries the operator should verify they haven't accidentally
        // included a generated or duplicated services.toml.
        const SERVICE_COUNT_WARN_THRESHOLD: usize = 256;
        if registry.entries.len() > SERVICE_COUNT_WARN_THRESHOLD {
            tracing::warn!(
                "services.toml registered {} services (threshold {}). \
                 Verify this is intentional — large registries increase memory use and \
                 credential-lookup noise. Consider splitting into multiple vault-proxy instances.",
                registry.entries.len(),
                SERVICE_COUNT_WARN_THRESHOLD,
            );
        }

        registry
    }
}

impl Default for ServiceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------------- //
// Helpers                                                                      //
// -------------------------------------------------------------------------- //

/// Return `true` if `path` contains a `..` or `.` path segment, indicating
/// a traversal attempt. Used to validate `login_path` values from
/// `services.toml` before they are concatenated with a base URL.
///
/// Examples that return `true`: `"/../admin"`, `"/./tokens"`, `"/api/../../secret"`.
/// Examples that return `false`: `"/tokens"`, `"/api/v1/login"`, `"/auth/login"`.
fn login_path_has_traversal(path: &str) -> bool {
    path.split('/').any(|seg| seg == ".." || seg == ".")
}

/// Internal legacy path — used only by the /vault/connecterr-secrets HTTP handlers.
/// Public users register services via services.toml and from_toml_file().
/// DO NOT add new service-specific logic here.
///
/// Map a media service type to a `ServiceEntry`, returning `None` for unknown
/// types.
fn build_media_entry(name: String, svc_type: &str, url: String, vault_prefix: &str) -> Option<ServiceEntry> {
    match svc_type {
        "plex" => Some(ServiceEntry {
            name,
            base_url: url,
            auth: AuthPattern::Header {
                header_name: "X-Plex-Token".to_string(),
                vault_item: format!("{} - Plex", vault_prefix),
            },
            insecure_tls: false,
            ca_cert_path: None,
        }),
        "sonarr" => Some(ServiceEntry {
            name,
            base_url: format!("{}/api/v3", url),
            auth: AuthPattern::Header {
                header_name: "X-Api-Key".to_string(),
                vault_item: format!("{} - Sonarr", vault_prefix),
            },
            insecure_tls: false,
            ca_cert_path: None,
        }),
        "radarr" => Some(ServiceEntry {
            name,
            base_url: format!("{}/api/v3", url),
            auth: AuthPattern::Header {
                header_name: "X-Api-Key".to_string(),
                vault_item: format!("{} - Radarr", vault_prefix),
            },
            insecure_tls: false,
            ca_cert_path: None,
        }),
        "overseerr" => Some(ServiceEntry {
            name,
            base_url: format!("{}/api/v1", url),
            auth: AuthPattern::Header {
                header_name: "X-Api-Key".to_string(),
                vault_item: format!("{} - Overseerr", vault_prefix),
            },
            insecure_tls: false,
            ca_cert_path: None,
        }),
        "tautulli" => Some(ServiceEntry {
            name,
            base_url: format!("{}/api/v2", url),
            auth: AuthPattern::QueryParam {
                param_name: "apikey".to_string(),
                vault_item: format!("{} - Tautulli", vault_prefix),
            },
            insecure_tls: false,
            ca_cert_path: None,
        }),
        _ => {
            tracing::warn!(svc_type, "unknown media service type — skipping");
            None
        }
    }
}

// -------------------------------------------------------------------------- //
// Tests                                                                        //
// -------------------------------------------------------------------------- //

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_config() -> serde_json::Value {
        json!({
            "modules": {
                "media": {
                    "enabled": true,
                    "services": [
                        { "name": "plex",      "type": "plex",      "url": "http://192.0.2.1:32400" },
                        { "name": "sonarr",    "type": "sonarr",    "url": "http://192.0.2.1:8989"  },
                        { "name": "radarr",    "type": "radarr",    "url": "http://192.0.2.1:7878"  },
                        { "name": "overseerr", "type": "overseerr", "url": "http://192.0.2.1:5055"  },
                        { "name": "tautulli",  "type": "tautulli",  "url": "http://192.0.2.1:8181"  }
                    ]
                },
                "unifi":     { "enabled": true, "controllers": [{ "name": "home", "url": "https://192.0.2.2", "site": "default" }] },
                "ha":        { "enabled": true, "instances": [{ "name": "home", "url": "http://192.0.2.3:8123" }] },
                "opnsense":  { "enabled": true, "instances": [{ "name": "main", "url": "https://192.0.2.4" }] },
                "npm":       { "enabled": true, "instances": [{ "name": "main", "url": "http://192.0.2.1:81" }] },
                "duplicati": { "enabled": true, "instances": [{ "name": "main", "url": "http://192.0.2.1:8200" }] }
            }
        })
    }

    #[test]
    fn test_from_config_all_services_registered() {
        let config = sample_config();
        let registry = ServiceRegistry::from_config(&config);
        let names = registry.list();

        for expected in &[
            "plex", "sonarr", "radarr", "overseerr", "tautulli",
            "unifi_home", "ha_home", "opnsense_main", "npm_main", "duplicati_main",
        ] {
            assert!(names.contains(expected), "missing service: {}", expected);
        }
    }

    #[test]
    fn test_sonarr_base_url_has_api_prefix() {
        let registry = ServiceRegistry::from_config(&sample_config());
        let svc = registry.get("sonarr").unwrap();
        assert_eq!(svc.base_url, "http://192.0.2.1:8989/api/v3");
    }

    #[test]
    fn test_tautulli_query_param() {
        let registry = ServiceRegistry::from_config(&sample_config());
        let svc = registry.get("tautulli").unwrap();
        match &svc.auth {
            AuthPattern::QueryParam { param_name, vault_item } => {
                assert_eq!(param_name, "apikey");
                assert_eq!(vault_item, "Connecterr - Tautulli");
            }
            other => panic!("expected QueryParam, got {:?}", other),
        }
    }

    #[test]
    fn test_opnsense_basic_auth() {
        let registry = ServiceRegistry::from_config(&sample_config());
        let svc = registry.get("opnsense_main").unwrap();
        assert!(svc.base_url.ends_with("/api"));
        match &svc.auth {
            AuthPattern::Basic { key_field, secret_field, .. } => {
                assert_eq!(key_field, "key");
                assert_eq!(secret_field, "secret");
            }
            other => panic!("expected Basic, got {:?}", other),
        }
    }

    #[test]
    fn test_unifi_dual_auth() {
        let registry = ServiceRegistry::from_config(&sample_config());
        let svc = registry.get("unifi_home").unwrap();
        assert_eq!(svc.base_url, "https://192.0.2.2/proxy/network");
        match &svc.auth {
            AuthPattern::UnifiDual { vault_item, login_path } => {
                assert_eq!(vault_item, "Connecterr - UniFi");
                assert_eq!(login_path, "/api/auth/login");
            }
            other => panic!("expected UnifiDual, got {:?}", other),
        }
    }

    #[test]
    fn test_npm_session_auth() {
        let registry = ServiceRegistry::from_config(&sample_config());
        let svc = registry.get("npm_main").unwrap();
        match &svc.auth {
            AuthPattern::Session { login_path, token_field, .. } => {
                assert_eq!(login_path, "/tokens");
                assert_eq!(token_field, "token");
            }
            other => panic!("expected Session, got {:?}", other),
        }
    }
}

#[cfg(test)]
mod from_vault_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn from_vault_registers_ha_with_bearer_auth() {
        let blob = json!({
            "ha": { "home": { "url": "http://192.0.2.3:8123" } }
        });
        let reg = ServiceRegistry::from_vault(&blob, "Connecterr");
        let entry = reg.get("ha_home").expect("ha_home should be registered");
        assert_eq!(entry.base_url, "http://192.0.2.3:8123");
        match &entry.auth {
            AuthPattern::Bearer { vault_item } => assert_eq!(vault_item, "Connecterr - Home Assistant"),
            _ => panic!("expected Bearer auth"),
        }
    }

    #[test]
    fn from_vault_registers_opnsense_with_basic_auth_and_api_suffix() {
        let blob = json!({ "opnsense": { "main": { "url": "https://192.0.2.4" } } });
        let reg = ServiceRegistry::from_vault(&blob, "Connecterr");
        let entry = reg.get("opnsense_main").expect("opnsense_main should be registered");
        assert_eq!(entry.base_url, "https://192.0.2.4/api");
        assert!(matches!(entry.auth, AuthPattern::Basic { .. }));
    }

    #[test]
    fn from_vault_registers_unifi_with_proxy_network_suffix() {
        let blob = json!({ "unifi": { "home": { "url": "https://192.0.2.2", "site": "default" } } });
        let reg = ServiceRegistry::from_vault(&blob, "Connecterr");
        let entry = reg.get("unifi_home").expect("unifi_home should be registered");
        assert_eq!(entry.base_url, "https://192.0.2.2/proxy/network");
        assert!(matches!(entry.auth, AuthPattern::UnifiDual { .. }));
    }

    #[test]
    fn from_vault_registers_all_media_services_by_type() {
        let blob = json!({
            "media": {
                "plex":      { "type": "plex",      "url": "http://plex" },
                "sonarr":    { "type": "sonarr",    "url": "http://sonarr" },
                "radarr":    { "type": "radarr",    "url": "http://radarr" },
                "overseerr": { "type": "overseerr", "url": "http://overseerr" },
                "tautulli":  { "type": "tautulli",  "url": "http://tautulli" },
            }
        });
        let reg = ServiceRegistry::from_vault(&blob, "Connecterr");
        for svc in ["plex", "sonarr", "radarr", "overseerr", "tautulli"] {
            assert!(reg.get(svc).is_some(), "missing {}", svc);
        }
    }

    #[test]
    fn from_vault_skips_items_without_url() {
        let blob = json!({ "ha": { "home": {} } });
        let reg = ServiceRegistry::from_vault(&blob, "Connecterr");
        assert!(reg.get("ha_home").is_none());
    }

    #[test]
    fn from_vault_empty_blob_returns_empty_registry() {
        let reg = ServiceRegistry::from_vault(&json!({}), "Connecterr");
        assert_eq!(reg.list().len(), 0);
    }

    #[test]
    fn test_from_vault_media_uses_vault_prefix() {
        let aggregated = serde_json::json!({
            "media": {
                "myplex": { "type": "plex", "url": "http://192.0.2.1:32400" }
            }
        });
        let registry = ServiceRegistry::from_vault(&aggregated, "myproxy");
        let svc = registry.get("myplex").unwrap();
        match &svc.auth {
            AuthPattern::Header { vault_item, .. } => {
                assert_eq!(vault_item, "myproxy - Plex");
            }
            other => panic!("expected Header, got {:?}", other),
        }
    }

    #[test]
    fn test_from_vault_uses_vault_prefix() {
        let aggregated = serde_json::json!({
            "ha": { "home": { "url": "http://192.0.2.10:8123" } }
        });
        let registry = ServiceRegistry::from_vault(&aggregated, "myproxy");
        let svc = registry.get("ha_home").unwrap();
        match &svc.auth {
            AuthPattern::Bearer { vault_item } => {
                assert_eq!(vault_item, "myproxy - Home Assistant");
            }
            other => panic!("expected Bearer, got {:?}", other),
        }
    }
}

#[cfg(test)]
mod toml_tests {
    use super::*;
    use std::io::Write;

    fn write_toml(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    #[test]
    fn test_bearer_service_from_toml() {
        let f = write_toml(r#"
[[service]]
name = "ha_home"
base_url = "http://192.0.2.1:8123"
auth = "bearer"
vault_item = "myproxy - HA"
"#);
        let registry = ServiceRegistry::from_toml_file(f.path());
        let svc = registry.get("ha_home").unwrap();
        assert_eq!(svc.base_url, "http://192.0.2.1:8123");
        match &svc.auth {
            AuthPattern::Bearer { vault_item } => assert_eq!(vault_item, "myproxy - HA"),
            other => panic!("expected Bearer, got {:?}", other),
        }
    }

    #[test]
    fn test_header_service_from_toml() {
        let f = write_toml(r#"
[[service]]
name = "sonarr"
base_url = "http://192.0.2.1:8989/api/v3"
auth = "header"
header_name = "X-Api-Key"
vault_item = "myproxy - Sonarr"
"#);
        let registry = ServiceRegistry::from_toml_file(f.path());
        let svc = registry.get("sonarr").unwrap();
        match &svc.auth {
            AuthPattern::Header { header_name, vault_item } => {
                assert_eq!(header_name, "X-Api-Key");
                assert_eq!(vault_item, "myproxy - Sonarr");
            }
            other => panic!("expected Header, got {:?}", other),
        }
    }

    #[test]
    fn test_missing_header_name_skips_service() {
        let f = write_toml(r#"
[[service]]
name = "bad"
base_url = "http://192.0.2.1:8080"
auth = "header"
vault_item = "myproxy - Bad"
"#);
        let registry = ServiceRegistry::from_toml_file(f.path());
        assert!(registry.get("bad").is_none(), "service with missing header_name should be skipped");
    }

    #[test]
    fn test_unifi_dual_from_toml() {
        let f = write_toml(r#"
[[service]]
name = "unifi_home"
base_url = "https://192.0.2.2/proxy/network"
auth = "unifi_dual"
vault_item = "myproxy - UniFi"
login_path = "/api/auth/login"
"#);
        let registry = ServiceRegistry::from_toml_file(f.path());
        let svc = registry.get("unifi_home").unwrap();
        match &svc.auth {
            AuthPattern::UnifiDual { vault_item, login_path } => {
                assert_eq!(vault_item, "myproxy - UniFi");
                assert_eq!(login_path, "/api/auth/login");
            }
            other => panic!("expected UnifiDual, got {:?}", other),
        }
    }

    #[test]
    fn test_missing_file_returns_empty_registry() {
        let registry = ServiceRegistry::from_toml_file(std::path::Path::new("/nonexistent/services.toml"));
        assert!(registry.list().is_empty());
    }

    #[test]
    fn test_trailing_slash_stripped_from_base_url() {
        let f = write_toml(r#"
[[service]]
name = "ha"
base_url = "http://192.0.2.1:8123/"
auth = "bearer"
vault_item = "myproxy - HA"
"#);
        let registry = ServiceRegistry::from_toml_file(f.path());
        let svc = registry.get("ha").unwrap();
        assert_eq!(svc.base_url, "http://192.0.2.1:8123");
    }

    #[test]
    fn test_query_param_service_from_toml() {
        let f = write_toml(r#"
[[service]]
name = "tautulli"
base_url = "http://192.0.2.1:8181"
auth = "query_param"
param_name = "apikey"
vault_item = "myproxy - Tautulli"
"#);
        let registry = ServiceRegistry::from_toml_file(f.path());
        match &registry.get("tautulli").unwrap().auth {
            AuthPattern::QueryParam { param_name, .. } => assert_eq!(param_name, "apikey"),
            other => panic!("expected QueryParam, got {:?}", other),
        }
    }

    #[test]
    fn test_basic_service_from_toml() {
        let f = write_toml(r#"
[[service]]
name = "opnsense"
base_url = "https://192.0.2.4/api"
auth = "basic"
key_field = "key"
secret_field = "secret"
vault_item = "myproxy - OPNsense"
insecure_tls = true
"#);
        let registry = ServiceRegistry::from_toml_file(f.path());
        let svc = registry.get("opnsense").unwrap();
        assert!(svc.insecure_tls);
        match &svc.auth {
            AuthPattern::Basic { key_field, secret_field, .. } => {
                assert_eq!(key_field, "key");
                assert_eq!(secret_field, "secret");
            }
            other => panic!("expected Basic, got {:?}", other),
        }
    }

    #[test]
    fn test_session_service_from_toml() {
        let f = write_toml(r#"
[[service]]
name = "npm"
base_url = "http://192.0.2.1:81/api"
auth = "session"
vault_item = "myproxy - NPM"
login_path = "/tokens"
token_field = "token"
"#);
        let registry = ServiceRegistry::from_toml_file(f.path());
        match &registry.get("npm").unwrap().auth {
            AuthPattern::Session { login_path, token_field, .. } => {
                assert_eq!(login_path, "/tokens");
                assert_eq!(token_field, "token");
            }
            other => panic!("expected Session, got {:?}", other),
        }
    }

    #[test]
    fn test_basic_missing_key_field_skips_service() {
        let f = write_toml(r#"
[[service]]
name = "bad_basic"
base_url = "https://192.0.2.4/api"
auth = "basic"
vault_item = "myproxy - Bad"
"#);
        let registry = ServiceRegistry::from_toml_file(f.path());
        assert!(registry.get("bad_basic").is_none(), "basic service missing key_field should be skipped");
    }

    /// iter-13: A base_url without an http/https scheme (e.g. "homeassistant.local:8123")
    /// must be rejected at load time with a clear diagnostic, not silently accepted
    /// or rejected with a confusing "link-local or cloud-metadata" error message.
    #[test]
    fn test_schemeless_base_url_skips_service() {
        let f = write_toml(r#"
[[service]]
name = "ha"
base_url = "homeassistant.local:8123"
auth = "bearer"
vault_item = "myproxy - HA"
"#);
        let registry = ServiceRegistry::from_toml_file(f.path());
        assert!(
            registry.get("ha").is_none(),
            "service with scheme-less base_url must be rejected"
        );
    }

    #[test]
    fn test_ssrf_blocked_base_url_skips_service() {
        // A services.toml pointing at a cloud-metadata endpoint must be
        // rejected at registry load time to prevent SSRF via proxied requests.
        let f = write_toml(r#"
[[service]]
name = "evil"
base_url = "http://169.254.169.254/latest/meta-data"
auth = "bearer"
vault_item = "myproxy - Evil"
"#);
        let registry = ServiceRegistry::from_toml_file(f.path());
        assert!(registry.get("evil").is_none(), "link-local/metadata base_url should be rejected");
    }

    #[test]
    fn test_ssrf_link_local_ipv6_base_url_skips_service() {
        let f = write_toml(r#"
[[service]]
name = "evil6"
base_url = "http://[fe80::1]/api"
auth = "bearer"
vault_item = "myproxy - Evil"
"#);
        let registry = ServiceRegistry::from_toml_file(f.path());
        assert!(registry.get("evil6").is_none(), "fe80:: link-local base_url should be rejected");
    }

    #[test]
    fn test_login_path_traversal_rejects_session_service() {
        // A crafted login_path with .. segments must be rejected at registry
        // load time so it cannot be used to target an unintended endpoint on
        // the upstream service during the login step.
        let f = write_toml(r#"
[[service]]
name = "evil_session"
base_url = "http://192.0.2.1:81/api"
auth = "session"
vault_item = "myproxy - Evil"
login_path = "/../admin/delete"
token_field = "token"
"#);
        let registry = ServiceRegistry::from_toml_file(f.path());
        assert!(
            registry.get("evil_session").is_none(),
            "session service with traversal login_path must be rejected"
        );
    }

    #[test]
    fn test_login_path_traversal_rejects_unifi_dual_service() {
        let f = write_toml(r#"
[[service]]
name = "evil_unifi"
base_url = "https://192.0.2.2/proxy/network"
auth = "unifi_dual"
vault_item = "myproxy - Evil"
login_path = "/api/./../../secret"
"#);
        let registry = ServiceRegistry::from_toml_file(f.path());
        assert!(
            registry.get("evil_unifi").is_none(),
            "unifi_dual service with traversal login_path must be rejected"
        );
    }

    #[test]
    fn test_login_path_traversal_helper() {
        assert!(login_path_has_traversal("/../admin"), ".. segment must be detected");
        assert!(login_path_has_traversal("/./tokens"), ". segment must be detected");
        assert!(login_path_has_traversal("/api/../../secret"), "interior .. must be detected");
        assert!(!login_path_has_traversal("/tokens"), "normal path must pass");
        assert!(!login_path_has_traversal("/api/v1/login"), "deep normal path must pass");
        assert!(!login_path_has_traversal("/auth/login"), "normal login path must pass");
    }

    #[test]
    fn test_duplicate_name_last_write_wins() {
        // Two [[service]] entries with the same name — only the second survives.
        // `register()` now emits a tracing::warn for this, but we can only assert
        // the observable behaviour (last entry is kept) in a unit test.
        let f = write_toml(r#"
[[service]]
name = "ha"
base_url = "http://192.0.2.1:8123"
auth = "bearer"
vault_item = "myproxy - HA"

[[service]]
name = "ha"
base_url = "http://192.0.2.2:8123"
auth = "bearer"
vault_item = "myproxy - HA v2"
"#);
        let registry = ServiceRegistry::from_toml_file(f.path());
        let svc = registry.get("ha").expect("service should be registered");
        // Last-write-wins: the second entry should be present.
        assert_eq!(svc.base_url, "http://192.0.2.2:8123",
            "duplicate name: second entry should overwrite first");
        // Only one entry should exist (no phantom first entry).
        assert_eq!(registry.list().len(), 1, "should have exactly one entry after dedup");
    }

    #[test]
    fn test_session_login_include_username_false() {
        let f = write_toml(r#"
[[service]]
name = "duplicati"
base_url = "http://192.0.2.1:8200/api/v1"
auth = "session"
vault_item = "vault-proxy - Duplicati"
login_path = "/auth/login"
token_field = "AccessToken"
login_include_username = false
"#);
        let registry = ServiceRegistry::from_toml_file(f.path());
        let svc = registry.get("duplicati").unwrap();
        match &svc.auth {
            AuthPattern::Session { login_include_username, .. } => {
                assert!(!login_include_username, "should exclude username from login body");
            }
            other => panic!("expected Session, got {:?}", other),
        }
    }

    #[test]
    fn test_session_login_include_username_defaults_true() {
        let f = write_toml(r#"
[[service]]
name = "npm"
base_url = "http://192.0.2.1:81/api"
auth = "session"
vault_item = "vault-proxy - NPM"
login_path = "/tokens"
token_field = "token"
"#);
        let registry = ServiceRegistry::from_toml_file(f.path());
        let svc = registry.get("npm").unwrap();
        match &svc.auth {
            AuthPattern::Session { login_include_username, .. } => {
                assert!(login_include_username, "should include username by default");
            }
            other => panic!("expected Session, got {:?}", other),
        }
    }

    // Issue-1 (iter-4): Service name validation tests.

    #[test]
    fn test_empty_service_name_is_rejected() {
        // TOML requires a value for `name`, but an empty string is valid TOML.
        // A service with name="" would register under the "" key and be
        // reachable via `{"service": ""}` — reject it.
        let f = write_toml(r#"
[[service]]
name = ""
base_url = "http://192.0.2.1:8123"
auth = "bearer"
vault_item = "myproxy - HA"
"#);
        let registry = ServiceRegistry::from_toml_file(f.path());
        assert!(registry.list().is_empty(), "empty name should be rejected");
    }

    #[test]
    fn test_all_whitespace_service_name_is_rejected() {
        let f = write_toml(r#"
[[service]]
name = "   "
base_url = "http://192.0.2.1:8123"
auth = "bearer"
vault_item = "myproxy - HA"
"#);
        let registry = ServiceRegistry::from_toml_file(f.path());
        assert!(registry.list().is_empty(), "all-whitespace name should be rejected");
    }

    #[test]
    fn test_service_name_with_null_byte_is_rejected() {
        // Null bytes in service names can confuse logging and routing.
        let toml = "[[service]]\nname = \"bad\x00name\"\nbase_url = \"http://192.0.2.1:8123\"\nauth = \"bearer\"\nvault_item = \"x\"\n";
        let f = write_toml(toml);
        let registry = ServiceRegistry::from_toml_file(f.path());
        assert!(registry.list().is_empty(), "name with null byte should be rejected");
    }

    // Issue-7 (iter-5): vault_item name validation tests.

    #[test]
    fn test_empty_vault_item_is_rejected() {
        let f = write_toml(r#"
[[service]]
name = "ha"
base_url = "http://192.0.2.1:8123"
auth = "bearer"
vault_item = ""
"#);
        let registry = ServiceRegistry::from_toml_file(f.path());
        assert!(
            registry.list().is_empty(),
            "service with empty vault_item should be rejected"
        );
    }

    #[test]
    fn test_null_byte_in_vault_item_is_rejected() {
        // Null bytes in vault_item would silently cause "item not found" at
        // runtime on every credential lookup — reject early at load time.
        let toml = "[[service]]\nname = \"ha\"\nbase_url = \"http://192.0.2.1:8123\"\nauth = \"bearer\"\nvault_item = \"bad\x00item\"\n";
        let f = write_toml(toml);
        let registry = ServiceRegistry::from_toml_file(f.path());
        assert!(
            registry.list().is_empty(),
            "vault_item with null byte should be rejected"
        );
    }

    // Issue (iter-10): Control character validation in service names.

    #[test]
    fn test_service_name_with_newline_is_rejected() {
        // A newline in a service name enables log injection:
        //   name = "foo\nERROR: vault unlocked" writes a fake ERROR line into logs.
        let toml = "[[service]]\nname = \"foo\\nbar\"\nbase_url = \"http://192.0.2.1:8123\"\nauth = \"bearer\"\nvault_item = \"x\"\n";
        let toml_with_ctrl = toml.replace("\\n", "\n");
        let f = write_toml(&toml_with_ctrl);
        let registry = ServiceRegistry::from_toml_file(f.path());
        assert!(
            registry.list().is_empty(),
            "name with newline (log injection vector) should be rejected"
        );
    }

    #[test]
    fn test_service_name_with_tab_is_rejected() {
        // Tab characters can break structured log parsers that use TSV format.
        let toml_with_tab = "[[service]]\nname = \"foo\tbar\"\nbase_url = \"http://192.0.2.1:8123\"\nauth = \"bearer\"\nvault_item = \"x\"\n";
        let f = write_toml(toml_with_tab);
        let registry = ServiceRegistry::from_toml_file(f.path());
        assert!(
            registry.list().is_empty(),
            "name with tab should be rejected"
        );
    }

    #[test]
    fn test_unicode_service_name_is_allowed() {
        // Multi-byte Unicode names (CJK, Arabic, emoji) have no security
        // impact and should not be blocked. Only ASCII control chars are banned.
        let f = write_toml(r#"
[[service]]
name = "my_服务"
base_url = "http://192.0.2.1:8123"
auth = "bearer"
vault_item = "vault-proxy - CJK Service"
"#);
        let registry = ServiceRegistry::from_toml_file(f.path());
        assert!(
            registry.list().contains(&"my_服务"),
            "Unicode service name should be accepted"
        );
    }

    // Issue (iter-14): Whitespace trimming of name and vault_item.

    #[test]
    fn test_service_name_with_leading_trailing_spaces_is_trimmed() {
        // A services.toml entry like name = "  ha_home  " should be reachable
        // via {"service": "ha_home"} — the spaces must be stripped at load time
        // so callers don't have to know about the config file's whitespace.
        let f = write_toml(r#"
[[service]]
name = "  ha_home  "
base_url = "http://192.0.2.1:8123"
auth = "bearer"
vault_item = "vault-proxy - HA"
"#);
        let registry = ServiceRegistry::from_toml_file(f.path());
        // The trimmed name "ha_home" must be reachable.
        assert!(
            registry.get("ha_home").is_some(),
            "service with leading/trailing spaces in name should be reachable after trimming"
        );
        // The untrimmed key must NOT be present.
        assert!(
            registry.get("  ha_home  ").is_none(),
            "service must not be registered under the untrimmed name"
        );
    }

    #[test]
    fn test_vault_item_with_leading_trailing_spaces_is_trimmed() {
        // A vault_item with spaces ("  vault-proxy - HA  ") would never match
        // the actual Vaultwarden item name and cause every credential lookup
        // to return "not found". Trimming at load time silently fixes this.
        let f = write_toml(r#"
[[service]]
name = "ha"
base_url = "http://192.0.2.1:8123"
auth = "bearer"
vault_item = "  vault-proxy - HA  "
"#);
        let registry = ServiceRegistry::from_toml_file(f.path());
        let svc = registry.get("ha").expect("service should be registered");
        match &svc.auth {
            AuthPattern::Bearer { vault_item } => {
                assert_eq!(vault_item, "vault-proxy - HA",
                    "vault_item should be trimmed of leading/trailing spaces");
            }
            other => panic!("expected Bearer, got {:?}", other),
        }
    }

    // iter-16: ca_cert PEM validation tests.

    /// A garbage ca_cert file (non-PEM content) must be rejected at load time
    /// with a clear error. Previously (iter-15) only file readability was checked;
    /// a file containing "not a cert" would pass load-time and fail at runtime
    /// with a cryptic TLS error.
    #[test]
    fn test_ca_cert_garbage_pem_is_rejected() {
        use std::io::Write as _;
        let mut certfile = tempfile::NamedTempFile::new().unwrap();
        certfile.write_all(b"not a certificate\n").unwrap();
        let cert_path = certfile.path().to_str().unwrap().to_string();

        let toml_content = format!(
            "[[service]]\nname = \"ca_test\"\nbase_url = \"https://192.0.2.10:8443/api\"\n\
             auth = \"bearer\"\nvault_item = \"test - CA Service\"\nca_cert = \"{}\"\n",
            cert_path.replace('\\', "\\\\")
        );
        let mut tf = tempfile::NamedTempFile::new().unwrap();
        tf.write_all(toml_content.as_bytes()).unwrap();

        let registry = ServiceRegistry::from_toml_file(tf.path());
        assert!(
            registry.get("ca_test").is_none(),
            "service with garbage ca_cert PEM must be rejected at load time (iter-16)"
        );
    }

    /// A missing ca_cert file must be rejected at load time.
    #[test]
    fn test_ca_cert_missing_file_is_rejected() {
        let f = write_toml(r#"
[[service]]
name = "ca_missing"
base_url = "https://192.0.2.10:8443/api"
auth = "bearer"
vault_item = "test - CA Service"
ca_cert = "/nonexistent/path/to/ca.pem"
"#);
        let registry = ServiceRegistry::from_toml_file(f.path());
        assert!(
            registry.get("ca_missing").is_none(),
            "service with missing ca_cert file must be rejected at load time"
        );
    }
}
