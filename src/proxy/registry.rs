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
    /// Gracefully handles a missing file (returns empty registry with a warning)
    /// and parse errors (returns empty registry with an error log).
    pub fn from_toml_file(path: &Path) -> Self {
        let mut registry = Self::new();

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("services.toml not found at {:?}: {} — starting with empty registry", path, e);
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

        for svc in parsed.service {
            let base_url = svc.base_url.trim_end_matches('/').to_string();

            // Validate base_url against SSRF policy. This prevents a
            // compromised/tricked services.toml from pointing the proxy at
            // cloud-metadata endpoints (169.254.169.254, fd00:ec2::254, etc.)
            // or link-local addresses. The check mirrors the one used by
            // `inject_creds` and `browser_rotate` in vault/handlers.rs.
            if !crate::vault::handlers::is_allowed_outbound_url(&base_url) {
                tracing::error!(
                    "service '{}': base_url '{}' is not allowed (link-local or cloud-metadata endpoint) — skipping",
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

            registry.register(ServiceEntry {
                name: svc.name,
                base_url,
                auth,
                insecure_tls: svc.insecure_tls,
            });
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
        }),
        "sonarr" => Some(ServiceEntry {
            name,
            base_url: format!("{}/api/v3", url),
            auth: AuthPattern::Header {
                header_name: "X-Api-Key".to_string(),
                vault_item: format!("{} - Sonarr", vault_prefix),
            },
            insecure_tls: false,
        }),
        "radarr" => Some(ServiceEntry {
            name,
            base_url: format!("{}/api/v3", url),
            auth: AuthPattern::Header {
                header_name: "X-Api-Key".to_string(),
                vault_item: format!("{} - Radarr", vault_prefix),
            },
            insecure_tls: false,
        }),
        "overseerr" => Some(ServiceEntry {
            name,
            base_url: format!("{}/api/v1", url),
            auth: AuthPattern::Header {
                header_name: "X-Api-Key".to_string(),
                vault_item: format!("{} - Overseerr", vault_prefix),
            },
            insecure_tls: false,
        }),
        "tautulli" => Some(ServiceEntry {
            name,
            base_url: format!("{}/api/v2", url),
            auth: AuthPattern::QueryParam {
                param_name: "apikey".to_string(),
                vault_item: format!("{} - Tautulli", vault_prefix),
            },
            insecure_tls: false,
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
}
