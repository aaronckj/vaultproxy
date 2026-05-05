//! Service auth registry — maps service names to their auth patterns and base URLs.

use std::collections::HashMap;

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
    Session {
        vault_item: String,
        login_path: String,
        token_field: String,
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
    /// Full base URL including any path prefix (e.g. "http://10.0.0.112:8989/api/v3").
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
    pub fn register(&mut self, entry: ServiceEntry) {
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

    /// Build a `ServiceRegistry` from the Connecterr config JSON.
    ///
    /// Reads `modules.media.services`, `modules.ha.instances`,
    /// `modules.opnsense.instances`, `modules.npm.instances`, and
    /// `modules.duplicati.instances`.
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
}

impl Default for ServiceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------------- //
// Helpers                                                                      //
// -------------------------------------------------------------------------- //

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
                        { "name": "plex",      "type": "plex",      "url": "http://10.0.0.112:32400" },
                        { "name": "sonarr",    "type": "sonarr",    "url": "http://10.0.0.112:8989"  },
                        { "name": "radarr",    "type": "radarr",    "url": "http://10.0.0.112:7878"  },
                        { "name": "overseerr", "type": "overseerr", "url": "http://10.0.0.112:5055"  },
                        { "name": "tautulli",  "type": "tautulli",  "url": "http://10.0.0.112:8181"  }
                    ]
                },
                "unifi":     { "enabled": true, "controllers": [{ "name": "home", "url": "https://10.0.0.1", "site": "default" }] },
                "ha":        { "enabled": true, "instances": [{ "name": "home", "url": "http://10.0.0.115:8123"  }] },
                "opnsense":  { "enabled": true, "instances": [{ "name": "main", "url": "https://10.0.0.167"       }] },
                "npm":       { "enabled": true, "instances": [{ "name": "main", "url": "http://10.0.0.112:81"    }] },
                "duplicati": { "enabled": true, "instances": [{ "name": "main", "url": "http://10.0.0.112:8200"  }] }
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
        assert_eq!(svc.base_url, "http://10.0.0.112:8989/api/v3");
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
        assert_eq!(svc.base_url, "https://10.0.0.1/proxy/network");
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
            "ha": { "home": { "url": "http://10.0.0.115:8123" } }
        });
        let reg = ServiceRegistry::from_vault(&blob, "Connecterr");
        let entry = reg.get("ha_home").expect("ha_home should be registered");
        assert_eq!(entry.base_url, "http://10.0.0.115:8123");
        match &entry.auth {
            AuthPattern::Bearer { vault_item } => assert_eq!(vault_item, "Connecterr - Home Assistant"),
            _ => panic!("expected Bearer auth"),
        }
    }

    #[test]
    fn from_vault_registers_opnsense_with_basic_auth_and_api_suffix() {
        let blob = json!({ "opnsense": { "main": { "url": "https://10.0.0.167" } } });
        let reg = ServiceRegistry::from_vault(&blob, "Connecterr");
        let entry = reg.get("opnsense_main").expect("opnsense_main should be registered");
        assert_eq!(entry.base_url, "https://10.0.0.167/api");
        assert!(matches!(entry.auth, AuthPattern::Basic { .. }));
    }

    #[test]
    fn from_vault_registers_unifi_with_proxy_network_suffix() {
        let blob = json!({ "unifi": { "home": { "url": "https://10.0.0.1", "site": "default" } } });
        let reg = ServiceRegistry::from_vault(&blob, "Connecterr");
        let entry = reg.get("unifi_home").expect("unifi_home should be registered");
        assert_eq!(entry.base_url, "https://10.0.0.1/proxy/network");
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
