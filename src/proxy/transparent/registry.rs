//! Host:port → ServiceEntry lookup, layered over the existing
//! ServiceRegistry. Built on demand from a ServiceRegistry snapshot
//! whenever SIGHUP rebuilds the underlying registry.

use anyhow::{bail, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use url::Url;

use crate::proxy::registry::{ServiceEntry, ServiceRegistry, TransparentMode};

#[derive(Default, Clone, Debug)]
pub struct TransparentRegistry {
    by_host_port: HashMap<String, Arc<ServiceEntry>>,
}

impl TransparentRegistry {
    /// Build from a snapshot of the existing ServiceRegistry. Filters
    /// out entries with `TransparentMode::Off`. Rejects host:port
    /// collisions across multiple services.
    pub fn build(registry: &ServiceRegistry) -> Result<Self> {
        let mut out: HashMap<String, Arc<ServiceEntry>> = HashMap::new();
        for entry in registry.iter() {
            if entry.transparent_mode == TransparentMode::Off {
                continue;
            }
            let url = Url::parse(&entry.base_url)
                .map_err(|e| anyhow::anyhow!("base_url for '{}' invalid: {e}", entry.name))?;
            let host = url
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("base_url for '{}' has no host", entry.name))?
                .to_lowercase();
            let port = url.port_or_known_default().unwrap_or(443);
            let key = format!("{host}:{port}");
            if let Some(prev) = out.get(&key) {
                bail!(
                    "transparent host:port collision: '{key}' is claimed by both '{}' and '{}'",
                    prev.name,
                    entry.name
                );
            }
            out.insert(key, Arc::new(entry.clone()));
        }
        Ok(Self { by_host_port: out })
    }

    pub fn lookup(&self, host: &str, port: u16) -> Option<Arc<ServiceEntry>> {
        let key = format!("{}:{}", host.to_lowercase(), port);
        self.by_host_port.get(&key).cloned()
    }
}

/// Cell holding the latest built TransparentRegistry. Updated by
/// SIGHUP reload (Phase 6).
#[allow(dead_code)]
pub type TransparentRegistryCell = Arc<RwLock<TransparentRegistry>>;

#[cfg(all(test, feature = "test-utils"))]
mod tests {
    use super::*;

    #[test]
    fn collision_rejected() {
        let toml = r#"
            [[service]]
            name = "a"
            base_url = "https://api.example.com"
            auth = "bearer"
            vault_item = "v1"
            transparent_mode = "host_inject"

            [[service]]
            name = "b"
            base_url = "https://api.example.com:443/v2"
            auth = "bearer"
            vault_item = "v2"
            transparent_mode = "host_inject"
        "#;
        let reg = ServiceRegistry::from_toml_str(toml);
        let err = TransparentRegistry::build(&reg).unwrap_err();
        assert!(err.to_string().contains("collision"));
    }

    #[test]
    fn lookup_case_insensitive_on_host() {
        let toml = r#"
            [[service]]
            name = "a"
            base_url = "https://API.Example.com:443"
            auth = "bearer"
            vault_item = "v1"
            transparent_mode = "host_inject"
        "#;
        let reg = ServiceRegistry::from_toml_str(toml);
        let tr = TransparentRegistry::build(&reg).unwrap();
        assert!(tr.lookup("api.example.com", 443).is_some());
        assert!(tr.lookup("API.EXAMPLE.COM", 443).is_some());
    }

    #[test]
    fn lookup_default_port_443() {
        let toml = r#"
            [[service]]
            name = "a"
            base_url = "https://api.example.com"
            auth = "bearer"
            vault_item = "v1"
            transparent_mode = "host_inject"
        "#;
        let reg = ServiceRegistry::from_toml_str(toml);
        let tr = TransparentRegistry::build(&reg).unwrap();
        assert!(tr.lookup("api.example.com", 443).is_some());
        assert!(tr.lookup("api.example.com", 8443).is_none());
    }

    #[test]
    fn off_mode_excluded() {
        let toml = r#"
            [[service]]
            name = "a"
            base_url = "https://api.example.com"
            auth = "bearer"
            vault_item = "v1"
        "#;
        let reg = ServiceRegistry::from_toml_str(toml);
        let tr = TransparentRegistry::build(&reg).unwrap();
        assert!(tr.lookup("api.example.com", 443).is_none());
    }
}
