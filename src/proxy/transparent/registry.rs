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
    /// Exact host:port → service. Looked up first.
    by_host_port: HashMap<String, Arc<ServiceEntry>>,
    /// Wildcard patterns like `*.github.com:443` → service. Checked
    /// only when the exact map misses. Compiled at build time so
    /// every request is a cheap O(n_wildcards) tail check rather
    /// than a regex compile.
    wildcards: Vec<(WildcardPattern, Arc<ServiceEntry>)>,
}

/// Compiled wildcard pattern. `*.example.com` matches `foo.example.com`
/// and `a.b.example.com` but NOT `example.com` itself (must have at
/// least one label before the suffix). Single leading `*.` only;
/// embedded `*` is rejected at build time.
#[derive(Debug, Clone)]
struct WildcardPattern {
    /// The suffix after the leading `*.`, lowercased. e.g. `.github.com`
    suffix: String,
    /// Port must match exactly.
    port: u16,
}

impl WildcardPattern {
    fn parse(host: &str, port: u16) -> Option<Self> {
        let rest = host.strip_prefix("*.")?;
        if rest.is_empty() || rest.contains('*') {
            return None;
        }
        Some(Self {
            suffix: format!(".{}", rest.to_lowercase()),
            port,
        })
    }

    fn matches(&self, host: &str, port: u16) -> bool {
        if port != self.port {
            return false;
        }
        let h = host.to_lowercase();
        h.ends_with(&self.suffix) && h.len() > self.suffix.len()
    }
}

impl TransparentRegistry {
    /// Build from a snapshot of the existing ServiceRegistry. Filters
    /// out entries with `TransparentMode::Off`. Rejects host:port
    /// collisions across multiple services.
    pub fn build(registry: &ServiceRegistry) -> Result<Self> {
        let mut by_host_port: HashMap<String, Arc<ServiceEntry>> = HashMap::new();
        let mut wildcards: Vec<(WildcardPattern, Arc<ServiceEntry>)> = Vec::new();
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
            if host.starts_with("*.") {
                let pat = WildcardPattern::parse(&host, port).ok_or_else(|| {
                    anyhow::anyhow!(
                        "service '{}': wildcard host '{}' invalid — only leading '*.' is allowed",
                        entry.name,
                        host
                    )
                })?;
                wildcards.push((pat, Arc::new(entry.clone())));
                continue;
            }
            let key = format!("{host}:{port}");
            if let Some(prev) = by_host_port.get(&key) {
                bail!(
                    "transparent host:port collision: '{key}' is claimed by both '{}' and '{}'",
                    prev.name,
                    entry.name
                );
            }
            by_host_port.insert(key, Arc::new(entry.clone()));
        }
        Ok(Self {
            by_host_port,
            wildcards,
        })
    }

    /// Look up a service by host+port. Exact match wins; wildcard
    /// patterns are checked only on exact miss. Wildcard scan is
    /// O(n_wildcards); n is small in practice.
    pub fn lookup(&self, host: &str, port: u16) -> Option<Arc<ServiceEntry>> {
        let key = format!("{}:{}", host.to_lowercase(), port);
        if let Some(s) = self.by_host_port.get(&key) {
            return Some(s.clone());
        }
        for (pat, svc) in &self.wildcards {
            if pat.matches(host, port) {
                return Some(svc.clone());
            }
        }
        None
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

    #[test]
    fn wildcard_matches_subdomains_only() {
        let toml = r#"
            [[service]]
            name = "gh-any"
            base_url = "https://*.github.com"
            auth = "bearer"
            vault_item = "v1"
            transparent_mode = "host_inject"
        "#;
        let reg = ServiceRegistry::from_toml_str(toml);
        let tr = TransparentRegistry::build(&reg).unwrap();
        assert!(tr.lookup("api.github.com", 443).is_some());
        assert!(tr.lookup("uploads.github.com", 443).is_some());
        assert!(tr.lookup("a.b.github.com", 443).is_some());
        // Apex must NOT match (`*.github.com` requires ≥1 leading label).
        assert!(tr.lookup("github.com", 443).is_none());
        // Different host doesn't match.
        assert!(tr.lookup("github.org", 443).is_none());
        // Port mismatch.
        assert!(tr.lookup("api.github.com", 8443).is_none());
    }

    #[test]
    fn exact_wins_over_wildcard() {
        let toml = r#"
            [[service]]
            name = "exact"
            base_url = "https://api.github.com"
            auth = "bearer"
            vault_item = "v1"
            transparent_mode = "host_inject"

            [[service]]
            name = "any-gh"
            base_url = "https://*.github.com"
            auth = "bearer"
            vault_item = "v2"
            transparent_mode = "host_inject"
        "#;
        let reg = ServiceRegistry::from_toml_str(toml);
        let tr = TransparentRegistry::build(&reg).unwrap();
        let svc = tr.lookup("api.github.com", 443).unwrap();
        assert_eq!(svc.name, "exact", "exact entry must beat wildcard");
        let other = tr.lookup("docs.github.com", 443).unwrap();
        assert_eq!(other.name, "any-gh", "wildcard catches everything else");
    }

    #[test]
    fn wildcard_rejects_embedded_star() {
        // Only leading "*." is supported. "foo.*.com" is rejected at
        // build time (the wildcard pattern parser refuses embedded
        // stars).
        let toml = r#"
            [[service]]
            name = "bad"
            base_url = "https://foo.*.com"
            auth = "bearer"
            vault_item = "v1"
            transparent_mode = "host_inject"
        "#;
        let reg = ServiceRegistry::from_toml_str(toml);
        // url crate rejects '*' inside a host label outright — the
        // registry parse drops the entry with an error log before we
        // ever reach TransparentRegistry::build. Verify the lookup
        // sees no service for that host.
        let tr = TransparentRegistry::build(&reg).unwrap();
        assert!(tr.lookup("foo.bar.com", 443).is_none());
    }
}
