//! Tool permission system — controls which MCP tools can execute freely,
//! which require confirmation, and which are blocked.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    Allow,
    Ask,
    Block,
    Log,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolPermissions {
    pub defaults: HashMap<String, Permission>,
    pub overrides: HashMap<String, Permission>,
}

impl Default for ToolPermissions {
    fn default() -> Self {
        let mut defaults = HashMap::new();
        defaults.insert("list".to_string(), Permission::Allow);
        defaults.insert("get".to_string(), Permission::Allow);
        defaults.insert("status".to_string(), Permission::Allow);
        defaults.insert("health".to_string(), Permission::Allow);
        defaults.insert("create".to_string(), Permission::Log);
        defaults.insert("update".to_string(), Permission::Log);
        defaults.insert("add".to_string(), Permission::Log);
        defaults.insert("delete".to_string(), Permission::Ask);
        defaults.insert("remove".to_string(), Permission::Ask);
        defaults.insert("ssh".to_string(), Permission::Ask);
        defaults.insert("rotate".to_string(), Permission::Ask);
        defaults.insert("change_password".to_string(), Permission::Ask);
        defaults.insert("firewall".to_string(), Permission::Ask);
        defaults.insert("restart".to_string(), Permission::Ask);

        Self {
            defaults,
            overrides: HashMap::new(),
        }
    }
}

impl ToolPermissions {
    /// Load permissions from a JSON file, returning defaults if not found or
    /// unparseable.
    pub fn load(path: &str) -> Self {
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                serde_json::from_str(&contents).unwrap_or_else(|e| {
                    tracing::warn!("failed to parse permissions file: {} — using defaults", e);
                    Self::default()
                })
            }
            Err(_) => {
                tracing::info!("no permissions file at {} — using defaults", path);
                Self::default()
            }
        }
    }

    /// Save permissions to a JSON file with restricted permissions (0600).
    /// Uses safe_write_config to reject symlinks.
    pub fn save(&self, path: &str) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        crate::secure::safe_write_config(path, json.as_bytes())
    }

    /// Get the effective permission for a tool. Checks overrides first,
    /// then matches tool name against category keywords, then defaults to Log.
    pub fn get_permission(&self, tool_name: &str) -> Permission {
        // 1. Exact override.
        if let Some(perm) = self.overrides.get(tool_name) {
            return perm.clone();
        }

        // 2. Category match — check if the tool name contains any category keyword.
        let lower = tool_name.to_lowercase();
        // Check more specific patterns first (longer keywords).
        let mut matched: Option<(&str, &Permission)> = None;
        for (category, perm) in &self.defaults {
            if lower.contains(category) {
                // Prefer longer (more specific) matches.
                if matched.is_none() || category.len() > matched.unwrap().0.len() {
                    matched = Some((category, perm));
                }
            }
        }

        if let Some((_, perm)) = matched {
            return perm.clone();
        }

        // 3. Default to Log.
        Permission::Log
    }

    /// Get the default category permission for a tool name (ignoring overrides).
    pub fn get_default_permission(&self, tool_name: &str) -> Permission {
        let lower = tool_name.to_lowercase();
        let mut matched: Option<(&str, &Permission)> = None;
        for (category, perm) in &self.defaults {
            if lower.contains(category) {
                if matched.is_none() || category.len() > matched.unwrap().0.len() {
                    matched = Some((category, perm));
                }
            }
        }
        matched.map(|(_, p)| p.clone()).unwrap_or(Permission::Log)
    }

    /// Determine the category for a tool name.
    pub fn get_category(&self, tool_name: &str) -> String {
        let lower = tool_name.to_lowercase();
        let mut matched: Option<&str> = None;
        for category in self.defaults.keys() {
            if lower.contains(category) {
                if matched.is_none() || category.len() > matched.unwrap().len() {
                    matched = Some(category);
                }
            }
        }
        matched.unwrap_or("other").to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults() {
        let perms = ToolPermissions::default();
        assert_eq!(perms.get_permission("net__list_interfaces"), Permission::Allow);
        assert_eq!(perms.get_permission("media__get_movies"), Permission::Allow);
        assert_eq!(perms.get_permission("docker__create_container"), Permission::Log);
        assert_eq!(perms.get_permission("ha__delete_entity"), Permission::Ask);
        assert_eq!(perms.get_permission("ssh__exec"), Permission::Ask);
        assert_eq!(perms.get_permission("vaultwarden__rotate_password"), Permission::Ask);
    }

    #[test]
    fn test_override() {
        let mut perms = ToolPermissions::default();
        perms.overrides.insert("ssh__exec".to_string(), Permission::Block);
        assert_eq!(perms.get_permission("ssh__exec"), Permission::Block);
    }
}
