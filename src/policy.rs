//! Rotation policy engine — scheduled credential rotation.

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub target: PolicyTarget,
    pub interval_days: u32,
    pub strategy: String, // "api" or "browser"
    pub enabled: bool,
    pub last_run: Option<String>,
    pub last_result: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTarget {
    #[serde(rename = "type")]
    pub target_type: String, // "folder", "tag", "all"
    pub value: Option<String>,
}

/// Load rotation policies, distinguishing "no file" from "corrupt file" and
/// logging the latter loudly. Silently swallowing parse errors would disable
/// ALL scheduled rotations without warning the operator.
pub fn load_policies(path: &str) -> Vec<Policy> {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => {
            tracing::warn!(
                "policies file at {} unreadable: {} — treating as empty",
                path,
                e
            );
            return Vec::new();
        }
    };
    match serde_json::from_str::<Vec<Policy>>(&raw) {
        Ok(policies) => policies
            .into_iter()
            // Drop obviously-broken entries at load time so the scheduler
            // never hot-loops on a policy with interval_days == 0.
            .filter(|p| {
                if p.interval_days == 0 {
                    tracing::warn!(
                        "policy '{}' has interval_days=0 — rejected (would hot-loop)",
                        p.id,
                    );
                    false
                } else {
                    true
                }
            })
            .collect(),
        Err(e) => {
            tracing::error!(
                "policies file at {} is corrupt: {} — no rotations will run until fixed",
                path,
                e,
            );
            Vec::new()
        }
    }
}

pub fn save_policies(path: &str, policies: &[Policy]) -> Result<()> {
    let data = serde_json::to_string_pretty(policies)?;
    crate::secure::safe_write_config(path, data.as_bytes())
}

pub fn delete_policy(path: &str, id: &str) -> Result<()> {
    let mut policies = load_policies(path);
    policies.retain(|p| p.id != id);
    save_policies(path, &policies)
}
