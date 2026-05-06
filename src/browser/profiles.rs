//! Site profiles — pre-configured selectors for common websites.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteProfile {
    pub login_url: Option<String>,
    pub password_change_url: Option<String>,
    pub login_username_selector: Option<String>,
    pub login_password_selector: Option<String>,
    pub login_submit_selector: Option<String>,
    pub password_current_selector: Option<String>,
    pub password_new_selector: Option<String>,
    pub password_confirm_selector: Option<String>,
    pub password_submit_selector: Option<String>,
}

pub fn load_profiles(path: &str) -> HashMap<String, SiteProfile> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

#[allow(dead_code)] // iter-82: used by future browser profile management UI; not yet wired to an HTTP route
pub fn save_profiles(path: &str, profiles: &HashMap<String, SiteProfile>) -> Result<()> {
    let data = serde_json::to_string_pretty(profiles)?;
    crate::secure::safe_write_config(path, data.as_bytes())
}

/// Match a URL to a site profile by extracting and looking up the domain.
pub fn match_profile<'a>(
    profiles: &'a HashMap<String, SiteProfile>,
    url: &str,
) -> Option<&'a SiteProfile> {
    // Extract domain from URL
    let domain = url
        .split("://")
        .nth(1)
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or("")
        .trim_start_matches("www.");

    // Try exact match first, then try parent domain
    profiles.get(domain).or_else(|| {
        // Try without subdomain: secure.chase.com → chase.com
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() > 2 {
            let parent = parts[parts.len() - 2..].join(".");
            profiles.get(parent.as_str())
        } else {
            None
        }
    })
}
