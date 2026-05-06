// iter-50: scaffold module — PlaywrightProcess and Pass-2 vision workflow are
// not fully wired to production call sites yet.  Remove this once all browser/*
// items on the v1.0 checklist are complete.
#![allow(dead_code)]

pub mod playwright;
pub mod profiles;
pub mod vision;
pub mod workflow;

use tokio::sync::RwLock;

use workflow::WorkflowState;

/// Browser agent state -- shared across handlers.
pub struct BrowserAgent {
    pub litellm_url: String,
    pub api_key: String,
    pub model_name: String,
    pub current_job: RwLock<Option<WorkflowState>>,
    pub last_screenshot: RwLock<Option<String>>,
}

impl BrowserAgent {
    pub fn new(litellm_url: &str, api_key: &str, model_name: &str) -> Self {
        Self {
            litellm_url: litellm_url.to_string(),
            api_key: api_key.to_string(),
            model_name: model_name.to_string(),
            current_job: RwLock::new(None),
            last_screenshot: RwLock::new(None),
        }
    }
}
