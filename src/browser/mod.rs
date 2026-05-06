// iter-81: this module is only compiled when `--features browser` is passed.
// The feature gate in main.rs (`#[cfg(feature = "browser")] mod browser;`)
// means rustc never sees this code when the feature is off — no dead-code
// suppression is needed, and none is present.
//
// When the feature IS on, all items here are reachable via the /browser/*
// routes in main.rs, so no dead-code warnings are expected in that build either.
// If a new helper is added to playwright/vision/workflow without wiring it to a
// route, rustc will correctly flag it — fix by wiring it or adding a targeted
// `#[allow(dead_code)]` at item level with a comment explaining why.

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
