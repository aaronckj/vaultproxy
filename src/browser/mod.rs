// iter-50: scaffold module — PlaywrightProcess and Pass-2 vision workflow are
// not fully wired to all production call sites yet.
//
// TODO(v1.0): Remove `#![allow(dead_code)]` once the following are complete:
//   - `PlaywrightProcess` used directly from browser_rotate background task
//   - `VisionModel` wired into the workflow for all screenshot-analysis steps
//   - `WorkflowState` exposed via the dashboard status endpoint
//   There is no separate milestone ticket yet; track under the v1.0 label in
//   the project issue tracker.
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
