// iter-50: scaffold module — credential audit engine is not deployed in most
// setups.  Several internal helpers (Pass-2 worker, telemetry, list_runs, etc.)
// are unreachable until the engine sidecar is running.  Remove this once all
// credential_audit items on the v1.0 checklist are complete.
#![allow(dead_code)]

pub mod db;
pub mod engine_client;
pub mod handlers;
pub mod marker;
pub mod orchestrator;
pub mod pass2;
pub mod types;
pub mod vault_adapter;
pub mod vw_adapter;

use axum::{
    routing::{get, post},
    Router,
};
use std::sync::Arc;

pub fn router(orch: Arc<orchestrator::Orchestrator<vw_adapter::VwAdapter>>) -> Router {
    Router::new()
        .route("/audit/credaudit/scan/start", post(handlers::scan_start))
        .route(
            "/audit/credaudit/review_pending/{run_id}",
            get(handlers::review_pending),
        )
        .route("/audit/credaudit/apply", post(handlers::apply))
        .with_state(orch)
}

#[cfg(test)]
mod tests {
    use crate::credential_audit::types::RunStatus;

    #[test]
    fn run_status_serializes_snake_case() {
        let r = RunStatus::PausedProxyDown;
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(s, "\"paused_proxy_down\"");
    }
}
