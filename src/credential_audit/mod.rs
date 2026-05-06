// iter-81: this module is only compiled when `--features engine` is passed.
// The feature gate in main.rs (`#[cfg(feature = "engine")] mod credential_audit;`)
// means rustc never sees this code when the feature is off — no dead-code
// suppression is needed, and none is present.
//
// Sub-modules included here:
//   db, types, marker, vault_adapter, vw_adapter — stable supporting types used
//   by handlers and orchestrator.
//   engine_client — HTTP client for the external credential-audit engine sidecar.
//   orchestrator   — scan coordination, DB writes, engine health checks.
//   pass2          — per-item login-attempt worker, rate-limiting, blacklisting.
//   handlers       — axum route handlers for /audit/credaudit/* endpoints.
//
// The in-process credential health audit (src/audit.rs + GET /vault/audit/run)
// is NOT part of this module and is always compiled regardless of this feature.

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
