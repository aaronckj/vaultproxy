use crate::credential_audit::orchestrator::{ApplyOutcome, Orchestrator};
use crate::credential_audit::types::ItemResult;
use crate::credential_audit::vw_adapter::VwAdapter;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use std::sync::Arc;

pub type SharedOrch = Arc<Orchestrator<VwAdapter>>;

#[derive(Debug, Deserialize)]
pub struct ApplyBody {
    pub run_id: String,
    #[serde(default = "default_dry_run")]
    pub dry_run: bool,
    pub item_ids: Option<Vec<String>>,
    #[serde(default)]
    pub confirm_bulk: bool,
}

fn default_dry_run() -> bool {
    true
}

pub async fn scan_start(
    State(orch): State<SharedOrch>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // TODO(iter-8): The blanket CONFLICT status is wrong for non-conflict errors.
    // `start_scan` returns Err for at least three distinct cases:
    //   - another scan already running  → 409 CONFLICT  (correct)
    //   - engine unreachable            → 503 SERVICE_UNAVAILABLE
    //   - DB failure                    → 500 INTERNAL_SERVER_ERROR
    // Distinguish them by matching on the error message or by introducing a typed
    // error enum so callers can act appropriately (e.g. retry on 503, not on 409).
    match orch.start_scan().await {
        Ok(run_id) => Ok(Json(serde_json::json!({"run_id": run_id}))),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("another audit run is in progress") {
                Err(StatusCode::CONFLICT)
            } else if msg.contains("engine is not reachable") {
                Err(StatusCode::SERVICE_UNAVAILABLE)
            } else {
                Err(StatusCode::INTERNAL_SERVER_ERROR)
            }
        }
    }
}

pub async fn review_pending(
    State(orch): State<SharedOrch>,
    Path(run_id): Path<String>,
) -> Result<Json<Vec<ItemResult>>, StatusCode> {
    orch.list_pending(&run_id)
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

pub async fn apply(
    State(orch): State<SharedOrch>,
    Json(body): Json<ApplyBody>,
) -> Result<Json<ApplyOutcome>, StatusCode> {
    orch.apply(&body.run_id, body.item_ids, body.dry_run, body.confirm_bulk)
        .await
        .map(Json)
        .map_err(|_| StatusCode::BAD_REQUEST)
}
