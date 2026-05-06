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

pub async fn scan_start(State(orch): State<SharedOrch>) -> axum::response::Response {
    use axum::response::IntoResponse;
    // Issue (iter-103): Return type was `Result<Json<Value>, StatusCode>`. Bare
    // `StatusCode` on the Err path produces an HTTP response with the correct
    // status code but an **empty body** — no `"ok": false`, no `"error"` field.
    // Callers and monitoring that parse the JSON body (e.g. checking `ok`) would
    // receive an empty string and panic or silently discard the error.
    // Changed to `axum::response::Response` so every branch returns a full body.
    //
    // Three distinct error cases:
    //   - another scan already running  → 409 CONFLICT
    //   - engine unreachable            → 503 SERVICE_UNAVAILABLE
    //   - DB failure / other            → 500 INTERNAL_SERVER_ERROR
    match orch.start_scan().await {
        Ok(run_id) => (
            StatusCode::OK,
            Json(serde_json::json!({"ok": true, "run_id": run_id})),
        )
            .into_response(),
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("another audit run is in progress") {
                // 409 Conflict — caller should poll the existing run_id.
                (
                    StatusCode::CONFLICT,
                    Json(serde_json::json!({
                        "ok": false,
                        "error": "another audit run is already in progress — poll the existing run_id",
                    })),
                )
                    .into_response()
            } else if msg.contains("engine is not reachable") {
                // iter-34 / iter-103: 503 with an actionable body.
                tracing::warn!(
                    "credaudit: scan/start rejected — credential audit engine is not reachable. \
                     Set CRED_AUDIT_ENGINE_URL to the engine's base URL (default http://127.0.0.1:8765). \
                     If the engine is not deployed, this endpoint will always return 503."
                );
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({
                        "ok": false,
                        "error": "credential audit engine is not reachable — set CRED_AUDIT_ENGINE_URL",
                    })),
                )
                    .into_response()
            } else {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"ok": false, "error": msg})),
                )
                    .into_response()
            }
        }
    }
}

pub async fn review_pending(
    State(orch): State<SharedOrch>,
    Path(run_id): Path<String>,
) -> Result<Json<Vec<ItemResult>>, (StatusCode, Json<serde_json::Value>)> {
    // Issue (iter-103): Error bodies were missing `"ok": false`. Every other
    // non-200 response in the codebase includes `"ok": false`; callers that
    // check `body["ok"] == false` would not detect these errors.
    orch.list_pending(&run_id).map(Json).map_err(|e| {
        let msg = e.to_string();
        if msg.contains("not found") {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "ok": false,
                    "error": format!("run_id '{}' not found — no scan has been started with this ID", run_id)
                })),
            )
        } else {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"ok": false, "error": msg})),
            )
        }
    })
}

pub async fn apply(
    State(orch): State<SharedOrch>,
    Json(body): Json<ApplyBody>,
) -> Result<Json<ApplyOutcome>, (StatusCode, Json<serde_json::Value>)> {
    // Issue (iter-103): Error bodies were missing `"ok": false`. Added for
    // consistency with all other non-200 responses in the codebase.
    orch.apply(&body.run_id, body.item_ids, body.dry_run, body.confirm_bulk)
        .await
        .map(Json)
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("not found") {
                (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({
                        "ok": false,
                        "error": format!(
                            "run_id '{}' not found — start a scan with POST /audit/credaudit/scan/start first",
                            body.run_id
                        )
                    })),
                )
            } else {
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"ok": false, "error": msg})),
                )
            }
        })
}
