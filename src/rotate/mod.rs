//! Rotation layer — dispatches credential rotation requests to per-service
//! strategy functions.

pub mod strategies;

use std::sync::Arc;

use axum::{extract::State, http::StatusCode, Json};
use serde::Deserialize;

use crate::proxy::AppState;
use strategies::RotationResult;

// -------------------------------------------------------------------------- //
// Request type                                                                 //
// -------------------------------------------------------------------------- //

/// Body accepted by `POST /rotate`.
#[derive(Debug, Deserialize)]
pub struct RotateRequest {
    /// Registered service name (e.g. "sonarr", "radarr").
    pub service: String,
    /// Rotation strategy to use.  Only "api" is accepted at this time.
    pub strategy: String,
}

// -------------------------------------------------------------------------- //
// Handler                                                                      //
// -------------------------------------------------------------------------- //

/// `POST /rotate` — rotate the API credential for the named service.
pub async fn handle_rotate(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RotateRequest>,
) -> Result<Json<RotationResult>, (StatusCode, Json<RotationResult>)> {
    // Only the "api" strategy is accepted.
    if req.strategy != "api" {
        let result = RotationResult {
            service: req.service.clone(),
            status: "error".to_string(),
            message: format!(
                "unsupported strategy '{}'; only 'api' is accepted",
                req.strategy
            ),
        };
        return Err((StatusCode::BAD_REQUEST, Json(result)));
    }

    // Dispatch to the per-service strategy function.
    let result = match req.service.as_str() {
        "sonarr" => strategies::rotate_sonarr().await,
        "radarr" => strategies::rotate_radarr().await,
        other => RotationResult {
            service: other.to_string(),
            status: "error".to_string(),
            message: format!("no rotation strategy registered for service '{}'", other),
        },
    };

    // Any successful rotation invalidates downstream caches that could
    // otherwise hand out stale credentials for up to 15 minutes. Evict the
    // rotated service's session token (if any) and clear any decrypted-cipher
    // caches. Current strategies are stubs — this is preventive but keeps
    // the invariant honest as strategies are implemented.
    if result.status == "success" {
        state.session_tokens.write().await.remove(&req.service);
        // Best-effort: a fresh sync pulls the rotated credential from the
        // upstream vault. Ignore errors — the rotation itself already
        // succeeded, and the next scheduled sync will catch up.
        if let Err(e) = state.vault.sync().await {
            tracing::warn!(
                "vault sync after rotate('{}') failed: {} — next scheduled sync will catch up",
                req.service, e
            );
        }
    }

    Ok(Json(result))
}
