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
///
/// # Security note (iter-6 audit)
///
/// This endpoint is accessible to any unauthenticated caller that can reach
/// 127.0.0.1:3201 (rate-limited and DNS-rebinding-guarded, but not
/// authentication-gated). Any process on localhost can therefore trigger a
/// credential rotation for any registered service name.
///
/// Current rotation strategies for `sonarr` and `radarr` are **stubs** that
/// return a placeholder result and perform no real action.
///
/// RESOLVED (iter-22): This endpoint is now gated behind the internal bearer
/// token via `require_internal_token` middleware applied to the `/rotate` sub-router
/// in `main.rs`. Callers must present `Authorization: Bearer <token>` where the
/// token is read from `$CONFIG_DIR/internal-token` (0o600 permissions).
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
    //
    // Issue (iter-32): `rotate_sonarr` and `rotate_radarr` return
    // `status: "unsupported"` — but the handler was returning HTTP 200 OK for
    // them. A caller cannot distinguish a successful rotation from an
    // unimplemented one by status code alone. Return 501 Not Implemented for
    // any result whose status is "unsupported" so callers and monitoring tools
    // can act on the correct signal. When a real implementation is added, it
    // should change the status to "success" and this path will return 200.
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

    // Issue (iter-26): Audit all rotation attempts regardless of success/failure.
    // /rotate was previously not logged to the structured AuditLog (only to
    // tracing). Operators need a persistent record of rotation attempts,
    // especially for troubleshooting failed rotations.
    state.audit_log.log(crate::security::audit_log::AuditEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        tool_name: "vault__rotate".to_string(),
        args_summary: format!("service={}, strategy={}", req.service, req.strategy),
        result_summary: format!("status={}: {}", result.status, result.message),
        permission: "Allowed".to_string(),
        trigger: "http".to_string(),
    });

    // Return 501 Not Implemented when the strategy is a known stub.
    // "unsupported" means the strategy exists in code but is not yet
    // implemented — this is distinct from "error" (bad input) and "success".
    if result.status == "unsupported" {
        return Err((StatusCode::NOT_IMPLEMENTED, Json(result)));
    }

    Ok(Json(result))
}
