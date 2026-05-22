// Library crate root — exposes modules needed by integration tests and the
// connecterr MCP server. Only non-feature-gated modules are included here.
// Feature-gated modules (browser, credential_audit, dashboard) remain
// main.rs-only unless needed.
//
// Note: proxy/mod.rs unit tests reference `crate::require_internal_token`,
// `crate::dns_rebinding_guard`, and `crate::handle_get_permissions`, which
// are defined in main.rs for the binary crate. The copies below keep the
// lib unit tests compiling without duplicating the business logic elsewhere.

pub mod access_log;
mod audit;
pub mod bearer_bridge;
pub mod cred_cache;
mod internal_token;
mod keystore;
mod launcher;
pub mod local_socket;
mod notify;
mod policy;
mod proxy;
mod rotate;
mod secure;
mod security;
mod setup;
mod sync;
mod tls;
mod totp;
mod tpm;
pub mod vault;
pub mod mcp_server;

use std::sync::Arc;
use axum::{extract::State as AxumState, Json as AxumJson};
use proxy::AppState;

/// Re-implementation of the `require_internal_token` middleware for the lib
/// crate context. Proxy unit tests reference `crate::require_internal_token`
/// which in the binary crate resolves to main.rs. This copy keeps those tests
/// compiling when the code is built as a library.
pub(crate) async fn require_internal_token(
    AxumState(state): AxumState<Arc<AppState>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    let provided = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim)
        .unwrap_or("");

    let expected = state.internal_token.as_str();
    let expected_bytes = expected.as_bytes();
    let provided_bytes = provided.as_bytes();
    let byte_diff = expected_bytes
        .iter()
        .enumerate()
        .fold(0u8, |acc, (i, &eb)| {
            let pb = provided_bytes.get(i).copied().unwrap_or(0);
            acc | (eb ^ pb)
        });
    let len_diff: u8 = if provided_bytes.len() == expected_bytes.len() { 0 } else { 1 };
    let valid = (byte_diff | len_diff) == 0;

    if !valid {
        tracing::warn!(
            "require_internal_token: rejected request to {} — missing or invalid Bearer token",
            req.uri().path()
        );
        return (
            StatusCode::UNAUTHORIZED,
            AxumJson(serde_json::json!({
                "ok": false,
                "error": "unauthorized — internal endpoint requires Authorization: Bearer <token>",
                "hint": "read the token from $CONFIG_DIR/internal-token"
            })),
        )
            .into_response();
    }

    next.run(req).await
}

/// Re-implementation of `dns_rebinding_guard` for the lib crate context.
pub(crate) async fn dns_rebinding_guard(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    match req.headers().get("host").and_then(|v| v.to_str().ok()) {
        None => {
            tracing::warn!("DNS rebinding guard: missing Host header — request blocked");
            return (
                StatusCode::FORBIDDEN,
                AxumJson(serde_json::json!({"ok": false, "error": "request blocked — missing host header"})),
            )
                .into_response();
        }
        Some(host) => {
            let host_part = host.split(':').next().unwrap_or(host);
            if host_part != "127.0.0.1" && host_part != "localhost" && host_part != "[::1]" {
                tracing::warn!("DNS rebinding blocked: Host={}", host);
                return (
                    StatusCode::FORBIDDEN,
                    AxumJson(serde_json::json!({"ok": false, "error": "request blocked — invalid host"})),
                )
                    .into_response();
            }
        }
    }
    next.run(req).await
}

/// Re-implementation of `handle_get_permissions` for the lib crate context.
pub(crate) async fn handle_get_permissions(
    AxumState(state): AxumState<Arc<AppState>>,
) -> AxumJson<serde_json::Value> {
    let (defaults, overrides) = {
        let perms = state.permissions.read().await;
        (perms.defaults.clone(), perms.overrides.clone())
    };
    let permissions_path = format!("{}/tool-permissions.json", state.config_dir);
    let config_file_exists = std::path::Path::new(&permissions_path).exists();
    let permissions_source = if config_file_exists { "file" } else { "built-in-defaults" };
    tracing::debug!("GET /vault/permissions — returning current tool permissions");
    AxumJson(serde_json::json!({
        "ok": true,
        "defaults": defaults,
        "overrides": overrides,
        "config_file_exists": config_file_exists,
        "permissions_source": permissions_source,
        "configured_vault_folder": state.vault_folder,
        "note": "GET /vault/permissions — current tool permission configuration"
    }))
}
