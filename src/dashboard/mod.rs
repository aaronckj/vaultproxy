//! Dashboard web UI — served on a separate port for credential management.

pub mod api;
pub mod auth;

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;

use crate::proxy::AppState;
use auth::SessionStore;

// -------------------------------------------------------------------------- //
// DashboardState                                                               //
// -------------------------------------------------------------------------- //

#[derive(Clone)]
pub struct DashboardState {
    /// None in setup/locked mode before vault is initialized.
    pub app: Option<Arc<AppState>>,
    pub sessions: SessionStore,
    pub config_dir: String,
    pub pending_password: Arc<tokio::sync::RwLock<Option<String>>>,
    /// Setup/unlock password shared with the main polling loop.
    /// Dashboard writes here after successful setup/unlock; main reads it to decrypt credentials.
    /// Setup/unlock password shuttled from the dashboard handler to the
    /// polling loop. Wrapped in `Zeroizing<String>` so `Drop` zeroes the
    /// underlying bytes — a plain `String` would free the allocation
    /// without overwriting, leaving the password readable on the heap
    /// until the allocator reused the page. Matches the zeroize discipline
    /// applied to every other sensitive buffer in the codebase.
    pub unlock_password: Arc<tokio::sync::RwLock<Option<zeroize::Zeroizing<String>>>>,
    /// None in setup/locked mode (vault not yet unlocked); Some once the vault
    /// is operational. Credential audit requires a live vault connection.
    /// Only populated when both `dashboard` and `engine` features are enabled.
    #[cfg(feature = "engine")]
    pub cred_audit_orch: Option<
        Arc<
            crate::credential_audit::orchestrator::Orchestrator<
                crate::credential_audit::vw_adapter::VwAdapter,
            >,
        >,
    >,
    /// Placeholder when the `engine` feature is disabled.
    /// `#[allow(dead_code)]` suppresses the "never read" lint — the field exists
    /// for structural symmetry with the `engine`-enabled variant so that call
    /// sites don't need feature gates when constructing `DashboardState`.
    #[cfg(not(feature = "engine"))]
    #[allow(dead_code)]
    pub cred_audit_orch: Option<()>,
}

// -------------------------------------------------------------------------- //
// Router                                                                       //
// -------------------------------------------------------------------------- //

pub fn router(state: DashboardState) -> Router {
    // Public routes — no session required (login, setup, static assets).
    let public_routes = Router::new()
        .route("/login", get(login_page))
        .route("/login", post(handle_login))
        .route("/setup", get(setup_page))
        .route("/setup", post(handle_setup))
        .route("/unlock", get(unlock_page))
        .route("/reset", get(reset_page))
        .route("/api/setup/configure", post(api::handle_configure))
        .route("/api/setup/unlock", post(api::handle_unlock))
        .route("/api/setup/reset", post(api::handle_reset))
        .route("/api/setup/status", get(api::handle_setup_status))
        .route("/api/settings/setup-status", get(api::setup_status))
        .route("/static/{*path}", get(serve_static));

    // Authenticated API routes — require a valid session cookie.
    // Build the base routes first, then conditionally merge feature-gated routes.
    let api_routes_base = Router::new()
        .route("/api/status", get(api::status))
        .route("/api/items", get(api::items))
        .route("/api/sync", get(api::sync_history))
        .route("/api/sync-trigger", post(api::sync_trigger))
        .route("/api/events", get(api::sse_events))
        .route("/api/audit", get(api::audit))
        .route("/api/policies", get(api::list_policies))
        .route("/api/policies", post(api::save_policy))
        .route(
            "/api/policies/{id}",
            axum::routing::delete(api::delete_policy_handler),
        )
        .route("/api/approvals", get(api::list_approvals))
        .route("/api/approvals", post(api::respond_approval))
        .route("/api/settings/tpm", get(api::tpm_status))
        .route(
            "/api/settings/setup-vaultwarden",
            post(api::setup_vaultwarden),
        )
        .route(
            "/api/settings/setup-cloud",
            post(api::setup_cloud_credentials),
        )
        .route(
            "/api/settings/change-password",
            post(api::change_master_password),
        )
        .route("/api/settings/cloud", post(api::setup_cloud_via_dashboard))
        .route("/api/settings/notifications", get(api::notification_status))
        .route(
            "/api/settings/notifications/test",
            post(api::notification_test),
        )
        .route("/api/profiles", get(api::list_profiles))
        .route("/api/profiles", post(api::save_profiles_handler))
        .route("/api/permissions", get(api::get_permissions))
        .route("/api/permissions", post(api::save_permissions))
        .route("/api/audit-log", get(api::get_audit_log))
        .route(
            "/api/rotation/acknowledge-password",
            post(api::handle_acknowledge_password),
        )
        .route("/api/credentials", get(api::get_credentials))
        .route(
            "/api/credentials/vaultwarden",
            post(api::update_vaultwarden_password),
        )
        .route(
            "/api/credentials/cloud",
            post(api::update_cloud_credentials),
        )
        .route(
            "/api/credentials/cloud/remove",
            post(api::remove_cloud_credentials),
        )
        .route(
            "/api/credentials/cloud/apikey",
            post(api::connect_cloud_apikey),
        );

    // iter-81: merge browser API routes only when the `browser` feature is on.
    // When off, the /api/browser/* paths return 404 (routes absent from router).
    #[cfg(feature = "browser")]
    let api_routes_base = {
        let browser_api = Router::new()
            .route("/api/browser/status", get(api::browser_status))
            .route("/api/browser/screenshot", get(api::browser_screenshot))
            .route("/api/browser/rotate", post(api::browser_rotate))
            .route("/api/browser/abort", post(api::browser_abort));
        api_routes_base.merge(browser_api)
    };

    // iter-81: merge credaudit API routes only when the `engine` feature is on.
    // When off, the /api/credaudit/* paths return 404 (routes absent from router).
    #[cfg(feature = "engine")]
    let api_routes_base = {
        let credaudit_api = Router::new()
            .route("/api/credaudit/runs", get(api::credaudit_runs_list))
            .route(
                "/api/credaudit/runs/{run_id}",
                get(api::credaudit_run_detail),
            )
            .route("/api/credaudit/scan_start", post(api::credaudit_scan_start))
            .route("/api/credaudit/apply", post(api::credaudit_apply))
            .route(
                "/api/credaudit/telemetry/{run_id}",
                get(api::credaudit_telemetry),
            )
            .route(
                "/api/credaudit/verify_start",
                post(api::credaudit_verify_start),
            );
        api_routes_base.merge(credaudit_api)
    };

    let api_routes = api_routes_base.layer(middleware::from_fn_with_state(
        state.clone(),
        require_session,
    ));

    // Authenticated page routes — middleware redirects to /login on missing session.
    let page_routes = Router::new()
        .route("/", get(index_page))
        .route("/items", get(items_page))
        .route("/sync", get(sync_page))
        .route("/audit", get(audit_page))
        .route("/audit-runs", get(audit_runs_page))
        .route("/policies", get(policies_page))
        .route("/approvals", get(approvals_page))
        .route("/settings", get(settings_page))
        .route("/rotation", get(rotation_page))
        .route("/permissions", get(permissions_page))
        .route("/audit-log", get(audit_log_page))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_session_redirect,
        ));

    public_routes
        .merge(api_routes)
        .merge(page_routes)
        .layer(axum::middleware::from_fn(csrf_origin_check))
        .layer(axum::middleware::from_fn(security_headers))
        // Issue (iter-103): 404 body was missing "ok": false.
        .fallback(|| async {
            (
                StatusCode::NOT_FOUND,
                Json(json!({"ok": false, "error": "not found"})),
            )
        })
        .with_state(state)
}

// -------------------------------------------------------------------------- //
// Page serving                                                                 //
// -------------------------------------------------------------------------- //

/// Cached dashboard directory resolved from the binary's own path (…/target/{profile}/vault-proxy → …/dashboard).
/// Keeps the lookup independent of the process cwd, so a systemd unit without
/// `WorkingDirectory=` still finds the HTML templates.
fn exe_relative_dashboard() -> Option<&'static std::path::Path> {
    static DIR: std::sync::OnceLock<Option<std::path::PathBuf>> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        let exe = std::env::current_exe().ok()?;
        let parent = exe.parent()?.parent()?.parent()?; // release/ → target/ → vault-proxy/
        let dir = parent.join("dashboard");
        dir.is_dir().then_some(dir)
    })
    .as_deref()
}

/// Try `/app/dashboard/{name}` (Docker), then exe-relative `.../dashboard/{name}`,
/// then `./dashboard/{name}` (cwd fallback for `cargo run`).
///
/// Rejects path traversal attempts (e.g. `../../../etc/passwd`) and caps
/// the served file size at 1 MB — without the cap, a misconfigured
/// bind-mount that exposes a large file on the static path would be
/// slurped into a heap `String` on every request.
fn read_page(name: &str) -> Result<String, StatusCode> {
    // Block path traversal: reject any component that is ".." or starts with "/"
    if name.contains("..") || name.starts_with('/') || name.starts_with('\\') {
        return Err(StatusCode::BAD_REQUEST);
    }

    const MAX_STATIC_BYTES: u64 = 1_048_576; // 1 MB
    let mut candidates: Vec<String> = vec![format!("/app/dashboard/{}", name)];
    if let Some(dir) = exe_relative_dashboard() {
        candidates.push(dir.join(name).to_string_lossy().into_owned());
    }
    candidates.push(format!("./dashboard/{}", name));
    for candidate in candidates {
        let meta = match std::fs::metadata(&candidate) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !meta.is_file() {
            continue;
        }
        if meta.len() > MAX_STATIC_BYTES {
            tracing::warn!(
                "serve_static refusing oversized file {} ({} bytes > {})",
                candidate,
                meta.len(),
                MAX_STATIC_BYTES,
            );
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        match std::fs::read_to_string(&candidate) {
            Ok(contents) => return Ok(contents),
            Err(_) => continue,
        }
    }
    Err(StatusCode::NOT_FOUND)
}

fn serve_page(name: &str) -> Response {
    match read_page(name) {
        Ok(html) => Html(html).into_response(),
        Err(code) => code.into_response(),
    }
}

/// Serve static files with correct content types.
async fn serve_static(axum::extract::Path(path): axum::extract::Path<String>) -> Response {
    let content = match read_page(&path) {
        Ok(c) => c,
        Err(code) => return code.into_response(),
    };

    let content_type = if path.ends_with(".css") {
        "text/css"
    } else if path.ends_with(".js") {
        "application/javascript"
    } else if path.ends_with(".svg") {
        "image/svg+xml"
    } else if path.ends_with(".png") {
        "image/png"
    } else {
        "application/octet-stream"
    };

    ([(header::CONTENT_TYPE, content_type)], content).into_response()
}

// -------------------------------------------------------------------------- //
// Page handlers                                                                //
// -------------------------------------------------------------------------- //

async fn login_page() -> Response {
    serve_page("login.html")
}

async fn setup_page() -> Response {
    serve_page("setup.html")
}

async fn unlock_page() -> Response {
    serve_page("unlock.html")
}

async fn reset_page() -> Response {
    serve_page("unlock.html")
}

// Page handlers — auth is enforced by the require_session_redirect middleware layer.
async fn index_page() -> Response {
    serve_page("index.html")
}
async fn items_page() -> Response {
    serve_page("items.html")
}
async fn sync_page() -> Response {
    serve_page("sync.html")
}
async fn audit_page() -> Response {
    serve_page("audit.html")
}
async fn audit_runs_page() -> Response {
    serve_page("audit-runs.html")
}
async fn policies_page() -> Response {
    serve_page("policies.html")
}
async fn approvals_page() -> Response {
    serve_page("approvals.html")
}
async fn settings_page() -> Response {
    serve_page("settings.html")
}
async fn rotation_page() -> Response {
    serve_page("rotation.html")
}
async fn permissions_page() -> Response {
    serve_page("permissions.html")
}
async fn audit_log_page() -> Response {
    serve_page("audit-log.html")
}

// -------------------------------------------------------------------------- //
// Auth handlers                                                                //
// -------------------------------------------------------------------------- //

#[derive(Deserialize)]
pub struct LoginRequest {
    pub password: String,
}

async fn handle_login(
    State(state): State<DashboardState>,
    payload: Result<Json<LoginRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(req) = match payload {
        Ok(j) => j,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid request"})),
            )
                .into_response()
        }
    };
    match state.sessions.login(&req.password).await {
        Ok(session_id) => {
            let cookie = format!(
                "session={}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400",
                session_id
            );
            ([(header::SET_COOKIE, cookie)], Json(json!({ "ok": true }))).into_response()
        }
        Err(e) => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "ok": false, "error": e })),
        )
            .into_response(),
    }
}

async fn handle_setup(
    State(state): State<DashboardState>,
    payload: Result<Json<LoginRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(req) = match payload {
        Ok(j) => j,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid request"})),
            )
                .into_response()
        }
    };

    if state.sessions.is_configured().await {
        return (
            StatusCode::CONFLICT,
            Json(json!({ "ok": false, "error": "password already configured" })),
        )
            .into_response();
    }

    // Shared strength policy with the CLI setup path — 12 chars + at least
    // two character classes. Matches iter-16's `validate_setup_password`.
    if let Err(e) = crate::setup::validate_setup_password(&req.password) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "error": e.to_string() })),
        )
            .into_response();
    }

    match state.sessions.set_password(&req.password).await {
        Ok(()) => {
            // Auto-login after setup.
            match state.sessions.login(&req.password).await {
                Ok(session_id) => {
                    let cookie = format!(
                        "session={}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400",
                        session_id
                    );
                    ([(header::SET_COOKIE, cookie)], Json(json!({ "ok": true }))).into_response()
                }
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "ok": false, "error": e })),
                )
                    .into_response(),
            }
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "error": e })),
        )
            .into_response(),
    }
}

// -------------------------------------------------------------------------- //
// Security headers middleware                                                  //
// -------------------------------------------------------------------------- //

/// CSRF origin check — rejects state-changing POST/PUT/DELETE requests to /api/*
/// unless the Origin or Referer header matches the dashboard host.
///
/// SameSite=Strict cookies already prevent cross-origin cookie attachment in
/// modern browsers, but this adds defense-in-depth for older browsers and
/// non-browser API clients that attach cookies manually.
async fn csrf_origin_check(req: Request, next: Next) -> Response {
    let method = req.method().clone();

    // Only check state-changing methods.
    let needs_check = method == axum::http::Method::POST
        || method == axum::http::Method::PUT
        || method == axum::http::Method::DELETE;

    let path = req.uri().path().to_string();

    // Only enforce on /api/* routes (not /login, /setup which are public forms).
    if needs_check && path.starts_with("/api/") {
        // On HTTP/2, hyper does NOT synthesize a `Host` header from the
        // `:authority` pseudo-header — the browser's TLS-ALPN negotiated
        // HTTP/2 against axum_server + rustls leaves `Host` absent. Fall
        // back to `req.uri().host()` (populated from `:authority` on h2).
        // Before iter-28 this combination 403'd every unlock POST with
        // "missing Host header" — iter-2 over-corrected a CSRF hole.
        let host_header = req
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .or_else(|| {
                req.uri().authority().map(|a| a.to_string()).or_else(|| {
                    req.uri().host().map(|h| match req.uri().port_u16() {
                        Some(p) => format!("{}:{}", h, p),
                        None => h.to_string(),
                    })
                })
            });

        let origin = req
            .headers()
            .get("origin")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let referer = req
            .headers()
            .get(header::REFERER)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        if let Some(ref host) = host_header {
            let origin_ok = origin
                .as_ref()
                .map(|o| {
                    // Origin is scheme://host[:port] — extract the host part.
                    o.split("://").nth(1).unwrap_or(o).trim_end_matches('/') == host
                })
                .unwrap_or(false);

            let referer_ok = referer
                .as_ref()
                .map(|r| {
                    // Referer is a full URL — extract the host.
                    url::Url::parse(r)
                        .ok()
                        .and_then(|u| {
                            u.host_str().map(|h| match u.port() {
                                Some(p) => format!("{}:{}", h, p),
                                None => h.to_string(),
                            })
                        })
                        .map(|rh| rh == *host)
                        .unwrap_or(false)
                })
                .unwrap_or(false);

            if !origin_ok && !referer_ok {
                tracing::warn!(
                    "CSRF check failed: {} {} (origin={:?}, referer={:?}, host={:?})",
                    method,
                    path,
                    origin,
                    referer,
                    host
                );
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({"error": "CSRF validation failed — origin mismatch"})),
                )
                    .into_response();
            }
        } else {
            // Real browsers always send Host on HTTP/1.1+. A hostless POST to
            // /api/* is either a misconfigured client or a CSRF attack using a
            // raw HTTP/1.0 request to dodge the origin/referer comparison —
            // reject it rather than fall through.
            tracing::warn!(
                "CSRF check rejected {} {}: missing Host header",
                method,
                path
            );
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "CSRF validation failed — missing Host header"})),
            )
                .into_response();
        }
    }

    next.run(req).await
}

/// Adds security headers to all dashboard responses.
async fn security_headers(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert("X-Frame-Options", "DENY".parse().unwrap());
    headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
    headers.insert("Referrer-Policy", "no-referrer".parse().unwrap());
    // No HSTS — self-signed cert on LAN, HSTS causes browser lockout
    // when cert changes on restart.
    headers.insert(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=(), payment=()"
            .parse()
            .unwrap(),
    );
    // Issue (iter-31): `unsafe-inline` is permitted for both script-src and
    // style-src because the dashboard HTML files contain inline <script> and
    // <style> blocks that would be blocked by a stricter policy.  This is a
    // known weakness: any XSS that injects inline script would not be stopped
    // by the CSP.  The correct fix is to extract all inline JS/CSS into
    // separate .js/.css files served under `/static/`, then tighten this header
    // to `script-src 'self'` with no `unsafe-inline`.  Until that refactor is
    // complete the inline allowance is intentional and documented here so it
    // is not accidentally "fixed" by removing the CSP header entirely.
    headers.insert(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
            .parse()
            .unwrap(),
    );
    response
}

// -------------------------------------------------------------------------- //
// API auth middleware                                                          //
// -------------------------------------------------------------------------- //

/// Axum middleware that rejects API requests without a valid session cookie.
/// Returns 401 Unauthorized as JSON instead of redirecting (for API callers).
async fn require_session(
    State(state): State<DashboardState>,
    req: Request,
    next: Next,
) -> Response {
    if !check_session(&state, req.headers()).await {
        // Issue (iter-103): 401 body was missing "ok": false.
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "ok": false, "error": "authentication required" })),
        )
            .into_response();
    }
    next.run(req).await
}

/// Axum middleware for page routes — redirects to the most appropriate entry
/// point based on system state:
///  - keystore not configured → `/setup`
///  - keystore locked          → `/unlock`
///  - unlocked + no session    → `/login`
///  - has session              → pass through to the requested page.
///
/// Before iter-30, a fresh restart dumped the user on `/login` even when the
/// keystore was locked. Entering the password on `/login` failed silently
/// (it's a dashboard-session check, not a keystore unlock), so the user had
/// to manually navigate to `/unlock` every time. Smart-routing `/` removes
/// that ceremony — one URL, right destination.
async fn require_session_redirect(
    State(state): State<DashboardState>,
    req: Request,
    next: Next,
) -> Response {
    if check_session(&state, req.headers()).await {
        return next.run(req).await;
    }
    // No session — figure out why the user isn't authenticated and
    // redirect to the page that will resolve the actual blocker.
    if !crate::keystore::is_configured(&state.config_dir) {
        return axum::response::Redirect::to("/setup").into_response();
    }
    // `state.app` is None while we're still in dashboard-only mode (keystore
    // exists but VaultManager hasn't been built yet) — that's the "locked"
    // state from the user's perspective.
    if state.app.is_none() {
        return axum::response::Redirect::to("/unlock").into_response();
    }
    redirect_login()
}

// -------------------------------------------------------------------------- //
// Helpers                                                                      //
// -------------------------------------------------------------------------- //

/// Extract session cookie and validate it.
async fn check_session(state: &DashboardState, headers: &axum::http::HeaderMap) -> bool {
    let cookie_header = match headers.get(header::COOKIE) {
        Some(v) => match v.to_str() {
            Ok(s) => s.to_string(),
            Err(_) => return false,
        },
        None => return false,
    };

    for part in cookie_header.split(';') {
        let part = part.trim();
        if let Some(val) = part.strip_prefix("session=") {
            return state.sessions.is_valid(val).await;
        }
    }

    false
}

fn redirect_login() -> Response {
    (StatusCode::SEE_OTHER, [(header::LOCATION, "/login")], "").into_response()
}
