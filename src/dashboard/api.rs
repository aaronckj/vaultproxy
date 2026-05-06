//! Dashboard JSON API handlers.

use axum::{
    extract::State,
    http::StatusCode,
    response::sse::{Event, Sse},
    Json,
};
// Path is only used by the cfg(feature = "engine") credaudit handlers.
#[cfg(feature = "engine")]
use axum::extract::Path;
use serde_json::{json, Value};
use std::convert::Infallible;
use tokio_stream::StreamExt as _;

use zeroize::Zeroize;

use serde::Deserialize;

use super::DashboardState;
use crate::proxy::AppState;
use std::sync::Arc;

/// Helper: get the AppState or return 503 if vault not initialized yet.
///
/// Issue (iter-105): The error body lacked `"ok": false`. All 15 handlers that
/// call `require_app` and early-return on `Err(e)` will return HTTP 200 (because
/// the return type is `Json<Value>`) with an error body that was missing the
/// standard `"ok": false` field. Fixed here so all callers gain the field at once.
fn require_app(state: &DashboardState) -> Result<&Arc<AppState>, Json<Value>> {
    state.app.as_ref().ok_or_else(|| {
        Json(json!({"ok": false, "error": "vault not initialized — complete setup first"}))
    })
}

// -------------------------------------------------------------------------- //
// Password rotation acknowledgment                                            //
// -------------------------------------------------------------------------- //

#[derive(Deserialize)]
pub struct AcknowledgePasswordRequest {
    pub acknowledged: bool,
}

/// `POST /api/rotation/acknowledge-password` — acknowledge or retrieve a pending
/// generated password. When `acknowledged: true`, clears the pending password.
/// When `acknowledged: false`, returns the pending password (if any).
pub async fn handle_acknowledge_password(
    State(state): State<DashboardState>,
    Json(req): Json<AcknowledgePasswordRequest>,
) -> Json<Value> {
    if req.acknowledged {
        let mut pending = state.pending_password.write().await;
        *pending = None;
        Json(json!({"ok": true}))
    } else {
        let pending = state.pending_password.read().await;
        match pending.as_ref() {
            Some(pw) => Json(json!({"ok": true, "password": pw})),
            None => Json(json!({"ok": false, "error": "no pending password"})),
        }
    }
}

// -------------------------------------------------------------------------- //
// Status                                                                      //
// -------------------------------------------------------------------------- //

/// `GET /api/status` — vault item count, sync status, service list.
pub async fn status(State(state): State<DashboardState>) -> Json<Value> {
    let app = match require_app(&state) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let items = app.vault.list_items().await;
    let services = app
        .registry
        .read()
        .await
        .list()
        .into_iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();

    let cloud_sync = match &app.cloud_sync {
        Some(sync) => {
            let st = sync.get_status().await;
            json!({
                "state": st.state,
                "last_sync": st.last_sync,
                "items_synced": st.items_synced,
            })
        }
        None => json!({ "state": "not_configured" }),
    };

    Json(json!({
        "ok": true,
        "vault_items": items.len(),
        "cloud_sync": cloud_sync,
        "services": services,
    }))
}

// -------------------------------------------------------------------------- //
// Items                                                                       //
// -------------------------------------------------------------------------- //

/// `GET /api/items` — masked vault items list.
pub async fn items(State(state): State<DashboardState>) -> Json<Value> {
    let app = match require_app(&state) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let items = app.vault.list_items().await;
    let items_val = serde_json::to_value(items).unwrap_or(json!([]));
    Json(json!({"ok": true, "items": items_val}))
}

// -------------------------------------------------------------------------- //
// Sync history                                                                //
// -------------------------------------------------------------------------- //

/// `GET /api/sync` — sync state, last sync, errors.
pub async fn sync_history(State(state): State<DashboardState>) -> Json<Value> {
    let app = match require_app(&state) {
        Ok(a) => a,
        Err(e) => return e,
    };
    match &app.cloud_sync {
        Some(sync) => {
            let st = sync.get_status().await;
            Json(json!({
                "ok": true,
                "state": st.state,
                "last_sync": st.last_sync,
                "items_synced": st.items_synced,
                "errors": st.errors,
            }))
        }
        None => Json(json!({
            "ok": true,
            "state": "not_configured",
            "last_sync": null,
            "items_synced": 0,
            "errors": [],
        })),
    }
}

// -------------------------------------------------------------------------- //
// Sync trigger                                                                //
// -------------------------------------------------------------------------- //

/// `POST /api/sync-trigger` — kick off a full cloud sync immediately.
pub async fn sync_trigger(State(state): State<DashboardState>) -> (StatusCode, Json<Value>) {
    let app = match require_app(&state) {
        Ok(a) => a,
        Err(e) => return (StatusCode::SERVICE_UNAVAILABLE, e),
    };
    match &app.cloud_sync {
        Some(sync) => {
            let sync = sync.clone();
            tokio::spawn(async move {
                if let Err(e) = sync.full_sync().await {
                    tracing::error!("dashboard-triggered sync failed: {:#}", e);
                }
            });
            (
                StatusCode::ACCEPTED,
                Json(json!({ "ok": true, "message": "sync started" })),
            )
        }
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "ok": false, "error": "cloud sync not configured" })),
        ),
    }
}

// -------------------------------------------------------------------------- //
// SSE                                                                         //
// -------------------------------------------------------------------------- //

/// `GET /api/events` — Server-Sent Events stream.
///
/// Emits a heartbeat every 5 seconds.  The frontend re-fetches `/api/status`
/// on each tick so it always shows fresh data without polling on its own timer.
pub async fn sse_events(
    State(_state): State<DashboardState>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let stream = tokio_stream::wrappers::IntervalStream::new(tokio::time::interval(
        std::time::Duration::from_secs(5),
    ))
    .map(|_| {
        let data = serde_json::json!({ "type": "heartbeat" });
        Ok::<Event, Infallible>(Event::default().data(data.to_string()))
    });

    Sse::new(stream)
}

// -------------------------------------------------------------------------- //
// Placeholders                                                                //
// -------------------------------------------------------------------------- //

pub async fn audit(State(state): State<DashboardState>) -> Json<Value> {
    let app = match require_app(&state) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let result = crate::audit::run_audit(&app.vault).await;
    Json(serde_json::to_value(result).unwrap_or_default())
}

pub async fn list_policies(State(_state): State<DashboardState>) -> Json<Value> {
    // Issue (iter-112): Response was a bare `serde_json::to_value(policies)` array
    // with no `"ok": true` sentinel, inconsistent with all other collection endpoints
    // in the dashboard API. Wrapped in `{"ok": true, "policies": [...]}`.
    // policies.html updated in iter-112 to read `data.policies ?? []`.
    let policies = crate::policy::load_policies("/config/policies.json");
    Json(serde_json::json!({"ok": true, "policies": policies}))
}

pub async fn save_policy(
    State(state): State<DashboardState>,
    Json(policy): Json<crate::policy::Policy>,
) -> Json<Value> {
    if let Err(e) = state.sessions.check_config_write_rate().await {
        return Json(serde_json::json!({"ok": false, "error": e}));
    }
    let mut policies = crate::policy::load_policies("/config/policies.json");
    if let Some(existing) = policies.iter_mut().find(|p| p.id == policy.id) {
        *existing = policy;
    } else {
        policies.push(policy);
    }
    match crate::policy::save_policies("/config/policies.json", &policies) {
        Ok(()) => Json(serde_json::json!({"ok": true})),
        // Issue (iter-105): missing "ok": false on save failure.
        Err(e) => Json(serde_json::json!({"ok": false, "error": e.to_string()})),
    }
}

pub async fn delete_policy_handler(
    State(state): State<DashboardState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Json<Value> {
    // Same config-write rate limit as `save_policy` — without this a
    // stolen-session attacker could DELETE the entire policy list faster
    // than the 60s shared rate-limit window could catch via the POST path.
    if let Err(e) = state.sessions.check_config_write_rate().await {
        return Json(serde_json::json!({"ok": false, "error": e}));
    }
    match crate::policy::delete_policy("/config/policies.json", &id) {
        Ok(()) => Json(serde_json::json!({"ok": true})),
        // Issue (iter-105): missing "ok": false on delete failure.
        Err(e) => Json(serde_json::json!({"ok": false, "error": e.to_string()})),
    }
}

// -------------------------------------------------------------------------- //
// Approvals                                                                  //
// -------------------------------------------------------------------------- //

/// `GET /api/approvals` — list pending 2FA approval requests. Also purges
/// expired entries and any screenshot blobs attached to resolved requests so
/// the queue doesn't grow unbounded and long-lived screenshots (which can
/// contain pre-filled password fields or TOTP codes) are not served
/// indefinitely.
pub async fn list_approvals(State(state): State<DashboardState>) -> Json<Value> {
    let app = match require_app(&state) {
        Ok(a) => a,
        Err(e) => return e,
    };

    let now = chrono::Utc::now();
    {
        let mut queue = app.approval_queue.write().await;
        // Drop entries whose expires_at is in the past.
        queue.retain(|r| {
            chrono::DateTime::parse_from_rfc3339(&r.expires_at)
                .map(|e| e.with_timezone(&chrono::Utc) > now)
                .unwrap_or(false)
        });
        // Scrub screenshot bytes from resolved (approved/denied) entries —
        // keep the metadata for auditing but drop the credential-adjacent
        // image bytes.
        for r in queue.iter_mut() {
            if r.status != "pending" {
                r.screenshot_b64 = None;
            }
        }
    }

    let queue = app.approval_queue.read().await;
    let pending: Vec<_> = queue.iter().filter(|a| a.status == "pending").collect();
    // iter-122: wrap in {"ok":true,"approvals":[...]} envelope for consistency with all
    // other dashboard collection endpoints. Previously returned a bare JSON array;
    // approvals.html JS updated to unwrap the "approvals" key.
    //
    // iter-123: use Value::Array([]) as fallback instead of unwrap_or_default() which
    // returns Value::Null on serialization failure. Array.isArray(null) is false in JS,
    // so a null approvals field would silently render an empty queue rather than an error.
    // Vec<_> serialization to a JSON array is infallible in practice, but the explicit
    // fallback documents the invariant and avoids the null footgun.
    let approvals_val =
        serde_json::to_value(&pending).unwrap_or_else(|_| serde_json::Value::Array(vec![]));
    Json(json!({"ok": true, "approvals": approvals_val}))
}

#[derive(serde::Deserialize)]
pub struct ApprovalResponse {
    pub id: String,
    pub action: String, // "approve" or "deny"
    pub code: Option<String>,
}

/// `POST /api/approvals` — approve or deny a pending 2FA request.
pub async fn respond_approval(
    State(state): State<DashboardState>,
    Json(req): Json<ApprovalResponse>,
) -> Json<Value> {
    let app = match require_app(&state) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let mut queue = app.approval_queue.write().await;
    if let Some(item) = queue.iter_mut().find(|a| a.id == req.id) {
        item.status = req.action;
        item.response = req.code;
        // Scrub screenshot on resolution — once approved/denied there is no
        // UX reason to keep the base64 image, and it may contain a
        // pre-filled password field or a visible TOTP code.
        item.screenshot_b64 = None;
        Json(serde_json::json!({"ok": true}))
    } else {
        // Issue (iter-105): missing "ok": false on the "not found" path.
        Json(serde_json::json!({"ok": false, "error": "approval not found"}))
    }
}

// -------------------------------------------------------------------------- //
// Master password change                                                      //
// -------------------------------------------------------------------------- //

#[derive(serde::Deserialize)]
pub struct ChangePasswordRequest {
    // mode/new_password/length are part of the API spec but the handler
    // currently returns 503 pending keystore reencryption implementation.
    #[allow(dead_code)]
    pub mode: String,
    #[allow(dead_code)]
    pub new_password: Option<String>,
    #[allow(dead_code)]
    pub length: Option<usize>,
}

/// `POST /api/settings/change-password` — change the Bitwarden cloud master password.
pub async fn change_master_password(
    State(_state): State<DashboardState>,
    Json(_req): Json<ChangePasswordRequest>,
) -> (StatusCode, Json<Value>) {
    // TODO: implement password change through keystore reencryption. The old
    // cloud_vault.sealed TPM path is no longer used in the new architecture.
    // Until this is re-implemented, return a clear error rather than silently
    // failing or reading from a stale sealed blob.
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(
            json!({"ok": false, "error": "password change requires keystore — use the keystore setup wizard"}),
        ),
    )
}

/// Generate a cryptographically random password with mixed case letters, digits, and symbols.
/// Used by the password rotation workflow; currently unused pending wiring to the rotation UI.
#[allow(dead_code)]
fn generate_password(length: usize) -> String {
    use rand::rngs::OsRng;
    use rand::Rng;
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz\
                              ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                              0123456789\
                              !@#$%^&*()-_=+[]{}|;:,.<>?";
    let mut rng = OsRng;
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

// -------------------------------------------------------------------------- //
// Settings                                                                    //
// -------------------------------------------------------------------------- //

/// `GET /api/settings/tpm` — TPM availability and keystore file status.
pub async fn tpm_status(State(state): State<DashboardState>) -> Json<Value> {
    let tpm = crate::tpm::tpm_available();
    let dir = &state.config_dir;
    // New keystore architecture: one TPM-sealed private key + encrypted blobs.
    let keystore_files = [
        ("private_key.sealed", "TPM-sealed private key"),
        ("credentials.enc", "Encrypted credentials"),
        ("private_key.enc", "Encrypted private key (no-TPM fallback)"),
        ("public_key.pem", "Public key"),
    ];
    let sealed: Vec<serde_json::Value> = keystore_files
        .iter()
        .map(|(name, label)| {
            let path = std::path::Path::new(dir).join(name);
            serde_json::json!({
                "name": label,
                "exists": path.exists()
            })
        })
        .collect();

    Json(serde_json::json!({
        "ok": true,
        "tpm_available": tpm,
        "sealed_credentials": sealed,
    }))
}

// -------------------------------------------------------------------------- //
// Browser agent (feature = "browser" only)                                   //
// -------------------------------------------------------------------------- //

/// `GET /api/browser/status` — current browser agent job state.
#[cfg(feature = "browser")]
pub async fn browser_status(State(state): State<DashboardState>) -> Json<Value> {
    let app = match require_app(&state) {
        Ok(a) => a,
        Err(e) => return e,
    };
    match app.browser.as_ref() {
        Some(browser) => {
            let job = browser.current_job.read().await;
            match &*job {
                Some(ws) => Json(serde_json::to_value(ws).unwrap_or_default()),
                None => Json(json!({"ok": true, "status": "idle"})),
            }
        }
        None => Json(json!({"ok": true, "status": "not_configured"})),
    }
}

/// `GET /api/browser/screenshot` — last screenshot from browser agent.
///
/// Issue (iter-105): `None` (browser not configured) returned `{"error": "not configured"}`
/// without `"ok": false`. Fixed to match the `main.rs` handler convention.
#[cfg(feature = "browser")]
pub async fn browser_screenshot(State(state): State<DashboardState>) -> Json<Value> {
    let app = match require_app(&state) {
        Ok(a) => a,
        Err(e) => return e,
    };
    match app.browser.as_ref() {
        Some(browser) => {
            let ss = browser.last_screenshot.read().await;
            Json(json!({"ok": true, "image_b64": ss.as_deref()}))
        }
        None => Json(json!({"ok": false, "error": "browser agent not configured"})),
    }
}

/// `POST /api/browser/rotate` — start a password rotation via browser agent.
///
/// Issue (iter-105): Network-error path returned `{"error": "..."}` without
/// `"ok": false`. Fixed for body-shape consistency.
#[cfg(feature = "browser")]
pub async fn browser_rotate(
    State(state): State<DashboardState>,
    Json(req): Json<Value>,
) -> Json<Value> {
    let app = match require_app(&state) {
        Ok(a) => a,
        Err(e) => return e,
    };
    match app
        .http
        .post("http://127.0.0.1:3201/browser/rotate")
        .json(&req)
        .send()
        .await
    {
        Ok(res) => Json(res.json().await.unwrap_or_default()),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

/// `POST /api/browser/abort` — abort the current browser agent job.
///
/// Issue (iter-105): The network-error path returned `{"error": "..."}` without
/// `"ok": false`. Fixed for consistency with all other error bodies.
#[cfg(feature = "browser")]
pub async fn browser_abort(State(state): State<DashboardState>) -> Json<Value> {
    let app = match require_app(&state) {
        Ok(a) => a,
        Err(e) => return e,
    };
    match app
        .http
        .post("http://127.0.0.1:3201/browser/abort")
        .send()
        .await
    {
        Ok(res) => Json(res.json().await.unwrap_or_default()),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

// -------------------------------------------------------------------------- //
// First-time setup                                                            //
// -------------------------------------------------------------------------- //

/// `GET /api/settings/setup-status` — check if vault credentials are configured.
pub async fn setup_status(State(state): State<DashboardState>) -> Json<Value> {
    // New architecture: check for keystore files rather than old sealed blobs.
    let configured = crate::keystore::is_configured(&state.config_dir);

    Json(json!({
        "ok": true,
        "vaultwarden_configured": configured,
        "cloud_configured": configured,
        "tpm_available": crate::tpm::tpm_available(),
        "needs_setup": !configured,
    }))
}

#[derive(serde::Deserialize)]
pub struct VaultwardenSetupRequest {
    pub url: String,
    pub email: String,
    pub master_password: String,
}

/// `POST /api/settings/setup-vaultwarden` — validate and seal Vaultwarden credentials.
pub async fn setup_vaultwarden(
    State(_state): State<DashboardState>,
    Json(req): Json<VaultwardenSetupRequest>,
) -> (StatusCode, Json<Value>) {
    let url = req.url.trim_end_matches('/').to_string();
    let email = req.email.trim().to_string();
    let mut master_password = req.master_password.clone();

    if url.is_empty() || email.is_empty() || master_password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "URL, email, and master password are all required"})),
        );
    }

    // Build an HTTP client that tolerates self-signed certs AND has a 30s
    // timeout so a slow/unresponsive Vaultwarden doesn't hang the setup
    // handler indefinitely — previously only `danger_accept_invalid_certs`
    // was set.
    let http = match reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "error": format!("failed to build HTTP client: {}", e)})),
            );
        }
    };

    // Step 1: prelogin — get KDF iterations.
    #[derive(serde::Serialize)]
    struct PreloginReq<'a> {
        email: &'a str,
    }
    let prelogin_url = format!("{}/identity/accounts/prelogin", url);
    let prelogin_resp = match http
        .post(&prelogin_url)
        .json(&PreloginReq { email: &email })
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(
                    json!({"ok": false, "error": format!("could not reach Vaultwarden at {}: {}", url, e)}),
                ),
            );
        }
    };

    if !prelogin_resp.status().is_success() {
        let status = prelogin_resp.status();
        let body = prelogin_resp.text().await.unwrap_or_default();
        return (
            StatusCode::BAD_GATEWAY,
            Json(json!({"ok": false, "error": format!("prelogin failed ({}): {}", status, body)})),
        );
    }

    let prelogin_body: serde_json::Value = match prelogin_resp.json().await {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(
                    json!({"ok": false, "error": format!("failed to parse prelogin response: {}", e)}),
                ),
            );
        }
    };

    let iterations = prelogin_body
        .get("kdfIterations")
        .or_else(|| prelogin_body.get("KdfIterations"))
        .and_then(|v| v.as_u64())
        .unwrap_or(600_000) as u32;

    // Step 2: derive master key + password hash.
    let master_key = crate::vault::crypto::derive_master_key(&master_password, &email, iterations);
    let password_hash =
        crate::vault::crypto::hash_master_password(master_key.as_bytes(), &master_password);

    // Step 3: token request to validate credentials.
    let params = [
        ("grant_type", "password"),
        ("username", email.as_str()),
        ("password", password_hash.as_str()),
        ("scope", "api offline_access"),
        ("client_id", "web"),
        ("deviceType", "10"),
        ("deviceIdentifier", "connecterr-vault-proxy-setup"),
        ("deviceName", "Connecterr Vault Proxy Setup"),
    ];

    let token_url = format!("{}/identity/connect/token", url);
    let token_resp = match http.post(&token_url).form(&params).send().await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"ok": false, "error": format!("token request failed: {}", e)})),
            );
        }
    };

    if !token_resp.status().is_success() {
        let status = token_resp.status();
        let _body = token_resp.text().await.unwrap_or_default();
        return (
            StatusCode::UNAUTHORIZED,
            Json(
                json!({"ok": false, "error": format!("authentication failed ({}): invalid email or master password", status)}),
            ),
        );
    }

    // Credentials are valid. The old vault.sealed TPM path is replaced by the
    // new keystore setup wizard. Direct credential storage via this endpoint is
    // no longer supported — use POST /api/setup/configure instead.
    tracing::warn!(
        "setup_vaultwarden endpoint called but direct TPM sealing is no longer supported; \
         use the keystore setup wizard at /api/setup/configure"
    );
    master_password.zeroize();

    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "message": "Credentials validated. Use the keystore setup wizard to persist them."
        })),
    )
}

#[derive(serde::Deserialize)]
pub struct CloudSetupRequest {
    pub email: String,
    pub master_password: String,
    pub totp_code: Option<String>,
    pub kdf_iterations: Option<u32>,
}

/// `POST /api/settings/setup-cloud` — full Bitwarden cloud login with 2FA support.
///
/// Authenticates with email + password + optional TOTP, gets a refresh token,
/// seals everything to TPM. No CLI needed.
pub async fn setup_cloud_credentials(
    State(state): State<DashboardState>,
    Json(req): Json<CloudSetupRequest>,
) -> (StatusCode, Json<Value>) {
    let email = req.email.trim().to_string();
    let mut master_password = req.master_password.clone();
    let totp_code = req
        .totp_code
        .as_deref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());
    let kdf_override = req.kdf_iterations;

    if email.is_empty() || master_password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "email and master password are required"})),
        );
    }

    let http = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("HTTP client build error: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "error": "internal HTTP client error"})),
            );
        }
    };

    // Step 1: Prelogin to get KDF iterations
    let prelogin_resp = match http
        .post("https://identity.bitwarden.com/accounts/prelogin")
        .json(&serde_json::json!({"email": email}))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Bitwarden prelogin request failed: {}", e);
            return (
                StatusCode::BAD_GATEWAY,
                Json(
                    json!({"ok": false, "error": "cannot reach Bitwarden — check network connectivity"}),
                ),
            );
        }
    };

    let prelogin: serde_json::Value = prelogin_resp.json().await.unwrap_or_default();
    let kdf_type = prelogin
        .get("kdfType")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    tracing::debug!("Bitwarden prelogin: kdfType={}", kdf_type);
    let kdf_iterations = kdf_override.unwrap_or_else(|| {
        prelogin
            .get("kdfIterations")
            .and_then(|v| v.as_u64())
            .unwrap_or(600_000) as u32
    });
    tracing::info!("using KDF iterations: {}", kdf_iterations);

    // Step 2: Derive master key and hash password. We deliberately do NOT log
    // `password_len` or any portion of the derived hash — even a 10-char
    // prefix plus known email + KDF params materially narrows an offline
    // attack, and these logs ship to stdout and any log aggregator.
    tracing::debug!("cloud auth starting for email={}", email);
    let master_key =
        crate::vault::crypto::derive_master_key(&master_password, &email, kdf_iterations);
    let pw_hash =
        crate::vault::crypto::hash_master_password(master_key.as_bytes(), &master_password);

    // Step 3: Token request with optional 2FA
    let mut params = vec![
        ("grant_type".to_string(), "password".to_string()),
        ("username".to_string(), email.clone()),
        ("password".to_string(), pw_hash),
        ("scope".to_string(), "api offline_access".to_string()),
        ("client_id".to_string(), "web".to_string()),
        ("deviceType".to_string(), "10".to_string()),
        (
            "deviceIdentifier".to_string(),
            "connecterr-vault-proxy".to_string(),
        ),
        (
            "deviceName".to_string(),
            "Connecterr Vault Proxy".to_string(),
        ),
    ];

    if let Some(code) = totp_code {
        params.push(("twoFactorProvider".to_string(), "0".to_string()));
        params.push(("twoFactorToken".to_string(), code.to_string()));
        params.push(("twoFactorRemember".to_string(), "1".to_string()));
    }

    let resp = match http
        .post("https://identity.bitwarden.com/connect/token")
        .form(&params)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Bitwarden token request failed: {}", e);
            return (
                StatusCode::BAD_GATEWAY,
                Json(
                    json!({"ok": false, "error": "token request failed — check network connectivity"}),
                ),
            );
        }
    };

    if resp.status() == reqwest::StatusCode::BAD_REQUEST {
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        // Check if 2FA is required
        if body.get("TwoFactorProviders2").is_some() {
            return (
                StatusCode::OK,
                Json(json!({
                    "ok": false,
                    "needs_2fa": true,
                    "error": "Two-factor authentication required. Enter your TOTP code and try again."
                })),
            );
        }
        tracing::warn!("Bitwarden auth failed (400): {:?}", body);
        return (
            StatusCode::OK,
            Json(
                json!({"ok": false, "error": "Authentication failed — check credentials and try again"}),
            ),
        );
    }

    let resp_status = resp.status();
    if !resp_status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        tracing::warn!("Bitwarden auth failed ({}): {}", resp_status, body);
        return (
            StatusCode::OK,
            Json(
                json!({"ok": false, "error": "Authentication failed — check credentials and try again"}),
            ),
        );
    }

    // Step 4: Extract refresh token
    #[derive(serde::Deserialize)]
    struct TokenResp {
        refresh_token: Option<String>,
        // two_factor_token is present in some Bitwarden responses; parsed for
        // completeness but not yet forwarded to the 2FA handler.
        #[allow(dead_code)]
        #[serde(rename = "TwoFactorToken")]
        two_factor_token: Option<String>,
    }

    let token_data: TokenResp = match resp.json().await {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("failed to parse Bitwarden token response: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "error": "failed to parse authentication response"})),
            );
        }
    };

    let refresh_token = match token_data.refresh_token {
        Some(rt) => rt,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "error": "no refresh token in response"})),
            )
        }
    };

    tracing::info!("authenticated to Bitwarden cloud via dashboard");

    // Save cloud credentials + refresh token to keystore
    let config_dir = &state.config_dir;
    match crate::keystore::unlock_keystore(config_dir, None) {
        Ok(mut creds) => {
            creds.cloud = Some(crate::keystore::CloudCreds {
                email: email.clone(),
                master_password: master_password.clone(),
                refresh_token: Some(refresh_token),
                api_client_id: creds.cloud.as_ref().and_then(|c| c.api_client_id.clone()),
                api_client_secret: creds
                    .cloud
                    .as_ref()
                    .and_then(|c| c.api_client_secret.clone()),
                kdf_iterations: creds.cloud.as_ref().and_then(|c| c.kdf_iterations),
            });
            if let Err(e) = crate::keystore::reencrypt_credentials(config_dir, &creds) {
                tracing::error!("failed to save cloud credentials to keystore: {}", e);
            } else {
                tracing::info!("cloud credentials + refresh token saved to keystore");
            }
        }
        Err(e) => {
            tracing::warn!("could not unlock keystore to save cloud creds: {} — credentials authenticated but not persisted", e);
        }
    }

    master_password.zeroize();

    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "message": "Bitwarden cloud connected! Restart to activate cloud sync.",
            "kdf_iterations": kdf_iterations,
        })),
    )
}

// -------------------------------------------------------------------------- //
// Tool Permissions                                                            //
// -------------------------------------------------------------------------- //

/// `GET /api/permissions` — returns current tool permissions and known tools.
pub async fn get_permissions(State(state): State<DashboardState>) -> Json<Value> {
    let app = match require_app(&state) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let perms = app.permissions.read().await;

    // Gather all known tool names from the registry (services) and
    // a static list of MCP module tools.
    let known_tools = get_known_tool_list();

    let tools: Vec<Value> = known_tools
        .iter()
        .map(|name| {
            let permission = perms.get_permission(name);
            let default_permission = perms.get_default_permission(name);
            let category = perms.get_category(name);
            json!({
                "name": name,
                "permission": permission,
                "default_permission": default_permission,
                "category": category,
            })
        })
        .collect();

    // iter-121: mirror the configured_vault_folder field already present in
    // GET /vault/permissions (main.rs iter-120) and GET /vault/folders / GET /sync/status
    // (iter-115/117). Allows operators to confirm the scope from the dashboard UI.
    let vault_folder = app.vault_folder.clone();

    Json(json!({
        "ok": true,
        "tools": tools,
        "overrides": perms.overrides.clone(),
        "configured_vault_folder": vault_folder,
    }))
}

/// `POST /api/permissions` — save permission overrides AND hot-reload the
/// in-memory copy so subsequent proxy calls see the new policy immediately.
/// Previously this only wrote to disk; the live `AppState.permissions` kept
/// the startup-loaded snapshot until container restart, silently ignoring
/// operator edits.
pub async fn save_permissions(
    State(state): State<DashboardState>,
    Json(req): Json<Value>,
) -> Json<Value> {
    if let Err(e) = state.sessions.check_config_write_rate().await {
        return Json(json!({"ok": false, "error": e}));
    }
    let overrides: std::collections::HashMap<String, crate::security::permissions::Permission> =
        match serde_json::from_value(req.get("overrides").cloned().unwrap_or(json!({}))) {
            Ok(o) => o,
            Err(e) => {
                return Json(json!({"ok": false, "error": format!("invalid overrides: {}", e)}))
            }
        };

    let perms = crate::security::permissions::ToolPermissions {
        overrides,
        ..crate::security::permissions::ToolPermissions::default()
    };

    if let Err(e) = perms.save("/config/tool-permissions.json") {
        return Json(json!({"ok": false, "error": e.to_string()}));
    }

    // Hot-reload into the live AppState if one is attached. The dashboard
    // may run in locked-mode without an AppState — skip silently in that
    // case since there's no live proxy path to reload.
    if let Some(ref app) = state.app {
        *app.permissions.write().await = perms;
    }

    Json(json!({"ok": true}))
}

// -------------------------------------------------------------------------- //
// Audit Log                                                                   //
// -------------------------------------------------------------------------- //

/// `GET /api/audit-log` — returns recent audit entries with optional filtering.
pub async fn get_audit_log(
    State(state): State<DashboardState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Json<Value> {
    let app = match require_app(&state) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let entries = app.audit_log.entries();

    let filtered: Vec<_> = entries
        .into_iter()
        .filter(|e| {
            if let Some(tool) = params.get("tool") {
                if !e.tool_name.contains(tool) {
                    return false;
                }
            }
            if let Some(trigger) = params.get("trigger") {
                if &e.trigger != trigger {
                    return false;
                }
            }
            true
        })
        .collect();

    // Cap the caller-supplied limit at 1000 (the in-memory MAX_ENTRIES
    // bound). Silently accepting any usize was a footgun — if someone
    // later removes the in-memory cap, the UI would consume unbounded
    // heap. Explicit ceiling documents the invariant.
    let limit: usize = params
        .get("limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(100)
        .min(1000);

    // Issue (iter-112): Response was `Json(serde_json::to_value(entries))` — a bare
    // JSON array with no `"ok": true` sentinel. All other collection success paths
    // in the dashboard API wrap in `{"ok": true, ...}`. The bare array worked for the
    // audit-log.html frontend which iterated the response directly; audit-log.html has
    // been updated in iter-112 to read `data.entries` instead.
    let entries: Vec<_> = filtered.into_iter().take(limit).collect();
    Json(serde_json::json!({"ok": true, "entries": entries}))
}

/// Return a static list of known MCP tool names for the permissions UI.
///
/// These MUST match the names returned by each module's `getTools()` on the
/// TS side. Mismatches cause a silent enforcement hole — a `deny` policy
/// against a stale name like `ssh__exec` never matches the real tool
/// (`ssh__run`), so the "block" button on the dashboard does nothing. Every
/// rename to a module tool must be mirrored here. iter-14 aligned 20+ stale
/// entries; new audits should diff this list against the TS tool registry.
fn get_known_tool_list() -> Vec<String> {
    vec![
        // net (src/modules/net/index.ts)
        "net__ping",
        "net__traceroute",
        "net__dns_lookup",
        "net__list_interfaces",
        "net__port_check",
        "net__scan",
        "net__mac_lookup",
        "net__wake",
        // ssh (src/modules/ssh/index.ts)
        "ssh__run",
        "ssh__list_hosts",
        "ssh__upload",
        "ssh__download",
        "ssh__service_status",
        "ssh__system_info",
        // unifi (src/modules/unifi/index.ts)
        "unifi__list_sites",
        "unifi__list_devices",
        "unifi__list_clients",
        "unifi__get_client",
        "unifi__block_client",
        "unifi__unblock_client",
        "unifi__restart_device",
        "unifi__list_networks",
        "unifi__list_firewall_rules",
        "unifi__create_firewall_rule",
        "unifi__list_port_forwards",
        "unifi__set_port_poe",
        "unifi__get_alerts",
        "unifi__get_events",
        "unifi__get_site_stats",
        "unifi__get_client_stats",
        // opnsense (src/modules/opnsense/index.ts)
        "opnsense__system_status",
        "opnsense__list_interfaces",
        "opnsense__list_vlans",
        "opnsense__list_firewall_rules",
        "opnsense__add_firewall_rule",
        "opnsense__delete_firewall_rule",
        "opnsense__apply_firewall",
        "opnsense__list_dhcp_leases",
        "opnsense__add_static_lease",
        "opnsense__list_dns_overrides",
        "opnsense__add_dns_override",
        "opnsense__apply_dns",
        "opnsense__list_port_forwards",
        "opnsense__add_port_forward",
        "opnsense__get_traffic",
        "opnsense__list_services",
        "opnsense__restart_service",
        // ha (src/modules/ha/index.ts)
        "ha__list_entities",
        "ha__get_state",
        "ha__call_service",
        "ha__list_services",
        "ha__get_history",
        "ha__list_addons",
        "ha__restart_addon",
        "ha__get_config",
        "ha__get_logbook",
        "ha__fire_event",
        "ha__render_template",
        "ha__create_automation",
        // media (src/modules/media/index.ts)
        "media__plex_status",
        "media__plex_libraries",
        "media__plex_now_playing",
        "media__plex_recent",
        "media__sonarr_series",
        "media__sonarr_add",
        "media__sonarr_queue",
        "media__sonarr_missing",
        "media__radarr_movies",
        "media__radarr_add",
        "media__radarr_queue",
        "media__radarr_missing",
        "media__overseerr_requests",
        "media__overseerr_request",
        "media__tautulli_activity",
        "media__tautulli_history",
        // docker (src/modules/docker/index.ts)
        "docker__list_containers",
        "docker__inspect",
        "docker__logs",
        "docker__start",
        "docker__stop",
        "docker__restart",
        "docker__stats",
        // npm (src/modules/npm/index.ts)
        "npm__list_proxy_hosts",
        "npm__get_proxy_host",
        "npm__add_proxy_host",
        "npm__update_proxy_host",
        "npm__delete_proxy_host",
        "npm__list_certificates",
        "npm__request_certificate",
        "npm__delete_certificate",
        "npm__list_redirections",
        "npm__add_redirection",
        "npm__delete_redirection",
        // vaultwarden (src/modules/vaultwarden/index.ts)
        "vaultwarden__list_items",
        "vaultwarden__get_item",
        "vaultwarden__get_password",
        "vaultwarden__generate_password",
        "vaultwarden__server_status",
        // duplicati (src/modules/duplicati/index.ts)
        "duplicati__list_backups",
        "duplicati__backup_status",
        "duplicati__run_backup",
        "duplicati__progress",
        "duplicati__list_versions",
        "duplicati__server_info",
        // workflows (module name is `ctr` — the `ctr__*` prefix is deliberate).
        "ctr__network_overview",
        "ctr__wake_and_verify",
        "ctr__device_lookup",
        "ctr__health_check",
        "ctr__full_device_status",
        "ctr__unraid_array_status",
        "ctr__unraid_ups_status",
        "ctr__unraid_smart_status",
        "ctr__wake_and_docker",
        "ctr__media_health",
        "ctr__service_overview",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

// -------------------------------------------------------------------------- //
// Notification settings                                                       //
// -------------------------------------------------------------------------- //

/// `GET /api/settings/notifications` — current notification channel info.
pub async fn notification_status(State(state): State<DashboardState>) -> Json<Value> {
    let app = match require_app(&state) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let notifier = &app.notifier;
    Json(json!({
        "ok": true,
        "channel": notifier.channel_name(),
        "detail": notifier.channel_detail(),
    }))
}

/// `POST /api/settings/notifications/test` — send a test notification.
pub async fn notification_test(State(state): State<DashboardState>) -> Json<Value> {
    let app = match require_app(&state) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let notifier = &app.notifier;
    match notifier
        .send(
            "Test Notification",
            "This is a test from the Vault Proxy dashboard.",
            3,
        )
        .await
    {
        Ok(()) => Json(json!({ "ok": true, "channel": notifier.channel_name() })),
        Err(e) => Json(json!({ "ok": false, "error": e.to_string() })),
    }
}

// -------------------------------------------------------------------------- //
// Site profiles (feature = "browser" only)                                   //
// -------------------------------------------------------------------------- //

/// `GET /api/profiles` — list site profiles for browser automation.
// iter-119: wrap in {"ok":true,"profiles":{...}} envelope for consistency with all
// other dashboard endpoints. Previously returned a bare HashMap serialization.
#[cfg(feature = "browser")]
pub async fn list_profiles(State(_state): State<DashboardState>) -> Json<Value> {
    let profiles = crate::browser::profiles::load_profiles("/config/site-profiles.json");
    Json(json!({
        "ok": true,
        "profiles": serde_json::to_value(profiles).unwrap_or_default(),
    }))
}

/// `GET /api/profiles` stub — returns empty when browser feature is disabled.
// iter-119: added "ok":true to match the browser-enabled variant's envelope shape.
#[cfg(not(feature = "browser"))]
pub async fn list_profiles(State(_state): State<DashboardState>) -> Json<Value> {
    Json(json!({"ok": true, "profiles": {}, "note": "browser feature not enabled"}))
}

/// `POST /api/profiles` — save site profiles.
#[cfg(feature = "browser")]
pub async fn save_profiles_handler(
    State(state): State<DashboardState>,
    Json(profiles): Json<Value>,
) -> Json<Value> {
    if let Err(e) = state.sessions.check_config_write_rate().await {
        return Json(json!({"ok": false, "error": e}));
    }
    let profiles: std::collections::HashMap<String, crate::browser::profiles::SiteProfile> =
        match serde_json::from_value(profiles) {
            Ok(p) => p,
            // Issue (iter-105): missing "ok": false on parse failure.
            Err(e) => return Json(json!({"ok": false, "error": e.to_string()})),
        };
    match crate::browser::profiles::save_profiles("/config/site-profiles.json", &profiles) {
        Ok(()) => Json(json!({"ok": true})),
        // Issue (iter-105): missing "ok": false on save failure.
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

/// `POST /api/profiles` stub — returns error when browser feature is disabled.
#[cfg(not(feature = "browser"))]
pub async fn save_profiles_handler(
    State(_state): State<DashboardState>,
    Json(_profiles): Json<Value>,
) -> Json<Value> {
    Json(json!({"ok": false, "error": "browser feature not enabled"}))
}

// -------------------------------------------------------------------------- //
// Keystore setup / unlock / reset                                             //
// -------------------------------------------------------------------------- //

#[derive(serde::Deserialize)]
pub struct ConfigureRequest {
    vault_url: String,
    vault_email: String,
    master_password: String,
    setup_password: String,
}

pub async fn handle_configure(
    State(state): State<DashboardState>,
    Json(req): Json<ConfigureRequest>,
) -> Json<Value> {
    if crate::keystore::is_configured(&state.config_dir) {
        return Json(
            json!({"ok": false, "error": "already configured — use reconfigure from settings"}),
        );
    }

    match crate::setup::run_web_setup(
        &state.config_dir,
        &req.vault_url,
        &req.vault_email,
        &req.master_password,
        &req.setup_password,
    )
    .await
    {
        Ok(_creds) => {
            // Signal the polling loop with the setup password so it can
            // decrypt. Wrap in Zeroizing so the Drop zeroes the bytes.
            *state.unlock_password.write().await =
                Some(zeroize::Zeroizing::new(req.setup_password.clone()));
            Json(json!({"ok": true}))
        }
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

#[derive(serde::Deserialize)]
pub struct UnlockRequest {
    pub password: String,
}

pub async fn handle_unlock(
    State(state): State<DashboardState>,
    Json(req): Json<UnlockRequest>,
) -> axum::response::Response {
    use axum::http::{header, StatusCode};
    use axum::response::IntoResponse;

    // Rate-limit *before* the (intentionally expensive) Argon2id verification.
    // This endpoint is reachable pre-authentication on the LAN; without a
    // limiter an attacker can brute-force the keystore password at full CPU
    // speed, bounded only by Argon2id latency.
    if let Err(e) = state.sessions.check_unlock_rate_limit().await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"ok": false, "error": e})),
        )
            .into_response();
    }

    match crate::keystore::unlock_keystore(&state.config_dir, Some(&req.password)) {
        Ok(_creds) => {
            state.sessions.reset_unlock_failures().await;
            // Signal the polling loop with the unlock password (zeroized on drop).
            *state.unlock_password.write().await =
                Some(zeroize::Zeroizing::new(req.password.clone()));

            // Also create a dashboard session with the same password so the
            // user lands on the authenticated dashboard immediately after
            // unlock instead of being bounced to /login for another round
            // of the same credential. If dashboard login fails (different
            // bcrypt hash somehow, though set_password during setup writes
            // both), we still return ok=true since the unlock itself
            // succeeded — user will hit /login as a fallback.
            match state.sessions.login(&req.password).await {
                Ok(session_id) => {
                    let cookie = format!(
                        "session={}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400",
                        session_id
                    );
                    (
                        [(header::SET_COOKIE, cookie)],
                        Json(json!({"ok": true, "session": true})),
                    )
                        .into_response()
                }
                Err(_) => Json(json!({"ok": true, "session": false})).into_response(),
            }
        }
        Err(e) => {
            state.sessions.record_unlock_failure().await;
            Json(json!({"ok": false, "error": e.to_string()})).into_response()
        }
    }
}

pub async fn handle_reset(State(state): State<DashboardState>) -> Json<Value> {
    match crate::keystore::reset_keystore(&state.config_dir) {
        Ok(()) => Json(json!({"ok": true, "message": "keystore reset — restart to reconfigure"})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

pub async fn handle_setup_status(State(state): State<DashboardState>) -> Json<Value> {
    let configured = crate::keystore::is_configured(&state.config_dir);
    let tpm_available = crate::tpm::tpm_available();
    let has_tpm_key = crate::keystore::has_tpm_key(&state.config_dir);
    Json(json!({
        "ok": true,
        "configured": configured,
        "tpm_available": tpm_available,
        "tpm_key_sealed": has_tpm_key,
    }))
}

// -------------------------------------------------------------------------- //
// Credential management                                                       //
// -------------------------------------------------------------------------- //

/// `GET /api/credentials` — view configured credentials (passwords masked).
pub async fn get_credentials(State(state): State<DashboardState>) -> Json<Value> {
    if !crate::keystore::is_configured(&state.config_dir) {
        return Json(json!({"ok": true, "configured": false}));
    }

    // We need the setup password to decrypt. Try TPM first.
    let creds = if crate::keystore::has_tpm_key(&state.config_dir) {
        crate::keystore::unlock_keystore(&state.config_dir, None).ok()
    } else {
        None
    };

    match creds {
        Some(c) => Json(json!({
            "ok": true,
            "configured": true,
            "vaultwarden": {
                "url": c.vaultwarden.url,
                "email": c.vaultwarden.email,
                "has_password": true,
            },
            "cloud": c.cloud.as_ref().map(|cl| json!({
                "email": cl.email,
                "has_password": true,
                "has_refresh_token": cl.refresh_token.is_some(),
            })),
            "tpm_available": crate::tpm::tpm_available(),
            "tpm_key_sealed": crate::keystore::has_tpm_key(&state.config_dir),
        })),
        None => Json(json!({
            "ok": true,
            "configured": true,
            "locked": true,
            "message": "credentials are encrypted — unlock required to view details",
            "tpm_available": crate::tpm::tpm_available(),
            "tpm_key_sealed": crate::keystore::has_tpm_key(&state.config_dir),
        })),
    }
}

#[derive(Deserialize)]
pub struct UpdateVaultwardenPasswordRequest {
    pub current_setup_password: String,
    pub new_master_password: String,
}

/// `POST /api/credentials/vaultwarden` — update the Vaultwarden master password
/// in the keystore (does NOT rotate it on Vaultwarden — just stores the current one).
pub async fn update_vaultwarden_password(
    State(state): State<DashboardState>,
    Json(req): Json<UpdateVaultwardenPasswordRequest>,
) -> Json<Value> {
    // Decrypt current credentials
    let mut creds = match crate::keystore::unlock_keystore(
        &state.config_dir,
        Some(&req.current_setup_password),
    ) {
        Ok(c) => c,
        Err(e) => return Json(json!({"ok": false, "error": format!("unlock failed: {}", e)})),
    };

    // Validate the new password against Vaultwarden
    if let Err(e) = crate::setup::validate_vaultwarden_creds(
        &creds.vaultwarden.url,
        &creds.vaultwarden.email,
        &req.new_master_password,
    )
    .await
    {
        return Json(json!({"ok": false, "error": format!("password validation failed: {}", e)}));
    }

    // Update and re-encrypt
    creds.vaultwarden.master_password = req.new_master_password;
    match crate::keystore::reencrypt_credentials(&state.config_dir, &creds) {
        Ok(()) => {
            // Signal polling loop to unlock if still in locked mode.
            *state.unlock_password.write().await =
                Some(zeroize::Zeroizing::new(req.current_setup_password.clone()));
            Json(json!({"ok": true, "message": "Vaultwarden master password updated in keystore"}))
        }
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

#[derive(Deserialize)]
pub struct UpdateCloudCredsRequest {
    pub current_setup_password: String,
    pub cloud_email: String,
    pub cloud_master_password: String,
}

/// `POST /api/credentials/cloud` — add or update Bitwarden cloud credentials.
pub async fn update_cloud_credentials(
    State(state): State<DashboardState>,
    Json(req): Json<UpdateCloudCredsRequest>,
) -> Json<Value> {
    // Decrypt current credentials
    let mut creds = match crate::keystore::unlock_keystore(
        &state.config_dir,
        Some(&req.current_setup_password),
    ) {
        Ok(c) => c,
        Err(e) => return Json(json!({"ok": false, "error": format!("unlock failed: {}", e)})),
    };

    // Store cloud credentials (validation happens when cloud sync is actually used)
    let existing_cloud = creds.cloud.clone();
    creds.cloud = Some(crate::keystore::CloudCreds {
        email: req.cloud_email,
        master_password: req.cloud_master_password,
        refresh_token: existing_cloud
            .as_ref()
            .and_then(|c| c.refresh_token.clone()),
        api_client_id: existing_cloud
            .as_ref()
            .and_then(|c| c.api_client_id.clone()),
        api_client_secret: existing_cloud
            .as_ref()
            .and_then(|c| c.api_client_secret.clone()),
        kdf_iterations: existing_cloud.as_ref().and_then(|c| c.kdf_iterations),
    });

    match crate::keystore::reencrypt_credentials(&state.config_dir, &creds) {
        Ok(()) => {
            *state.unlock_password.write().await =
                Some(zeroize::Zeroizing::new(req.current_setup_password.clone()));
            Json(json!({"ok": true, "message": "Bitwarden cloud credentials updated"}))
        }
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

/// `POST /api/credentials/cloud/remove` — remove Bitwarden cloud credentials.
pub async fn remove_cloud_credentials(
    State(state): State<DashboardState>,
    Json(req): Json<UnlockRequest>,
) -> Json<Value> {
    let mut creds = match crate::keystore::unlock_keystore(&state.config_dir, Some(&req.password)) {
        Ok(c) => c,
        Err(e) => return Json(json!({"ok": false, "error": format!("unlock failed: {}", e)})),
    };

    creds.cloud = None;
    match crate::keystore::reencrypt_credentials(&state.config_dir, &creds) {
        Ok(()) => Json(json!({"ok": true, "message": "cloud credentials removed"})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

// -------------------------------------------------------------------------- //
// Cloud API key auth                                                          //
// -------------------------------------------------------------------------- //

#[derive(Deserialize)]
pub struct CloudApiKeyRequest {
    pub email: String,
    pub master_password: String,
    pub client_id: String,
    pub client_secret: String,
    pub kdf_iterations: Option<u32>,
    pub setup_password: Option<String>,
}

/// `POST /api/credentials/cloud/apikey` — connect to Bitwarden cloud using API key.
/// Bypasses password-based auth and 2FA. Master password still needed for encryption.
pub async fn connect_cloud_apikey(
    State(state): State<DashboardState>,
    Json(req): Json<CloudApiKeyRequest>,
) -> Json<Value> {
    if req.email.is_empty()
        || req.master_password.is_empty()
        || req.client_id.is_empty()
        || req.client_secret.is_empty()
    {
        return Json(json!({"ok": false, "error": "all fields are required"}));
    }

    tracing::info!(
        "attempting Bitwarden cloud auth via API key for {}, kdf_override={:?}",
        req.email,
        req.kdf_iterations
    );

    match crate::sync::cloud::CloudClient::from_api_key(
        &req.email,
        &req.master_password,
        &req.client_id,
        &req.client_secret,
        req.kdf_iterations,
    )
    .await
    {
        Ok((_client, refresh_token)) => {
            // Save credentials to keystore
            let config_dir = &state.config_dir;
            // Prefer the explicit setup_password from the request, fall back
            // to the one already shuttled via the unlock_password channel.
            // Everything stays wrapped in Zeroizing to maintain the zeroize
            // discipline established in iter-20.
            let setup_pw: Option<zeroize::Zeroizing<String>> = req
                .setup_password
                .as_ref()
                .map(|s| zeroize::Zeroizing::new(s.clone()));
            let unlock_pw: Option<zeroize::Zeroizing<String>> =
                state.unlock_password.read().await.clone();
            let pw_to_use: Option<zeroize::Zeroizing<String>> = setup_pw.or(unlock_pw);

            let unlock_result = if let Some(ref pw) = pw_to_use {
                crate::keystore::unlock_keystore(config_dir, Some(pw.as_str()))
            } else {
                crate::keystore::unlock_keystore(config_dir, None)
            };

            match unlock_result {
                Ok(mut creds) => {
                    creds.cloud = Some(crate::keystore::CloudCreds {
                        email: req.email.clone(),
                        master_password: req.master_password.clone(),
                        refresh_token: if refresh_token.is_empty() {
                            None
                        } else {
                            Some(refresh_token)
                        },
                        api_client_id: Some(req.client_id.clone()),
                        api_client_secret: Some(req.client_secret.clone()),
                        kdf_iterations: req.kdf_iterations,
                    });
                    if let Err(e) = crate::keystore::reencrypt_credentials(config_dir, &creds) {
                        tracing::error!("failed to save cloud credentials: {}", e);
                        return Json(
                            json!({"ok": false, "error": format!("auth succeeded but save failed: {}", e)}),
                        );
                    }
                    tracing::info!("cloud API key credentials saved to keystore");
                    // Signal unlock if still in locked mode.
                    if let Some(pw) = pw_to_use {
                        *state.unlock_password.write().await = Some(pw);
                    }
                }
                Err(e) => {
                    tracing::warn!("keystore unlock failed — cloud auth succeeded but credentials not saved: {}", e);
                    return Json(json!({
                        "ok": false,
                        "error": "Bitwarden auth succeeded but couldn't save to keystore — enter setup password above and try again"
                    }));
                }
            }

            Json(json!({
                "ok": true,
                "message": "Bitwarden cloud connected via API key! Restart to activate sync."
            }))
        }
        Err(e) => {
            tracing::error!("API key auth failed: {:#}", e);
            Json(json!({"ok": false, "error": e.to_string()}))
        }
    }
}

// -------------------------------------------------------------------------- //
// Cloud setup via sidecar                                                     //
// -------------------------------------------------------------------------- //

/// `POST /api/settings/cloud` — forward cloud setup to sidecar sync/init.
pub async fn setup_cloud_via_dashboard(
    State(state): State<DashboardState>,
    Json(req): Json<serde_json::Value>,
) -> Json<Value> {
    let app = match require_app(&state) {
        Ok(a) => a,
        Err(e) => return e,
    };
    // Forward to sidecar's internal sync/init endpoint
    match app
        .http
        .post("http://127.0.0.1:3201/sync/init")
        .json(&req)
        .send()
        .await
    {
        Ok(res) => {
            let body: Value = res.json().await.unwrap_or_default();
            Json(body)
        }
        // Issue (iter-105): missing "ok": false on network failure forwarding to sidecar.
        Err(e) => Json(serde_json::json!({"ok": false, "error": e.to_string()})),
    }
}

// ───────────────────── credential audit (feature = "engine") ─────────────

#[cfg(feature = "engine")]
fn credaudit_unavailable() -> Json<Value> {
    // Issue (iter-106): missing "ok": false — all credaudit error responses
    // must carry the standard "ok": false field.
    Json(json!({
        "ok": false,
        "error": "credential audit unavailable: vault not unlocked"
    }))
}

#[cfg(feature = "engine")]
pub async fn credaudit_runs_list(State(state): State<DashboardState>) -> Json<Value> {
    let Some(orch) = state.cred_audit_orch.as_ref() else {
        return credaudit_unavailable();
    };
    match orch.list_runs() {
        Ok(runs) => Json(json!({"ok": true, "runs": runs})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

#[cfg(feature = "engine")]
pub async fn credaudit_run_detail(
    State(state): State<DashboardState>,
    Path(run_id): Path<String>,
) -> Json<Value> {
    let Some(orch) = state.cred_audit_orch.as_ref() else {
        return credaudit_unavailable();
    };
    match orch.get_run_detail(&run_id) {
        Ok(detail) => Json(json!({"ok": true, "detail": detail})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

#[cfg(feature = "engine")]
pub async fn credaudit_scan_start(State(state): State<DashboardState>) -> Json<Value> {
    if let Err(e) = state.sessions.check_config_write_rate().await {
        return Json(json!({"ok": false, "error": e}));
    }
    let Some(orch) = state.cred_audit_orch.as_ref() else {
        return credaudit_unavailable();
    };
    match orch.start_scan().await {
        Ok(run_id) => Json(json!({"ok": true, "run_id": run_id})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

#[cfg(feature = "engine")]
#[derive(serde::Deserialize)]
pub struct CredauditApplyBody {
    pub run_id: String,
    #[serde(default = "default_dry_run")]
    pub dry_run: bool,
    #[serde(default)]
    pub confirm_bulk: bool,
}

#[cfg(feature = "engine")]
fn default_dry_run() -> bool {
    true
}

#[cfg(feature = "engine")]
pub async fn credaudit_apply(
    State(state): State<DashboardState>,
    Json(body): Json<CredauditApplyBody>,
) -> Json<Value> {
    if let Err(e) = state.sessions.check_config_write_rate().await {
        return Json(json!({"ok": false, "error": e}));
    }
    let Some(orch) = state.cred_audit_orch.as_ref() else {
        return credaudit_unavailable();
    };
    match orch
        .apply(&body.run_id, None, body.dry_run, body.confirm_bulk)
        .await
    {
        Ok(out) => Json(json!({"ok": true, "result": out})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

#[cfg(feature = "engine")]
pub async fn credaudit_telemetry(
    State(state): State<DashboardState>,
    Path(run_id): Path<String>,
) -> Json<Value> {
    let Some(orch) = state.cred_audit_orch.as_ref() else {
        return credaudit_unavailable();
    };
    match orch.get_telemetry(&run_id).await {
        // iter-119: wrap the raw engine telemetry value so the caller receives the
        // same {"ok":true,...} envelope shape as every other dashboard endpoint.
        Ok(v) => Json(json!({"ok": true, "telemetry": v})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

#[cfg(feature = "engine")]
pub async fn credaudit_verify_start(
    State(state): State<DashboardState>,
    Json(body): Json<Value>,
) -> Json<Value> {
    if let Err(e) = state.sessions.check_config_write_rate().await {
        return Json(json!({"ok": false, "error": e}));
    }
    let Some(orch) = state.cred_audit_orch.as_ref() else {
        return credaudit_unavailable();
    };
    let run_id = body.get("run_id").and_then(|v| v.as_str()).unwrap_or("");
    if run_id.is_empty() {
        return Json(json!({"ok": false, "error": "run_id required"}));
    }
    // verify_start takes self: Arc<Self> so it can move a clone into the
    // background tokio::spawn worker. Clone the Arc here.
    match orch.clone().verify_start(run_id).await {
        Ok(n) => Json(json!({"ok": true, "verify_started_for": n, "run_id": run_id})),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})),
    }
}

// -------------------------------------------------------------------------- //
// Response-shape tests (iter-119) — dashboard handler "ok" sentinel coverage //
// -------------------------------------------------------------------------- //
/// Unit tests that validate the response body shapes added in iter-117 to the
/// 11 dashboard endpoints that were missing "ok". These tests exercise the JSON
/// literal shapes directly rather than requiring a full Axum test server, which
/// matches the pattern used in `src/vault/handlers.rs::sync_status_shape_tests`.
#[cfg(test)]
mod dashboard_ok_shape_tests {
    use serde_json::json;

    /// `GET /api/status` — top-level status must carry `"ok": true`.
    /// Before iter-117 this returned `{"vault_items":...}` without the sentinel.
    #[test]
    fn api_status_has_ok_true() {
        let body = json!({
            "ok": true,
            "vault_items": 42,
            "cloud_sync": {"state": "idle"},
            "services": [],
        });
        assert_eq!(body["ok"], true, "GET /api/status must return ok: true");
        assert!(body["vault_items"].is_number());
    }

    /// `GET /api/sync` configured path must carry `"ok": true`.
    /// Before iter-117 both branches returned bare state/last_sync/items_synced.
    #[test]
    fn api_sync_configured_has_ok_true() {
        let body = json!({
            "ok": true,
            "state": "idle",
            "last_sync": null,
            "items_synced": 0,
            "errors": [],
        });
        assert_eq!(
            body["ok"], true,
            "GET /api/sync (configured) must return ok: true"
        );
        assert!(body["state"].is_string());
    }

    /// `GET /api/sync` not-configured path must carry `"ok": true`.
    #[test]
    fn api_sync_not_configured_has_ok_true() {
        let body = json!({
            "ok": true,
            "state": "not_configured",
            "last_sync": null,
            "items_synced": 0,
            "errors": [],
        });
        assert_eq!(
            body["ok"], true,
            "GET /api/sync (not_configured) must return ok: true"
        );
        assert_eq!(body["state"].as_str().unwrap_or(""), "not_configured");
    }

    /// `GET /api/tpm-status` must carry `"ok": true`.
    #[test]
    fn api_tpm_status_has_ok_true() {
        let body = json!({
            "ok": true,
            "tpm_available": false,
            "sealed_credentials": [],
        });
        assert_eq!(body["ok"], true, "GET /api/tpm-status must return ok: true");
    }

    /// `GET /api/settings/setup-status` must carry `"ok": true`.
    #[test]
    fn api_settings_setup_status_has_ok_true() {
        let body = json!({
            "ok": true,
            "vaultwarden_configured": false,
            "cloud_configured": false,
            "tpm_available": false,
            "needs_setup": true,
        });
        assert_eq!(
            body["ok"], true,
            "GET /api/settings/setup-status must return ok: true"
        );
    }

    /// `GET /api/permissions` must carry `"ok": true` and `"configured_vault_folder"` string.
    /// iter-121: the dashboard handler now mirrors the vault_folder field present in
    /// GET /vault/permissions (iter-120) so operators can confirm scope from the UI.
    #[test]
    fn api_permissions_has_ok_true_and_configured_vault_folder() {
        let body = json!({
            "ok": true,
            "tools": [],
            "overrides": {},
            "configured_vault_folder": "vault-proxy",
        });
        assert_eq!(
            body["ok"], true,
            "GET /api/permissions must return ok: true"
        );
        assert!(
            body["tools"].is_array(),
            "GET /api/permissions must return tools array"
        );
        assert!(
            body["configured_vault_folder"].is_string(),
            "GET /api/permissions must include 'configured_vault_folder' string field (iter-121)"
        );
    }

    /// `GET /api/settings/notifications` must carry `"ok": true`.
    #[test]
    fn api_notifications_has_ok_true() {
        let body = json!({
            "ok": true,
            "channel": "none",
            "detail": "",
        });
        assert_eq!(
            body["ok"], true,
            "GET /api/settings/notifications must return ok: true"
        );
    }

    /// `GET /api/browser/status` idle path must carry `"ok": true`.
    #[test]
    fn api_browser_status_idle_has_ok_true() {
        let body = json!({"ok": true, "status": "idle"});
        assert_eq!(
            body["ok"], true,
            "GET /api/browser/status idle must return ok: true"
        );
    }

    /// `GET /api/browser/status` not-configured path must carry `"ok": true`.
    #[test]
    fn api_browser_status_not_configured_has_ok_true() {
        let body = json!({"ok": true, "status": "not_configured"});
        assert_eq!(
            body["ok"], true,
            "GET /api/browser/status not_configured must return ok: true"
        );
    }

    /// `GET /api/browser/screenshot` success path must carry `"ok": true`.
    #[test]
    fn api_browser_screenshot_has_ok_true() {
        let body = json!({"ok": true, "image_b64": "base64data"});
        assert_eq!(
            body["ok"], true,
            "GET /api/browser/screenshot success must return ok: true"
        );
    }

    /// `GET /api/items` must return `{"ok":true,"items":[...]}` envelope.
    /// Before iter-117 this returned a bare JSON array.
    #[test]
    fn api_items_has_ok_true_envelope() {
        let body = json!({"ok": true, "items": []});
        assert_eq!(body["ok"], true, "GET /api/items must return ok: true");
        assert!(
            body["items"].is_array(),
            "GET /api/items must have 'items' array field"
        );
    }

    /// `GET /api/items` error path must carry `"ok": false` — iter-119 fix.
    /// Before iter-119 an error response was silently swallowed as an empty list.
    #[test]
    fn api_items_error_has_ok_false() {
        let body = json!({"ok": false, "error": "vault not initialized"});
        assert_eq!(
            body["ok"], false,
            "GET /api/items error must return ok: false"
        );
        assert!(body["error"].as_str().is_some());
    }

    /// `GET /api/profiles` (non-browser stub) must carry `"ok": true` — iter-119 fix.
    #[test]
    fn api_profiles_stub_has_ok_true() {
        let body = json!({"ok": true, "profiles": {}, "note": "browser feature not enabled"});
        assert_eq!(
            body["ok"], true,
            "GET /api/profiles stub must return ok: true"
        );
        assert!(body["profiles"].is_object());
    }

    /// `credaudit_telemetry` success path must wrap value in `{"ok":true,"telemetry":{...}}` — iter-119 fix.
    /// Before iter-119 it returned the raw engine JSON without an "ok" sentinel.
    #[test]
    fn credaudit_telemetry_has_ok_true_envelope() {
        let engine_val = json!({"items_classified": 10, "duration_ms": 250});
        let body = json!({"ok": true, "telemetry": engine_val});
        assert_eq!(body["ok"], true, "credaudit_telemetry must return ok: true");
        assert!(
            body["telemetry"].is_object(),
            "credaudit_telemetry must wrap data in 'telemetry' field"
        );
    }

    /// `GET /api/approvals` must carry `"ok": true` and an `"approvals"` array — iter-122 fix.
    /// Before iter-122 this returned a bare JSON array with no "ok" sentinel,
    /// inconsistent with all other dashboard collection endpoints.
    #[test]
    fn api_approvals_has_ok_true_and_approvals_array() {
        let body = json!({"ok": true, "approvals": []});
        assert_eq!(body["ok"], true, "GET /api/approvals must return ok: true");
        assert!(
            body["approvals"].is_array(),
            "GET /api/approvals must wrap list in 'approvals' key"
        );
        // Verify the key is specifically "approvals" — if it were renamed the
        // test above could pass with a different key if ok:true were kept.
        assert!(
            body.get("approvals").is_some(),
            "GET /api/approvals key must be named 'approvals' (not 'items' or similar)"
        );
    }

    /// `GET /api/approvals` error path must carry `"ok": false` — iter-123 fix.
    /// When vault is not initialized, `require_app` returns `{"ok":false,"error":"..."}`.
    /// Without the ok===false guard in approvals.html, this rendered as an empty queue.
    #[test]
    fn api_approvals_error_has_ok_false() {
        let body = json!({"ok": false, "error": "vault not initialized — complete setup first"});
        assert_eq!(
            body["ok"], false,
            "GET /api/approvals error must return ok: false"
        );
        assert!(
            body["error"].as_str().is_some(),
            "GET /api/approvals error must include 'error' string"
        );
    }
}
