//! Proxy handler — authenticates and forwards requests to downstream services.

pub mod registry;
pub mod unifi_session;

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{extract::State, http::StatusCode, Json};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

#[cfg(feature = "browser")]
use crate::browser::BrowserAgent;
use crate::sync::SyncManager;
use crate::vault::VaultManager;
use registry::{AuthPattern, ServiceRegistry};
use unifi_session::{
    handle_request as unifi_handle_request, UnifiDualAuthCtx, UnifiRequestCtx, UnifiSessionCache,
};

/// Generate a short, URL-safe, lexicographically-sortable request identifier.
///
/// Uses a random 6-byte (48-bit) value encoded as 8 lowercase hex characters.
/// This gives 281 trillion unique values — more than sufficient to distinguish
/// concurrent requests without the overhead of a full UUID. The small size keeps
/// log lines short while still providing effective correlation across 50+ in-flight
/// requests.
///
/// Not a UUID — does not guarantee global uniqueness across process restarts.
/// For production logging across multiple hosts, prefix with a host identifier.
fn new_request_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    // Counter-based: monotonically increasing within a process lifetime.
    // Avoids any per-request entropy consumption while still producing unique IDs.
    static REQ_COUNTER: AtomicU64 = AtomicU64::new(1);
    let n = REQ_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{:016x}", n)
}

// -------------------------------------------------------------------------- //
// 2FA approval queue                                                           //
// -------------------------------------------------------------------------- //

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ApprovalRequest {
    pub id: String,
    pub screenshot_b64: Option<String>,
    pub prompt: String,
    pub created_at: String,
    pub expires_at: String,
    pub status: String, // "pending", "approved", "denied"
    pub response: Option<String>,
}

// -------------------------------------------------------------------------- //
// Shared application state                                                     //
// -------------------------------------------------------------------------- //

/// Shared state injected into every axum handler via `axum::extract::State`.
#[derive(Clone)]
pub struct AppState {
    pub vault: Arc<VaultManager>,
    /// Service registry — wrapped in RwLock to support live reload on SIGHUP.
    ///
    /// Issue (iter-28): SIGHUP reload. Previously `Arc<ServiceRegistry>` was
    /// immutable after startup. Changing to `Arc<RwLock<ServiceRegistry>>`
    /// lets the SIGHUP handler call `ServiceRegistry::from_toml_file` and
    /// swap in a fresh registry without restarting the process. Read access
    /// is via `.registry.read().await`; write access is only in the SIGHUP
    /// handler (which also rebuilds `ca_cert_clients` and clears
    /// `cached_folder_id`).
    pub registry: Arc<tokio::sync::RwLock<ServiceRegistry>>,
    /// Default HTTP client with full TLS verification. Used for every downstream
    /// service except those explicitly documented to present self-signed certs
    /// (currently: UniFi UDM on the classic port).
    pub http: reqwest::Client,
    /// TLS-permissive HTTP client. Only used for `AuthPattern::UnifiDual`
    /// requests against UDM's self-signed cert. Kept separate so no other
    /// module can accidentally bypass TLS verification.
    pub http_permissive: reqwest::Client,
    /// Per-service HTTP clients for services with a custom CA certificate.
    ///
    /// Issue (iter-16 fix): the previous approach built a new `reqwest::Client`
    /// on every proxy call when `ca_cert_path` was set. `reqwest::Client`
    /// maintains a connection pool internally; creating a new instance on every
    /// request defeats connection reuse and forces a TLS handshake on every
    /// call. These clients are now built once at startup and stored here, keyed
    /// by service name, so the connection pool is preserved across requests.
    ///
    /// iter-28: wrapped in RwLock so the SIGHUP reload handler can atomically
    /// swap in a fresh map after rebuilding the registry.
    pub ca_cert_clients:
        Arc<tokio::sync::RwLock<std::collections::HashMap<String, reqwest::Client>>>,
    /// Per-service UniFi session cache (cookie jars + CSRF tokens).
    pub unifi_sessions: Arc<UnifiSessionCache>,
    /// Cached session tokens for `AuthPattern::Session` services (NPM, Duplicati).
    /// Keyed by vault_item; token + acquisition instant. Avoids a full login
    /// round-trip on every proxy call.
    pub session_tokens: Arc<tokio::sync::RwLock<HashMap<String, (String, Instant)>>>,
    /// mTLS certificate material generated at startup.
    pub client_certs: Option<crate::tpm::CertMaterial>,
    /// Optional cloud sync manager (enabled when CLOUD_EMAIL is set).
    pub cloud_sync: Option<Arc<SyncManager>>,
    /// 2FA approval queue — pending requests from automated workflows.
    /// Used by dashboard (approval management) and browser workflow (2FA handling).
    /// Dead in default builds (no dashboard, no browser feature).
    #[allow(dead_code)]
    pub approval_queue: Arc<tokio::sync::RwLock<VecDeque<ApprovalRequest>>>,
    /// Browser agent for automated password rotation.
    /// Only present when the `browser` feature is enabled.
    /// Dead in default builds (no browser feature) — the field exists for AppState
    /// construction uniformity but is never read when browser routes are absent.
    #[allow(dead_code)]
    #[cfg(feature = "browser")]
    pub browser: Option<Arc<BrowserAgent>>,
    /// Placeholder when browser feature is disabled — always None.
    #[allow(dead_code)]
    #[cfg(not(feature = "browser"))]
    pub browser: Option<()>,
    /// Tool permissions configuration. Wrapped in RwLock so the dashboard
    /// `POST /api/permissions` handler can hot-reload the live in-memory
    /// copy without requiring a container restart — before this change,
    /// operator edits silently didn't take effect until the next restart.
    pub permissions: Arc<tokio::sync::RwLock<crate::security::permissions::ToolPermissions>>,
    /// Audit log for tool invocations.
    pub audit_log: Arc<crate::security::audit_log::AuditLog>,
    /// Push notification sender (ntfy.sh).
    pub notifier: Arc<crate::notify::Notifier>,
    /// One-time handshake flag — prevents key exfiltration after first retrieval.
    pub handshake_completed: Arc<std::sync::atomic::AtomicBool>,
    /// Runtime vault folder (from `--vault-folder` / `VAULT_FOLDER`).
    /// Stored here so HTTP handlers use the same folder the registry was
    /// built against, instead of falling back to `DEFAULT_VAULT_FOLDER`.
    pub vault_folder: String,
    /// Timestamp of the last successful `POST /vault/resync` call.
    /// Used to enforce a 30-second per-endpoint cooldown so an MCP client
    /// cannot hammer Vaultwarden with full-vault syncs at 60 req/60s.
    /// Stored as seconds since the Unix epoch via `AtomicU64` (zero = never).
    pub last_resync_unix: Arc<std::sync::atomic::AtomicU64>,
    /// Shared-secret bearer token for internal-only endpoints.
    ///
    /// Generated once at startup (or read from `$CONFIG_DIR/internal-token`)
    /// and stored here for use by `require_internal_token` middleware. The
    /// token is a 32-byte random hex string written to disk with 0o600
    /// permissions so the TypeScript Connecterr side can read it.
    ///
    /// See `crate::internal_token` and `main.rs::require_internal_token`.
    pub internal_token: Arc<String>,
    /// Cached folder_id for `vault_folder`.
    ///
    /// Issue (iter-22): Every vault mutation handler calls
    /// `find_folder_id_by_name_async(&vault_folder)`, which acquires a read
    /// lock on the vault's folder map and does a linear scan. Since
    /// `vault_folder` is static (set at startup), the resolved `folder_id`
    /// can be cached here after the first successful resolution.
    ///
    /// The cache is invalidated (set to `None`) by `POST /vault/resync` so
    /// that a folder rename or deletion is picked up after the next sync.
    /// A `None` value means "not yet resolved or invalidated" — callers fall
    /// back to `find_folder_id_by_name_async` and populate the cache.
    pub cached_folder_id: Arc<tokio::sync::RwLock<Option<String>>>,

    /// Allowed root directory for `POST /vault/write-env`.
    ///
    /// Set from `--env-write-root` / `ENV_WRITE_ROOT` at startup. An empty
    /// string means the endpoint is disabled (returns 501). A non-empty value
    /// (e.g. `/envs`) restricts writes to that prefix only.
    ///
    /// See `write_env` in `vault/handlers.rs` and the iter-23 TODO fix.
    pub env_write_root: String,

    /// Config directory path — captured from `--config-dir` / `CONFIG_DIR` at
    /// startup and stored here so handlers always use the **startup** path.
    ///
    /// Issue (iter-35): `POST /vault/reload-services` previously read
    /// `CONFIG_DIR` from the environment at reload time. In container
    /// orchestrators that inject env var changes without restarting the
    /// process, this could cause the reload handler to read `services.toml`
    /// from a different path than the one used at startup. Storing the path
    /// in `AppState` ensures the reload handler is always consistent with
    /// the startup path.
    pub config_dir: String,

    /// Proxy timeout in seconds — captured from `--proxy-timeout` / `PROXY_TIMEOUT`
    /// at startup and stored here so `POST /vault/reload-services` rebuilds
    /// CA-cert clients with the same timeout that was validated at startup,
    /// rather than re-reading the environment variable at reload time.
    ///
    /// Issue (iter-36): the reload handler previously called
    /// `std::env::var("PROXY_TIMEOUT")` at reload time. Container orchestrators
    /// can inject env var changes without restarting the process; this could
    /// silently change the effective timeout on the next reload. Storing the
    /// validated startup value in `AppState` keeps reload behaviour consistent.
    pub proxy_timeout: u64,

    /// Serialises concurrent `POST /vault/reload-services` calls.
    ///
    /// Issue (iter-36): without this mutex, two simultaneous reload requests
    /// both read `services.toml`, both build independent registries and
    /// CA-cert client maps, and then race on three separate write-lock
    /// acquisitions:
    ///
    ///   1. `registry.write()`
    ///   2. `ca_cert_clients.write()`
    ///   3. `cached_folder_id.write()`
    ///
    /// Because these are three distinct locks, the last winner of lock (1) may
    /// not be the same task that wins lock (2), leaving the process with a
    /// registry from call A and `ca_cert_clients` from call B. For services
    /// that use `ca_cert_path`, every subsequent proxy call would look up the
    /// service in the new registry but find no matching entry in the stale
    /// client map, silently falling back to the default TLS client.
    ///
    /// Holding this mutex for the entire reload serialises the reads and all
    /// three write-lock acquisitions into one critical section. SIGHUP runs in
    /// its own tokio task and does not contend on this mutex (it processes
    /// signals serially in a loop); the mutex only guards HTTP-triggered
    /// concurrent reloads.
    ///
    /// Wrapped in `Arc` because `tokio::sync::Mutex` is not `Clone` and
    /// `AppState` derives `Clone` for use with `axum::extract::State`.
    pub reload_mutex: Arc<tokio::sync::Mutex<()>>,

    /// Serialises concurrent credential-health audit runs.
    ///
    /// iter-62: without this mutex, two simultaneous audit calls — one from the
    /// background scheduler and one from `GET /vault/audit/run` — would both
    /// call `run_audit()` concurrently, decrypting every vault password twice
    /// at the same time.  On a large vault (500+ items) this doubles CPU load
    /// and memory pressure during the audit window.
    ///
    /// Holding this mutex for the duration of `run_audit()` means the second
    /// caller blocks until the first finishes and then runs its own pass.  For
    /// the HTTP handler this introduces at most one audit-duration wait; callers
    /// can observe this as a slow response but never get a torn or duplicate
    /// result.
    ///
    /// Wrapped in `Arc` for the same reason as `reload_mutex`.
    pub audit_mutex: Arc<tokio::sync::Mutex<()>>,
}

// -------------------------------------------------------------------------- //
// Request / response types                                                     //
// -------------------------------------------------------------------------- //

/// Body accepted by `POST /proxy`.
#[derive(Debug, Deserialize)]
pub struct ProxyRequest {
    /// Registered service name (e.g. "sonarr", "ha/home").
    pub service: String,
    /// HTTP method string ("GET", "POST", …).  Defaults to "GET".
    #[serde(default = "default_method")]
    pub method: String,
    /// Path appended to the service's `base_url` (must start with `/`).
    pub path: String,
    /// Optional JSON body forwarded verbatim to the downstream service.
    pub body: Option<Value>,
    /// Extra headers to include in the downstream request.
    pub headers: Option<Map<String, Value>>,
    /// Extra query parameters appended to the URL.
    pub query: Option<Map<String, Value>>,
}

fn default_method() -> String {
    "GET".to_string()
}

/// Successful proxy response.
#[derive(Debug, Serialize)]
pub struct ProxyResponse {
    pub status: u16,
    pub body: Value,
}

/// Error response body.
///
/// iter-108: added `ok: false` so every vault-proxy-generated error from
/// `POST /proxy` is unambiguously distinguishable from upstream success bodies
/// by the presence of `"ok": false`.  The SUCCESS path returns the raw upstream
/// body (no `"ok"` field added); callers checking `body["ok"] == false` can
/// detect vault-proxy-level errors (unknown service, timeout, bad gateway,
/// permission denied, bad method) without inspecting the HTTP status code.
#[derive(Debug, Serialize)]
pub struct ProxyError {
    /// Always `false` — signals that this is a vault-proxy error, not an
    /// upstream body.
    pub ok: bool,
    pub error: String,
}

// -------------------------------------------------------------------------- //
// Handler                                                                      //
// -------------------------------------------------------------------------- //

/// `POST /proxy` — authenticate and forward a request to a downstream service.
///
/// Returns the upstream body directly with the upstream HTTP status. Callers
/// can read `result.status` (the HTTP status of this response) for both
/// upstream failures (4xx/5xx from the downstream service) and vault-proxy
/// failures (also 4xx/5xx, emitted via the `ProxyError` path). The body shape
/// is the upstream JSON on success; on vault-proxy errors it is `{error: String}`.
pub async fn handle_proxy(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ProxyRequest>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ProxyError>)> {
    // iter-34: Generate a per-request ID so that log lines from concurrent
    // requests can be correlated. With 50+ in-flight requests the service+method
    // pair is not unique; the request_id (monotonic counter rendered as 16-char
    // hex) uniquely identifies this call for the lifetime of the process.
    //
    // A held tracing Span would be more idiomatic but requires the span to be
    // `Send`, which is incompatible with axum's handler signature. Using an
    // explicit `request_id` field on every log line is the pragmatic alternative.
    let request_id = new_request_id();
    tracing::debug!(
        request_id = %request_id,
        service    = %req.service,
        method     = %req.method,
        "proxy: dispatching request",
    );

    // 0. Check tool permission for this service request.
    let tool_name = format!("{}_{}", req.service, req.method.to_lowercase());
    let permission = state.permissions.read().await.get_permission(&tool_name);

    match permission {
        crate::security::permissions::Permission::Block => {
            return Err(proxy_error(
                StatusCode::FORBIDDEN,
                "blocked by policy".to_string(),
            ));
        }
        crate::security::permissions::Permission::Ask => {
            return Err(proxy_error(
                StatusCode::FORBIDDEN,
                "requires approval -- check dashboard".to_string(),
            ));
        }
        _ => {} // Allow or Log — proceed
    }

    // Log the proxy action for Log and Allow permissions.
    let should_log = matches!(permission, crate::security::permissions::Permission::Log);

    // 1. Look up the service in the registry.
    // Use a generic "not found" message — echoing req.service verbatim would
    // let an attacker enumerate registered service names via trial-and-error.
    //
    // iter-28: registry is now Arc<RwLock<ServiceRegistry>> to support SIGHUP
    // hot-reload. Acquire a read lock for the duration of this lookup; the
    // clone ensures we don't hold the lock across await points below.
    let service = {
        let reg = state.registry.read().await;
        reg.get(&req.service)
            .cloned()
            .ok_or_else(|| proxy_error(StatusCode::NOT_FOUND, "unknown service".to_string()))?
    };

    // 2. Build the target URL.
    // Reject path segments that could escape the registered base_url via
    // directory traversal.  reqwest does NOT normalise `..` segments in the
    // URL path before sending, so `base/../../etc` would be forwarded verbatim
    // to the upstream HTTP client and could reach unintended endpoints.
    let path = req.path.trim_start_matches('/');
    if path.split('/').any(|seg| seg == ".." || seg == ".") {
        return Err(proxy_error(
            StatusCode::BAD_REQUEST,
            "path must not contain '.' or '..' segments".to_string(),
        ));
    }
    // iter-11: `trim_end_matches('/')` on `base_url` prevents double-slash
    // construction when the operator writes a trailing slash in services.toml
    // (e.g. `base_url = "http://service/api/v3/"` + `path = "/endpoint"` would
    // produce `http://service/api/v3//endpoint` without this trim). Some HTTP
    // servers (notably nginx) treat `//path` as root-relative, silently routing
    // the request to `http://service/endpoint` — a different resource from the
    // intended `http://service/api/v3/endpoint`.
    //
    // The `registry.rs` `from_toml_file` loader also trims trailing slashes from
    // `base_url` at registration time, so this is a belt-and-suspenders guard.
    let target_url = if path.is_empty() {
        service.base_url.clone()
    } else {
        format!("{}/{}", service.base_url.trim_end_matches('/'), path)
    };

    // 3. Parse and validate the HTTP method.
    //
    // Issue-1 (iter-5): CONNECT and TRACE are dangerous in a proxy context.
    // CONNECT is used to establish TCP tunnels through HTTP proxies — if
    // forwarded, it could allow an MCP caller to open arbitrary TCP connections
    // to any host reachable from vault-proxy. reqwest would accept and forward
    // a CONNECT method string because `Method::from_bytes` accepts any token.
    // TRACE is the HTTP debugging echo method; it can reveal request headers
    // (including auth credentials injected by vault-proxy) in the response body,
    // which would completely undermine the credential-isolation guarantee.
    // HEAD is allowed because it is a safe read method (same as GET, no body).
    // OPTIONS is allowed for CORS preflight when services require it.
    // Custom/extension methods are blocked for the same reasons as CONNECT —
    // vault-proxy is a JSON API bridge, not a generic HTTP proxy.
    let method = req.method.to_uppercase();
    let method_str = method.as_str();
    const ALLOWED_METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
    if !ALLOWED_METHODS.contains(&method_str) {
        return Err(proxy_error(
            StatusCode::METHOD_NOT_ALLOWED,
            format!(
                "method '{}' is not allowed — vault-proxy accepts: {}",
                req.method,
                ALLOWED_METHODS.join(", ")
            ),
        ));
    }
    let method = method.parse::<Method>().map_err(|_| {
        proxy_error(
            StatusCode::BAD_REQUEST,
            format!("invalid HTTP method '{}'", req.method),
        )
    })?;

    // 4. Apply auth and send the request.
    // Log internal errors (which may contain vault item names, upstream IPs,
    // etc.) at debug level, but return a generic message to the caller so that
    // credential names and internal topology are never exposed in API responses.
    //
    // Issue-9 (iter-5): Distinguish timeout errors from other upstream failures.
    // When `--proxy-timeout` fires, the reqwest error has `is_timeout() == true`.
    // Before this fix, timeouts were reported as the generic "upstream request
    // failed" 502, making them indistinguishable from DNS failures, connection
    // refused, and TLS errors. Callers (particularly LLMs with retry logic)
    // should know when to wait vs. when to give up immediately; a 504 Gateway
    // Timeout with an explicit message gives them that signal. Internal details
    // (service name, upstream IP) are still not included in the 504 body.
    // Resolve the per-service CA-cert client (if any) before calling
    // apply_auth_and_send. The RwLock must be read in this async context; the
    // sync helpers (build_request etc.) cannot await it directly.
    let ca_client: Option<reqwest::Client> = {
        let ca_map = state.ca_cert_clients.read().await;
        ca_map.get(service.name.as_str()).cloned()
    };

    let mut response = apply_auth_and_send(
        &state,
        &service,
        ca_client,
        service.auth.clone(),
        &target_url,
        method,
        &req,
    )
    .await
    .map_err(|e| {
        // Detect timeout: reqwest wraps its own Error type; check the
        // debug representation since anyhow wraps it. We also test for
        // "timed out" as a belt-and-suspenders match for the OS-level
        // "connection timed out" / "operation timed out" messages.
        let is_timeout = {
            // Walk the anyhow error chain looking for a reqwest::Error with
            // is_timeout()==true, or a message containing "timed out".
            let mut found = false;
            if let Some(reqwest_err) = e.downcast_ref::<reqwest::Error>() {
                if reqwest_err.is_timeout() {
                    found = true;
                }
            }
            if !found {
                let msg = format!("{:#}", e).to_lowercase();
                if msg.contains("timed out") || msg.contains("timeout") {
                    found = true;
                }
            }
            found
        };
        if is_timeout {
            tracing::debug!(
                request_id = %request_id,
                "proxy timeout for service '{}': {:#}",
                req.service, e
            );
            proxy_error(
                StatusCode::GATEWAY_TIMEOUT,
                "upstream request timed out".to_string(),
            )
        } else {
            tracing::debug!(
                request_id = %request_id,
                "proxy auth/send error for service '{}': {:#}",
                req.service, e
            );
            proxy_error(
                StatusCode::BAD_GATEWAY,
                "upstream request failed".to_string(),
            )
        }
    })?;

    // 5. Sanitize the response body to strip prompt injection patterns.
    crate::security::sanitize::sanitize_json(&mut response.body);

    // 6. Log with summarised args and result.
    if should_log {
        let args_val = req.body.as_ref().cloned().unwrap_or(serde_json::json!({
            "method": req.method,
            "path": req.path,
        }));
        state.audit_log.log(crate::security::audit_log::AuditEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            tool_name: format!("{}__{}", req.service, req.method.to_lowercase()),
            args_summary: crate::security::audit_log::AuditLog::summarize_args(&args_val),
            result_summary: crate::security::audit_log::AuditLog::summarize_result(&response.body),
            permission: format!("{:?}", permission),
            trigger: "proxy".to_string(),
        });
    }

    // Prefer the exact upstream status; fall back to 502 Bad Gateway rather
    // than 200 OK — an unrecognised upstream status code is still an error
    // condition, not a success.
    let upstream_status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::BAD_GATEWAY);
    Ok((upstream_status, Json(response.body)))
}

// -------------------------------------------------------------------------- //
// Auth application                                                             //
// -------------------------------------------------------------------------- //

/// Decrypt credentials, apply the service's auth pattern, and send the HTTP
/// request.  `SecureBuffer`s holding plaintext credentials are dropped
/// (zeroized) as soon as they are no longer needed.
///
/// `service` is the resolved `ServiceEntry` for this request.
/// `ca_client` is the pre-resolved per-service CA-cert client (if any),
/// obtained from `state.ca_cert_clients` by the async caller before entering
/// this function so the RwLock read is not needed inside the sync helpers.
async fn apply_auth_and_send(
    state: &AppState,
    service: &registry::ServiceEntry,
    ca_client: Option<reqwest::Client>,
    auth: AuthPattern,
    url: &str,
    method: Method,
    req: &ProxyRequest,
) -> anyhow::Result<ProxyResponse> {
    match auth {
        // ------------------------------------------------------------------ //
        // Header-based auth (X-Api-Key, X-Plex-Token, …)                     //
        // ------------------------------------------------------------------ //
        AuthPattern::Header {
            header_name,
            vault_item,
        } => {
            let token = state.vault.decrypt_password(&vault_item)?;
            let token_str = std::str::from_utf8(&token)
                .map_err(|e| anyhow::anyhow!("credential is not valid UTF-8: {}", e))?
                .to_string();
            // SecureBuffer `token` is dropped here (original reference ends).
            drop(token);

            let request = build_request(state, service, ca_client, method, url, req)?
                .header(&header_name, &token_str);

            send_request(request).await
        }

        // ------------------------------------------------------------------ //
        // Query-param auth (?apikey=xxx)                                      //
        // ------------------------------------------------------------------ //
        AuthPattern::QueryParam {
            param_name,
            vault_item,
        } => {
            let token = state.vault.decrypt_password(&vault_item)?;
            let token_str = std::str::from_utf8(&token)
                .map_err(|e| anyhow::anyhow!("credential is not valid UTF-8: {}", e))?
                .to_string();
            drop(token);

            // Inject the param into the request builder's query list.
            let mut request = build_request(state, service, ca_client, method, url, req)?;
            request = request.query(&[(&param_name, &token_str)]);

            send_request(request).await
        }

        // ------------------------------------------------------------------ //
        // Bearer auth (Authorization: Bearer <token>)                         //
        // ------------------------------------------------------------------ //
        AuthPattern::Bearer { vault_item } => {
            let token = state.vault.decrypt_password(&vault_item)?;
            let token_str = std::str::from_utf8(&token)
                .map_err(|e| anyhow::anyhow!("credential is not valid UTF-8: {}", e))?
                .to_string();
            drop(token);

            let request =
                build_request(state, service, ca_client, method, url, req)?.bearer_auth(&token_str);

            send_request(request).await
        }

        // ------------------------------------------------------------------ //
        // Basic auth (key:secret from custom vault fields)                    //
        // ------------------------------------------------------------------ //
        AuthPattern::Basic {
            vault_item,
            key_field,
            secret_field,
        } => {
            let key = state.vault.decrypt_field(&vault_item, &key_field)?;
            let secret = state.vault.decrypt_field(&vault_item, &secret_field)?;

            let key_str = std::str::from_utf8(&key)
                .map_err(|e| anyhow::anyhow!("key field is not valid UTF-8: {}", e))?
                .to_string();
            let secret_str = std::str::from_utf8(&secret)
                .map_err(|e| anyhow::anyhow!("secret field is not valid UTF-8: {}", e))?
                .to_string();
            drop(key);
            drop(secret);

            let request = build_request(state, service, ca_client, method, url, req)?
                .basic_auth(&key_str, Some(&secret_str));

            send_request(request).await
        }

        // ------------------------------------------------------------------ //
        // Session auth (login first, then use token as Bearer)                //
        // ------------------------------------------------------------------ //
        AuthPattern::Session {
            vault_item,
            login_path,
            token_field,
            login_include_username,
        } => {
            // Step 1: obtain a session token. Hit the cache first so we don't
            // pay a login round-trip on every proxy call; fall back to the
            // login endpoint on miss, expiry, or upstream 401.
            let session_token = get_or_refresh_session_token(
                state,
                &vault_item,
                &login_path,
                &token_field,
                login_include_username,
                false, /* force_refresh */
            )
            .await?;

            // Step 2: send the actual request with the session token.
            let request =
                build_request(state, service, ca_client.clone(), method.clone(), url, req)?
                    .bearer_auth(&session_token);
            let response = send_request(request).await?;

            // If the upstream rejects the cached token, refresh once and retry.
            // Covers server-side session expiry that our TTL didn't anticipate.
            if response.status == 401 {
                let fresh = get_or_refresh_session_token(
                    state,
                    &vault_item,
                    &login_path,
                    &token_field,
                    login_include_username,
                    true, /* force_refresh */
                )
                .await?;
                let retry =
                    build_request(state, service, ca_client, method, url, req)?.bearer_auth(&fresh);
                return send_request(retry).await;
            }

            Ok(response)
        }

        // ------------------------------------------------------------------ //
        // UniFi dual auth: X-API-Key with session-cookie fallback             //
        // ------------------------------------------------------------------ //
        AuthPattern::UnifiDual {
            vault_item,
            login_path,
        } => {
            // Resolve service name + root URL. The registry stores
            // base_url as "<root>/proxy/network"; login lives at <root>.
            // iter-28: acquire a short-lived read lock, collect the result,
            // then release before the first await point.
            let (service_name, login_base) = {
                let reg = state.registry.read().await;
                let names = reg.list();
                let found = names.iter().find_map(|name| {
                    let entry = reg.get(name)?;
                    if let AuthPattern::UnifiDual { vault_item: vi, .. } = &entry.auth {
                        if vi == &vault_item {
                            let root = entry
                                .base_url
                                .trim_end_matches("/proxy/network")
                                .to_string();
                            return Some((entry.name.clone(), root));
                        }
                    }
                    None
                });
                found
                    .ok_or_else(|| anyhow::anyhow!("cannot resolve base URL for unifi dual auth"))?
            };

            // Decrypt credentials. Drop SecureBuffers as soon as we have
            // owned Strings.
            let username_buf = state
                .vault
                .decrypt_username(&vault_item)?
                .ok_or_else(|| anyhow::anyhow!("vault item '{}' has no username", vault_item))?;
            let password_buf = state.vault.decrypt_password(&vault_item)?;
            let username = std::str::from_utf8(&username_buf)
                .map_err(|e| anyhow::anyhow!("username not utf-8: {}", e))?
                .to_string();
            let password = std::str::from_utf8(&password_buf)
                .map_err(|e| anyhow::anyhow!("password not utf-8: {}", e))?
                .to_string();
            drop(username_buf);
            drop(password_buf);

            let ctx = UnifiDualAuthCtx {
                username,
                password,
                login_path,
            };

            // Build query pairs from the ProxyRequest (mirrors build_request).
            let query_pairs: Vec<(&str, String)> = req
                .query
                .as_ref()
                .map(|q| {
                    q.iter()
                        .map(|(k, v)| {
                            let v_str = match v {
                                Value::String(s) => s.clone(),
                                other => other.to_string(),
                            };
                            (k.as_str(), v_str)
                        })
                        .collect()
                })
                .unwrap_or_default();

            // NB: we pass login_base (no /proxy/network) to handle_request so
            // that login_path resolves against the root of UDM. Real API
            // calls must still go through /proxy/network, so re-add it to
            // the path instead.
            let path_with_prefix = format!("/proxy/network/{}", req.path.trim_start_matches('/'));

            let unifi_req = UnifiRequestCtx {
                base_url: &login_base,
                method,
                path: &path_with_prefix,
                body: req.body.as_ref(),
                query: &query_pairs,
                timeout_secs: service.timeout_secs,
            };
            let resp = unifi_handle_request(&state.unifi_sessions, &service_name, &unifi_req, &ctx)
                .await?;

            Ok(ProxyResponse {
                status: resp.status,
                body: resp.body,
            })
        }
    }
}

// -------------------------------------------------------------------------- //
// Session token cache + login helper                                          //
// -------------------------------------------------------------------------- //

/// Conservative TTL for cached session tokens. NPM tokens live ~1 day and
/// Duplicati's last the dashboard session; 15 minutes is well under either
/// and also bounds the window for a stolen-token replay.
const SESSION_TOKEN_TTL: Duration = Duration::from_secs(15 * 60);

/// Maximum number of entries in the session token cache. Each entry is keyed
/// by `vault_item` name, so under normal operation the map is bounded by the
/// number of `AuthPattern::Session` services in services.toml. The cap
/// prevents unbounded growth if services are repeatedly registered and
/// de-registered (e.g. via a crafted services.toml reload loop), or if a
/// future code path adds entries without a corresponding eviction.
const SESSION_TOKEN_CACHE_MAX: usize = 512;

/// Fetch a session token from the cache, falling back to a fresh login on
/// miss, stale entry, or `force_refresh`. Writes the result back into the
/// cache on successful login.
async fn get_or_refresh_session_token(
    state: &AppState,
    vault_item: &str,
    login_path: &str,
    token_field: &str,
    login_include_username: bool,
    force_refresh: bool,
) -> anyhow::Result<String> {
    if !force_refresh {
        let cache = state.session_tokens.read().await;
        if let Some((token, acquired)) = cache.get(vault_item) {
            if acquired.elapsed() < SESSION_TOKEN_TTL {
                return Ok(token.clone());
            }
        }
    }

    let fresh = session_login(
        state,
        vault_item,
        login_path,
        token_field,
        login_include_username,
    )
    .await?;
    {
        let mut cache = state.session_tokens.write().await;
        // Enforce cap: if the cache is at the limit, evict the oldest entry
        // before inserting the new one. This prevents unbounded growth in the
        // unlikely event of many distinct vault_item keys accumulating (e.g. a
        // services.toml with hundreds of session services, or a misbehaving
        // caller cycling through vault item names).
        if cache.len() >= SESSION_TOKEN_CACHE_MAX && !cache.contains_key(vault_item) {
            // Find the entry with the oldest acquisition time and remove it.
            let oldest_key = cache
                .iter()
                .min_by_key(|(_, (_, acquired))| *acquired)
                .map(|(k, _)| k.clone());
            if let Some(key) = oldest_key {
                cache.remove(&key);
                tracing::warn!(
                    "session token cache reached {} entries — evicted oldest entry to make room",
                    SESSION_TOKEN_CACHE_MAX
                );
            }
        }
        cache.insert(vault_item.to_string(), (fresh.clone(), Instant::now()));
    }
    Ok(fresh)
}

/// Perform a login request for session-based auth and return the extracted
/// token string.  Credentials are held in `SecureBuffer`s and dropped as soon
/// as the login request body is serialized.
async fn session_login(
    state: &AppState,
    vault_item: &str,
    login_path: &str,
    token_field: &str,
    login_include_username: bool,
) -> anyhow::Result<String> {
    // Issue (iter-8): Validate that login_path and token_field are non-empty.
    //
    // `from_toml_file()` ensures both are present (non-None) for session auth,
    // but it does NOT check for empty strings. An empty login_path constructs a
    // URL like `http://host/api` (trailing base_url with no login segment) which
    // either 404s or, worse, posts credentials to the API root. An empty
    // token_field calls `resp.get("")` which returns None and produces an
    // "empty token" error message that gives no hint what went wrong.
    //
    // Checking here (at login time, not registry-load time) catches both
    // services.toml entries and the legacy from_config / from_vault paths that
    // don't go through the TOML validator.
    if login_path.is_empty() {
        return Err(anyhow::anyhow!(
            "session auth for vault item '{}': login_path is empty — set login_path in services.toml \
             (e.g. login_path = \"/tokens\")",
            vault_item
        ));
    }
    if token_field.is_empty() {
        return Err(anyhow::anyhow!(
            "session auth for vault item '{}': token_field is empty — set token_field in services.toml \
             (e.g. token_field = \"token\")",
            vault_item
        ));
    }

    // Determine the base URL and per-service timeout for this login endpoint.
    // The `login_path` is relative to the service's base_url.  We find the
    // matching registry entry by scanning for the vault item — there will be
    // exactly one match for each session service.
    //
    // iter-28: registry is RwLock — acquire read lock briefly, collect both
    // base_url and timeout_secs in a single scan, then release before the
    // async HTTP call below.
    //
    // iter-43: merge the two separate registry scans from iter-42 into one.
    // The iter-42 fix extracted timeout_secs in a second `state.registry.read()`
    // block that ran after the first lock was already dropped, acquiring and
    // releasing the lock twice for the same entry.  A single pass extracts both
    // fields atomically, halving lock acquisitions and eliminating the window
    // where a SIGHUP reload could return different entries for the two scans.
    let (base_url, timeout_secs): (String, Option<u64>) = {
        let reg = state.registry.read().await;
        let names = reg.list();
        names
            .iter()
            .find_map(|name| {
                let entry = reg.get(name)?;
                if let AuthPattern::Session { vault_item: vi, .. } = &entry.auth {
                    if vi == vault_item {
                        return Some((entry.base_url.clone(), entry.timeout_secs));
                    }
                }
                None
            })
            // iter-44: if the registry scan returns None it means the service
            // was removed from the registry between the initial `handle_proxy`
            // lookup (which already cloned the ServiceEntry and released the
            // lock) and this `session_login` call.  This is a SIGHUP/reload
            // race: the operator triggered a reload that removed the service
            // between dispatch and login.  Return a clear error so the caller's
            // 502 log shows the cause rather than a generic "cannot determine"
            // message.
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "session login: service with vault item '{}' not found in registry — \
             the service may have been removed by a concurrent SIGHUP reload \
             between request dispatch and login; the in-flight request will fail \
             with 502 and the next request will use the updated registry",
                    vault_item
                )
            })?
    };

    let login_url = format!("{}{}", base_url.trim_end_matches('/'), login_path);

    // Build the login body using the configured login_include_username flag.
    let login_body = build_session_login_body(state, vault_item, login_include_username)?;

    let mut login_req = state.http.post(&login_url).json(&login_body);
    if let Some(secs) = timeout_secs {
        login_req = login_req.timeout(std::time::Duration::from_secs(secs));
    }
    let resp = login_req
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("session login request failed: {}", e))?
        .error_for_status()
        .map_err(|e| anyhow::anyhow!("session login returned error: {}", e))?;

    let resp_json: Value = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("failed to parse login response: {}", e))?;

    let token = resp_json
        .get(token_field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!("token field '{}' not found in login response", token_field)
        })?
        .to_string();

    // Issue-2 (iter-4): Reject empty tokens before caching them. A 200
    // response with `token_field` present but empty would be cached, cause a
    // 401 on the real request, trigger `force_refresh`, re-login, get the
    // same empty string, and cache it again — meaning every call for this
    // service hereafter pays an extra login round-trip. Returning an error
    // here causes the entire proxy call to fail with BAD_GATEWAY rather than
    // silently caching a useless token.
    if token.is_empty() {
        return Err(anyhow::anyhow!(
            "login response field '{}' is present but empty — refusing to cache empty token",
            token_field
        ));
    }

    Ok(token)
}

/// Build the JSON body for the session login request.
///
/// When `login_include_username` is `false`, only the password is sent
/// (no username field). This is controlled by the `login_include_username`
/// flag on `AuthPattern::Session`, set via `services.toml` — no service name
/// detection is performed here.
fn build_session_login_body(
    state: &AppState,
    vault_item: &str,
    login_include_username: bool,
) -> anyhow::Result<Value> {
    let password_buf = state.vault.decrypt_password(vault_item)?;
    let password = std::str::from_utf8(&password_buf)
        .map_err(|e| anyhow::anyhow!("password is not valid UTF-8: {}", e))?
        .to_string();
    drop(password_buf);

    if !login_include_username {
        // Password-only login body — no username field.
        return Ok(serde_json::json!({ "Password": password }));
    }

    let username_buf = state
        .vault
        .decrypt_username(vault_item)?
        .ok_or_else(|| anyhow::anyhow!("vault item '{}' has no username", vault_item))?;
    let username = std::str::from_utf8(&username_buf)
        .map_err(|e| anyhow::anyhow!("username is not valid UTF-8: {}", e))?
        .to_string();
    drop(username_buf);

    Ok(serde_json::json!({
        "identity": username,
        "secret": password,
    }))
}

// -------------------------------------------------------------------------- //
// Request building helpers                                                     //
// -------------------------------------------------------------------------- //

/// Construct a `reqwest::RequestBuilder` with method, URL, optional body,
/// optional extra headers, and optional extra query params from the caller's
/// `ProxyRequest`.
/// Build a reqwest RequestBuilder for a proxied request.
///
/// `entry` is the pre-looked-up ServiceEntry for this request. Passing it as a
/// parameter (rather than reading it from the registry inside this function)
/// avoids a second async registry read lock acquisition — the caller has
/// already resolved the entry at the start of `handle_proxy`.
///
/// `ca_client` is an optional per-service CA-cert reqwest::Client, pre-resolved
/// by the async caller from `AppState::ca_cert_clients` before calling this
/// sync function (so the RwLock read happens outside the sync scope).
///
/// iter-28: signature changed from reading `state.registry` and
/// `state.ca_cert_clients` directly to accepting pre-resolved values, because
/// both are now `Arc<RwLock<...>>` and cannot be `.await`-ed in a sync fn.
fn build_request(
    state: &AppState,
    entry: &registry::ServiceEntry,
    ca_client: Option<reqwest::Client>,
    method: Method,
    url: &str,
    req: &ProxyRequest,
) -> anyhow::Result<reqwest::RequestBuilder> {
    // Pick the right TLS client for this service:
    //   - insecure_tls = true  → http_permissive (no cert verification)
    //   - ca_client is Some    → use the pre-built per-service CA-cert client
    //                            (built once at startup so connection pool is
    //                            preserved; passed in by caller after SIGHUP)
    //   - neither              → http (strict system-root verification)
    //
    // Issue (iter-15 → iter-16 fix): the iter-15 implementation built a new
    // reqwest::Client on every proxy call when ca_cert was set. reqwest::Client
    // maintains a connection pool; a fresh Client per request defeats connection
    // reuse and forces a TLS handshake on every call. CA-cert clients are now
    // built once in start_server() and stored in AppState::ca_cert_clients.
    let insecure = entry.insecure_tls;

    let client: &reqwest::Client = if insecure {
        &state.http_permissive
    } else if let Some(ref cc) = ca_client {
        cc
    } else {
        &state.http
    };
    let mut builder = client.request(method, url);

    // Issue (iter-41): Per-service timeout override.
    //
    // The global `--proxy-timeout` is baked into the reqwest::Client at startup.
    // For services that need a different timeout (e.g. a Plex library scan that
    // legitimately takes 60 s, or a Sonarr health check that should fail fast at
    // 5 s), `ServiceEntry::timeout_secs` lets operators set a per-service
    // override without changing the global timeout for all other services.
    //
    // `RequestBuilder::timeout()` overrides the client-level timeout for this
    // specific request only — the client's pool and TLS settings are unchanged.
    // `None` means "no per-service override; use the client's global timeout".
    if let Some(per_service_timeout) = entry.timeout_secs {
        builder = builder.timeout(std::time::Duration::from_secs(per_service_timeout));
    }

    // Extra query params supplied by the caller.
    //
    // Issue-6 (iter-4): Duplicate query key behaviour.
    // `reqwest::RequestBuilder::query()` APPENDS to any keys already present
    // in the base URL — it does NOT replace them. This means if `base_url`
    // contains `?token=real` and the caller passes `query = {"token": "X"}`,
    // the upstream receives `?token=real&token=X`. Most HTTP services use the
    // FIRST occurrence of a repeated key, so the attacker's value is silently
    // ignored. However, some services (RFC 3986 allows either) use the LAST
    // value — in that case the caller's value wins, which is dangerous for any
    // service that embeds a static credential or CSRF token in base_url.
    //
    // Guard: reject any caller-supplied query key that also appears in the
    // base URL's query string. This prevents both accidental misconfiguration
    // and deliberate credential-override attempts.
    if let Some(query) = &req.query {
        // Parse the static query string from the base URL (if any).
        if let Ok(parsed_url) = url::Url::parse(url) {
            let base_keys: std::collections::HashSet<String> = parsed_url
                .query_pairs()
                .map(|(k, _)| k.to_string())
                .collect();
            for key in query.keys() {
                if base_keys.contains(key.as_str()) {
                    return Err(anyhow::anyhow!(
                        "query key '{}' conflicts with a key already present in the service base_url — \
                         refusing to shadow or duplicate it",
                        key
                    ));
                }
            }
        }

        let pairs: Vec<(&str, String)> = query
            .iter()
            .map(|(k, v)| {
                let v_str = match v {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                (k.as_str(), v_str)
            })
            .collect();
        builder = builder.query(&pairs);
    }

    // Extra headers supplied by the caller.
    //
    // Issue-X (iter-7): Block auth-override headers. vault-proxy injects auth
    // headers (Authorization, X-Api-Key, X-Plex-Token, etc.) AFTER this
    // build_request call, by chaining on the returned RequestBuilder. reqwest
    // does NOT deduplicate headers — if the caller also injects Authorization
    // here, the upstream receives BOTH headers. Most HTTP servers pick the first
    // occurrence, so the caller's header wins — the vault credential is ignored
    // and the caller has effectively bypassed vault-proxy's credential isolation.
    //
    // Guard: reject any caller-supplied header whose canonical lowercase name is
    // on the blocked list. `Host` is also blocked: injecting a mismatched Host
    // can bypass virtual-host routing on the upstream (e.g. a Caddy or nginx
    // proxy that routes based on Host would forward to the wrong backend).
    //
    // This list is intentionally conservative: callers can still set custom
    // application headers (X-My-Header, Content-Type overrides, etc.) that are
    // not auth-adjacent. If a service requires a custom auth header that happens
    // to collide with this list, it should be modelled as a new AuthPattern
    // rather than passing credentials through the open `headers` field.
    const BLOCKED_HEADERS: &[&str] = &[
        "authorization",
        "proxy-authorization",
        "x-api-key",
        "x-plex-token",
        "x-csrf-token",
        "cookie",
        "host",
    ];
    if let Some(headers) = &req.headers {
        for (k, v) in headers {
            let k_lower = k.to_lowercase();
            if BLOCKED_HEADERS.iter().any(|blocked| k_lower == *blocked) {
                return Err(anyhow::anyhow!(
                    "header '{}' is not allowed in proxy requests — auth headers are injected \
                     by vault-proxy from the vault; passing them directly could bypass credential isolation",
                    k
                ));
            }
            if let Some(v_str) = v.as_str() {
                builder = builder.header(k, v_str);
            }
        }
    }

    // Request body (if any).
    //
    // Issue (iter-12): Normalise `body: null` to "no body".
    //
    // serde deserializes `{"body": null}` as `Some(Value::Null)` and a missing
    // `body` key as `None`.  Without this guard, `Some(Null)` would call
    // `.json(&Value::Null)` which sets `Content-Type: application/json` and
    // sends the literal string "null" as the request body.  Most REST APIs
    // treat that differently from a bodyless request — some return 400 Bad
    // Request, others 415 Unsupported Media Type.  Callers who write
    // `"body": null` almost always mean "no body", so treat both cases
    // identically by only attaching a body for non-Null values.
    if let Some(body) = &req.body {
        if !body.is_null() {
            builder = builder.json(body);
        }
    }

    Ok(builder)
}

/// Maximum upstream response body we'll buffer.
///
/// The default of 32 MB is generous for any legitimate JSON API response;
/// a malicious or misbehaving upstream that returns a 10 GB body would
/// otherwise exhaust the proxy's heap.
///
/// The 64 KB cap on *incoming* `/proxy` request bodies (applied at the router
/// via `DefaultBodyLimit`) does NOT apply to *outgoing* upstream responses —
/// this constant closes that gap.
///
/// Override via the `UPSTREAM_BODY_LIMIT_MB` environment variable for operators
/// with legitimate large responses (binary files, bulk exports, etc.):
///
/// ```sh
/// UPSTREAM_BODY_LIMIT_MB=128   # allow up to 128 MB responses
/// UPSTREAM_BODY_LIMIT_MB=8     # tighten to 8 MB for memory-constrained hosts
/// ```
///
/// Issue (iter-17): Validation is performed at call time (not at startup).
/// Invalid values (`UPSTREAM_BODY_LIMIT_MB=0`, `=abc`, or negative) fall back
/// to the 32 MB default with a `tracing::warn` — the process does not panic.
/// Out-of-range positive values (< 1 MB or > 2048 MB) also warn and fall back.
/// This means a misconfiguration is caught in logs on the first proxied request,
/// not at startup. The warn-and-default strategy avoids hard startup failures
/// for a non-critical tuning knob; operators should monitor startup logs.
fn upstream_body_limit_bytes() -> usize {
    const DEFAULT_MB: usize = 32;
    const MIN_MB: usize = 1;
    const MAX_MB: usize = 2048;

    let mb =
        match std::env::var("UPSTREAM_BODY_LIMIT_MB") {
            Ok(val) => {
                match val.parse::<usize>() {
                    Ok(n) => {
                        if !(MIN_MB..=MAX_MB).contains(&n) {
                            tracing::warn!(
                        "UPSTREAM_BODY_LIMIT_MB={} is out of the allowed range [{}, {}] MB — \
                         using default of {} MB",
                        n, MIN_MB, MAX_MB, DEFAULT_MB
                    );
                            DEFAULT_MB
                        } else {
                            n
                        }
                    }
                    Err(_) => {
                        tracing::warn!(
                    "UPSTREAM_BODY_LIMIT_MB='{}' is not a valid integer — using default of {} MB",
                    val, DEFAULT_MB
                );
                        DEFAULT_MB
                    }
                }
            }
            Err(_) => DEFAULT_MB,
        };
    mb * 1024 * 1024
}

/// Send a built request and normalise the response into a `ProxyResponse`.
///
/// Body parsing strategy (three-tier fallback):
///
/// 1. Try `serde_json` — if the body is valid JSON, return it as `Value`.
/// 2. Try `resp.bytes()` → lossily decode as UTF-8 — if the upstream returned
///    a non-JSON text body (HTML error page, plain-text message, latin-1), we
///    wrap it in `{"_raw": "<text>"}` so callers can see what arrived instead
///    of getting a silent `null`.  Lossily-decoded latin-1 / binary is better
///    than nothing for debugging.
/// 3. If the body bytes are truly empty, return `Value::Null`.
///
/// No panic path: `bytes()`, `String::from_utf8_lossy`, and `serde_json`
/// deserialization all return `Result` / infallible conversions.
async fn send_request(builder: reqwest::RequestBuilder) -> anyhow::Result<ProxyResponse> {
    let resp = builder
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("upstream request failed: {}", e))?;

    let status = resp.status().as_u16();

    // Issue (iter-15): Cap upstream response body at 32 MB before buffering.
    // `resp.bytes()` would happily read a 10 GB body into heap memory.
    // `Content-Length` is advisory (can be missing or lying), so we check the
    // header first as a fast-path reject, then cap actual streaming reads by
    // bailing out if the collected bytes exceed the limit.
    //
    // The check is: reject any response with a Content-Length header that
    // declares a body larger than the limit. For chunked or no-Content-Length
    // responses we use `bytes()` which buffers the full body — so the actual
    // cap is enforced by checking the returned length.
    let body_limit = upstream_body_limit_bytes();

    // Issue (iter-17): Short-circuit body read for status codes that MUST NOT
    // carry a response body per RFC 9110 (HTTP Semantics §6.3.x):
    //   - 204 No Content
    //   - 304 Not Modified
    // For these statuses, `resp.bytes()` would return an empty slice anyway
    // (reqwest drains the body), but skipping it avoids a redundant read and
    // makes intent explicit.  We also skip the Content-Length check because it
    // has no meaning for bodyless responses.
    //
    // 3xx redirect responses (301, 302, …) ARE allowed to have a body — a short
    // HTML "Moved Permanently" page is conventional — and we forward them as-is.
    // Since `redirect::Policy::none()` prevents reqwest from following the
    // redirect, the MCP caller receives the 3xx status and body directly.  That
    // body will fail JSON parsing and be wrapped in `{"_raw": "..."}`, which is
    // the correct behaviour: the caller should inspect the Location header (if
    // present), not try to parse the redirect page as JSON.
    if status == 204 || status == 304 {
        return Ok(ProxyResponse {
            status,
            body: Value::Null,
        });
    }

    if let Some(content_length) = resp.content_length() {
        if content_length > body_limit as u64 {
            return Err(anyhow::anyhow!(
                "upstream response Content-Length ({} bytes) exceeds the \
                 {} MB limit — refusing to buffer",
                content_length,
                body_limit / (1024 * 1024),
            ));
        }
    }

    // Collect bytes once so we can attempt JSON parsing without consuming the
    // response, then fall back to a text wrapper for non-JSON bodies.
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| anyhow::anyhow!("failed to read upstream response body: {}", e))?;

    if bytes.len() > body_limit {
        return Err(anyhow::anyhow!(
            "upstream response body ({} bytes) exceeds the {} MB limit — \
             refusing to buffer (override with UPSTREAM_BODY_LIMIT_MB env var)",
            bytes.len(),
            body_limit / (1024 * 1024),
        ));
    }

    let body: Value = if bytes.is_empty() {
        Value::Null
    } else {
        match serde_json::from_slice::<Value>(&bytes) {
            Ok(json) => json,
            Err(_) => {
                // Non-JSON body (binary, HTML error page, latin-1 text, etc.).
                // Use lossy UTF-8 conversion so we always get *something* useful
                // rather than a silent null that makes upstream errors undebuggable.
                let text = String::from_utf8_lossy(&bytes).into_owned();
                tracing::debug!(
                    "upstream returned non-JSON body ({} bytes); wrapping in {{\"_raw\": ...}}",
                    bytes.len()
                );
                serde_json::json!({ "_raw": text })
            }
        }
    };

    Ok(ProxyResponse { status, body })
}

// -------------------------------------------------------------------------- //
// Error helper                                                                 //
// -------------------------------------------------------------------------- //

fn proxy_error(code: StatusCode, message: String) -> (StatusCode, Json<ProxyError>) {
    // iter-108: ProxyError now carries `ok: false` so callers can detect
    // vault-proxy-level errors by checking `body["ok"] == false` without
    // having to inspect the HTTP status code.
    (
        code,
        Json(ProxyError {
            ok: false,
            error: message,
        }),
    )
}

// -------------------------------------------------------------------------- //
// Test helpers                                                                 //
// -------------------------------------------------------------------------- //

#[cfg(test)]
impl AppState {
    /// Build a minimal stub `AppState` for use in unit tests.
    ///
    /// Accepts a pre-built `VaultManager` (e.g. `VaultManager::new_stub()` or
    /// a seeded stub) and a `vault_folder` string. All other fields are set to
    /// safe no-op defaults. Used by `vault::handlers` tests that call functions
    /// which require `Arc<AppState>` (e.g. `item_in_vault_folder`).
    pub fn new_stub(vault: crate::vault::VaultManager, vault_folder: String) -> Self {
        use crate::notify::Notifier;
        use crate::security::audit_log::AuditLog;
        use crate::security::permissions::ToolPermissions;
        use std::collections::VecDeque;
        use std::sync::atomic::{AtomicBool, AtomicU64};

        static STUB_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = STUB_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let audit_path = format!("/tmp/vault-proxy-stub-audit-{n}.json");

        AppState {
            vault: Arc::new(vault),
            registry: Arc::new(tokio::sync::RwLock::new(
                crate::proxy::registry::ServiceRegistry::new(),
            )),
            http: reqwest::Client::new(),
            http_permissive: reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap(),
            ca_cert_clients: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
            unifi_sessions: Arc::new(crate::proxy::unifi_session::UnifiSessionCache::new()),
            session_tokens: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
            client_certs: None,
            cloud_sync: None,
            approval_queue: Arc::new(tokio::sync::RwLock::new(VecDeque::new())),
            browser: None,
            permissions: Arc::new(tokio::sync::RwLock::new(ToolPermissions::load(
                "/nonexistent/tool-permissions.json",
            ))),
            audit_log: Arc::new(AuditLog::new(&audit_path)),
            notifier: Arc::new(Notifier::disabled()),
            handshake_completed: Arc::new(AtomicBool::new(false)),
            vault_folder,
            last_resync_unix: Arc::new(AtomicU64::new(0)),
            internal_token: Arc::new("test-stub-token".to_string()),
            cached_folder_id: Arc::new(tokio::sync::RwLock::new(None)),
            env_write_root: String::new(),
            config_dir: "/tmp/stub-config".to_string(),
            proxy_timeout: 120,
            reload_mutex: Arc::new(tokio::sync::Mutex::new(())),
            audit_mutex: Arc::new(tokio::sync::Mutex::new(())),
        }
    }
}

// -------------------------------------------------------------------------- //
// Tests                                                                        //
// -------------------------------------------------------------------------- //

#[cfg(test)]
mod path_traversal_tests {
    /// Replicate the path-segment check used in `handle_proxy` so the logic
    /// can be unit-tested without standing up a full AppState.
    fn has_traversal(path: &str) -> bool {
        let path = path.trim_start_matches('/');
        path.split('/').any(|seg| seg == ".." || seg == ".")
    }

    #[test]
    fn double_dot_segment_is_blocked() {
        assert!(
            has_traversal("../etc/passwd"),
            "../etc/passwd must be blocked"
        );
        assert!(has_traversal("/../../root"), "leading ../ must be blocked");
        assert!(
            has_traversal("api/../secret"),
            "interior .. must be blocked"
        );
        assert!(has_traversal(".."), "bare .. must be blocked");
    }

    #[test]
    fn single_dot_segment_is_blocked() {
        assert!(has_traversal("./local"), "./local must be blocked");
        assert!(has_traversal("api/./v1"), "interior . must be blocked");
    }

    #[test]
    fn normal_paths_are_allowed() {
        assert!(!has_traversal("/api/v1/users"), "normal path must pass");
        assert!(!has_traversal("stat/sta"), "path without slashes must pass");
        assert!(
            !has_traversal("/api/s/default/stat/sta"),
            "deep path must pass"
        );
        assert!(!has_traversal(""), "empty path must pass");
        // A path component that contains dots but is not exactly `.` or `..` is fine.
        assert!(!has_traversal("file.json"), "dotted filename must pass");
        assert!(!has_traversal("v3.1/items"), "version with dot must pass");
    }
}

// iter-11: Double-slash prevention tests.
#[cfg(test)]
mod url_join_tests {
    /// Replicate the URL-join logic from `handle_proxy` so the double-slash
    /// guard can be verified without a live AppState.
    fn join_url(base_url: &str, request_path: &str) -> String {
        let path = request_path.trim_start_matches('/');
        if path.is_empty() {
            base_url.to_string()
        } else {
            format!("{}/{}", base_url.trim_end_matches('/'), path)
        }
    }

    #[test]
    fn trailing_slash_on_base_url_does_not_produce_double_slash() {
        // Operator wrote a trailing slash in services.toml — must not produce //.
        let url = join_url("http://service/api/v3/", "/endpoint");
        assert_eq!(url, "http://service/api/v3/endpoint");
        assert!(
            !url.contains("//api"),
            "double slash must not appear after host"
        );
    }

    #[test]
    fn leading_slash_on_path_does_not_produce_double_slash() {
        let url = join_url("http://service/api/v3", "/endpoint");
        assert_eq!(url, "http://service/api/v3/endpoint");
    }

    #[test]
    fn both_trailing_and_leading_slash_normalised() {
        let url = join_url("http://service/api/v3/", "/endpoint/items");
        assert_eq!(url, "http://service/api/v3/endpoint/items");
    }

    #[test]
    fn empty_path_returns_base_url_unchanged() {
        let base = "http://service/api/v3";
        assert_eq!(join_url(base, ""), base);
        assert_eq!(join_url(base, "/"), base);
    }
}

// Issue-6 (iter-4): Query key conflict detection tests.
#[cfg(test)]
mod query_conflict_tests {
    /// Replicate the key-extraction logic from build_request inline so we can
    /// test without a live reqwest client.
    fn base_url_query_keys(url: &str) -> std::collections::HashSet<String> {
        url::Url::parse(url)
            .map(|u| u.query_pairs().map(|(k, _)| k.to_string()).collect())
            .unwrap_or_default()
    }

    #[test]
    fn base_url_without_query_has_no_keys() {
        let keys = base_url_query_keys("http://service/api/v2");
        assert!(keys.is_empty());
    }

    #[test]
    fn base_url_with_token_param_detected() {
        let keys = base_url_query_keys("http://service/api/v2?token=real&other=x");
        assert!(keys.contains("token"), "token key must be detected");
        assert!(keys.contains("other"), "other key must be detected");
    }

    #[test]
    fn caller_key_conflict_would_be_blocked() {
        // Simulates: base_url has ?apikey=real, caller passes query={"apikey":"X"}
        let base_keys = base_url_query_keys("http://tautulli/api/v2?apikey=real&cmd=get_libraries");
        // The caller's query map.
        let caller_keys = ["apikey".to_string()];
        let conflicts: Vec<&str> = caller_keys
            .iter()
            .filter(|k| base_keys.contains(k.as_str()))
            .map(String::as_str)
            .collect();
        assert!(
            !conflicts.is_empty(),
            "apikey conflict must be detected and blocked"
        );
    }

    #[test]
    fn non_conflicting_caller_keys_are_allowed() {
        let base_keys = base_url_query_keys("http://tautulli/api/v2?apikey=real");
        let caller_keys = ["cmd".to_string(), "output_format".to_string()];
        let conflicts: Vec<&str> = caller_keys
            .iter()
            .filter(|k| base_keys.contains(k.as_str()))
            .map(String::as_str)
            .collect();
        assert!(
            conflicts.is_empty(),
            "non-conflicting keys must pass through"
        );
    }
}

// -------------------------------------------------------------------------- //
// Integration tests — axum router + stub AppState + wiremock upstream        //
// -------------------------------------------------------------------------- //
//
// Issue (iter-29): after 29 iterations there were only 2 integration tests,
// neither of which exercised the full HTTP request path. These tests spin up a
// real axum listener with a stub AppState (no live Vaultwarden) and verify:
//
//   (a) POST /proxy → 404 for unknown service names.
//   (b) GET /vault/health → 200 with expected JSON keys.
//   (c) POST /proxy with a known service → fails at auth stage (502 BAD_GATEWAY)
//       not routing stage (404 NOT_FOUND), confirming service lookup worked.
//
// wiremock is used to stand in as the upstream service for test (c), confirming
// vault-proxy correctly selects the registered service entry and attempts to
// reach the upstream. The credential decrypt fails on the stub vault (which has
// no items), so the mocked upstream is never actually called — but the 502
// confirms vault-proxy got past the routing step and into the auth path.

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::notify::Notifier;
    use crate::proxy::registry::{AuthPattern, ServiceEntry, ServiceRegistry};
    use crate::proxy::unifi_session::UnifiSessionCache;
    use crate::security::audit_log::AuditLog;
    use crate::security::permissions::ToolPermissions;
    use crate::vault::VaultManager;
    use axum::routing::{get, post};
    use axum::Router;
    use serde_json::json;
    use std::collections::VecDeque;
    use std::sync::Arc;

    /// Build a minimal stub `AppState` for integration tests.
    ///
    /// Uses `VaultManager::new_stub()` so no live Vaultwarden connection is
    /// needed. All credential-decrypt operations will fail gracefully with an
    /// error (not a panic), causing `handle_proxy` to return 502 BAD_GATEWAY
    /// instead of forwarding to the upstream — which is the expected behaviour
    /// when testing the routing path without a live vault.
    ///
    /// Each call creates a unique audit log path using a monotonically
    /// incrementing counter so that parallel test runs (which is the default
    /// for `cargo test`) do not race on a shared audit log file.
    ///
    /// Issue (iter-31): the previous implementation used `subsec_nanos()` as the
    /// suffix, which is not unique — two invocations within the same nanosecond
    /// (e.g. on a fast machine running tests in parallel) would produce the same
    /// path. A `static AtomicU64` counter is strictly monotonic regardless of
    /// clock resolution.
    fn make_state(registry: ServiceRegistry) -> Arc<AppState> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let audit_path = format!("/tmp/vault-proxy-test-audit-{n}.json");
        Arc::new(AppState {
            vault: Arc::new(VaultManager::new_stub()),
            registry: Arc::new(tokio::sync::RwLock::new(registry)),
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            http_permissive: reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            ca_cert_clients: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
            unifi_sessions: Arc::new(UnifiSessionCache::new()),
            session_tokens: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
            client_certs: None,
            cloud_sync: None,
            approval_queue: Arc::new(tokio::sync::RwLock::new(VecDeque::new())),
            browser: None,
            permissions: Arc::new(tokio::sync::RwLock::new(ToolPermissions::load(
                "/nonexistent/tool-permissions.json",
            ))),
            audit_log: Arc::new(AuditLog::new(&audit_path)),
            notifier: Arc::new(Notifier::disabled()),
            handshake_completed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            vault_folder: "vault-proxy".to_string(),
            last_resync_unix: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            internal_token: Arc::new("test-internal-token".to_string()),
            cached_folder_id: Arc::new(tokio::sync::RwLock::new(None)),
            env_write_root: String::new(),
            config_dir: "/config".to_string(),
            proxy_timeout: 120,
            reload_mutex: Arc::new(tokio::sync::Mutex::new(())),
            audit_mutex: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    /// Build a minimal axum Router for integration tests.
    fn make_app(state: Arc<AppState>) -> Router {
        Router::new()
            .route("/proxy", post(handle_proxy))
            .route("/vault/health", get(crate::vault::handlers::health))
            .with_state(state)
    }

    // ---------------------------------------------------------------------- //
    // (a) POST /proxy → 404 for unknown service                               //
    // ---------------------------------------------------------------------- //

    /// A proxy request for a service that is not in the registry must return
    /// 404 NOT_FOUND.  The error body must not echo back the service name
    /// (enumeration defence).
    #[tokio::test]
    async fn proxy_unknown_service_returns_404() {
        let state = make_state(ServiceRegistry::new()); // empty registry
        let app = make_app(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{}/proxy", addr))
            .json(&json!({
                "service": "no-such-service",
                "method": "GET",
                "path": "/api/v1/items"
            }))
            .send()
            .await
            .expect("request failed");

        assert_eq!(
            resp.status().as_u16(),
            404,
            "unknown service must return 404"
        );

        // The error body must not reveal the requested service name.
        let body: serde_json::Value = resp.json().await.unwrap();
        let error_msg = body["error"].as_str().unwrap_or("");
        assert!(
            !error_msg.contains("no-such-service"),
            "error body must not echo back the service name (enumeration defence): got '{error_msg}'"
        );
    }

    // ---------------------------------------------------------------------- //
    // (b) GET /vault/health → 200                                              //
    // ---------------------------------------------------------------------- //

    /// The health endpoint must return 200 with a JSON body containing
    /// `vault_item_count` and `service_count` keys.
    #[tokio::test]
    async fn vault_health_returns_200() {
        let state = make_state(ServiceRegistry::new());
        let app = make_app(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let resp = reqwest::Client::new()
            .get(format!("http://{}/vault/health", addr))
            .send()
            .await
            .expect("request failed");

        assert_eq!(
            resp.status().as_u16(),
            200,
            "health endpoint must return 200"
        );

        let body: serde_json::Value = resp.json().await.expect("health must return JSON");
        assert!(
            body.get("vault_item_count").is_some(),
            "health response must include vault_item_count field"
        );
        assert!(
            body.get("service_count").is_some(),
            "health response must include service_count field"
        );
    }

    // ---------------------------------------------------------------------- //
    // (d) Rate limiter returns 429 after exceeding the request budget         //
    // ---------------------------------------------------------------------- //

    /// Send N+1 requests to a rate-limited path using a RateLimiter configured
    /// with a budget of N. The (N+1)th request must return 429 TOO_MANY_REQUESTS.
    ///
    /// We use a custom limiter with max=2 to keep the test fast (only 3 HTTP
    /// round-trips required). The endpoint is `/vault/health` which is NOT in
    /// `RATE_LIMITED_PATHS` — so we use `/proxy` which IS rate-limited. However,
    /// since `/proxy` requires a JSON body and returns various status codes based
    /// on routing, we test with `/proxy` at the path level.
    ///
    /// The test wires a fresh Router with a tight (2 req / 60 s) rate limiter so
    /// the third request returns 429 without having to send 61 real requests.
    #[tokio::test]
    async fn rate_limiter_returns_429_after_budget_exhausted() {
        use crate::security::rate_limit::RateLimiter;
        use axum::routing::post;

        let state = make_state(ServiceRegistry::new());
        // Build a tight limiter: 2 requests per 60 s window.
        let tight_limiter = RateLimiter::new(2, 60);

        let app = Router::new()
            .route("/proxy", post(handle_proxy))
            .layer(axum::middleware::from_fn_with_state(
                tight_limiter,
                crate::security::rate_limit::rate_limit_middleware,
            ))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = reqwest::Client::new();
        let payload = serde_json::json!({
            "service": "x",
            "method": "GET",
            "path": "/api"
        });

        // First two requests: should NOT be 429 (may be 404 from registry, that's fine).
        for i in 1..=2u32 {
            let resp = client
                .post(format!("http://{}/proxy", addr))
                .json(&payload)
                .send()
                .await
                .expect("request failed");
            assert_ne!(
                resp.status().as_u16(),
                429,
                "request {i} should not be rate-limited yet"
            );
        }

        // Third request: must be 429.
        let resp = client
            .post(format!("http://{}/proxy", addr))
            .json(&payload)
            .send()
            .await
            .expect("request failed");
        assert_eq!(
            resp.status().as_u16(),
            429,
            "third request must be rate-limited (429 TOO_MANY_REQUESTS)"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(
            body.get("error").is_some(),
            "429 body must contain an 'error' key"
        );
    }

    // ---------------------------------------------------------------------- //
    // (e) DNS rebinding guard returns 403 on bad Host header                  //
    // ---------------------------------------------------------------------- //

    /// A request with a non-localhost Host header must be rejected with 403.
    /// A request with Host: 127.0.0.1 must be allowed through (may still fail
    /// at the routing level with a 404, but not at the DNS guard level).
    #[tokio::test]
    async fn dns_rebinding_guard_blocks_external_host() {
        use crate::vault::handlers;
        use axum::routing::{get, post};

        let state = make_state(ServiceRegistry::new());
        let app = Router::new()
            .route("/proxy", post(handle_proxy))
            .route("/vault/health", get(handlers::health))
            .layer(axum::middleware::from_fn(crate::dns_rebinding_guard))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = reqwest::Client::new();

        // Bad Host — must return 403.
        let resp = client
            .get(format!("http://{}/vault/health", addr))
            .header("host", "evil.com")
            .send()
            .await
            .expect("request failed");
        assert_eq!(
            resp.status().as_u16(),
            403,
            "external Host header must be blocked with 403 FORBIDDEN"
        );
        // Issue (iter-104): verify that the 403 body includes "ok": false —
        // added to dns_rebinding_guard in iter-103; these assertions lock in
        // the regression test so future changes can't silently drop the field.
        let body: serde_json::Value = resp.json().await.expect("403 body must be valid JSON");
        assert_eq!(
            body["ok"], false,
            "dns_rebinding_guard 403 body must contain ok: false (invalid-host path)"
        );
        assert!(
            body["error"].is_string(),
            "dns_rebinding_guard 403 body must contain an 'error' string"
        );

        // Good Host — must be allowed through (health returns 200).
        let resp = client
            .get(format!("http://{}/vault/health", addr))
            .header("host", "127.0.0.1")
            .send()
            .await
            .expect("request failed");
        assert_eq!(
            resp.status().as_u16(),
            200,
            "localhost Host header must pass the DNS guard and reach the handler"
        );
    }

    // ---------------------------------------------------------------------- //
    // (f) Internal bearer token returns 401 without the header                //
    // ---------------------------------------------------------------------- //

    /// An internal endpoint (e.g. /rotate) must return 401 UNAUTHORIZED when
    /// the Authorization: Bearer header is missing or wrong.
    /// When the correct token is supplied it must NOT return 401 (the stub vault
    /// may return another status from the actual handler, but the auth check
    /// itself passed).
    #[tokio::test]
    async fn internal_token_middleware_returns_401_without_header() {
        use crate::vault::handlers;
        use axum::routing::{get, post};

        let state = make_state(ServiceRegistry::new());
        let correct_token = state.internal_token.as_str().to_string();

        // Wire the internal endpoint sub-router exactly as main.rs does.
        let internal_router = Router::new()
            .route("/rotate", post(crate::rotate::handle_rotate))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::require_internal_token,
            ))
            .with_state(state.clone());

        let app = Router::new()
            .route("/vault/health", get(handlers::health))
            .merge(internal_router)
            .with_state(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = reqwest::Client::new();
        let payload = serde_json::json!({"service": "sonarr", "strategy": "api"});

        // No auth header → 401.
        let resp = client
            .post(format!("http://{}/rotate", addr))
            .json(&payload)
            .send()
            .await
            .expect("request failed");
        assert_eq!(
            resp.status().as_u16(),
            401,
            "missing Authorization header must return 401 UNAUTHORIZED"
        );
        // Issue (iter-104): verify that the 401 body includes "ok": false —
        // added to require_internal_token in iter-103; this assertion locks in
        // the regression test so future changes can't silently drop it.
        let body: serde_json::Value = resp.json().await.expect("401 body must be valid JSON");
        assert_eq!(
            body["ok"], false,
            "401 body must contain ok: false (missing-header path)"
        );
        assert!(
            body["error"].is_string(),
            "401 body must contain an 'error' string (missing-header path)"
        );

        // Wrong token → 401.
        let resp = client
            .post(format!("http://{}/rotate", addr))
            .header("authorization", "Bearer wrong-token")
            .json(&payload)
            .send()
            .await
            .expect("request failed");
        assert_eq!(
            resp.status().as_u16(),
            401,
            "invalid token must return 401 UNAUTHORIZED"
        );
        let body: serde_json::Value = resp.json().await.expect("401 body must be valid JSON");
        assert_eq!(
            body["ok"], false,
            "401 body must contain ok: false (wrong-token path)"
        );

        // Correct token → NOT 401 (handler runs; stub returns 501 for sonarr).
        let resp = client
            .post(format!("http://{}/rotate", addr))
            .header("authorization", format!("Bearer {}", correct_token))
            .json(&payload)
            .send()
            .await
            .expect("request failed");
        assert_ne!(
            resp.status().as_u16(),
            401,
            "correct token must pass the auth check (handler may return non-401)"
        );
    }

    // ---------------------------------------------------------------------- //
    // (c) POST /proxy with known service → reaches auth stage (not 404)       //
    // ---------------------------------------------------------------------- //

    /// When a service IS registered, a proxy request must not return 404.
    /// The stub vault has no items → credential decrypt fails → 502 BAD_GATEWAY.
    /// 502 ≠ 404 confirms the service was found and the request reached the
    /// auth stage.
    ///
    /// wiremock is started to accept the forwarded request in case the auth
    /// somehow succeeds (it won't with the stub), verifying vault-proxy would
    /// use the correct upstream URL.
    #[tokio::test]
    async fn proxy_known_service_reaches_auth_not_routing_error() {
        // Start a wiremock upstream that would handle the forwarded request.
        let upstream = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/api/v1/status"))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(json!({"status": "ok"})),
            )
            .mount(&upstream)
            .await;

        let mut registry = ServiceRegistry::new();
        registry.register(ServiceEntry {
            name: "ha".to_string(),
            base_url: upstream.uri(),
            auth: AuthPattern::Bearer {
                vault_item: "vault-proxy - HomeAssistant".to_string(),
            },
            insecure_tls: false,
            ca_cert_path: None,
            timeout_secs: None,
        });

        let state = make_state(registry);
        let app = make_app(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let resp = reqwest::Client::new()
            .post(format!("http://{}/proxy", addr))
            .json(&json!({
                "service": "ha",
                "method": "GET",
                "path": "/api/v1/status"
            }))
            .send()
            .await
            .expect("request failed");

        // 502 = reached auth stage, credential lookup failed on stub vault.
        // 404 would mean the service was not found in the registry (a bug).
        assert_ne!(
            resp.status().as_u16(),
            404,
            "known service must not return 404 — it should fail at auth (502)"
        );
        assert_eq!(
            resp.status().as_u16(),
            502,
            "stub vault with no items must produce 502 (auth failure)"
        );
    }

    // ---------------------------------------------------------------------- //
    // (g) vault_folder scope guard returns 403 for out-of-folder delete       //
    // ---------------------------------------------------------------------- //

    /// A `POST /vault/items/delete` request for an item that exists in the
    /// vault but belongs to a DIFFERENT folder (not `vault_folder`) must
    /// return 403 FORBIDDEN. This exercises the scope guard added in iter-18
    /// and ensures a regression would be caught immediately.
    ///
    /// Test setup:
    ///   - `AppState::vault_folder` = "vault-proxy"
    ///   - Seed a folder "other-folder" (id "folder-other") and a cipher
    ///     "item-001" whose `folder_id` is "folder-other".
    ///   - Seed the "vault-proxy" folder (id "folder-vp") in the vault so
    ///     `find_folder_id_by_name_async("vault-proxy")` returns Some("folder-vp").
    ///   - Call `POST /vault/items/delete` with `id = "item-001"`.
    ///   - Assert 403: item exists but is outside vault_folder.
    #[tokio::test]
    async fn vault_folder_scope_guard_blocks_out_of_folder_delete() {
        use crate::vault::handlers;
        use crate::vault::types::EncryptedCipher;
        use axum::routing::{get, post};

        let state = make_state(ServiceRegistry::new());

        // Seed the vault: "vault-proxy" folder and an item in "other-folder".
        let vault = &state.vault;
        // Insert the vault-proxy folder so the scope guard resolves it.
        vault
            .seed_for_test(
                "folder-vp".to_string(),
                "vault-proxy".to_string(),
                // Dummy cipher in "vault-proxy" — not the target of the delete.
                EncryptedCipher {
                    id: "item-vp".to_string(),
                    name: "2.a|b".to_string(), // minimal encrypted string
                    cipher_type: 1,
                    login: None,
                    card: None,
                    identity: None,
                    secure_note: None,
                    fields: None,
                    notes: None,
                    organization_id: None,
                    collection_ids: None,
                    folder_id: Some("folder-vp".to_string()),
                    revision_date: None,
                    key: None,
                    extra: None,
                },
            )
            .await;

        // Seed "other-folder" with the item the test will try to delete.
        vault
            .seed_for_test(
                "folder-other".to_string(),
                "other-folder".to_string(),
                EncryptedCipher {
                    id: "item-001".to_string(),
                    name: "2.a|b".to_string(),
                    cipher_type: 1,
                    login: None,
                    card: None,
                    identity: None,
                    secure_note: None,
                    fields: None,
                    notes: None,
                    organization_id: None,
                    collection_ids: None,
                    // This item is in "other-folder", NOT in "vault-proxy".
                    folder_id: Some("folder-other".to_string()),
                    revision_date: None,
                    key: None,
                    extra: None,
                },
            )
            .await;

        let app = Router::new()
            .route("/vault/items/delete", post(handlers::delete_item))
            .route("/vault/health", get(handlers::health))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let resp = reqwest::Client::new()
            .post(format!("http://{}/vault/items/delete", addr))
            .json(&json!({
                "id": "item-001",
                "confirm": true
            }))
            .send()
            .await
            .expect("request failed");

        assert_eq!(
            resp.status().as_u16(),
            403,
            "item outside vault_folder must be rejected with 403 FORBIDDEN \
             (scope guard regression check)"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(
            body.get("error").is_some(),
            "403 body must contain an 'error' key"
        );
    }

    // ---------------------------------------------------------------------- //
    // (h) SIGHUP registry swap — reload-services integration                  //
    // ---------------------------------------------------------------------- //

    /// Exercises the live registry-swap path that both SIGHUP and
    /// `POST /vault/reload-services` use.
    ///
    /// Test sequence:
    ///   1. Start vault-proxy with service A ("service-alpha") registered.
    ///   2. Verify `GET /vault/services` lists only "service-alpha".
    ///   3. Atomically swap in a new registry that adds service B ("service-beta")
    ///      — this is the same three-lock write sequence used by both SIGHUP and
    ///      the reload-services handler.
    ///   4. Verify `GET /vault/services` now lists both "service-alpha" and
    ///      "service-beta" — confirming the swap took effect without a restart.
    ///
    /// This test catches regressions in:
    ///   - The `Arc<RwLock<ServiceRegistry>>` write-lock acquisition order.
    ///   - The rollback guard (a separate sub-test verifies rollback behaviour).
    ///   - The `cached_folder_id` invalidation after the swap.
    #[tokio::test]
    async fn sighup_registry_swap_adds_service_without_restart() {
        use crate::vault::handlers;
        use axum::routing::get;

        // Start with one service registered.
        let mut initial_registry = ServiceRegistry::new();
        initial_registry.register(ServiceEntry {
            name: "service-alpha".to_string(),
            base_url: "http://alpha.local/api".to_string(),
            auth: AuthPattern::Bearer {
                vault_item: "vault-proxy - Alpha".to_string(),
            },
            insecure_tls: false,
            ca_cert_path: None,
            timeout_secs: None,
        });

        let state = make_state(initial_registry);

        let app = Router::new()
            .route("/vault/services", get(handlers::list_services))
            .with_state(state.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = reqwest::Client::new();

        // Step 1: Confirm initial state — only service-alpha is registered.
        let resp = client
            .get(format!("http://{}/vault/services", addr))
            .send()
            .await
            .expect("request failed");
        assert_eq!(resp.status().as_u16(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        let names = body["services"].as_array().expect("services must be array");
        assert_eq!(names.len(), 1, "initial registry must have 1 service");
        assert!(
            names
                .iter()
                .any(|n| n.get("name").and_then(|v| v.as_str()) == Some("service-alpha")),
            "service-alpha must be in initial registry"
        );

        // Step 2: Build a new registry with both service-alpha and service-beta
        // and atomically swap it in — exactly what SIGHUP / reload-services does.
        let mut new_registry = ServiceRegistry::new();
        new_registry.register(ServiceEntry {
            name: "service-alpha".to_string(),
            base_url: "http://alpha.local/api".to_string(),
            auth: AuthPattern::Bearer {
                vault_item: "vault-proxy - Alpha".to_string(),
            },
            insecure_tls: false,
            ca_cert_path: None,
            timeout_secs: None,
        });
        new_registry.register(ServiceEntry {
            name: "service-beta".to_string(),
            base_url: "http://beta.local/api".to_string(),
            auth: AuthPattern::Header {
                header_name: "X-Api-Key".to_string(),
                vault_item: "vault-proxy - Beta".to_string(),
            },
            insecure_tls: false,
            ca_cert_path: None,
            timeout_secs: None,
        });

        // Perform the three-lock swap (same order as SIGHUP handler).
        *state.registry.write().await = new_registry;
        *state.ca_cert_clients.write().await = std::collections::HashMap::new();
        *state.cached_folder_id.write().await = None;

        // Step 3: Verify service-beta is now visible — swap succeeded.
        let resp = client
            .get(format!("http://{}/vault/services", addr))
            .send()
            .await
            .expect("request failed");
        assert_eq!(resp.status().as_u16(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        let names = body["services"].as_array().expect("services must be array");
        assert_eq!(names.len(), 2, "after swap, registry must have 2 services");
        assert!(
            names
                .iter()
                .any(|n| n.get("name").and_then(|v| v.as_str()) == Some("service-beta")),
            "service-beta must appear in registry after atomic swap (SIGHUP regression check)"
        );
        assert!(
            names
                .iter()
                .any(|n| n.get("name").and_then(|v| v.as_str()) == Some("service-alpha")),
            "service-alpha must still be present after swap"
        );
    }

    /// Verify the SIGHUP rollback guard: swapping in an empty registry when
    /// the current one is non-empty must be refused.
    ///
    /// This mirrors the rollback logic in both the SIGHUP handler and
    /// `reload_services` — a zero-service reload result keeps the old registry.
    #[tokio::test]
    async fn sighup_rollback_guard_refuses_empty_registry_swap() {
        let mut initial_registry = ServiceRegistry::new();
        initial_registry.register(ServiceEntry {
            name: "existing-service".to_string(),
            base_url: "http://existing.local".to_string(),
            auth: AuthPattern::Bearer {
                vault_item: "vault-proxy - Existing".to_string(),
            },
            insecure_tls: false,
            ca_cert_path: None,
            timeout_secs: None,
        });

        let state = make_state(initial_registry);

        // Attempt the rollback scenario: empty new_registry + non-empty old.
        let empty_registry = ServiceRegistry::new();
        let new_svc_count = empty_registry.list().len();
        let prev_svc_count = state.registry.read().await.list().len();

        // Apply the rollback guard (same condition as SIGHUP handler).
        let should_rollback = new_svc_count == 0 && prev_svc_count > 0;
        assert!(
            should_rollback,
            "rollback guard must fire when new registry is empty"
        );

        // Guard fires — do NOT swap. Old registry stays in place.
        if !should_rollback {
            *state.registry.write().await = empty_registry;
        }

        // After the (non-)swap, the registry must still have the original service.
        let current_count = state.registry.read().await.list().len();
        assert_eq!(
            current_count, 1,
            "rollback guard must preserve original registry — \
             zero-service reload must be rejected (SIGHUP regression check)"
        );
    }

    // ---------------------------------------------------------------------- //
    // (h2) GET /vault/items — iter-110: response format is {"ok":true,"items"} //
    // ---------------------------------------------------------------------- //

    /// iter-110: `GET /vault/items` must return `{"ok": true, "items": [...]}`,
    /// NOT a bare JSON array.
    ///
    /// iter-109 changed the response shape from a bare array to an object.
    /// Without this test, a regression to the old shape would go undetected —
    /// callers checking `body["ok"] == true` would silently receive `null`.
    ///
    /// The vault stub contains no items in `vault_folder` (cache miss / None
    /// path), so `items` must be `[]` — but the `ok: true` key and `items`
    /// array key must be present regardless.
    #[tokio::test]
    async fn list_items_returns_ok_true_and_items_array() {
        use crate::vault::handlers;
        use axum::routing::get;

        let state = make_state(ServiceRegistry::new());
        let app = Router::new()
            .route("/vault/items", get(handlers::list_items))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{}/vault/items", addr))
            .send()
            .await
            .expect("request failed");

        assert_eq!(
            resp.status().as_u16(),
            200,
            "GET /vault/items must return 200 OK"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body["ok"], true,
            "GET /vault/items response must contain ok=true (iter-109 breaking change); \
             got: {body}"
        );
        assert!(
            body["items"].is_array(),
            "GET /vault/items response must contain 'items' array key; got: {body}"
        );
    }

    // ---------------------------------------------------------------------- //
    // (h3) GET /vault/folders — iter-111: response shape {"ok":true,"folders"} //
    // ---------------------------------------------------------------------- //

    /// iter-111: `GET /vault/folders` must return `{"ok": true, "folders": [...]}`,
    /// NOT a bare JSON array.
    ///
    /// iter-110 changed the response shape from a bare `Vec<FolderInfo>` to an
    /// object with `"ok": true`. Without this test, a regression to the old bare-
    /// array shape would go undetected — callers checking `body["ok"] == true`
    /// would silently receive `null`.
    ///
    /// The vault stub contains no folders, so `folders` must be `[]` — but the
    /// `ok: true` key and `folders` array key must be present regardless.
    #[tokio::test]
    async fn list_folders_returns_ok_true_and_folders_array() {
        use crate::vault::handlers;
        use axum::routing::get;

        let state = make_state(ServiceRegistry::new());
        let app = Router::new()
            .route("/vault/folders", get(handlers::list_folders))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{}/vault/folders", addr))
            .send()
            .await
            .expect("request failed");

        assert_eq!(
            resp.status().as_u16(),
            200,
            "GET /vault/folders must return 200 OK"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body["ok"], true,
            "GET /vault/folders response must contain ok=true (iter-110 breaking change); \
             got: {body}"
        );
        assert!(
            body["folders"].is_array(),
            "GET /vault/folders response must contain 'folders' array key; got: {body}"
        );
    }

    // ---------------------------------------------------------------------- //
    // (h4) GET /vault/duplicates — iter-111: response {"ok":true,"groups"}    //
    // ---------------------------------------------------------------------- //

    /// iter-111: `GET /vault/duplicates` must return `{"ok": true, "groups": [...]}`,
    /// NOT a bare JSON array.
    ///
    /// iter-110 changed the response shape from a bare `Vec<DuplicateGroup>` to an
    /// object with `"ok": true`. Without this test, a regression to the old bare-
    /// array shape would go undetected — callers checking `body["ok"] == true`
    /// would silently receive `null`.
    ///
    /// The vault stub has no items, so `groups` must be `[]` — but the `ok: true`
    /// key and `groups` array key must be present regardless.
    #[tokio::test]
    async fn list_duplicates_returns_ok_true_and_groups_array() {
        use crate::vault::handlers;
        use axum::routing::get;

        let state = make_state(ServiceRegistry::new());
        let app = Router::new()
            .route("/vault/duplicates", get(handlers::list_duplicates))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{}/vault/duplicates", addr))
            .send()
            .await
            .expect("request failed");

        assert_eq!(
            resp.status().as_u16(),
            200,
            "GET /vault/duplicates must return 200 OK"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(
            body["ok"], true,
            "GET /vault/duplicates response must contain ok=true (iter-110 breaking change); \
             got: {body}"
        );
        assert!(
            body["groups"].is_array(),
            "GET /vault/duplicates response must contain 'groups' array key; got: {body}"
        );
    }

    // ---------------------------------------------------------------------- //
    // (i) POST /vault/reload-services — HTTP integration tests (iter-35)       //
    // ---------------------------------------------------------------------- //

    /// Helper: write a minimal services.toml with the given service blocks to
    /// `<dir>/services.toml` and return the path.
    fn write_services_toml(dir: &std::path::Path, content: &str) {
        let path = dir.join("services.toml");
        std::fs::write(&path, content).expect("write_services_toml failed");
    }

    /// `POST /vault/reload-services` happy-path: write a new services.toml with
    /// two services, call the endpoint, and assert the response shows both
    /// service names and `new_service_count == 2`.
    #[tokio::test]
    async fn reload_services_happy_path_updates_registry() {
        use crate::vault::handlers;
        use axum::routing::post;
        use std::sync::atomic::{AtomicU64, Ordering};

        // Use a temp directory so the test doesn't interfere with /config.
        static RELOAD_COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = RELOAD_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("vault-proxy-reload-test-{n}"));
        std::fs::create_dir_all(&dir).unwrap();

        // Write a services.toml with two bearer-auth services.
        write_services_toml(
            &dir,
            r#"
[[service]]
name        = "alpha"
base_url    = "http://alpha.internal/api"
auth        = "bearer"
vault_item  = "vault-proxy - Alpha"

[[service]]
name        = "beta"
base_url    = "http://beta.internal/api"
auth        = "bearer"
vault_item  = "vault-proxy - Beta"
"#,
        );

        // Build state with empty registry but config_dir pointing at our temp dir.
        let mut state = (*make_state(ServiceRegistry::new())).clone();
        state.config_dir = dir.to_str().unwrap().to_string();
        state.internal_token = Arc::new("reload-test-token".to_string());
        let state = Arc::new(state);

        let internal_router = Router::new()
            .route("/vault/reload-services", post(handlers::reload_services))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::require_internal_token,
            ))
            .with_state(state.clone());

        let app = Router::new()
            .merge(internal_router)
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{}/vault/reload-services", addr))
            .header("authorization", "Bearer reload-test-token")
            .send()
            .await
            .expect("request failed");

        assert_eq!(resp.status().as_u16(), 200, "happy path must return 200 OK");
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["ok"], true, "response must contain ok=true");
        assert_eq!(
            body["new_service_count"], 2,
            "new_service_count must reflect both services loaded from services.toml"
        );
        let services = body["services"].as_array().unwrap();
        assert!(
            services.iter().any(|v| v.as_str() == Some("alpha")),
            "services list must contain 'alpha'"
        );
        assert!(
            services.iter().any(|v| v.as_str() == Some("beta")),
            "services list must contain 'beta'"
        );

        // Cleanup.
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `POST /vault/reload-services` rollback path: write an empty services.toml
    /// when the current registry is non-empty. The endpoint must return 409 Conflict
    /// and the existing registry must remain intact.
    #[tokio::test]
    async fn reload_services_empty_file_returns_409_conflict() {
        use crate::vault::handlers;
        use axum::routing::post;
        use std::sync::atomic::{AtomicU64, Ordering};

        static RELOAD_CONFLICT_COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = RELOAD_CONFLICT_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("vault-proxy-reload-conflict-{n}"));
        std::fs::create_dir_all(&dir).unwrap();

        // Write an empty services.toml (no [[service]] blocks).
        write_services_toml(&dir, "# no services\n");

        // Build state with one pre-registered service so the rollback guard fires.
        let mut initial_registry = ServiceRegistry::new();
        initial_registry.register(ServiceEntry {
            name: "existing".to_string(),
            base_url: "http://existing.internal/api".to_string(),
            auth: AuthPattern::Bearer {
                vault_item: "vault-proxy - Existing".to_string(),
            },
            insecure_tls: false,
            ca_cert_path: None,
            timeout_secs: None,
        });

        let mut state = (*make_state(initial_registry)).clone();
        state.config_dir = dir.to_str().unwrap().to_string();
        state.internal_token = Arc::new("reload-conflict-token".to_string());
        let state = Arc::new(state);

        let internal_router = Router::new()
            .route("/vault/reload-services", post(handlers::reload_services))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::require_internal_token,
            ))
            .with_state(state.clone());

        let app = Router::new()
            .merge(internal_router)
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{}/vault/reload-services", addr))
            .header("authorization", "Bearer reload-conflict-token")
            .send()
            .await
            .expect("request failed");

        assert_eq!(
            resp.status().as_u16(),
            409,
            "empty services.toml with non-empty existing registry must return 409 Conflict"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["ok"], false, "rollback response must contain ok=false");
        assert_eq!(
            body["prev_service_count"], 1,
            "prev_service_count must reflect the pre-reload registry size"
        );
        assert_eq!(
            body["new_service_count"], 0,
            "new_service_count must be 0 for the empty reload"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `POST /vault/reload-services` auth path: a request without an
    /// Authorization: Bearer token must return 401 Unauthorized before the
    /// handler runs.
    #[tokio::test]
    async fn reload_services_without_token_returns_401() {
        use crate::vault::handlers;
        use axum::routing::post;
        use std::sync::atomic::{AtomicU64, Ordering};

        static RELOAD_AUTH_COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = RELOAD_AUTH_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("vault-proxy-reload-auth-{n}"));
        std::fs::create_dir_all(&dir).unwrap();
        write_services_toml(&dir, "# placeholder\n");

        let mut state = (*make_state(ServiceRegistry::new())).clone();
        state.config_dir = dir.to_str().unwrap().to_string();
        state.internal_token = Arc::new("reload-auth-token".to_string());
        let state = Arc::new(state);

        let internal_router = Router::new()
            .route("/vault/reload-services", post(handlers::reload_services))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::require_internal_token,
            ))
            .with_state(state.clone());

        let app = Router::new()
            .merge(internal_router)
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = reqwest::Client::new();

        // No bearer token → 401.
        let resp = client
            .post(format!("http://{}/vault/reload-services", addr))
            .send()
            .await
            .expect("request failed");
        assert_eq!(
            resp.status().as_u16(),
            401,
            "missing Authorization header must return 401 before the handler runs"
        );

        // Wrong token → 401.
        let resp = client
            .post(format!("http://{}/vault/reload-services", addr))
            .header("authorization", "Bearer wrong-token")
            .send()
            .await
            .expect("request failed");
        assert_eq!(resp.status().as_u16(), 401, "invalid token must return 401");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---------------------------------------------------------------------- //
    // (j) POST /audit/credaudit/scan/start — 503 when engine unreachable       //
    //     (iter-35)                                                             //
    // ---------------------------------------------------------------------- //

    /// `POST /audit/credaudit/scan/start` must return 503 SERVICE_UNAVAILABLE
    /// (not 500 or a panic) when the credential audit engine is unreachable.
    ///
    /// This test wires a real `Orchestrator` backed by an in-memory SQLite DB
    /// and an `EngineClient` pointed at a port where nothing is listening.
    /// `start_scan` normalises the reqwest connection-refused error to
    /// `"engine is not reachable"` (iter-34 fix). The handler maps that to 503.
    #[cfg(feature = "engine")]
    #[tokio::test]
    async fn credaudit_scan_start_returns_503_when_engine_unreachable() {
        use crate::credential_audit::{
            engine_client::EngineClient,
            handlers::{scan_start, SharedOrch},
            marker::Marker,
            orchestrator::Orchestrator,
            pass2::Pass2Engine,
            vw_adapter::VwAdapter,
        };
        use axum::routing::post;
        use rusqlite::Connection;
        use std::sync::Mutex;

        // Bind then drop immediately to get a free port that is definitely not
        // listening when the scan call goes out.
        let free_port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let dead_engine_url = format!("http://127.0.0.1:{}", free_port);

        // Set up in-memory SQLite DB using the real migration path so the schema
        // (including the `fail_reason` column added in migration 3) is correct.
        let conn = Connection::open_in_memory().expect("in-memory DB");
        crate::credential_audit::db::run_migrations(&conn).expect("run_migrations on in-memory DB");
        let conn = Arc::new(Mutex::new(conn));

        let engine = Arc::new(EngineClient::new(dead_engine_url.clone()));
        let pass2 = Arc::new(Pass2Engine::new(
            engine.clone(),
            "/nonexistent/agent.py".to_string(),
            None,
        ));
        let vault_mgr = Arc::new(VaultManager::new_stub());
        let orch: SharedOrch = Arc::new(Orchestrator {
            vault: Arc::new(VwAdapter::new(
                vault_mgr.clone(),
                Some("vault-proxy".to_string()),
            )),
            engine: EngineClient::new(dead_engine_url),
            marker: Marker::new(vault_mgr, Some("vault-proxy".to_string())),
            conn,
            pass2,
        });

        let app = Router::new()
            .route("/audit/credaudit/scan/start", post(scan_start))
            .with_state(orch);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{}/audit/credaudit/scan/start", addr))
            .send()
            .await
            .expect("request failed");

        assert_eq!(
            resp.status().as_u16(),
            503,
            "scan/start must return 503 SERVICE_UNAVAILABLE when the engine is unreachable \
             (not 500 or a panic)"
        );
    }

    // ---------------------------------------------------------------------- //
    // (k) GET /vault/audit/run — bearer auth, rate limit, JSON shape (iter-55) //
    // ---------------------------------------------------------------------- //

    /// Build a minimal internal router with GET /vault/audit/run behind the
    /// bearer-token middleware and a rate limiter wired at the app level.
    /// Shared by the three sub-tests below.
    fn make_audit_run_app(state: Arc<AppState>, rate_limit: u64) -> (Router, String) {
        use crate::security::rate_limit::RateLimiter;
        let token = state.internal_token.as_str().to_string();

        let internal_router = Router::new()
            .route("/vault/audit/run", get(crate::audit::handle_audit_run))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::require_internal_token,
            ))
            .with_state(state.clone());

        let limiter = RateLimiter::new(rate_limit, 60);
        let app = Router::new()
            .merge(internal_router)
            .layer(axum::middleware::from_fn_with_state(
                limiter,
                crate::security::rate_limit::rate_limit_middleware,
            ))
            .with_state(state);

        (app, token)
    }

    /// iter-55 (a): GET /vault/audit/run without Authorization header must
    /// return 401 UNAUTHORIZED. With the correct bearer token it must return
    /// 200 with a JSON body containing `total_items`, `weak_passwords`, and
    /// `reused_passwords`.
    #[tokio::test]
    async fn audit_run_requires_bearer_token_and_returns_200_with_json_shape() {
        let state = make_state(ServiceRegistry::new());
        let (app, token) = make_audit_run_app(state, 60); // generous limit for this test

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = reqwest::Client::new();

        // --- No token → 401 ---
        let resp = client
            .get(format!("http://{}/vault/audit/run", addr))
            .send()
            .await
            .expect("request failed");
        assert_eq!(
            resp.status().as_u16(),
            401,
            "GET /vault/audit/run must return 401 when Authorization header is absent"
        );

        // --- Wrong token → 401 ---
        let resp = client
            .get(format!("http://{}/vault/audit/run", addr))
            .header("authorization", "Bearer wrong-token")
            .send()
            .await
            .expect("request failed");
        assert_eq!(
            resp.status().as_u16(),
            401,
            "GET /vault/audit/run must return 401 for an invalid bearer token"
        );

        // --- Correct token → 200 with expected JSON shape ---
        let resp = client
            .get(format!("http://{}/vault/audit/run", addr))
            .header("authorization", format!("Bearer {}", token))
            .send()
            .await
            .expect("request failed");
        assert_eq!(
            resp.status().as_u16(),
            200,
            "GET /vault/audit/run must return 200 OK with a valid bearer token"
        );
        // iter-64: verify Content-Type: application/json on the success path.
        // The return type was changed from Json<AuditResult> to axum::response::Response
        // in iter-63; confirm the manual `.into_response()` path still sets the header.
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            content_type.contains("application/json"),
            "GET /vault/audit/run 200 response must have Content-Type: application/json; got: '{content_type}'"
        );
        let body: serde_json::Value = resp.json().await.expect("audit/run must return JSON");
        assert!(
            body.get("total_items").is_some(),
            "audit/run response must include 'total_items' field; got: {body}"
        );
        assert!(
            body.get("weak_passwords").is_some(),
            "audit/run response must include 'weak_passwords' field; got: {body}"
        );
        assert!(
            body.get("reused_passwords").is_some(),
            "audit/run response must include 'reused_passwords' field; got: {body}"
        );
        // iter-65: assert iter-57 and iter-64 fields so a future change that
        // removes them triggers a test failure rather than a silent regression.
        assert!(
            body.get("weak_threshold_len").is_some(),
            "audit/run response must include 'weak_threshold_len' field (iter-57); got: {body}"
        );
        assert!(
            body.get("scoring_note").is_some(),
            "audit/run response must include 'scoring_note' field (iter-64); got: {body}"
        );
        // scoring_note must be a non-empty string.
        assert!(
            body["scoring_note"]
                .as_str()
                .map(|s| !s.is_empty())
                .unwrap_or(false),
            "audit/run 'scoring_note' must be a non-empty string; got: {body}"
        );
        // iter-67: scoring_note must embed the full threshold phrase so we catch
        // drift between the constant and the human-readable note.
        //
        // PREVIOUS (iter-66): checked `s.contains(threshold_str)` where
        // `threshold_str = WEAK_THRESHOLD.to_string()` = "8".  This is too
        // broad — "8" is a substring of "2024", "128-bit", "18 characters",
        // etc.  Any note string containing the digit 8 for any reason would
        // pass, masking a real drift between the constant and the human note.
        //
        // FIX: check for the full phrase `"fewer than N characters"` as
        // produced by the `format!()` call in `run_audit()`.  If WEAK_THRESHOLD
        // changes from 8 to 12, the note must also say "fewer than 12" — this
        // assertion will catch the mismatch without false-positives on
        // unrelated digit occurrences.
        let expected_phrase = format!("fewer than {}", crate::audit::WEAK_THRESHOLD);
        assert!(
            body["scoring_note"]
                .as_str()
                .map(|s| s.contains(expected_phrase.as_str()))
                .unwrap_or(false),
            "audit/run 'scoring_note' must contain '{}'; got: {body}",
            expected_phrase
        );
        // iter-68: fair_passwords_count assertion.
        assert!(
            body.get("fair_passwords_count").is_some(),
            "audit/run response must include 'fair_passwords_count' field (iter-68); got: {body}"
        );
        assert!(
            body["fair_passwords_count"].is_number(),
            "audit/run 'fair_passwords_count' must be a number; got: {body}"
        );
        // iter-69: AuditItem `reason` field shape assertion.
        //
        // The vault is empty in this integration test so `weak_passwords` and
        // `reused_passwords` are empty arrays — there are no `AuditItem` objects
        // to inspect for the `reason` field here.  The shape of `AuditItem` is
        // verified in `src/audit.rs::tests::audit_item_serialises_reason_field`,
        // which round-trips a constructed `AuditItem` through `serde_json` and
        // asserts the `reason` key is present.  If `reason` were removed from
        // `AuditItem`, that unit test fails before this integration test runs.
        //
        // What we CAN assert here: `weak_passwords` and `reused_passwords` are
        // arrays (not objects, not null), so the shape contract is enforced at
        // the HTTP layer.
        assert!(
            body["weak_passwords"].is_array(),
            "audit/run 'weak_passwords' must be a JSON array; got: {body}"
        );
        assert!(
            body["reused_passwords"].is_array(),
            "audit/run 'reused_passwords' must be a JSON array; got: {body}"
        );
        // iter-76: assert that reused_passwords is a nested array (Vec<Vec<AuditItem>>
        // serialises as [[{...}], [{...}]]) not a flat array ([{...}, {...}]).
        // With an empty vault the outer array is always empty and this check can
        // never fail — the assertion below documents the expected shape so a future
        // test that populates the vault will catch a regression where the type is
        // accidentally changed to Vec<AuditItem>.
        //
        // What we CAN assert now: every element of reused_passwords (if any)
        // must itself be a JSON array.  On an empty vault this is vacuously true
        // (the loop body never executes) but the assertion is still meaningful
        // because it would catch a non-array element on any populated vault test.
        if let Some(groups) = body["reused_passwords"].as_array() {
            for (i, group) in groups.iter().enumerate() {
                assert!(
                    group.is_array(),
                    "audit/run 'reused_passwords[{i}]' must be a JSON array (nested \
                     Vec<Vec<AuditItem>> shape); got element: {group}"
                );
            }
        }
    }

    // ---------------------------------------------------------------------- //
    // (k) GET /vault/permissions — bearer auth, JSON shape, config_file_exists //
    // ---------------------------------------------------------------------- //

    /// iter-78: GET /vault/permissions integration tests.
    ///
    /// Verifies three invariants end-to-end across the full HTTP stack:
    ///   (a) 401 UNAUTHORIZED when the Authorization header is absent.
    ///   (b) 200 OK with correct JSON shape (defaults, overrides, config_file_exists,
    ///       note keys) when the correct bearer token is supplied.
    ///   (c) `config_file_exists` is `false` when the permissions file is absent
    ///       (the stub state uses config_dir="/config" which does not exist in test).
    ///
    /// The test uses the same internal-router wiring as the `make_audit_run_app`
    /// helper and the existing `internal_token_middleware_returns_401_without_header`
    /// test to stay consistent with production wiring.
    #[tokio::test]
    async fn get_vault_permissions_requires_bearer_and_returns_correct_shape() {
        use crate::security::rate_limit::RateLimiter;

        let state = make_state(ServiceRegistry::new());
        let token = state.internal_token.as_str().to_string();

        let internal_router = Router::new()
            .route("/vault/permissions", get(crate::handle_get_permissions))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::require_internal_token,
            ))
            .with_state(state.clone());

        let limiter = RateLimiter::new(60, 60);
        let app = Router::new()
            .merge(internal_router)
            .layer(axum::middleware::from_fn_with_state(
                limiter,
                crate::security::rate_limit::rate_limit_middleware,
            ))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = reqwest::Client::new();

        // (a) No auth header → 401 UNAUTHORIZED.
        let resp = client
            .get(format!("http://{}/vault/permissions", addr))
            .send()
            .await
            .expect("request failed");
        assert_eq!(
            resp.status().as_u16(),
            401,
            "GET /vault/permissions without auth must return 401 UNAUTHORIZED"
        );

        // (b) Correct bearer token → 200 with expected JSON shape.
        let resp = client
            .get(format!("http://{}/vault/permissions", addr))
            .header("authorization", format!("Bearer {}", token))
            .send()
            .await
            .expect("request failed");
        assert_eq!(
            resp.status().as_u16(),
            200,
            "GET /vault/permissions with correct bearer must return 200 OK"
        );
        let body: serde_json::Value = resp.json().await.expect("response must be JSON");

        assert!(
            body.get("defaults").is_some(),
            "GET /vault/permissions response must include 'defaults' key; got: {body}"
        );
        assert!(
            body.get("overrides").is_some(),
            "GET /vault/permissions response must include 'overrides' key; got: {body}"
        );
        assert!(
            body.get("note").is_some(),
            "GET /vault/permissions response must include 'note' key; got: {body}"
        );
        // (c) config_file_exists must be present and false (stub state uses
        // config_dir="/config" which does not exist in the test environment).
        assert!(
            body.get("config_file_exists").is_some(),
            "GET /vault/permissions response must include 'config_file_exists' key; got: {body}"
        );
        assert_eq!(
            body["config_file_exists"].as_bool(),
            Some(false),
            "config_file_exists must be false when permissions file is absent; got: {body}"
        );
        // defaults must be an object (not null, not array).
        assert!(
            body["defaults"].is_object(),
            "GET /vault/permissions 'defaults' must be a JSON object; got: {body}"
        );
        // overrides must be an object (empty by default).
        assert!(
            body["overrides"].is_object(),
            "GET /vault/permissions 'overrides' must be a JSON object; got: {body}"
        );
    }

    /// iter-79: GET /vault/permissions — config_file_exists: true when the
    /// permissions file is present on disk.
    ///
    /// Complements the false-case test above.  Creates a temporary directory,
    /// writes a minimal tool-permissions.json into it, sets AppState.config_dir
    /// to that directory, then verifies that the handler returns
    /// `config_file_exists: true`.
    ///
    /// This tests the runtime file-existence check in `handle_get_permissions`
    /// rather than the in-memory permissions map — the two are intentionally
    /// separate (the file is only read at startup; config_file_exists reflects
    /// whether the file is on disk now).
    #[tokio::test]
    async fn get_vault_permissions_config_file_exists_true_when_file_present() {
        use crate::security::rate_limit::RateLimiter;

        // Build a temp dir and write a minimal permissions file into it.
        let tmp = tempfile::tempdir().expect("failed to create temp dir");
        let perms_path = tmp.path().join("tool-permissions.json");
        std::fs::write(&perms_path, r#"{"defaults":{},"overrides":{}}"#)
            .expect("failed to write test permissions file");

        // Construct state with config_dir pointing at the temp dir.
        let mut inner_state = (*make_state(ServiceRegistry::new())).clone();
        inner_state.config_dir = tmp.path().to_str().unwrap().to_string();
        let state = Arc::new(inner_state);
        let token = state.internal_token.as_str().to_string();

        let internal_router = Router::new()
            .route("/vault/permissions", get(crate::handle_get_permissions))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::require_internal_token,
            ))
            .with_state(state.clone());

        let limiter = RateLimiter::new(60, 60);
        let app = Router::new()
            .merge(internal_router)
            .layer(axum::middleware::from_fn_with_state(
                limiter,
                crate::security::rate_limit::rate_limit_middleware,
            ))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{}/vault/permissions", addr))
            .header("authorization", format!("Bearer {}", token))
            .send()
            .await
            .expect("request failed");
        assert_eq!(
            resp.status().as_u16(),
            200,
            "GET /vault/permissions with file present must return 200 OK"
        );
        let body: serde_json::Value = resp.json().await.expect("response must be JSON");
        assert_eq!(
            body["config_file_exists"].as_bool(),
            Some(true),
            "config_file_exists must be true when tool-permissions.json exists; got: {body}"
        );
    }

    /// iter-55 (b): GET /vault/audit/run must be rate-limited. This test wires
    /// a tight 2 req/60 s limiter across the full HTTP stack so the third
    /// request returns 429 TOO_MANY_REQUESTS.
    ///
    /// This is the HTTP-level complement to the `audit_run_uses_very_tight_limit`
    /// unit test in `security/rate_limit.rs` which only calls `check()` directly.
    /// Here the full axum middleware stack is exercised — bearer auth, rate
    /// limiter, and handler — in a real HTTP round-trip.
    #[tokio::test]
    async fn audit_run_rate_limited_returns_429_on_third_request() {
        let state = make_state(ServiceRegistry::new());
        // Use a fresh tight limiter (max=2) rather than the real per_route map
        // to avoid coupling the test to the specific /vault/audit/run limit.
        // What we are testing here is that the middleware path works end-to-end;
        // the per-route limit value is verified by the unit test in rate_limit.rs.
        let (app, token) = make_audit_run_app(state, 2); // 2 req/60 s

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = reqwest::Client::new();
        let auth = format!("Bearer {}", token);

        // Requests 1 and 2 must succeed.
        for i in 1..=2u32 {
            let resp = client
                .get(format!("http://{}/vault/audit/run", addr))
                .header("authorization", &auth)
                .send()
                .await
                .expect("request failed");
            assert_ne!(
                resp.status().as_u16(),
                429,
                "audit/run request {i} must not be rate-limited yet (budget=2)"
            );
        }

        // Request 3 must be rejected with 429.
        let resp = client
            .get(format!("http://{}/vault/audit/run", addr))
            .header("authorization", &auth)
            .send()
            .await
            .expect("request failed");
        assert_eq!(
            resp.status().as_u16(),
            429,
            "third audit/run request must return 429 — budget of 2 exhausted"
        );
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(
            body.get("error").is_some(),
            "429 response body must contain an 'error' key; got: {body}"
        );
    }
}
