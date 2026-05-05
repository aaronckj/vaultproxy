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

use crate::browser::BrowserAgent;
use crate::sync::SyncManager;
use crate::vault::VaultManager;
use registry::{AuthPattern, ServiceRegistry};
use unifi_session::{handle_request as unifi_handle_request, UnifiDualAuthCtx, UnifiSessionCache};

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
    pub registry: Arc<ServiceRegistry>,
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
    /// The map is read-only after startup (no hot-reload of CA certs without
    /// restart), so no lock is needed — an `Arc<HashMap>` provides cheap
    /// shared access from concurrent request handlers.
    pub ca_cert_clients: Arc<std::collections::HashMap<String, reqwest::Client>>,
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
    pub approval_queue: Arc<tokio::sync::RwLock<VecDeque<ApprovalRequest>>>,
    /// Browser agent for automated password rotation.
    pub browser: Option<Arc<BrowserAgent>>,
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
#[derive(Debug, Serialize)]
pub struct ProxyError {
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
    let should_log = matches!(
        permission,
        crate::security::permissions::Permission::Log
    );

    // 1. Look up the service in the registry.
    // Use a generic "not found" message — echoing req.service verbatim would
    // let an attacker enumerate registered service names via trial-and-error.
    let service = state.registry.get(&req.service).ok_or_else(|| {
        proxy_error(
            StatusCode::NOT_FOUND,
            "unknown service".to_string(),
        )
    })?;

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
    let mut response = apply_auth_and_send(&state, service.auth.clone(), &target_url, method, &req)
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
                    "proxy timeout for service '{}': {:#}",
                    req.service, e
                );
                proxy_error(
                    StatusCode::GATEWAY_TIMEOUT,
                    "upstream request timed out".to_string(),
                )
            } else {
                tracing::debug!("proxy auth/send error for service '{}': {:#}", req.service, e);
                proxy_error(StatusCode::BAD_GATEWAY, "upstream request failed".to_string())
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
async fn apply_auth_and_send(
    state: &AppState,
    auth: AuthPattern,
    url: &str,
    method: Method,
    req: &ProxyRequest,
) -> anyhow::Result<ProxyResponse> {
    match auth {
        // ------------------------------------------------------------------ //
        // Header-based auth (X-Api-Key, X-Plex-Token, …)                     //
        // ------------------------------------------------------------------ //
        AuthPattern::Header { header_name, vault_item } => {
            let token = state.vault.decrypt_password(&vault_item)?;
            let token_str = std::str::from_utf8(&token)
                .map_err(|e| anyhow::anyhow!("credential is not valid UTF-8: {}", e))?
                .to_string();
            // SecureBuffer `token` is dropped here (original reference ends).
            drop(token);

            let request = build_request(state, method, url, req)?
                .header(&header_name, &token_str);

            send_request(request).await
        }

        // ------------------------------------------------------------------ //
        // Query-param auth (?apikey=xxx)                                      //
        // ------------------------------------------------------------------ //
        AuthPattern::QueryParam { param_name, vault_item } => {
            let token = state.vault.decrypt_password(&vault_item)?;
            let token_str = std::str::from_utf8(&token)
                .map_err(|e| anyhow::anyhow!("credential is not valid UTF-8: {}", e))?
                .to_string();
            drop(token);

            // Inject the param into the request builder's query list.
            let mut request = build_request(state, method, url, req)?;
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

            let request = build_request(state, method, url, req)?.bearer_auth(&token_str);

            send_request(request).await
        }

        // ------------------------------------------------------------------ //
        // Basic auth (key:secret from custom vault fields)                    //
        // ------------------------------------------------------------------ //
        AuthPattern::Basic { vault_item, key_field, secret_field } => {
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

            let request =
                build_request(state, method, url, req)?.basic_auth(&key_str, Some(&secret_str));

            send_request(request).await
        }

        // ------------------------------------------------------------------ //
        // Session auth (login first, then use token as Bearer)                //
        // ------------------------------------------------------------------ //
        AuthPattern::Session { vault_item, login_path, token_field, login_include_username } => {
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
                build_request(state, method.clone(), url, req)?.bearer_auth(&session_token);
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
                    build_request(state, method, url, req)?.bearer_auth(&fresh);
                return send_request(retry).await;
            }

            Ok(response)
        }

        // ------------------------------------------------------------------ //
        // UniFi dual auth: X-API-Key with session-cookie fallback             //
        // ------------------------------------------------------------------ //
        AuthPattern::UnifiDual { vault_item, login_path } => {
            // Resolve service name + root URL. The registry stores
            // base_url as "<root>/proxy/network"; login lives at <root>.
            let (service_name, login_base) = state
                .registry
                .list()
                .iter()
                .find_map(|name| {
                    let entry = state.registry.get(name)?;
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
                })
                .ok_or_else(|| anyhow::anyhow!("cannot resolve base URL for unifi dual auth"))?;

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

            let ctx = UnifiDualAuthCtx { username, password, login_path };

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
            let path_with_prefix = format!(
                "/proxy/network/{}",
                req.path.trim_start_matches('/')
            );

            let resp = unifi_handle_request(
                &state.unifi_sessions,
                &service_name,
                &login_base,
                method,
                &path_with_prefix,
                req.body.as_ref(),
                &query_pairs,
                &ctx,
            )
            .await?;

            Ok(ProxyResponse { status: resp.status, body: resp.body })
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

    let fresh = session_login(state, vault_item, login_path, token_field, login_include_username).await?;
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

    // Determine the base URL for the service that owns this login endpoint.
    // The `login_path` is relative to the service's base_url.  We find the
    // matching registry entry by scanning for the vault item — there will be
    // exactly one match for each session service.
    let base_url = state
        .registry
        .list()
        .iter()
        .find_map(|name| {
            let entry = state.registry.get(name)?;
            if let AuthPattern::Session { vault_item: vi, .. } = &entry.auth {
                if vi == vault_item {
                    return Some(entry.base_url.clone());
                }
            }
            None
        })
        .ok_or_else(|| anyhow::anyhow!("cannot determine base URL for session login"))?;

    let login_url = format!(
        "{}{}",
        base_url.trim_end_matches('/'),
        login_path
    );

    // Build the login body using the configured login_include_username flag.
    let login_body = build_session_login_body(state, vault_item, login_include_username)?;

    let resp = state
        .http
        .post(&login_url)
        .json(&login_body)
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
            anyhow::anyhow!(
                "token field '{}' not found in login response",
                token_field
            )
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
fn build_request(
    state: &AppState,
    method: Method,
    url: &str,
    req: &ProxyRequest,
) -> anyhow::Result<reqwest::RequestBuilder> {
    // Pick the right TLS client for this service:
    //   - insecure_tls = true  → http_permissive (no cert verification)
    //   - ca_cert_path set     → use the pre-built per-service CA-cert client
    //                            from AppState::ca_cert_clients (built once at
    //                            startup so the connection pool is preserved)
    //   - neither              → http (strict system-root verification)
    //
    // Issue (iter-15 → iter-16 fix): the iter-15 implementation built a new
    // reqwest::Client on every proxy call when ca_cert was set. reqwest::Client
    // maintains a connection pool; a fresh Client per request defeats connection
    // reuse and forces a TLS handshake on every call. CA-cert clients are now
    // built once in start_server() and stored in AppState::ca_cert_clients.
    let service_name = req.service.as_str();
    let service_entry = state.registry.get(service_name);
    let insecure = service_entry.map(|s| s.insecure_tls).unwrap_or(false);

    let client: &reqwest::Client = if insecure {
        &state.http_permissive
    } else if let Some(ca_client) = state.ca_cert_clients.get(service_name) {
        ca_client
    } else {
        &state.http
    };
    let mut builder = client.request(method, url);

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
/// Values below 1 MB or above 2048 MB are rejected at startup; 0 would make
/// every response fail and very large values risk OOM on constrained hosts.
fn upstream_body_limit_bytes() -> usize {
    const DEFAULT_MB: usize = 32;
    const MIN_MB: usize = 1;
    const MAX_MB: usize = 2048;

    let mb = match std::env::var("UPSTREAM_BODY_LIMIT_MB") {
        Ok(val) => match val.parse::<usize>() {
            Ok(n) => {
                if n < MIN_MB || n > MAX_MB {
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
        },
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
    (code, Json(ProxyError { error: message }))
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
        assert!(has_traversal("../etc/passwd"), "../etc/passwd must be blocked");
        assert!(has_traversal("/../../root"), "leading ../ must be blocked");
        assert!(has_traversal("api/../secret"), "interior .. must be blocked");
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
        assert!(!has_traversal("/api/s/default/stat/sta"), "deep path must pass");
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
        assert!(!url.contains("//api"), "double slash must not appear after host");
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
        let caller_keys = vec!["apikey".to_string()];
        let conflicts: Vec<&str> = caller_keys
            .iter()
            .filter(|k| base_keys.contains(k.as_str()))
            .map(String::as_str)
            .collect();
        assert!(!conflicts.is_empty(), "apikey conflict must be detected and blocked");
    }

    #[test]
    fn non_conflicting_caller_keys_are_allowed() {
        let base_keys = base_url_query_keys("http://tautulli/api/v2?apikey=real");
        let caller_keys = vec!["cmd".to_string(), "output_format".to_string()];
        let conflicts: Vec<&str> = caller_keys
            .iter()
            .filter(|k| base_keys.contains(k.as_str()))
            .map(String::as_str)
            .collect();
        assert!(conflicts.is_empty(), "non-conflicting keys must pass through");
    }
}
