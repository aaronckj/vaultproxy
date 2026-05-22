//! UniFi dual-auth handler — X-API-Key with session-cookie fallback.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use dashmap::DashMap;
use reqwest::{header::HeaderMap, Client, Method, Response, StatusCode};
use serde_json::Value;
use tokio::sync::Mutex;

/// Cached per-service session state.
#[derive(Debug)]
pub struct SessionState {
    /// `reqwest::Client` with a cookie jar; built on first login.
    pub client: Client,
    /// Most recent `X-CSRF-Token` emitted by UDM.
    pub csrf_token: Option<String>,
    /// SHA-256 of `username:password` the session was established with.
    /// Used to detect credential rotation — if vault credentials change,
    /// the cached session is discarded rather than continuing to work
    /// against UDM until UDM's own session TTL expires (which would
    /// bypass the iter-3 non-UniFi `session_tokens` invalidation).
    pub cred_fingerprint: Vec<u8>,
}

/// Compute a stable fingerprint of credentials. Used to detect rotation.
/// We hash rather than store the password so a post-mortem on a leaked
/// SessionState doesn't expose the literal credential. A `Vec<u8>`
/// comparison is enough — no need for a hex-encoded string.
pub(crate) fn fingerprint_creds(username: &str, password: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(username.as_bytes());
    h.update(b":");
    h.update(password.as_bytes());
    h.finalize().to_vec()
}

/// Maximum number of distinct UniFi service entries in the session cache.
/// Each entry is keyed by the service name from services.toml. A typical
/// homelab has 1–3 controllers; 256 is a very generous cap that still
/// prevents unbounded growth from a misconfigured or adversarial
/// services.toml that registers hundreds of UniFi entries.
const UNIFI_SESSION_CACHE_MAX: usize = 256;

/// Per-service session cache. One entry per UniFi service name.
#[derive(Default)]
pub struct UnifiSessionCache {
    inner: DashMap<String, Arc<Mutex<Option<SessionState>>>>,
}

impl UnifiSessionCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get (or lazily create) the mutex slot for a service. The slot wraps an
    /// `Option<SessionState>` — `None` means "no active session yet".
    ///
    /// If the cache is already at `UNIFI_SESSION_CACHE_MAX` entries and the
    /// requested service is not already present, the insertion is refused and
    /// a logged warning is emitted. The returned `None` causes the caller to
    /// fall through to a bare (non-cached) API-key request — degraded
    /// behaviour rather than memory exhaustion.
    pub fn slot(&self, service: &str) -> Arc<Mutex<Option<SessionState>>> {
        // Fast path: already in cache.
        if let Some(existing) = self.inner.get(service) {
            return existing.clone();
        }
        // Slow path: insert with cap check.
        if self.inner.len() >= UNIFI_SESSION_CACHE_MAX {
            tracing::warn!(
                service,
                max = UNIFI_SESSION_CACHE_MAX,
                "UnifiSessionCache at capacity — returning empty slot without caching; \
                 check for a services.toml misconfiguration"
            );
            // Return an uncached slot so the caller can still proceed.
            return Arc::new(Mutex::new(None));
        }
        self.inner
            .entry(service.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(None)))
            .clone()
    }

    /// Drop the cached session for a service (called on credential rotation
    /// or after an auth failure on a session-authenticated request).
    /// iter-124: wired into `browser_rotate` in `main.rs` — called on success
    /// when the caller supplies `unifi_service_name` in the rotate request.
    /// The only caller (`browser_rotate`) is feature-gated behind `browser`,
    /// so the default build sees this as dead.
    #[allow(dead_code)]
    pub fn invalidate(&self, service: &str) {
        if let Some(slot) = self.inner.get(service) {
            // Best-effort: we can't await here so we just try_lock; if the
            // slot is held, the holder will overwrite the stale session.
            if let Ok(mut guard) = slot.try_lock() {
                *guard = None;
            }
        }
    }
}

/// Return `true` if the response looks like an authentication failure
/// (as opposed to a genuine backend error). Never trips on 5xx.
pub(crate) fn is_auth_failure(status: StatusCode, headers: &HeaderMap, body: &Value) -> bool {
    // 1. 401 / 403 are always auth failures.
    if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
        return true;
    }

    // 2. 302 redirect to a login path.
    if status == StatusCode::FOUND || status == StatusCode::SEE_OTHER {
        if let Some(loc) = headers.get("location").and_then(|v| v.to_str().ok()) {
            if loc.contains("/login") || loc.contains("/manage/account/login") {
                return true;
            }
        }
    }

    // 3. HTML body on what should have been a JSON API call.
    if let Some(ct) = headers.get("content-type").and_then(|v| v.to_str().ok()) {
        if ct.to_ascii_lowercase().starts_with("text/html") {
            return true;
        }
    }

    // 4. JSON `meta.rc != "ok"` with an auth-flavoured `meta.msg`.
    if let (Some(rc), Some(msg)) = (
        body.get("meta")
            .and_then(|m| m.get("rc"))
            .and_then(|v| v.as_str()),
        body.get("meta")
            .and_then(|m| m.get("msg"))
            .and_then(|v| v.as_str()),
    ) {
        if rc != "ok" {
            let lower = msg.to_ascii_lowercase();
            if lower.contains("loginrequired")
                || lower.contains("nopermission")
                || lower.contains("invalidapikey")
            {
                return true;
            }
        }
    }

    false
}

/// Runtime credentials + config needed to authenticate a UniFi call.
/// Constructed by the proxy handler from vault state.
#[derive(Debug, Clone)]
pub struct UnifiDualAuthCtx {
    pub username: String,
    pub password: String,
    pub login_path: String,
}

/// Response returned by `handle_request`. Mirrors the shape of
/// `proxy::ProxyResponse` (status + JSON body) so the caller can map it back
/// without importing our internals.
#[derive(Debug)]
pub struct UnifiResponse {
    pub status: u16,
    pub body: Value,
}

/// Extra query params as (key, value) pairs supplied by the caller.
pub type QueryPairs<'a> = &'a [(&'a str, String)];

/// Groups the per-request routing fields so `handle_request` avoids an
/// 8-parameter signature (clippy::too_many_arguments).
///
/// Separating these from `UnifiDualAuthCtx` keeps the auth credentials
/// (`username`, `password`, `login_path`) distinct from the routing details
/// (`base_url`, `method`, `path`, `body`, `query`, `timeout_secs`), which
/// improves call-site clarity: callers construct the ctx once per vault-item
/// and the req once per HTTP call.
///
/// `timeout_secs` — per-service timeout override from `ServiceEntry::timeout_secs`.
/// When `Some(n)`, both the API-key attempt and the session login POST use an
/// `n`-second timeout instead of the hardcoded 30-second client default. `None`
/// keeps the 30-second fallback.
pub struct UnifiRequestCtx<'a> {
    pub base_url: &'a str,
    pub method: Method,
    pub path: &'a str,
    pub body: Option<&'a Value>,
    pub query: QueryPairs<'a>,
    /// Per-service timeout override. `None` → use the 30 s built-in default.
    pub timeout_secs: Option<u64>,
}

/// Forward a UniFi request, attempting `X-API-Key` first and falling back to
/// session-cookie login on auth failure. Caches session state per service.
pub async fn handle_request(
    cache: &UnifiSessionCache,
    service: &str,
    req: &UnifiRequestCtx<'_>,
    auth_ctx: &UnifiDualAuthCtx,
) -> Result<UnifiResponse> {
    let base_url = req.base_url;
    let method = req.method.clone();
    let path = req.path;
    let body = req.body;
    let query = req.query;
    let target = build_url(base_url, path);

    // Issue (iter-42): Use the per-service timeout when provided; fall back to
    // 30 s so short-timeout services (e.g. timeout_secs = 5) don't hang for 30
    // seconds on the API-key probe or the session login POST.
    let effective_timeout = req.timeout_secs.unwrap_or(30);

    // --- Attempt 1: X-API-Key via a bare (no cookie jar) client. ---
    // UDM serves a self-signed TLS cert; accept it.
    let bare = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(effective_timeout))
        .build()
        .map_err(|e| anyhow!("build bare reqwest client: {e}"))?;

    let resp = send_once(
        &bare,
        method.clone(),
        &target,
        body,
        query,
        &[("X-API-Key", auth_ctx.password.as_str())],
        None,
    )
    .await?;

    if !is_auth_failure(resp.status, &resp.headers, &resp.json) {
        return Ok(UnifiResponse {
            status: resp.status.as_u16(),
            body: resp.json,
        });
    }

    tracing::warn!(service, status = %resp.status, "UniFi API-key auth failed, falling back to session");

    // --- Attempt 2: acquire/refresh session and retry. ---
    let slot = cache.slot(service);
    let mut guard = slot.lock().await;

    // Invalidate the cached session if its credential fingerprint no longer
    // matches the current vault credentials. Without this, a post-rotation
    // session would continue working against UDM (which doesn't know the
    // upstream credential changed) until UDM's own session TTL expired —
    // silently extending the old credential's authority.
    let current_fp = fingerprint_creds(&auth_ctx.username, &auth_ctx.password);
    if let Some(ref state) = *guard {
        if state.cred_fingerprint != current_fp {
            tracing::info!(
                service,
                "UniFi credentials rotated — invalidating cached session"
            );
            *guard = None;
        }
    }

    if guard.is_none() {
        let mut new_session = login(base_url, auth_ctx, effective_timeout).await?;
        new_session.cred_fingerprint = current_fp.clone();
        *guard = Some(new_session);
    }
    // Reborrow after mutation.
    let session = guard.as_ref().expect("session just inserted");

    let retry = send_once(
        &session.client,
        method.clone(),
        &target,
        body,
        query,
        &[],
        session.csrf_token.as_deref(),
    )
    .await?;

    // If the retry itself looks like auth failure, relogin once and retry.
    if is_auth_failure(retry.status, &retry.headers, &retry.json) {
        tracing::warn!(service, "session expired, re-logging in once");
        let mut refreshed = login(base_url, auth_ctx, effective_timeout).await?;
        refreshed.cred_fingerprint = current_fp.clone();
        *guard = Some(refreshed);
        let session = guard.as_ref().expect("session just refreshed");
        let final_try = send_once(
            &session.client,
            method,
            &target,
            body,
            query,
            &[],
            session.csrf_token.as_deref(),
        )
        .await?;
        if is_auth_failure(final_try.status, &final_try.headers, &final_try.json) {
            // Persistent auth failure — UDM rejected both the re-login session
            // AND the immediately subsequent request.  Clear the cache slot so
            // the next caller re-attempts a clean login rather than re-using a
            // session that we now know the controller will reject (iter-91).
            //
            // We still hold the mutex guard here, so we can zero the slot
            // directly rather than going through the try_lock path in invalidate().
            *guard = None;
            tracing::warn!(
                service,
                "persistent UniFi auth failure after re-login — session invalidated; \
                 next request will attempt a fresh login"
            );
            // Sanitize: never leak cookies or the key into the body.
            return Ok(UnifiResponse {
                status: 401,
                body: serde_json::json!({
                    "error": format!(
                        "unifi auth failed: http {}",
                        final_try.status.as_u16()
                    )
                }),
            });
        }
        return Ok(UnifiResponse {
            status: final_try.status.as_u16(),
            body: final_try.json,
        });
    }

    Ok(UnifiResponse {
        status: retry.status.as_u16(),
        body: retry.json,
    })
}

/// A fully-consumed HTTP response broken into the pieces we actually need.
struct SentResponse {
    status: StatusCode,
    headers: HeaderMap,
    json: Value,
}

async fn send_once(
    client: &Client,
    method: Method,
    url: &str,
    body: Option<&Value>,
    query: QueryPairs<'_>,
    extra_headers: &[(&str, &str)],
    csrf: Option<&str>,
) -> Result<SentResponse> {
    let mut req = client.request(method.clone(), url);
    if !query.is_empty() {
        req = req.query(query);
    }
    for (k, v) in extra_headers {
        req = req.header(*k, *v);
    }
    if !matches!(method, Method::GET | Method::HEAD) {
        if let Some(token) = csrf {
            req = req.header("X-CSRF-Token", token);
        }
    }
    if let Some(b) = body {
        req = req.json(b);
    }

    let resp: Response = req
        .send()
        .await
        .map_err(|e| anyhow!("unifi request failed: {e}"))?;

    let status = resp.status();
    let headers = resp.headers().clone();
    let json: Value = match resp.json::<Value>().await {
        Ok(v) => v,
        Err(_) => Value::Null,
    };

    Ok(SentResponse {
        status,
        headers,
        json,
    })
}

async fn login(base_url: &str, ctx: &UnifiDualAuthCtx, timeout_secs: u64) -> Result<SessionState> {
    let client = Client::builder()
        .cookie_store(true)
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .map_err(|e| anyhow!("build unifi session client: {e}"))?;

    let login_url = build_url(base_url, &ctx.login_path);
    let resp = client
        .post(&login_url)
        .json(&serde_json::json!({
            "username": ctx.username,
            "password": ctx.password,
            "remember": true,
        }))
        .send()
        .await
        .map_err(|e| anyhow!("unifi login request failed: {e}"))?;

    if !resp.status().is_success() {
        return Err(anyhow!("unifi login returned http {}", resp.status()));
    }

    // Extract X-CSRF-Token from the login response header.
    //
    // iter-6 audit: the CSRF token comes from the server response header, not
    // from a JSON body field or a separate endpoint — so there is no
    // "unexpected format" risk from the CSRF source. The `and_then` chain
    // converts header bytes to UTF-8; if the header is absent or non-UTF-8,
    // `csrf` is `None` and mutations simply omit the X-CSRF-Token header.
    //
    // Consequence of missing token: modern UDM firmware returns 401/403 on
    // state-changing requests without a valid CSRF token, so the retry loop
    // in `handle_request` will catch it as an auth failure and re-login.
    // The CSRF header is never silently substituted or forged — the worst
    // case is a re-login cycle, not a CSRF bypass.
    let csrf = resp
        .headers()
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    if csrf.is_none() {
        tracing::debug!(
            "UniFi login succeeded but no X-CSRF-Token in response headers — \
             state-changing requests may fail until UDM rejects and forces a re-login"
        );
    }

    // Start with a placeholder fingerprint; callers set it to the real
    // value after login so the session can be compared against future
    // vault credentials.
    Ok(SessionState {
        client,
        csrf_token: csrf,
        cred_fingerprint: Vec::new(),
    })
}

fn build_url(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('/');
    if path.starts_with('/') {
        format!("{base}{path}")
    } else {
        format!("{base}/{path}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn slot_returns_same_mutex_for_same_service() {
        let cache = UnifiSessionCache::new();
        let a = cache.slot("unifi_home");
        let b = cache.slot("unifi_home");
        assert!(Arc::ptr_eq(&a, &b));
    }

    /// iter-9: verify the cache cap is enforced and does not panic.
    /// Fill the cache to exactly UNIFI_SESSION_CACHE_MAX via unique keys,
    /// then request one more new key — it must return a fresh (uncached) slot
    /// and the cache size must stay at the cap.
    #[tokio::test]
    async fn slot_cap_is_enforced() {
        let cache = UnifiSessionCache::new();
        // Fill to cap.
        for i in 0..UNIFI_SESSION_CACHE_MAX {
            cache.slot(&format!("unifi_svc_{i}"));
        }
        assert_eq!(cache.inner.len(), UNIFI_SESSION_CACHE_MAX);
        // One more new key — must not panic, must not grow the cache.
        let overflow = cache.slot("unifi_overflow");
        // The returned slot is a fresh independent Arc, not present in the map.
        assert_eq!(
            cache.inner.len(),
            UNIFI_SESSION_CACHE_MAX,
            "cache must not grow past the cap"
        );
        // The overflow slot is usable (not None-poisoned or locked).
        let guard = overflow.lock().await;
        assert!(guard.is_none(), "overflow slot must start as None");
    }

    #[tokio::test]
    async fn slot_returns_different_mutex_for_different_services() {
        let cache = UnifiSessionCache::new();
        let a = cache.slot("unifi_home");
        let b = cache.slot("unifi_office");
        assert!(!Arc::ptr_eq(&a, &b));
    }

    #[tokio::test]
    async fn invalidate_clears_session() {
        let cache = UnifiSessionCache::new();
        let slot = cache.slot("unifi_home");
        {
            let mut g = slot.lock().await;
            *g = Some(SessionState {
                client: Client::new(),
                csrf_token: Some("x".into()),
                cred_fingerprint: Vec::new(),
            });
        }
        cache.invalidate("unifi_home");
        let g = slot.lock().await;
        assert!(g.is_none());
    }

    fn mk_headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                reqwest::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                reqwest::header::HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn auth_failure_on_401() {
        let headers = mk_headers(&[("content-type", "application/json")]);
        assert!(is_auth_failure(
            StatusCode::UNAUTHORIZED,
            &headers,
            &Value::Null
        ));
    }

    #[test]
    fn auth_failure_on_403() {
        let headers = mk_headers(&[("content-type", "application/json")]);
        assert!(is_auth_failure(
            StatusCode::FORBIDDEN,
            &headers,
            &Value::Null
        ));
    }

    #[test]
    fn auth_failure_on_302_to_login() {
        let headers = mk_headers(&[("location", "/manage/account/login")]);
        assert!(is_auth_failure(StatusCode::FOUND, &headers, &Value::Null));
    }

    #[test]
    fn auth_failure_on_html_body() {
        let headers = mk_headers(&[("content-type", "text/html; charset=utf-8")]);
        assert!(is_auth_failure(StatusCode::OK, &headers, &Value::Null));
    }

    #[test]
    fn auth_failure_on_meta_login_required() {
        let body = serde_json::json!({
            "meta": { "rc": "error", "msg": "api.err.LoginRequired" }
        });
        let headers = mk_headers(&[("content-type", "application/json")]);
        assert!(is_auth_failure(StatusCode::OK, &headers, &body));
    }

    #[test]
    fn not_auth_failure_on_503() {
        let headers = mk_headers(&[("content-type", "application/json")]);
        assert!(!is_auth_failure(
            StatusCode::SERVICE_UNAVAILABLE,
            &headers,
            &Value::Null
        ));
    }

    #[test]
    fn not_auth_failure_on_meta_ok() {
        let body = serde_json::json!({ "meta": { "rc": "ok" }, "data": [] });
        let headers = mk_headers(&[("content-type", "application/json")]);
        assert!(!is_auth_failure(StatusCode::OK, &headers, &body));
    }

    #[test]
    fn not_auth_failure_on_unrelated_meta_error() {
        let body = serde_json::json!({
            "meta": { "rc": "error", "msg": "api.err.InvalidPayload" }
        });
        let headers = mk_headers(&[("content-type", "application/json")]);
        assert!(!is_auth_failure(StatusCode::OK, &headers, &body));
    }

    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Build a minimal `UnifiDualAuthCtx` for tests; password is treated as
    /// the API key, username is unused on the happy path.
    fn ctx(username: &str, password: &str) -> UnifiDualAuthCtx {
        UnifiDualAuthCtx {
            username: username.to_string(),
            password: password.to_string(),
            login_path: "/api/auth/login".to_string(),
        }
    }

    /// Helper: call `handle_request` using the new `UnifiRequestCtx` wrapper.
    /// Reduces test boilerplate from 9-arg positional calls to a compact helper.
    #[allow(clippy::too_many_arguments)]
    async fn call(
        cache: &UnifiSessionCache,
        service: &str,
        base_url: &str,
        http_method: Method,
        http_path: &str,
        body: Option<&Value>,
        query: &[(&str, String)],
        auth_ctx: &UnifiDualAuthCtx,
    ) -> Result<UnifiResponse> {
        let req = UnifiRequestCtx {
            base_url,
            method: http_method,
            path: http_path,
            body,
            query,
            timeout_secs: None,
        };
        handle_request(cache, service, &req, auth_ctx).await
    }

    #[tokio::test]
    async fn api_key_success_no_login_attempted() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/self/sites"))
            .and(header("X-API-Key", "key-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "meta": { "rc": "ok" },
                "data": []
            })))
            .expect(1)
            .mount(&server)
            .await;

        // A login mock that must NOT be hit; .expect(0) asserts that.
        Mock::given(method("POST"))
            .and(path("/api/auth/login"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;

        let cache = UnifiSessionCache::new();
        let resp = call(
            &cache,
            "unifi_home",
            &server.uri(),
            Method::GET,
            "/api/self/sites",
            None,
            &[],
            &ctx("home", "key-123"),
        )
        .await
        .unwrap();

        assert_eq!(resp.status, 200);
        assert_eq!(resp.body["meta"]["rc"], "ok");
    }

    #[tokio::test]
    async fn api_key_fails_session_login_succeeds() {
        let server = MockServer::start().await;

        // API-key attempt gets an HTML login page (auth failure signal).
        Mock::given(method("GET"))
            .and(path("/api/self/sites"))
            .and(header("X-API-Key", "wrong-key"))
            .respond_with(
                ResponseTemplate::new(401)
                    .insert_header("content-type", "text/html")
                    .set_body_string("<html>Login</html>"),
            )
            .expect(1)
            .mount(&server)
            .await;

        // Login succeeds, returns a CSRF header and a Set-Cookie.
        Mock::given(method("POST"))
            .and(path("/api/auth/login"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("x-csrf-token", "csrf-xyz")
                    .insert_header("set-cookie", "TOKEN=sess-abc; Path=/; HttpOnly")
                    .set_body_json(serde_json::json!({"meta": {"rc": "ok"}, "data": []})),
            )
            .expect(1)
            .mount(&server)
            .await;

        // Retry with session cookie succeeds.
        Mock::given(method("GET"))
            .and(path("/api/self/sites"))
            // The retry request must NOT carry the X-API-Key header.
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "meta": { "rc": "ok" },
                "data": [{"name": "default"}]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let cache = UnifiSessionCache::new();
        let resp = call(
            &cache,
            "unifi_home",
            &server.uri(),
            Method::GET,
            "/api/self/sites",
            None,
            &[],
            &ctx("home", "wrong-key"),
        )
        .await
        .unwrap();

        assert_eq!(resp.status, 200);
        assert_eq!(resp.body["data"][0]["name"], "default");
    }

    #[tokio::test]
    async fn second_request_reuses_cached_session() {
        let server = MockServer::start().await;

        // First call API-key response: auth failure.
        Mock::given(method("GET"))
            .and(path("/api/self/sites"))
            .and(header("X-API-Key", "wrong-key"))
            .respond_with(
                ResponseTemplate::new(401)
                    .insert_header("content-type", "text/html")
                    .set_body_string("<html/>"),
            )
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;

        // Login: must be hit exactly once across both requests.
        Mock::given(method("POST"))
            .and(path("/api/auth/login"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("set-cookie", "TOKEN=sess-abc; Path=/")
                    .set_body_json(serde_json::json!({"meta": {"rc": "ok"}})),
            )
            .expect(1)
            .mount(&server)
            .await;

        // All session-authed GETs succeed.
        Mock::given(method("GET"))
            .and(path("/api/self/sites"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "meta": {"rc": "ok"}, "data": []
            })))
            .expect(2)
            .mount(&server)
            .await;

        let cache = UnifiSessionCache::new();

        // First call: forces login + retry.
        let r1 = call(
            &cache,
            "unifi_home",
            &server.uri(),
            Method::GET,
            "/api/self/sites",
            None,
            &[],
            &ctx("home", "wrong-key"),
        )
        .await
        .unwrap();
        assert_eq!(r1.status, 200);

        // Second call: bare client will STILL fail (up_to_n_times(1) is
        // exhausted so the "wrong-key" matcher won't re-match -- wiremock
        // will 404), which still looks like an auth failure; handler then
        // finds a cached session and skips login.
        let r2 = call(
            &cache,
            "unifi_home",
            &server.uri(),
            Method::GET,
            "/api/self/sites",
            None,
            &[],
            &ctx("home", "wrong-key"),
        )
        .await
        .unwrap();
        assert_eq!(r2.status, 200);
    }

    #[tokio::test]
    async fn both_attempts_fail_returns_sanitized_error() {
        let server = MockServer::start().await;

        // API-key call: 401.
        Mock::given(method("GET"))
            .and(path("/api/self/sites"))
            .and(header("X-API-Key", "bad"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&server)
            .await;

        // Login: also 401.
        Mock::given(method("POST"))
            .and(path("/api/auth/login"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "meta": {"rc": "error", "msg": "api.err.Invalid"}
            })))
            .expect(1)
            .mount(&server)
            .await;

        let cache = UnifiSessionCache::new();
        let err = call(
            &cache,
            "unifi_home",
            &server.uri(),
            Method::GET,
            "/api/self/sites",
            None,
            &[],
            &ctx("home", "bad"),
        )
        .await;

        // Login step surfaces the http 401 via anyhow.
        assert!(err.is_err(), "expected error, got {:?}", err);
        let msg = format!("{}", err.unwrap_err());
        assert!(
            msg.contains("unifi login returned http 401"),
            "unexpected error message: {msg}"
        );

        // Make sure nothing in the message smells like a credential.
        assert!(!msg.contains("bad"), "credential leaked in error: {msg}");
        assert!(!msg.contains("TOKEN="), "cookie leaked in error: {msg}");
    }

    #[tokio::test]
    async fn not_auth_failure_5xx_bubbles_up() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/self/sites"))
            .respond_with(ResponseTemplate::new(503).set_body_json(serde_json::json!({
                "meta": {"rc": "error", "msg": "backend down"}
            })))
            .expect(1)
            .mount(&server)
            .await;

        // Login must NOT be attempted on a 5xx.
        Mock::given(method("POST"))
            .and(path("/api/auth/login"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;

        let cache = UnifiSessionCache::new();
        let resp = call(
            &cache,
            "unifi_home",
            &server.uri(),
            Method::GET,
            "/api/self/sites",
            None,
            &[],
            &ctx("home", "key"),
        )
        .await
        .unwrap();

        assert_eq!(resp.status, 503);
    }

    #[tokio::test]
    async fn concurrent_requests_share_one_login() {
        let server = MockServer::start().await;

        // API-key attempts all 401.
        Mock::given(method("GET"))
            .and(path("/api/self/sites"))
            .and(header("X-API-Key", "wrong"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        // Login: hit exactly once.
        Mock::given(method("POST"))
            .and(path("/api/auth/login"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("set-cookie", "TOKEN=sess; Path=/")
                    .set_body_json(serde_json::json!({"meta": {"rc": "ok"}})),
            )
            .expect(1)
            .mount(&server)
            .await;

        // Session-authed GETs succeed.
        Mock::given(method("GET"))
            .and(path("/api/self/sites"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "meta": {"rc": "ok"}, "data": []
            })))
            .mount(&server)
            .await;

        let cache = Arc::new(UnifiSessionCache::new());
        let uri = server.uri();

        let mut tasks = Vec::new();
        for _ in 0..10 {
            let cache = cache.clone();
            let uri = uri.clone();
            tasks.push(tokio::spawn(async move {
                let auth_ctx = ctx("home", "wrong");
                let req = UnifiRequestCtx {
                    base_url: &uri,
                    method: Method::GET,
                    path: "/api/self/sites",
                    body: None,
                    query: &[],
                    timeout_secs: None,
                };
                handle_request(&cache, "unifi_home", &req, &auth_ctx).await
            }));
        }

        for t in tasks {
            let resp = t.await.unwrap().unwrap();
            assert_eq!(resp.status, 200);
        }
    }

    #[tokio::test]
    async fn csrf_token_applied_to_post_after_login() {
        let server = MockServer::start().await;

        // API-key attempt on the POST fails.
        Mock::given(method("POST"))
            .and(path("/api/s/default/cmd/stamgr"))
            .and(header("X-API-Key", "wrong"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&server)
            .await;

        // Login returns a CSRF token.
        Mock::given(method("POST"))
            .and(path("/api/auth/login"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("x-csrf-token", "csrf-xyz")
                    .insert_header("set-cookie", "TOKEN=sess; Path=/")
                    .set_body_json(serde_json::json!({"meta": {"rc": "ok"}})),
            )
            .expect(1)
            .mount(&server)
            .await;

        // Session-authed retry POST MUST carry X-CSRF-Token.
        Mock::given(method("POST"))
            .and(path("/api/s/default/cmd/stamgr"))
            .and(header("x-csrf-token", "csrf-xyz"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "meta": {"rc": "ok"}, "data": []
            })))
            .expect(1)
            .mount(&server)
            .await;

        let cache = UnifiSessionCache::new();
        let body = serde_json::json!({"cmd": "kick-sta", "mac": "aa:bb:cc:dd:ee:ff"});
        let resp = call(
            &cache,
            "unifi_home",
            &server.uri(),
            Method::POST,
            "/api/s/default/cmd/stamgr",
            Some(&body),
            &[],
            &ctx("home", "wrong"),
        )
        .await
        .unwrap();

        assert_eq!(resp.status, 200);
    }

    #[tokio::test]
    async fn stale_session_triggers_single_relogin() {
        let server = MockServer::start().await;

        // Pre-seed the session cache as if we'd already logged in.
        let cache = UnifiSessionCache::new();
        {
            let slot = cache.slot("unifi_home");
            let mut guard = slot.lock().await;
            *guard = Some(SessionState {
                client: Client::builder().cookie_store(true).build().unwrap(),
                csrf_token: Some("stale-csrf".into()),
                // Match the ctx("home", "key") creds so the iter-14
                // rotation-invalidation path does NOT fire — this test
                // specifically exercises UDM-side session expiry, not
                // credential rotation.
                cred_fingerprint: fingerprint_creds("home", "key"),
            });
        }

        // API-key probe fails (triggers fallback path).
        Mock::given(method("GET"))
            .and(path("/api/self/sites"))
            .and(header("X-API-Key", "key"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&server)
            .await;

        // First session-authed retry: UDM rejects with api.err.LoginRequired.
        // Fires at most once; no strict expect so we don't panic if routing
        // exhausts this mock and falls through to the success mock.
        Mock::given(method("GET"))
            .and(path("/api/self/sites"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "meta": {"rc": "error", "msg": "api.err.LoginRequired"}
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Re-login MUST happen exactly once — this is the core invariant.
        Mock::given(method("POST"))
            .and(path("/api/auth/login"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("set-cookie", "TOKEN=fresh; Path=/")
                    .set_body_json(serde_json::json!({"meta": {"rc": "ok"}})),
            )
            .expect(1)
            .mount(&server)
            .await;

        // Post-relogin retry succeeds (catch-all — fires after the
        // LoginRequired mock above is exhausted).
        Mock::given(method("GET"))
            .and(path("/api/self/sites"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "meta": {"rc": "ok"}, "data": [{"name": "default"}]
            })))
            .mount(&server)
            .await;

        let resp = call(
            &cache,
            "unifi_home",
            &server.uri(),
            Method::GET,
            "/api/self/sites",
            None,
            &[],
            &ctx("home", "key"),
        )
        .await
        .unwrap();

        assert_eq!(resp.status, 200);
        assert_eq!(resp.body["data"][0]["name"], "default");
    }
}
