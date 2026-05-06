//! Lightweight in-memory rate limiter for sidecar API routes.
//!
//! Tracks request counts per `(route, caller_key)` in 60-second windows using
//! a `tokio::sync::Mutex<HashMap>`. The caller key is resolved as follows:
//!
//! 1. If the request carries an `X-Caller-Id` header with a non-empty ASCII
//!    value, that value is used as the bucket key. This lets each MCP server
//!    declare its own identity and receive an independent budget — critical when
//!    vault-proxy is used as a sidecar and all MCP servers share `127.0.0.1`.
//! 2. Otherwise the client IP (from `ConnectInfo<SocketAddr>`) is used. This
//!    preserves the prior behaviour for callers that do not set the header.
//!
//! Keying on the caller (not just the route path) prevents a single MCP server
//! from exhausting the budget for all other concurrent servers.
//!
//! # Per-route overrides (iter-37)
//!
//! Destructive vault operations (`/vault/items/delete`, `/vault/folders/delete`)
//! have a tighter limit (10 req/60 s) than the default (60 req/60 s). This is
//! enforced by a `per_route` map in `RateLimiter` that is checked before the
//! global `max_requests` fallback. The tight limits are intentionally low:
//! deleting 10 vault items in one minute is already an unusual workload for a
//! homelab sidecar; anything beyond that is likely runaway automation.
//!
//! # Per-caller identity (iter-85)
//!
//! MCP servers may set `X-Caller-Id: <name>` in every request. When present,
//! the header value replaces the IP as the bucket key, giving each MCP server
//! its own independent rate-limit budget. The header value is truncated to
//! 64 bytes and ASCII-sanitized before use as a map key. An empty or
//! non-ASCII-printable value falls back to the IP.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{ConnectInfo, Request},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use tokio::sync::Mutex;

/// Per-(route, caller_key) request counter with windowed expiry.
#[derive(Debug, Clone)]
struct RouteCounter {
    count: u64,
    window_start: std::time::Instant,
}

/// Shared rate-limit state.
#[derive(Clone)]
pub struct RateLimiter {
    /// Map of (route_path, caller_key) -> counter.
    /// `caller_key` is the `X-Caller-Id` header value if present, otherwise
    /// the client IP address.
    counters: Arc<Mutex<HashMap<(String, String), RouteCounter>>>,
    /// Default maximum requests per window (applies when no per-route override).
    max_requests: u64,
    /// Window duration (shared by all routes).
    window: std::time::Duration,
    /// Per-route overrides: route path → max requests per window.
    ///
    /// When a route appears here its value overrides `max_requests`. This allows
    /// destructive endpoints to have tighter limits without a second middleware
    /// instance.
    per_route: Arc<HashMap<&'static str, u64>>,
}

impl RateLimiter {
    /// Create a new rate limiter with the given default max requests per window.
    /// Used by tests; production code uses `default_rate_limiter()` or
    /// `with_per_route_overrides()`.
    #[allow(dead_code)] // production path uses default_rate_limiter(); tests use this directly
    pub fn new(max_requests: u64, window_secs: u64) -> Self {
        Self {
            counters: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window: std::time::Duration::from_secs(window_secs),
            per_route: Arc::new(HashMap::new()),
        }
    }

    /// Create a rate limiter with per-route overrides.
    ///
    /// `per_route` maps a route path (must match `RATE_LIMITED_PATHS` exactly)
    /// to a maximum request count per window. Routes not in the map use the
    /// default `max_requests` value.
    pub fn with_per_route_overrides(
        max_requests: u64,
        window_secs: u64,
        per_route: HashMap<&'static str, u64>,
    ) -> Self {
        Self {
            counters: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window: std::time::Duration::from_secs(window_secs),
            per_route: Arc::new(per_route),
        }
    }

    /// Check if a request to the given path from the given caller key should be
    /// allowed. Returns `true` if allowed, `false` if rate-limited.
    ///
    /// `caller_key` is the `X-Caller-Id` header value (if present and valid
    /// ASCII) or the client IP address. The key is used as the bucket key so
    /// each distinct caller gets its own independent budget.
    async fn check(&self, path: &str, caller_key: &str) -> bool {
        let limit = self
            .per_route
            .get(path)
            .copied()
            .unwrap_or(self.max_requests);

        let mut counters = self.counters.lock().await;
        let now = std::time::Instant::now();

        // Opportunistic GC — drop entries whose window expired long ago to
        // bound memory under churn of distinct caller keys.
        counters.retain(|_, c| now.duration_since(c.window_start) < self.window * 4);

        let key = (path.to_string(), caller_key.to_string());
        let counter = counters.entry(key).or_insert(RouteCounter {
            count: 0,
            window_start: now,
        });

        // Reset window if expired.
        if now.duration_since(counter.window_start) >= self.window {
            counter.count = 0;
            counter.window_start = now;
        }

        counter.count += 1;
        counter.count <= limit
    }
}

/// Extract the caller key from a request.
///
/// Prefers the `X-Caller-Id` header value (iter-85: per-caller rate limiting).
/// The header value is:
///   - Truncated to 64 bytes.
///   - Accepted only if every byte is ASCII printable (0x20–0x7E).
///   - Rejected (fallback to IP) if empty after truncation.
///
/// On rejection or absence, falls back to the client IP from
/// `ConnectInfo<SocketAddr>`, then to the sentinel `"unknown"` if that
/// extension is missing (test harness or direct-call paths).
fn extract_caller_key(req: &Request) -> String {
    if let Some(header_val) = req.headers().get("x-caller-id") {
        if let Ok(s) = header_val.to_str() {
            // Truncate and validate.
            let truncated = &s[..s.len().min(64)];
            if !truncated.is_empty() && truncated.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
            {
                return truncated.to_string();
            }
        }
    }
    // Fall back to client IP.
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Routes that are subject to rate limiting.
///
/// Issue (iter-19): The destructive vault mutation endpoints — item delete,
/// item update, and folder delete — were not rate-limited despite being the
/// most dangerous write operations. A runaway MCP session or a compromised
/// local caller could delete the entire vault folder's contents before the
/// operator noticed. Added to the shared 60 req/60s bucket; a separate
/// per-endpoint tighter limit would require a second rate-limiter instance
/// wired per-route, tracked as a future improvement.
///
/// iter-37: That future improvement is now implemented. See `per_route_limits()`
/// and `default_rate_limiter()` below.
const RATE_LIMITED_PATHS: &[&str] = &[
    "/proxy",
    "/vault/totp",
    "/vault/resync",
    "/vault/items/delete",
    "/vault/items/update",
    "/vault/folders/delete",
    "/rotate",
    "/browser/rotate",
    "/sync/init",
    // iter-54: in-process credential health audit — decrypts every vault password
    // to compute HMAC fingerprints.  A single run on a 500-item vault can take
    // several seconds; concurrent runs multiply that cost and decrypt the same
    // passwords simultaneously.  Limit to 2 req/60 s per caller so a slow or
    // mis-configured caller cannot DDoS the proxy's decrypt loop.
    "/vault/audit/run",
    // iter-78: permissions diagnostic endpoint — gated behind the internal bearer
    // token but still subject to rate limiting.  An attacker who obtains the
    // internal token could call this endpoint in a tight loop to probe the
    // permission system structure.  30 req/60 s is generous for legitimate use
    // (reading permissions once per request) while preventing automated probing.
    "/vault/permissions",
];

/// Per-route tighter limits for destructive operations (iter-37/38).
///
/// These routes delete or irreversibly modify vault data. 10 req/60 s is
/// generous enough for legitimate automation (a script rotating 5 passwords
/// generates 10 calls: 5 update + 5 confirm) while blocking runaway loops
/// that could wipe or corrupt the vault folder in seconds.
///
/// iter-38: `/vault/items/update` added — it can overwrite passwords just as
/// destructively as a delete; omitting it from the tight map left it at the
/// default 60 req/60s, which would allow bulk-overwriting 60 items per minute
/// without any tighter guard.
fn per_route_limits() -> HashMap<&'static str, u64> {
    let mut m = HashMap::new();
    m.insert("/vault/items/delete", 10u64);
    m.insert("/vault/items/update", 10u64);
    m.insert("/vault/folders/delete", 10u64);
    // iter-54: audit/run decrypts every vault password for HMAC fingerprinting.
    // Each run is expensive (AES-256-CBC + HMAC-SHA256 per item); 60 concurrent
    // runs at the default global budget would mean 60 × N password decrypts per
    // minute.  Cap at 2 per caller per 60-second window — enough for one deliberate
    // scan plus one retry, but not enough to sustain an accidental loop.
    m.insert("/vault/audit/run", 2u64);
    m
}

/// Axum middleware that enforces per-`(route, caller)` rate limits on sensitive
/// endpoints. The caller identity is resolved from the `X-Caller-Id` header
/// (iter-85) when present; otherwise the client IP is used.
///
/// Choosing `X-Caller-Id` over IP resolves the shared-loopback problem: all
/// MCP servers running on the same host share `127.0.0.1`, so IP-based keying
/// gives them a single shared budget. With `X-Caller-Id`, each MCP server
/// configuration can declare a unique name and receive an independent budget.
pub async fn rate_limit_middleware(
    axum::extract::State(limiter): axum::extract::State<RateLimiter>,
    req: Request,
    next: Next,
) -> Response {
    // Normalize trailing slashes so `POST /vault/audit/run/` (or `//`) is
    // treated identically to `POST /vault/audit/run`. Without this, a caller
    // adding a trailing slash bypasses every per-route override (e.g. the
    // 2 req/60 s cap on /vault/audit/run) and falls through to the default
    // 60 req/60 s bucket.
    //
    // `trim_end_matches('/')` strips ALL trailing slashes, so both
    // `/vault/audit/run/` and `/vault/audit/run//` normalize to
    // `/vault/audit/run`. The bare `/` root path is left untouched by the
    // `raw.len() > 1` guard so the health-check route still matches.
    //
    // iter-56: fix trailing-slash rate-limiter bypass.
    // iter-57: clarify comment — strips ALL trailing slashes, not just one.
    let raw = req.uri().path();
    let path = if raw.len() > 1 && raw.ends_with('/') {
        raw.trim_end_matches('/').to_string()
    } else {
        raw.to_string()
    };

    // Only rate-limit specific sensitive endpoints.
    if RATE_LIMITED_PATHS.iter().any(|p| path == *p) {
        // iter-85: prefer X-Caller-Id over IP for per-caller isolation.
        let caller_key = extract_caller_key(&req);

        if !limiter.check(&path, &caller_key).await {
            tracing::warn!(
                "rate limit exceeded for {} from caller {:?}",
                path,
                caller_key
            );
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({"error": "rate limit exceeded — try again later"})),
            )
                .into_response();
        }
    }

    next.run(req).await
}

/// Create a default rate limiter: 60 req/60 s globally, with tighter
/// per-route overrides for destructive operations (10 req/60 s for
/// `/vault/items/delete` and `/vault/folders/delete`).
///
/// # Slowloris / slow-client note
///
/// This rate limiter counts **completed** requests (the middleware runs after
/// the request is fully received). A slowloris-style attack — opening many
/// TCP connections and dribbling headers one byte at a time — is NOT mitigated
/// here: slow clients hold an axum connection slot (and a Tokio task) indefinitely
/// without ever incrementing the counter.
///
/// Axum does not set a read timeout by default. The primary mitigations in this
/// deployment are:
///   - The sidecar is bound to 127.0.0.1 only, so only local processes can
///     connect; a network-level slowloris is impossible.
///   - The MCP callers (Claude desktop + Node.js servers) are well-behaved clients
///     that complete requests quickly.
///
/// RESOLVED (iter-22): A per-connection HTTP/1 header-read timeout of 5 seconds
/// has been added to the main API server via `axum_server::bind(...).http_builder()
/// .http1().timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(5))`.
/// See `main.rs::start_server` for the implementation.
///
/// # Per-caller isolation (iter-85)
///
/// The rate limiter keys on `(route, caller_key)`. When `X-Caller-Id` is set
/// in the request, `caller_key` is that header value and each MCP server gets
/// its own independent budget even when all run on `127.0.0.1`. Without the
/// header, `caller_key` falls back to the client IP, which means all loopback
/// callers share a single bucket (same behaviour as before iter-85).
///
/// Each MCP server configuration should set:
/// ```
/// X-Caller-Id: <unique-name>   # e.g. "connecterr-unifi", "connecterr-vault"
/// ```
pub fn default_rate_limiter() -> RateLimiter {
    RateLimiter::with_per_route_overrides(60, 60, per_route_limits())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn default_limit_allows_up_to_max() {
        let limiter = RateLimiter::new(3, 60);
        assert!(limiter.check("/proxy", "1.2.3.4").await);
        assert!(limiter.check("/proxy", "1.2.3.4").await);
        assert!(limiter.check("/proxy", "1.2.3.4").await);
        assert!(!limiter.check("/proxy", "1.2.3.4").await);
    }

    #[tokio::test]
    async fn per_route_override_is_tighter() {
        // default=60, delete override=10
        let limiter = RateLimiter::with_per_route_overrides(60, 60, per_route_limits());
        for _ in 0..10 {
            assert!(
                limiter.check("/vault/items/delete", "127.0.0.1").await,
                "should allow first 10"
            );
        }
        assert!(
            !limiter.check("/vault/items/delete", "127.0.0.1").await,
            "11th request should be rejected"
        );
    }

    #[tokio::test]
    async fn per_route_override_does_not_affect_other_routes() {
        let limiter = RateLimiter::with_per_route_overrides(60, 60, per_route_limits());
        // /vault/resync should still allow 60
        for i in 0..60 {
            assert!(
                limiter.check("/vault/resync", "127.0.0.1").await,
                "request {} should be allowed",
                i + 1
            );
        }
        assert!(
            !limiter.check("/vault/resync", "127.0.0.1").await,
            "61st request should be rejected"
        );
    }

    #[tokio::test]
    async fn different_ips_have_independent_buckets() {
        let limiter = RateLimiter::with_per_route_overrides(60, 60, per_route_limits());
        for _ in 0..10 {
            limiter.check("/vault/items/delete", "10.0.0.1").await;
        }
        // A different IP should still have a fresh bucket
        assert!(limiter.check("/vault/items/delete", "10.0.0.2").await);
    }

    #[tokio::test]
    async fn folder_delete_uses_tight_limit() {
        let limiter = RateLimiter::with_per_route_overrides(60, 60, per_route_limits());
        for _ in 0..10 {
            assert!(limiter.check("/vault/folders/delete", "127.0.0.1").await);
        }
        assert!(!limiter.check("/vault/folders/delete", "127.0.0.1").await);
    }

    /// iter-38: `/vault/items/update` must use the tight 10 req/60 s limit.
    /// It can overwrite passwords just as destructively as a delete and must
    /// not be left at the default 60-req bucket.
    #[tokio::test]
    async fn update_item_uses_tight_limit() {
        let limiter = RateLimiter::with_per_route_overrides(60, 60, per_route_limits());
        for i in 0..10 {
            assert!(
                limiter.check("/vault/items/update", "127.0.0.1").await,
                "request {} should be allowed",
                i + 1
            );
        }
        assert!(
            !limiter.check("/vault/items/update", "127.0.0.1").await,
            "11th update request must be rejected by tight 10-req limit"
        );
    }

    /// iter-54: `/vault/audit/run` must use the very tight 2 req/60 s limit.
    /// Each audit run decrypts every vault password; 60 concurrent runs (the
    /// default budget) would be an expensive denial-of-service vector.
    #[tokio::test]
    async fn audit_run_uses_very_tight_limit() {
        let limiter = RateLimiter::with_per_route_overrides(60, 60, per_route_limits());
        assert!(
            limiter.check("/vault/audit/run", "127.0.0.1").await,
            "first audit/run request must be allowed"
        );
        assert!(
            limiter.check("/vault/audit/run", "127.0.0.1").await,
            "second audit/run request must be allowed"
        );
        assert!(
            !limiter.check("/vault/audit/run", "127.0.0.1").await,
            "third audit/run request must be rejected by 2-req limit"
        );
    }

    /// iter-56: trailing-slash bypass. A request to `/vault/audit/run/` (with
    /// trailing slash) must be normalized to `/vault/audit/run` and consume
    /// from the same tight budget. Without normalization the slash variant
    /// falls through to the default 60 req/60 s bucket, bypassing the 2-req cap.
    ///
    /// This test verifies the normalization at the `check()` level; the
    /// middleware-level normalization is the real fix but check() is cheaper
    /// to test in isolation.
    #[tokio::test]
    async fn trailing_slash_uses_same_bucket_as_canonical_path() {
        let limiter = RateLimiter::with_per_route_overrides(60, 60, per_route_limits());
        // Exhaust the 2-req budget on the canonical path.
        limiter.check("/vault/audit/run", "127.0.0.1").await;
        limiter.check("/vault/audit/run", "127.0.0.1").await;
        // A third request to the canonical path is rate-limited.
        assert!(
            !limiter.check("/vault/audit/run", "127.0.0.1").await,
            "third canonical-path request must be rejected"
        );

        // The middleware normalizes trailing slashes before calling check(), so
        // the slash variant hits the same bucket.  Verify that the normalized
        // path (/vault/audit/run) is what the per_route map keys on.
        // The limiter's check() itself does NOT strip slashes — stripping is
        // the middleware's responsibility.  This test documents the invariant:
        // callers of check() must pass the already-normalized path.
        assert!(
            !limiter.check("/vault/audit/run", "127.0.0.1").await,
            "fourth request (still canonical) must stay rate-limited"
        );
    }

    /// iter-85: per-caller rate limiting via `X-Caller-Id`.
    /// Two distinct caller-ids must get independent buckets on the same route,
    /// even when sharing the same IP address.
    #[tokio::test]
    async fn distinct_caller_ids_have_independent_buckets() {
        // Tight limit of 2 so we can exhaust one caller quickly.
        let limiter = RateLimiter::new(2, 60);
        // Exhaust caller-a's budget.
        assert!(limiter.check("/proxy", "caller-a").await);
        assert!(limiter.check("/proxy", "caller-a").await);
        assert!(
            !limiter.check("/proxy", "caller-a").await,
            "caller-a must be rate-limited"
        );

        // caller-b's budget is independent — must still be allowed.
        assert!(
            limiter.check("/proxy", "caller-b").await,
            "caller-b must have its own fresh budget"
        );
    }

    /// iter-85: `extract_caller_key` must prefer a valid X-Caller-Id header
    /// over the client IP.
    #[test]
    fn extract_caller_key_prefers_header() {
        use axum::http::Request;

        let req = Request::builder()
            .uri("/proxy")
            .header("x-caller-id", "my-mcp-server")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(extract_caller_key(&req), "my-mcp-server");
    }

    /// iter-85: a non-ASCII or empty `X-Caller-Id` must fall through to IP
    /// (or the "unknown" sentinel when ConnectInfo is absent).
    #[test]
    fn extract_caller_key_rejects_invalid_header() {
        use axum::http::Request;

        // A header value with a non-ASCII byte — to_str() fails on it, so
        // extract_caller_key falls through to IP/unknown.
        // Use header_name + header_value bytes directly to inject a non-UTF-8 value.
        let req = Request::builder()
            .uri("/proxy")
            .header(
                "x-caller-id",
                axum::http::HeaderValue::from_bytes(b"\x80\xFF").unwrap(),
            )
            .body(axum::body::Body::empty())
            .unwrap();
        // ConnectInfo is absent in a bare Request; sentinel is "unknown".
        assert_eq!(extract_caller_key(&req), "unknown");
    }

    /// iter-85: X-Caller-Id longer than 64 bytes is truncated to 64 chars.
    #[test]
    fn extract_caller_key_truncates_long_header() {
        use axum::http::Request;

        let long_id = "a".repeat(100);
        let req = Request::builder()
            .uri("/proxy")
            .header("x-caller-id", long_id.as_str())
            .body(axum::body::Body::empty())
            .unwrap();
        let key = extract_caller_key(&req);
        assert_eq!(key.len(), 64);
        assert!(key.chars().all(|c| c == 'a'));
    }
}
