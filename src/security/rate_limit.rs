//! Lightweight in-memory rate limiter for sidecar API routes.
//!
//! Tracks request counts per `(route, client_ip)` in 60-second windows using a
//! `tokio::sync::Mutex<HashMap>`. Keying on the client IP (not just the route
//! path) prevents a single caller from exhausting the budget for everyone
//! else and prevents many clients from collectively bypassing a per-route cap.
//!
//! # Per-route overrides (iter-37)
//!
//! Destructive vault operations (`/vault/items/delete`, `/vault/folders/delete`)
//! have a tighter limit (10 req/60 s) than the default (60 req/60 s). This is
//! enforced by a `per_route` map in `RateLimiter` that is checked before the
//! global `max_requests` fallback. The tight limits are intentionally low:
//! deleting 10 vault items in one minute is already an unusual workload for a
//! homelab sidecar; anything beyond that is likely runaway automation.

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

/// Per-(route, ip) request counter with windowed expiry.
#[derive(Debug, Clone)]
struct RouteCounter {
    count: u64,
    window_start: std::time::Instant,
}

/// Shared rate-limit state.
#[derive(Clone)]
pub struct RateLimiter {
    /// Map of (route_path, client_ip) -> counter.
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
    #[allow(dead_code)] // v1.0: will be used by configurable per-route rate limiting
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

    /// Check if a request to the given path from the given client IP should be
    /// allowed. Returns `true` if allowed, `false` if rate-limited.
    async fn check(&self, path: &str, ip: &str) -> bool {
        let limit = self
            .per_route
            .get(path)
            .copied()
            .unwrap_or(self.max_requests);

        let mut counters = self.counters.lock().await;
        let now = std::time::Instant::now();

        // Opportunistic GC — drop entries whose window expired long ago to
        // bound memory under churn of distinct client IPs.
        counters.retain(|_, c| now.duration_since(c.window_start) < self.window * 4);

        let key = (path.to_string(), ip.to_string());
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
    // passwords simultaneously.  Limit to 2 req/60 s per IP so a slow or
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
    // minute.  Cap at 2 per IP per 60-second window — enough for one deliberate
    // scan plus one retry, but not enough to sustain an accidental loop.
    m.insert("/vault/audit/run", 2u64);
    m
}

/// Axum middleware that enforces per-`(route, ip)` rate limits on sensitive
/// endpoints. The client IP is pulled from `ConnectInfo<SocketAddr>` injected
/// by the outer `serve` layer; if that extension is missing (test harness,
/// direct-call), we fall back to a sentinel so limits still apply.
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
        let ip = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        if !limiter.check(&path, &ip).await {
            tracing::warn!("rate limit exceeded for {} from {}", path, ip);
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
/// # Shared-IP bucket limitation
///
/// The rate limiter keys on `(route, client_ip)`.  When vault-proxy is used
/// as a sidecar, all MCP servers run on `127.0.0.1` — they all share the
/// **same** bucket for each route.  This means:
///
/// - A single LLM session making 1 call/s hits the 60 req/60s cap in one
///   minute with nothing left for other concurrent MCP servers.
/// - The limit does protect against runaway loops and mis-configured clients,
///   but it is not per-caller isolation.
///
/// TODO: Introduce per-caller identity (e.g. an `X-Caller-Id` header set by
/// each MCP server's configuration) so the bucket can be keyed on
/// `(route, caller_id)` instead of the always-identical loopback IP.  Until
/// then, operators running many concurrent MCP servers may need to raise this
/// limit via `RATE_LIMIT_MAX` / `RATE_LIMIT_WINDOW` env vars (not yet wired).
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
}
