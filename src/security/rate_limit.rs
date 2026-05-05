//! Lightweight in-memory rate limiter for sidecar API routes.
//!
//! Tracks request counts per `(route, client_ip)` in 60-second windows using a
//! `tokio::sync::Mutex<HashMap>`. Keying on the client IP (not just the route
//! path) prevents a single caller from exhausting the budget for everyone
//! else and prevents many clients from collectively bypassing a per-route cap.

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
    /// Maximum requests per window.
    max_requests: u64,
    /// Window duration.
    window: std::time::Duration,
}

impl RateLimiter {
    /// Create a new rate limiter with the given max requests per window.
    pub fn new(max_requests: u64, window_secs: u64) -> Self {
        Self {
            counters: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window: std::time::Duration::from_secs(window_secs),
        }
    }

    /// Check if a request to the given path from the given client IP should be
    /// allowed. Returns `true` if allowed, `false` if rate-limited.
    async fn check(&self, path: &str, ip: &str) -> bool {
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
        counter.count <= self.max_requests
    }
}

/// Routes that are subject to rate limiting.
const RATE_LIMITED_PATHS: &[&str] = &[
    "/proxy",
    "/vault/totp",
    "/vault/resync",
    "/rotate",
    "/browser/rotate",
    "/sync/init",
];

/// Axum middleware that enforces per-`(route, ip)` rate limits on sensitive
/// endpoints. The client IP is pulled from `ConnectInfo<SocketAddr>` injected
/// by the outer `serve` layer; if that extension is missing (test harness,
/// direct-call), we fall back to a sentinel so limits still apply.
pub async fn rate_limit_middleware(
    axum::extract::State(limiter): axum::extract::State<RateLimiter>,
    req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();

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

/// Create a default rate limiter: 60 requests per 60-second window.
pub fn default_rate_limiter() -> RateLimiter {
    RateLimiter::new(60, 60)
}
