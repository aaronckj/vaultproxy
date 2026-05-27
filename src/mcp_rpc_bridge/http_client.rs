//! Upstream MCP HTTP client. POSTs JSON-RPC requests to a streamable-HTTP
//! / SSE endpoint, injecting the bearer token from `HeaderInjector` on
//! every request. Retries exactly once on HTTP 401 after forcing a token
//! refresh — the typical recovery path when an upstream rotates its
//! signing key between requests.
//!
//! Implements the `Forwarder` trait so it can be dropped into
//! `stdio_server::serve()` without code changes.

use anyhow::{bail, Context, Result};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use reqwest::StatusCode;
use secrecy::ExposeSecret;
use std::sync::Arc;
use std::time::Duration;

use super::header_injector::HeaderInjector;
use super::Forwarder;

pub struct HttpClient {
    upstream: String,
    injector: Arc<HeaderInjector>,
    http: reqwest::Client,
}

impl HttpClient {
    pub fn new(upstream: String, injector: Arc<HeaderInjector>) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .context("build reqwest client")?;
        Ok(Self {
            upstream,
            injector,
            http,
        })
    }

    /// Send a single request body to the upstream with the current
    /// bearer header. Returns the parsed JSON body on 2xx, or an error
    /// containing the status + body snippet on non-2xx.
    async fn send_once(&self, body: &serde_json::Value) -> Result<reqwest::Response> {
        let token = self.injector.current_token().await;
        let resp = self
            .http
            .post(&self.upstream)
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json, text/event-stream")
            .header(AUTHORIZATION, format!("Bearer {}", token.expose_secret()))
            .json(body)
            .send()
            .await
            .with_context(|| format!("POST {}", self.upstream))?;
        Ok(resp)
    }

    /// Parse a streamable-HTTP / SSE response into a single JSON value.
    /// Plain JSON bodies are deserialized directly; SSE event streams
    /// have the first `data: ...` frame parsed and returned.
    async fn parse_body(resp: reqwest::Response) -> Result<serde_json::Value> {
        let ct = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase();
        let body = resp.text().await.context("read upstream body")?;
        if body.trim().is_empty() {
            return Ok(serde_json::Value::Null);
        }
        if ct.contains("text/event-stream") {
            // SSE: each event is one or more lines, terminated by a
            // blank line. `data:` lines carry the payload. For a
            // request/response bridge we want the first non-empty
            // `data:` frame.
            for chunk in body.split("\n\n") {
                for line in chunk.lines() {
                    let line = line.trim();
                    if let Some(data) = line.strip_prefix("data:") {
                        let data = data.trim();
                        if data.is_empty() {
                            continue;
                        }
                        return serde_json::from_str(data)
                            .with_context(|| format!("parse SSE data frame: {data}"));
                    }
                }
            }
            bail!("SSE body had no data frames: {}", truncate(&body, 256));
        }
        serde_json::from_str(&body)
            .with_context(|| format!("parse JSON body: {}", truncate(&body, 256)))
    }
}

#[async_trait::async_trait]
impl Forwarder for HttpClient {
    async fn forward(&self, request: serde_json::Value) -> Result<serde_json::Value> {
        let resp = self.send_once(&request).await?;
        let status = resp.status();
        if status == StatusCode::UNAUTHORIZED {
            tracing::warn!("upstream returned 401, forcing token refresh and retrying once");
            self.injector
                .force_refresh()
                .await
                .context("force_refresh after 401")?;
            let resp2 = self.send_once(&request).await?;
            if !resp2.status().is_success() {
                let status2 = resp2.status();
                let body = resp2.text().await.unwrap_or_default();
                bail!("upstream {} after retry: {}", status2, truncate(&body, 256));
            }
            return Self::parse_body(resp2).await;
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("upstream {}: {}", status, truncate(&body, 256));
        }
        Self::parse_body(resp).await
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}
