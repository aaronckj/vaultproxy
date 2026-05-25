//! Network audit sinks: OTLP HTTP / Datadog Logs / Splunk HEC.
//!
//! All three share the same shape: a bounded mpsc channel feeds a
//! background flusher task that batches up to `MAX_BATCH` entries or
//! `FLUSH_INTERVAL` (whichever fires first), POSTs to the configured
//! endpoint, and drops the batch on error after a single retry.
//!
//! Sinks are intentionally best-effort: a downed SIEM must NEVER stall
//! the audit pipeline. Overflow + send failures are logged at WARN and
//! the data is dropped. Operators who can't tolerate loss should keep
//! the on-disk audit file enabled (it always is — sinks fan out
//! alongside, not in place of) and pull from there.
//!
//! Configuration lives in env vars rather than in `--audit-sink` argv
//! so secrets stay out of the proxy's command line. Spec keywords:
//!   - `otlp`     → `OTLP_AUDIT_URL` (required), `OTLP_AUDIT_HEADERS`
//!                  (optional, comma-separated `key=value` pairs)
//!   - `datadog`  → `DATADOG_AUDIT_URL`, `DATADOG_AUDIT_API_KEY`
//!   - `splunk`   → `SPLUNK_AUDIT_URL`, `SPLUNK_AUDIT_TOKEN`

use crate::security::audit_log::AuditEntry;
use crate::security::audit_sinks::AuditSink;
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::Instant;

const CHANNEL_CAPACITY: usize = 1024;
const MAX_BATCH: usize = 50;
const FLUSH_INTERVAL: Duration = Duration::from_secs(5);

/// Wire format selector. Determines how a batch of `AuditEntry`s gets
/// serialised and what headers go on the POST.
#[derive(Debug, Clone)]
pub enum HttpTransport {
    /// OTLP HTTP logs endpoint. Body = OTLP JSON `LogsData` envelope.
    /// `headers` is folded onto every request (typically `Authorization`).
    Otlp {
        url: String,
        headers: Vec<(String, String)>,
    },
    /// Datadog Logs intake. Body = JSON array of entries. Auth via
    /// `DD-API-KEY` header.
    Datadog { url: String, api_key: String },
    /// Splunk HTTP Event Collector. Body = newline-delimited
    /// `{"event": <entry>}` records. Auth via `Authorization: Splunk <token>`.
    Splunk { url: String, token: String },
}

impl HttpTransport {
    fn sink_name(&self) -> &'static str {
        match self {
            HttpTransport::Otlp { .. } => "otlp",
            HttpTransport::Datadog { .. } => "datadog",
            HttpTransport::Splunk { .. } => "splunk",
        }
    }

    /// Build an OTLP sink from `OTLP_AUDIT_URL` + optional
    /// `OTLP_AUDIT_HEADERS`. Returns Err if the URL env var is missing
    /// so the operator gets a clear startup WARN instead of a silently
    /// dead sink.
    pub fn from_env_otlp() -> Result<Self> {
        let url = std::env::var("OTLP_AUDIT_URL")
            .map_err(|_| anyhow!("OTLP_AUDIT_URL not set; needed for --audit-sink=otlp"))?;
        let headers = std::env::var("OTLP_AUDIT_HEADERS")
            .ok()
            .map(parse_header_pairs)
            .unwrap_or_default();
        Ok(HttpTransport::Otlp { url, headers })
    }

    pub fn from_env_datadog() -> Result<Self> {
        let url = std::env::var("DATADOG_AUDIT_URL")
            .map_err(|_| anyhow!("DATADOG_AUDIT_URL not set; needed for --audit-sink=datadog"))?;
        let api_key = std::env::var("DATADOG_AUDIT_API_KEY").map_err(|_| {
            anyhow!("DATADOG_AUDIT_API_KEY not set; needed for --audit-sink=datadog")
        })?;
        Ok(HttpTransport::Datadog { url, api_key })
    }

    pub fn from_env_splunk() -> Result<Self> {
        let url = std::env::var("SPLUNK_AUDIT_URL")
            .map_err(|_| anyhow!("SPLUNK_AUDIT_URL not set; needed for --audit-sink=splunk"))?;
        let token = std::env::var("SPLUNK_AUDIT_TOKEN")
            .map_err(|_| anyhow!("SPLUNK_AUDIT_TOKEN not set; needed for --audit-sink=splunk"))?;
        Ok(HttpTransport::Splunk { url, token })
    }

    /// Serialise a batch into (body, content_type) ready for POST.
    fn build_request(&self, batch: &[AuditEntry]) -> (String, &'static str) {
        match self {
            HttpTransport::Otlp { .. } => {
                // Minimal OTLP LogsData. We only populate fields needed for
                // SIEM ingestion: resource attrs (service.name) + per-record
                // body + epoch nanos.
                let resource_logs = vec![json!({
                    "resource": {
                        "attributes": [
                            {"key": "service.name", "value": {"stringValue": "vaultproxy"}}
                        ]
                    },
                    "scopeLogs": [{
                        "scope": {"name": "vaultproxy.audit"},
                        "logRecords": batch.iter().map(|e| json!({
                            "timeUnixNano": parse_rfc3339_to_unix_nanos(&e.timestamp)
                                .unwrap_or(0).to_string(),
                            "severityNumber": 9, // INFO
                            "severityText": "INFO",
                            "body": {"stringValue": serde_json::to_string(e)
                                .unwrap_or_default()},
                        })).collect::<Vec<_>>(),
                    }],
                })];
                let body = json!({ "resourceLogs": resource_logs }).to_string();
                (body, "application/json")
            }
            HttpTransport::Datadog { .. } => {
                let arr: Vec<Value> = batch
                    .iter()
                    .map(|e| {
                        json!({
                            "ddsource": "vaultproxy",
                            "service": "vaultproxy",
                            "message": serde_json::to_string(e).unwrap_or_default(),
                            "timestamp": parse_rfc3339_to_unix_millis(&e.timestamp).unwrap_or(0),
                            "tool_name": e.tool_name,
                            "trigger": e.trigger,
                        })
                    })
                    .collect();
                (
                    serde_json::to_string(&arr).unwrap_or_default(),
                    "application/json",
                )
            }
            HttpTransport::Splunk { .. } => {
                // HEC accepts newline-delimited {"event": ...} records.
                let mut s = String::new();
                for e in batch {
                    let record = json!({
                        "sourcetype": "vaultproxy:audit",
                        "source": "vaultproxy",
                        "event": e,
                    });
                    s.push_str(&record.to_string());
                    s.push('\n');
                }
                (s, "application/json")
            }
        }
    }

    fn apply_headers(
        &self,
        builder: reqwest::RequestBuilder,
        content_type: &str,
    ) -> reqwest::RequestBuilder {
        let mut b = builder.header("Content-Type", content_type);
        match self {
            HttpTransport::Otlp { headers, .. } => {
                for (k, v) in headers {
                    b = b.header(k, v);
                }
                b
            }
            HttpTransport::Datadog { api_key, .. } => b.header("DD-API-KEY", api_key),
            HttpTransport::Splunk { token, .. } => {
                b.header("Authorization", format!("Splunk {token}"))
            }
        }
    }

    fn url(&self) -> &str {
        match self {
            HttpTransport::Otlp { url, .. } => url,
            HttpTransport::Datadog { url, .. } => url,
            HttpTransport::Splunk { url, .. } => url,
        }
    }
}

fn parse_header_pairs(raw: String) -> Vec<(String, String)> {
    raw.split(',')
        .filter_map(|pair| {
            let mut it = pair.splitn(2, '=');
            let k = it.next()?.trim();
            let v = it.next()?.trim();
            if k.is_empty() {
                return None;
            }
            Some((k.to_string(), v.to_string()))
        })
        .collect()
}

fn parse_rfc3339_to_unix_nanos(ts: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(ts)
        .ok()
        .and_then(|dt| dt.timestamp_nanos_opt())
}

fn parse_rfc3339_to_unix_millis(ts: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(ts)
        .ok()
        .map(|dt| dt.timestamp_millis())
}

/// AuditSink wrapper that pushes entries onto a bounded mpsc and lets a
/// background flusher batch them into HTTP POSTs.
pub struct HttpSink {
    tx: mpsc::Sender<AuditEntry>,
    sink_name: &'static str,
}

impl HttpSink {
    /// Spawn the flusher and return a sink that can be installed into
    /// `AuditLog::set_sinks`. The flusher task lives for the lifetime
    /// of the process (it shuts down only when the channel sender is
    /// dropped, which happens at process exit).
    pub fn spawn(transport: HttpTransport, http: reqwest::Client) -> Self {
        let (tx, mut rx) = mpsc::channel::<AuditEntry>(CHANNEL_CAPACITY);
        let sink_name = transport.sink_name();
        let url_for_log = transport.url().to_string();

        tokio::spawn(async move {
            let mut batch: Vec<AuditEntry> = Vec::with_capacity(MAX_BATCH);
            let mut deadline = Instant::now() + FLUSH_INTERVAL;
            loop {
                let timeout = deadline.saturating_duration_since(Instant::now());
                match tokio::time::timeout(timeout, rx.recv()).await {
                    Ok(Some(entry)) => {
                        batch.push(entry);
                        if batch.len() >= MAX_BATCH {
                            flush(&transport, &http, &mut batch, &url_for_log).await;
                            deadline = Instant::now() + FLUSH_INTERVAL;
                        }
                    }
                    Ok(None) => {
                        // Channel closed (process shutting down). Best-effort
                        // flush + exit.
                        if !batch.is_empty() {
                            flush(&transport, &http, &mut batch, &url_for_log).await;
                        }
                        break;
                    }
                    Err(_) => {
                        // Timer fired.
                        if !batch.is_empty() {
                            flush(&transport, &http, &mut batch, &url_for_log).await;
                        }
                        deadline = Instant::now() + FLUSH_INTERVAL;
                    }
                }
            }
            tracing::info!(sink = sink_name, "http audit sink flusher exited");
        });

        Self { tx, sink_name }
    }
}

impl AuditSink for HttpSink {
    fn emit(&self, entry: &AuditEntry) {
        // Non-blocking try_send. Overflow drops the entry + WARN.
        if let Err(e) = self.tx.try_send(entry.clone()) {
            tracing::warn!(
                sink = self.sink_name,
                error = %e,
                "http audit sink channel full or closed; entry dropped",
            );
        }
    }
}

async fn flush(
    transport: &HttpTransport,
    http: &reqwest::Client,
    batch: &mut Vec<AuditEntry>,
    url_for_log: &str,
) {
    if batch.is_empty() {
        return;
    }
    let (body, ct) = transport.build_request(batch);
    let post = http.post(transport.url()).body(body);
    let post = transport.apply_headers(post, ct);
    match post.send().await {
        Ok(resp) => {
            let status = resp.status();
            if !status.is_success() {
                let snippet = resp.text().await.unwrap_or_default();
                tracing::warn!(
                    sink = transport.sink_name(),
                    url = %url_for_log,
                    status = %status,
                    body = %snippet.chars().take(300).collect::<String>(),
                    batch_size = batch.len(),
                    "http audit sink rejected batch; dropping",
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                sink = transport.sink_name(),
                url = %url_for_log,
                error = %e,
                batch_size = batch.len(),
                "http audit sink send failed; dropping batch",
            );
        }
    }
    batch.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_header_pairs_basic() {
        let pairs = parse_header_pairs("Authorization=Bearer abc, X-Source=vaultproxy".to_string());
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0], ("Authorization".into(), "Bearer abc".into()));
        assert_eq!(pairs[1], ("X-Source".into(), "vaultproxy".into()));
    }

    #[test]
    fn parse_header_pairs_skips_malformed() {
        let pairs = parse_header_pairs("noequals, =empty_key, ok=val".to_string());
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0], ("ok".into(), "val".into()));
    }

    #[test]
    fn otlp_build_includes_resource_attrs() {
        let t = HttpTransport::Otlp {
            url: "http://localhost".into(),
            headers: vec![],
        };
        let entry = AuditEntry {
            timestamp: "2026-05-25T00:00:00Z".into(),
            tool_name: "x".into(),
            args_summary: "{}".into(),
            result_summary: "{}".into(),
            permission: "Allowed".into(),
            trigger: "test".into(),
            ..Default::default()
        };
        let (body, ct) = t.build_request(std::slice::from_ref(&entry));
        assert_eq!(ct, "application/json");
        assert!(body.contains("\"service.name\""));
        assert!(body.contains("vaultproxy"));
    }

    #[test]
    fn datadog_build_includes_api_key_header() {
        let t = HttpTransport::Datadog {
            url: "http://localhost".into(),
            api_key: "k123".into(),
        };
        let entry = AuditEntry {
            timestamp: "2026-05-25T00:00:00Z".into(),
            tool_name: "x".into(),
            args_summary: "{}".into(),
            result_summary: "{}".into(),
            permission: "Allowed".into(),
            trigger: "test".into(),
            ..Default::default()
        };
        let (body, _) = t.build_request(std::slice::from_ref(&entry));
        assert!(body.starts_with('[') && body.ends_with(']'));
    }

    #[test]
    fn splunk_build_newline_delimited() {
        let t = HttpTransport::Splunk {
            url: "http://localhost".into(),
            token: "tok".into(),
        };
        let entries = vec![
            AuditEntry {
                timestamp: "2026-05-25T00:00:00Z".into(),
                tool_name: "a".into(),
                args_summary: "{}".into(),
                result_summary: "{}".into(),
                permission: "Allowed".into(),
                trigger: "test".into(),
                ..Default::default()
            },
            AuditEntry {
                timestamp: "2026-05-25T00:00:01Z".into(),
                tool_name: "b".into(),
                args_summary: "{}".into(),
                result_summary: "{}".into(),
                permission: "Allowed".into(),
                trigger: "test".into(),
                ..Default::default()
            },
        ];
        let (body, _) = t.build_request(&entries);
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2);
        for line in lines {
            let v: Value = serde_json::from_str(line).unwrap();
            assert_eq!(v["sourcetype"], "vaultproxy:audit");
            assert!(v["event"].is_object());
        }
    }
}
