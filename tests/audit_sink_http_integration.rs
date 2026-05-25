//! E2E: AuditLog → HttpSink → wiremock. Proves the batching flusher
//! actually POSTs the right shape against each transport, end-to-end.

#![cfg(feature = "test-utils")]

use std::sync::Arc;
use std::time::Duration;
use vaultproxy::security::audit_log::{AuditEntry, AuditLog};
use vaultproxy::security::audit_sinks_http::{HttpSink, HttpTransport};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn sample_entry(tool: &str) -> AuditEntry {
    AuditEntry {
        timestamp: "2026-05-25T00:00:00Z".into(),
        tool_name: tool.into(),
        args_summary: "{}".into(),
        result_summary: "{}".into(),
        permission: "Allowed".into(),
        trigger: "test".into(),
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn splunk_sink_posts_batched_event_stream() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/services/collector/event"))
        .and(header("Authorization", "Splunk tok-abc"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;

    let url = format!("{}/services/collector/event", server.uri());
    let http = reqwest::Client::new();
    let sink = HttpSink::spawn(
        HttpTransport::Splunk {
            url,
            token: "tok-abc".into(),
        },
        http,
    );

    let dir = tempfile::tempdir().unwrap();
    let mut log = AuditLog::new(dir.path().join("audit-log.json").to_str().unwrap());
    log.set_sinks(vec![Box::new(sink)]);
    let log = Arc::new(log);

    for n in 0..3 {
        log.log(sample_entry(&format!("splunk_{n}")));
    }

    // Wait past the flusher's FLUSH_INTERVAL so the batch flushes.
    tokio::time::sleep(Duration::from_millis(5500)).await;

    let requests = server.received_requests().await.expect("requests");
    assert_eq!(
        requests.len(),
        1,
        "splunk sink should batch into a single POST",
    );
    let body = std::str::from_utf8(&requests[0].body).unwrap();
    let lines: Vec<&str> = body.trim_end_matches('\n').split('\n').collect();
    assert_eq!(lines.len(), 3, "splunk body must be newline-delimited");
    for line in lines {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["sourcetype"], "vaultproxy:audit");
        assert!(v["event"].is_object());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn datadog_sink_posts_array_with_api_key() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v2/logs"))
        .and(header("DD-API-KEY", "ddk-xyz"))
        .respond_with(ResponseTemplate::new(202))
        .mount(&server)
        .await;

    let url = format!("{}/api/v2/logs", server.uri());
    let http = reqwest::Client::new();
    let sink = HttpSink::spawn(
        HttpTransport::Datadog {
            url,
            api_key: "ddk-xyz".into(),
        },
        http,
    );

    let dir = tempfile::tempdir().unwrap();
    let mut log = AuditLog::new(dir.path().join("audit-log.json").to_str().unwrap());
    log.set_sinks(vec![Box::new(sink)]);
    let log = Arc::new(log);

    log.log(sample_entry("dd_a"));
    log.log(sample_entry("dd_b"));

    tokio::time::sleep(Duration::from_millis(5500)).await;

    let requests = server.received_requests().await.expect("requests");
    assert_eq!(requests.len(), 1, "datadog sink should batch into one POST");
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    let arr = body.as_array().expect("datadog body must be an array");
    assert_eq!(arr.len(), 2);
    for record in arr {
        assert_eq!(record["service"], "vaultproxy");
        assert_eq!(record["ddsource"], "vaultproxy");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn otlp_sink_posts_logs_envelope() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/logs"))
        .and(header("Authorization", "Bearer otlp-tok"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let url = format!("{}/v1/logs", server.uri());
    let http = reqwest::Client::new();
    let sink = HttpSink::spawn(
        HttpTransport::Otlp {
            url,
            headers: vec![("Authorization".into(), "Bearer otlp-tok".into())],
        },
        http,
    );

    let dir = tempfile::tempdir().unwrap();
    let mut log = AuditLog::new(dir.path().join("audit-log.json").to_str().unwrap());
    log.set_sinks(vec![Box::new(sink)]);
    let log = Arc::new(log);

    log.log(sample_entry("otlp_a"));

    tokio::time::sleep(Duration::from_millis(5500)).await;

    let requests = server.received_requests().await.expect("requests");
    assert_eq!(requests.len(), 1);
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).unwrap();
    let resource_logs = body["resourceLogs"]
        .as_array()
        .expect("OTLP body must have resourceLogs");
    assert_eq!(resource_logs.len(), 1);
    let svc = resource_logs[0]["resource"]["attributes"][0].clone();
    assert_eq!(svc["key"], "service.name");
    assert_eq!(svc["value"]["stringValue"], "vaultproxy");
    let records = resource_logs[0]["scopeLogs"][0]["logRecords"]
        .as_array()
        .unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["severityText"], "INFO");
}
