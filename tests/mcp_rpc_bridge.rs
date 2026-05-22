use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use secrecy::ExposeSecret;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

use vaultproxy::mcp_rpc_bridge::header_injector::HeaderInjector;
use vaultproxy::mcp_rpc_bridge::stdio_server::serve_streams;
use vaultproxy::mcp_rpc_bridge::Forwarder;

/// Run a one-shot socket server that listens on `path` and, for every
/// `get_item_fields` request, replies with a token derived from the
/// shared counter. Returns a JoinHandle the caller can abort.
///
/// Binds the listener synchronously before spawning so callers may
/// connect immediately on return — avoids a race where the test
/// constructs `HeaderInjector::new()` before the accept loop is live.
fn spawn_fake_socket(path: PathBuf, version: Arc<AtomicU64>) -> tokio::task::JoinHandle<()> {
    let listener = UnixListener::bind(&path).expect("bind fake socket");
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => return,
            };
            let v = version.clone();
            tokio::spawn(async move {
                let (read_half, mut write_half) = stream.into_split();
                let mut reader = BufReader::new(read_half);
                let mut line = String::new();
                if reader.read_line(&mut line).await.is_err() {
                    return;
                }
                let req: serde_json::Value = match serde_json::from_str(line.trim()) {
                    Ok(v) => v,
                    Err(_) => return,
                };
                if req["op"] != "get_item_fields" {
                    return;
                }
                let n = v.load(Ordering::SeqCst);
                let field = req["fields"][0].as_str().unwrap_or("password");
                let resp = serde_json::json!({
                    "ok": true,
                    "fields": { field: format!("tok-v{n}") },
                });
                let _ = write_half
                    .write_all(serde_json::to_string(&resp).unwrap().as_bytes())
                    .await;
                let _ = write_half.write_all(b"\n").await;
                let _ = write_half.shutdown().await;
            });
        }
    })
}

fn tmp_socket() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vp.sock");
    (dir, path)
}

#[tokio::test]
async fn fetches_initial_token_on_new() {
    let (_dir, sock) = tmp_socket();
    let version = Arc::new(AtomicU64::new(1));
    let _server = spawn_fake_socket(sock.clone(), version.clone());

    let inj = HeaderInjector::new(
        sock,
        "Test Bearer".to_string(),
        "password".to_string(),
        Duration::from_secs(60),
    )
    .await
    .unwrap();
    assert_eq!(inj.current_token().await.expose_secret(), "tok-v1");
}

#[tokio::test]
async fn refreshes_after_ttl() {
    let (_dir, sock) = tmp_socket();
    let version = Arc::new(AtomicU64::new(1));
    let _server = spawn_fake_socket(sock.clone(), version.clone());

    let inj = HeaderInjector::new(
        sock,
        "Test Bearer".to_string(),
        "password".to_string(),
        Duration::from_millis(100),
    )
    .await
    .unwrap();
    assert_eq!(inj.current_token().await.expose_secret(), "tok-v1");

    // Advance server-side version.
    version.store(2, Ordering::SeqCst);

    // Wait past the TTL window.
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert_eq!(
        inj.current_token().await.expose_secret(),
        "tok-v2",
        "after TTL elapses, current_token should fetch the new value"
    );
}

#[tokio::test]
async fn force_refresh_returns_new_value() {
    let (_dir, sock) = tmp_socket();
    let version = Arc::new(AtomicU64::new(1));
    let _server = spawn_fake_socket(sock.clone(), version.clone());

    let inj = HeaderInjector::new(
        sock,
        "Test Bearer".to_string(),
        "password".to_string(),
        Duration::from_secs(3600), // long TTL so only force_refresh updates
    )
    .await
    .unwrap();
    assert_eq!(inj.current_token().await.expose_secret(), "tok-v1");

    version.store(7, Ordering::SeqCst);
    inj.force_refresh().await.unwrap();
    assert_eq!(inj.current_token().await.expose_secret(), "tok-v7");
}

#[tokio::test]
async fn new_errors_when_socket_missing() {
    let dir = tempfile::tempdir().unwrap();
    let bogus = dir.path().join("does-not-exist.sock");
    let res = HeaderInjector::new(
        bogus,
        "X".to_string(),
        "password".to_string(),
        Duration::from_secs(60),
    )
    .await;
    assert!(res.is_err(), "missing socket should error on initial fetch");
}

#[tokio::test]
async fn keeps_stale_token_when_refresh_fails() {
    let (dir, sock) = tmp_socket();
    let version = Arc::new(AtomicU64::new(1));
    let server = spawn_fake_socket(sock.clone(), version.clone());

    let inj = HeaderInjector::new(
        sock.clone(),
        "Test Bearer".to_string(),
        "password".to_string(),
        Duration::from_millis(50),
    )
    .await
    .unwrap();
    assert_eq!(inj.current_token().await.expose_secret(), "tok-v1");

    // Kill the server, remove the socket file, and advance past the TTL.
    server.abort();
    let _ = std::fs::remove_file(&sock);
    tokio::time::sleep(Duration::from_millis(150)).await;

    // current_token must NOT clear the cached value when refresh fails.
    // The injector's policy is "prefer stale to nothing" so the upstream
    // 401 path (handled in http_client) is what actually invalidates a
    // bad token.
    let tok = inj.current_token().await;
    assert_eq!(
        tok.expose_secret(),
        "tok-v1",
        "stale token must be preserved when refresh fails"
    );
    drop(dir);
}

// ---------------------------------------------------------------------------
// Wave 3 Task 10: stdio_server tests
// ---------------------------------------------------------------------------

/// Test-only forwarder that echoes the request back with a synthesized
/// result. Used by stdio_server tests to verify framing without spinning
/// up a real HTTP upstream.
struct EchoForwarder;

#[async_trait::async_trait]
impl Forwarder for EchoForwarder {
    async fn forward(&self, req: serde_json::Value) -> anyhow::Result<serde_json::Value> {
        let id = req.get("id").cloned().unwrap_or(serde_json::Value::Null);
        let method = req.get("method").and_then(serde_json::Value::as_str).unwrap_or("").to_string();
        Ok(serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "echo": method, "params": req.get("params").cloned() },
        }))
    }
}

/// Forwarder that always errors, to test the error envelope path.
struct FailingForwarder(String);

#[async_trait::async_trait]
impl Forwarder for FailingForwarder {
    async fn forward(&self, _: serde_json::Value) -> anyhow::Result<serde_json::Value> {
        anyhow::bail!("simulated upstream failure: {}", self.0)
    }
}

#[tokio::test]
async fn stdio_server_echoes_one_request() {
    use std::sync::Arc;
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"params\":{}}\n";
    let mut output: Vec<u8> = Vec::new();
    serve_streams(&input[..], &mut output, Arc::new(EchoForwarder)).await.unwrap();

    let s = String::from_utf8(output).unwrap();
    let line = s.lines().next().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
    assert_eq!(parsed["jsonrpc"], "2.0");
    assert_eq!(parsed["id"], 1);
    assert_eq!(parsed["result"]["echo"], "ping");
}

#[tokio::test]
async fn stdio_server_handles_multiple_requests_in_sequence() {
    use std::sync::Arc;
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"a\",\"params\":{}}\n\
                  {\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"b\",\"params\":{}}\n\
                  {\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"c\",\"params\":{}}\n";
    let mut output: Vec<u8> = Vec::new();
    serve_streams(&input[..], &mut output, Arc::new(EchoForwarder)).await.unwrap();

    let s = String::from_utf8(output).unwrap();
    let lines: Vec<_> = s.lines().collect();
    assert_eq!(lines.len(), 3);
    for (i, line) in lines.iter().enumerate() {
        let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(parsed["id"], (i as u64) + 1);
        assert_eq!(parsed["result"]["echo"], ["a", "b", "c"][i]);
    }
}

#[tokio::test]
async fn stdio_server_returns_parse_error_envelope_on_bad_json() {
    use std::sync::Arc;
    let input = b"not json at all\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"valid\",\"params\":{}}\n";
    let mut output: Vec<u8> = Vec::new();
    serve_streams(&input[..], &mut output, Arc::new(EchoForwarder)).await.unwrap();

    let s = String::from_utf8(output).unwrap();
    let lines: Vec<_> = s.lines().collect();
    assert_eq!(lines.len(), 2, "one error envelope, then one valid response");

    let parse_err: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(parse_err["error"]["code"], -32700);
    assert!(parse_err["error"]["message"].as_str().unwrap().contains("Parse error"));

    let valid: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(valid["id"], 2);
    assert_eq!(valid["result"]["echo"], "valid");
}

#[tokio::test]
async fn stdio_server_returns_forwarder_error_envelope() {
    use std::sync::Arc;
    let input = b"{\"jsonrpc\":\"2.0\",\"id\":42,\"method\":\"x\",\"params\":{}}\n";
    let mut output: Vec<u8> = Vec::new();
    serve_streams(
        &input[..],
        &mut output,
        Arc::new(FailingForwarder("upstream offline".into())),
    ).await.unwrap();

    let s = String::from_utf8(output).unwrap();
    let line = s.lines().next().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
    assert_eq!(parsed["jsonrpc"], "2.0");
    assert_eq!(parsed["id"], 42);
    assert_eq!(parsed["error"]["code"], -32099);
    assert!(parsed["error"]["message"].as_str().unwrap().contains("upstream offline"));
}

#[tokio::test]
async fn stdio_server_skips_blank_lines() {
    use std::sync::Arc;
    let input = b"\n\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"go\",\"params\":{}}\n\n";
    let mut output: Vec<u8> = Vec::new();
    serve_streams(&input[..], &mut output, Arc::new(EchoForwarder)).await.unwrap();

    let s = String::from_utf8(output).unwrap();
    let lines: Vec<_> = s.lines().collect();
    assert_eq!(lines.len(), 1);
    let parsed: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(parsed["result"]["echo"], "go");
}

// ---------------------------------------------------------------------------
// Wave 3 Task 11: http_client tests
// ---------------------------------------------------------------------------

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode as AxumStatus};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::Json;
use axum::Router;
use std::net::SocketAddr;
use std::sync::Mutex;

use vaultproxy::mcp_rpc_bridge::http_client::HttpClient;

#[derive(Default)]
struct FakeUpstreamState {
    received_tokens: Mutex<Vec<String>>,
    fail_with_401_until: Mutex<u32>, // counter; if >0, next response is 401 and counter decrements
    response_mode: Mutex<&'static str>, // "json" | "sse"
}

async fn fake_handler(
    State(state): State<Arc<FakeUpstreamState>>,
    headers: HeaderMap,
    Json(req): Json<serde_json::Value>,
) -> axum::response::Response {
    let tok = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    state.received_tokens.lock().unwrap().push(tok);

    {
        let mut n = state.fail_with_401_until.lock().unwrap();
        if *n > 0 {
            *n -= 1;
            return (AxumStatus::UNAUTHORIZED, "no").into_response();
        }
    }

    let id = req.get("id").cloned().unwrap_or(serde_json::Value::Null);
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": { "method_seen": req.get("method") },
    });

    let mode = *state.response_mode.lock().unwrap();
    if mode == "sse" {
        let sse_body = format!(
            "data: {}\n\n",
            serde_json::to_string(&body).unwrap()
        );
        (
            AxumStatus::OK,
            [(axum::http::header::CONTENT_TYPE, "text/event-stream")],
            sse_body,
        )
            .into_response()
    } else {
        (AxumStatus::OK, Json(body)).into_response()
    }
}

async fn spawn_fake_upstream(
    state: Arc<FakeUpstreamState>,
) -> (String, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route("/mcp", post(fake_handler))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let h = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (format!("http://{}/mcp", addr), h)
}

async fn build_injector() -> (
    tempfile::TempDir,
    Arc<HeaderInjector>,
    Arc<AtomicU64>,
    tokio::task::JoinHandle<()>,
) {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("vp.sock");
    let version = Arc::new(AtomicU64::new(1));
    let server = spawn_fake_socket(sock.clone(), version.clone());
    let inj = HeaderInjector::new(
        sock,
        "X".to_string(),
        "password".to_string(),
        Duration::from_secs(3600),
    )
    .await
    .unwrap();
    (dir, Arc::new(inj), version, server)
}

#[tokio::test]
async fn http_client_injects_authorization_header_json() {
    let (_dir, inj, _ver, _socket_h) = build_injector().await;
    let upstream_state = Arc::new(FakeUpstreamState::default());
    *upstream_state.response_mode.lock().unwrap() = "json";
    let (url, _upstream_h) = spawn_fake_upstream(upstream_state.clone()).await;

    let client = HttpClient::new(url, inj).unwrap();
    let resp = client
        .forward(serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}
        }))
        .await
        .unwrap();

    assert_eq!(resp["result"]["method_seen"], "ping");
    let tokens = upstream_state.received_tokens.lock().unwrap();
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0], "Bearer tok-v1");
}

#[tokio::test]
async fn http_client_parses_sse_body() {
    let (_dir, inj, _ver, _socket_h) = build_injector().await;
    let upstream_state = Arc::new(FakeUpstreamState::default());
    *upstream_state.response_mode.lock().unwrap() = "sse";
    let (url, _upstream_h) = spawn_fake_upstream(upstream_state.clone()).await;

    let client = HttpClient::new(url, inj).unwrap();
    let resp = client
        .forward(serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "sse-test", "params": {}
        }))
        .await
        .unwrap();

    assert_eq!(resp["result"]["method_seen"], "sse-test");
}

#[tokio::test]
async fn http_client_refreshes_on_401_and_retries() {
    let (_dir, inj, version, _socket_h) = build_injector().await;
    let upstream_state = Arc::new(FakeUpstreamState::default());
    *upstream_state.fail_with_401_until.lock().unwrap() = 1; // first request 401s
    let (url, _upstream_h) = spawn_fake_upstream(upstream_state.clone()).await;

    let client = HttpClient::new(url, inj).unwrap();

    // Between the initial token fetch and the retry, advance the version
    // so the post-refresh token is observably different.
    version.store(2, Ordering::SeqCst);

    let resp = client
        .forward(serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}
        }))
        .await
        .unwrap();
    assert_eq!(resp["result"]["method_seen"], "ping");

    let tokens = upstream_state.received_tokens.lock().unwrap();
    assert_eq!(tokens.len(), 2, "expected initial 401 + retry");
    assert_eq!(tokens[0], "Bearer tok-v1");
    assert_eq!(tokens[1], "Bearer tok-v2");
}

#[tokio::test]
async fn http_client_propagates_non_401_errors() {
    let (_dir, inj, _ver, _socket_h) = build_injector().await;
    let upstream_state = Arc::new(FakeUpstreamState::default());
    let (url, _upstream_h) = spawn_fake_upstream(upstream_state.clone()).await;

    // Point at a definitely-bogus path under the same host so we get a 404.
    let bogus = url.replace("/mcp", "/does-not-exist");
    let client = HttpClient::new(bogus, inj).unwrap();
    let res = client
        .forward(serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "x", "params": {}
        }))
        .await;
    let err = res.unwrap_err();
    let msg = format!("{err:?}");
    assert!(msg.contains("404"), "expected 404 error, got: {msg}");
}
