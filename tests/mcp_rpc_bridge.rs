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
