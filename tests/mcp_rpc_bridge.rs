use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use secrecy::ExposeSecret;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

use vaultproxy::mcp_rpc_bridge::header_injector::HeaderInjector;

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
