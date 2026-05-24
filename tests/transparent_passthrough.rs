//! E2E for transparent passthrough mode.
//!
//! Spawns a local TCP echo server, brings up the transparent listener,
//! drives a raw TCP client through HTTPS_PROXY-style CONNECT semantics,
//! and asserts bytes round-trip unmodified.

#![cfg(all(feature = "transparent", feature = "test-utils"))]

use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Start a TCP echo server on an ephemeral port. Returns the bound port.
async fn spawn_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

#[tokio::test]
async fn passthrough_relays_bytes_unmodified() {
    use vaultproxy::proxy::transparent;

    let upstream_port = spawn_echo().await;

    let state = Arc::new(vaultproxy::test_support::stub_app_state().await);

    // Bind to ephemeral port, release, let spawn_listener rebind.
    let listener_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let bound = std::net::TcpListener::bind(listener_addr).unwrap();
    let bound_addr = bound.local_addr().unwrap();
    drop(bound);

    transparent::spawn_listener(bound_addr, state)
        .await
        .unwrap();

    // Brief delay to allow the listener task to come up.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Connect as if curl with HTTPS_PROXY set.
    let mut client = TcpStream::connect(bound_addr).await.unwrap();
    let connect_line = format!(
        "CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\r\n"
    );
    client.write_all(connect_line.as_bytes()).await.unwrap();

    // Read 200 Connection established.
    let mut buf = [0u8; 512];
    let n = client.read(&mut buf).await.unwrap();
    let response = std::str::from_utf8(&buf[..n]).unwrap();
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "expected 200 from transparent listener, got: {response}"
    );

    // Verify bytes echo through the tunnel.
    let payload = b"hello from the agent";
    client.write_all(payload).await.unwrap();
    let mut echo = [0u8; 32];
    let n = client.read(&mut echo).await.unwrap();
    assert_eq!(&echo[..n], payload);
}
