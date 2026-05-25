//! E2E: upstream h2 connection pool (v1.10.0+).
//!
//! Drives N sequential requests through the proxy against an h2c
//! upstream that counts how many distinct h2 connections it accepts.
//! With the pool enabled (`AppState.h2_upstream_pool`), all N
//! requests share one upstream h2 connection — the counter stays at 1.
//! Without the pool, each request would open a fresh connection
//! (counter == N) so the assertion is meaningful.

#![cfg(all(feature = "transparent", feature = "test-utils"))]

use bytes::Bytes;
use h2::client;
use http::{Method, Request, Response, StatusCode};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// h2c upstream that increments `accepted_connections` for every
/// successfully-handshaken h2 connection and replies 200 with `reply`
/// on every request.
async fn spawn_counting_h2c_upstream(
    accepted_connections: Arc<AtomicUsize>,
    reply: &'static [u8],
) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => continue,
            };
            let counter = accepted_connections.clone();
            tokio::spawn(async move {
                let mut conn = match h2::server::handshake(tcp).await {
                    Ok(c) => c,
                    Err(_) => return,
                };
                counter.fetch_add(1, Ordering::SeqCst);
                while let Some(stream) = conn.accept().await {
                    let (_req, mut respond) = match stream {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    let resp = Response::builder().status(StatusCode::OK).body(()).unwrap();
                    let mut send = match respond.send_response(resp, false) {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    let _ = send.send_data(Bytes::from_static(reply), true);
                }
            });
        }
    });
    port
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2_upstream_pool_reuses_one_connection() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let connections = Arc::new(AtomicUsize::new(0));
    let upstream_port = spawn_counting_h2c_upstream(connections.clone(), b"pool-ok").await;
    std::env::set_var("VP_TRANSPARENT_TEST_FORCE_H2", "1");

    let state_inner = vaultproxy::test_support::stub_app_state().await;
    {
        use vaultproxy::proxy::registry::{
            AuthPattern, ServiceEntry, ServiceRegistry, TransparentMode,
        };
        let mut reg = ServiceRegistry::new();
        reg.register(ServiceEntry {
            name: "test_pool".into(),
            base_url: format!("http://127.0.0.1:{upstream_port}"),
            auth: AuthPattern::Bearer {
                vault_item: "pool-bearer".into(),
            },
            insecure_tls: false,
            ca_cert_path: None,
            timeout_secs: None,
            transparent_mode: TransparentMode::HostInject,
        });
        *state_inner.registry.write().await = reg;
    }
    state_inner
        .vault
        .seed_test_password("vault-proxy", "pool-bearer", "vault-pool-token")
        .await;
    let state = Arc::new(state_inner);

    let bound = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let bound_addr = bound.local_addr().unwrap();
    drop(bound);
    let ca = Arc::new(vaultproxy::tls::ca::TransparentCa::generate("e2e-pool").unwrap());
    let ca_pem = ca.cert_pem.clone();
    vaultproxy::proxy::transparent::spawn_listener_with_ca(bound_addr, state.clone(), ca)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Drive 3 sequential h2 requests over ONE persistent agent
    // connection. The proxy must reuse the upstream h2 connection
    // for all three.
    let mut tcp = TcpStream::connect(bound_addr).await.unwrap();
    let connect = format!(
        "CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\r\n"
    );
    tcp.write_all(connect.as_bytes()).await.unwrap();
    let mut buf = [0u8; 256];
    let mut drained = Vec::new();
    while !drained.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = tcp.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        drained.extend_from_slice(&buf[..n]);
    }

    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut ca_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
    {
        roots.add(c).unwrap();
    }
    let mut cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let name = rustls::pki_types::ServerName::try_from("127.0.0.1".to_string()).unwrap();
    let tls = connector.connect(name, tcp).await.expect("inner h2 TLS");
    let (h2, conn) = client::handshake(tls).await.expect("agent h2 handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut h2 = h2.ready().await.expect("agent h2 ready");

    for _ in 0..3 {
        let req = Request::builder()
            .method(Method::GET)
            .uri("https://127.0.0.1/me")
            .body(())
            .unwrap();
        let (resp_fut, _send) = h2.send_request(req, true).expect("send_request");
        let resp = resp_fut.await.expect("response");
        assert_eq!(resp.status(), 200);
        let mut body_stream = resp.into_body();
        let mut body = Vec::new();
        while let Some(chunk) = body_stream.data().await {
            body.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(body, b"pool-ok");
    }

    // Give the upstream h2 server task a beat to register all accepts.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let observed = connections.load(Ordering::SeqCst);
    assert_eq!(
        observed, 1,
        "pool must reuse ONE upstream h2 connection across 3 requests; saw {observed}",
    );

    std::env::remove_var("VP_TRANSPARENT_TEST_FORCE_H2");
}
