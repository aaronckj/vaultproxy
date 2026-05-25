//! E2E: native HTTP/2 to the upstream (v1.8.0+).
//!
//! Spins up a hand-rolled h2c (HTTP/2 cleartext, prior-knowledge)
//! upstream that records the headers it received. Drives an h2 agent
//! through the transparent MITM listener and verifies:
//!   * The proxy forwards the request to the upstream over native h2
//!     (no http/1.1 re-frame in either direction).
//!   * The upstream receives the vault-injected Bearer.
//!   * The agent gets the upstream's h2 response back over h2.
//!
//! Uses `VP_TRANSPARENT_TEST_FORCE_H2=1` so the proxy's upstream
//! client speaks h2 plain TCP (no TLS dance against a stub cert).

#![cfg(all(feature = "transparent", feature = "test-utils"))]

use bytes::Bytes;
use h2::client;
use http::{Method, Request, Response, StatusCode};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// One request's worth of captured headers.
type CapturedHeaders = Vec<(String, String)>;
/// Shared sink for every request the test upstream observes.
type CapturedRequests = Arc<Mutex<Vec<CapturedHeaders>>>;

/// Tiny h2c upstream. Records every request's headers into the given
/// `CapturedRequests` and replies with `{status: 200, body: <reply>}`.
async fn spawn_h2c_upstream(captured: CapturedRequests, reply: &'static [u8]) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => continue,
            };
            let captured = captured.clone();
            tokio::spawn(async move {
                let mut conn = match h2::server::handshake(tcp).await {
                    Ok(c) => c,
                    Err(_) => return,
                };
                while let Some(stream) = conn.accept().await {
                    let (req, mut respond) = match stream {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    let (parts, _body) = req.into_parts();
                    let hdrs: CapturedHeaders = parts
                        .headers
                        .iter()
                        .map(|(k, v)| {
                            (
                                k.as_str().to_string(),
                                v.to_str().unwrap_or_default().to_string(),
                            )
                        })
                        .collect();
                    captured.lock().unwrap().push(hdrs);
                    let resp = Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "text/plain")
                        .body(())
                        .unwrap();
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
async fn h2_end_to_end_upstream_native_h2() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let captured = Arc::new(Mutex::new(Vec::new()));
    let upstream_port = spawn_h2c_upstream(captured.clone(), b"upstream-h2-ok").await;

    // Tell the proxy to use h2-with-prior-knowledge against the upstream.
    std::env::set_var("VP_TRANSPARENT_TEST_FORCE_H2", "1");

    let state_inner = vaultproxy::test_support::stub_app_state().await;
    {
        use vaultproxy::proxy::registry::{
            AuthPattern, ServiceEntry, ServiceRegistry, TransparentMode,
        };
        let mut reg = ServiceRegistry::new();
        reg.register(ServiceEntry {
            name: "test_h2_up".into(),
            base_url: format!("http://127.0.0.1:{upstream_port}"),
            auth: AuthPattern::Bearer {
                vault_item: "h2-up-bearer".into(),
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
        .seed_test_password("vault-proxy", "h2-up-bearer", "vault-h2-up-token")
        .await;
    let state = Arc::new(state_inner);

    let bound = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let bound_addr = bound.local_addr().unwrap();
    drop(bound);
    let ca = Arc::new(vaultproxy::tls::ca::TransparentCa::generate("e2e-h2-up").unwrap());
    let ca_pem = ca.cert_pem.clone();
    vaultproxy::proxy::transparent::spawn_listener_with_ca(bound_addr, state.clone(), ca)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Agent → proxy: CONNECT then TLS+ALPN=h2.
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

    let req = Request::builder()
        .method(Method::GET)
        .uri("https://127.0.0.1/me")
        .header("authorization", "Bearer attacker")
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
    assert_eq!(body, b"upstream-h2-ok");

    let cap = captured.lock().unwrap().clone();
    assert!(
        !cap.is_empty(),
        "upstream h2c server must have received at least one request",
    );
    let first = &cap[0];
    let bearer = first
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    assert_eq!(
        bearer, "Bearer vault-h2-up-token",
        "upstream MUST see vault-injected bearer, not the agent's smuggled one",
    );

    std::env::remove_var("VP_TRANSPARENT_TEST_FORCE_H2");
}
