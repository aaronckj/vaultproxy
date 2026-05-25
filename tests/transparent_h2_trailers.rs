//! E2E: HTTP/2 trailers pass-through (v1.11.0+). gRPC's grpc-status /
//! grpc-message live in trailers; this proves the proxy forwards them
//! end-to-end on the h2-↔-h2 path.

#![cfg(all(feature = "transparent", feature = "test-utils"))]

use bytes::Bytes;
use h2::client;
use http::{HeaderMap, Method, Request, Response, StatusCode};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn spawn_h2c_trailers_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => continue,
            };
            tokio::spawn(async move {
                let mut conn = match h2::server::handshake(tcp).await {
                    Ok(c) => c,
                    Err(_) => return,
                };
                while let Some(stream) = conn.accept().await {
                    let (_req, mut respond) = match stream {
                        Ok(p) => p,
                        Err(_) => continue,
                    };
                    let resp = Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", "application/grpc")
                        .body(())
                        .unwrap();
                    let mut send = match respond.send_response(resp, false) {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    let _ = send.send_data(Bytes::from_static(b"grpc-body"), false);
                    let mut tr = HeaderMap::new();
                    tr.insert("grpc-status", "0".parse().unwrap());
                    tr.insert("grpc-message", "OK".parse().unwrap());
                    let _ = send.send_trailers(tr);
                }
            });
        }
    });
    port
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2_trailers_pass_through_end_to_end() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let upstream_port = spawn_h2c_trailers_upstream().await;
    std::env::set_var("VP_TRANSPARENT_TEST_FORCE_H2", "1");

    let state_inner = vaultproxy::test_support::stub_app_state().await;
    {
        use vaultproxy::proxy::registry::{
            AuthPattern, ServiceEntry, ServiceRegistry, TransparentMode,
        };
        let mut reg = ServiceRegistry::new();
        reg.register(ServiceEntry {
            name: "test_grpc".into(),
            base_url: format!("http://127.0.0.1:{upstream_port}"),
            auth: AuthPattern::Bearer {
                vault_item: "grpc-bearer".into(),
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
        .seed_test_password("vault-proxy", "grpc-bearer", "vault-grpc-token")
        .await;
    let state = Arc::new(state_inner);

    let bound = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let bound_addr = bound.local_addr().unwrap();
    drop(bound);
    let ca = Arc::new(vaultproxy::tls::ca::TransparentCa::generate("e2e-trailers").unwrap());
    let ca_pem = ca.cert_pem.clone();
    vaultproxy::proxy::transparent::spawn_listener_with_ca(bound_addr, state.clone(), ca)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

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
        .method(Method::POST)
        .uri("https://127.0.0.1/Service/Method")
        .header("content-type", "application/grpc")
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
    assert_eq!(body, b"grpc-body");
    let trailers = body_stream
        .trailers()
        .await
        .expect("trailers result")
        .expect("upstream MUST forward trailers end-to-end via the proxy");
    assert_eq!(trailers.get("grpc-status").unwrap(), "0");
    assert_eq!(trailers.get("grpc-message").unwrap(), "OK");

    std::env::remove_var("VP_TRANSPARENT_TEST_FORCE_H2");
}
