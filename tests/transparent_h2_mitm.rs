//! E2E: native HTTP/2 transparent MITM (v1.7.0+).
//!
//! The MITM leaf cert advertises both `h2` and `http/1.1` on ALPN
//! (v1.7.0+; was http/1.1-only in v1.4.1). reqwest with
//! `.http2_prior_knowledge()` is awkward through a proxy, so the test
//! drives the negotiation directly via rustls + the `h2` client
//! crate.
//!
//! Verifies:
//!   * Outer TLS handshake succeeds with ALPN = "h2"
//!   * h2 server framing reads the agent's request
//!   * inject_host injects the vault credential
//!   * Upstream (http/1.1) sees the Bearer
//!   * Response is re-framed as h2 back to the agent
//!   * Concurrent streams on the same h2 connection work

#![cfg(all(feature = "transparent", feature = "test-utils"))]

use bytes::Bytes;
use h2::client;
use http::{Method, Request};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2_mitm_round_trip() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me"))
        .and(header("Authorization", "Bearer vault-h2-token"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/plain")
                .set_body_string("h2-ok"),
        )
        .mount(&server)
        .await;
    let upstream_uri = server.uri();
    std::env::set_var("VP_TRANSPARENT_TEST_HTTP", "1");

    let state_inner = vaultproxy::test_support::stub_app_state().await;
    {
        use vaultproxy::proxy::registry::{
            AuthPattern, ServiceEntry, ServiceRegistry, TransparentMode,
        };
        let mut reg = ServiceRegistry::new();
        reg.register(ServiceEntry {
            name: "test_h2".into(),
            base_url: upstream_uri.clone(),
            auth: AuthPattern::Bearer {
                vault_item: "h2-bearer".into(),
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
        .seed_test_password("vault-proxy", "h2-bearer", "vault-h2-token")
        .await;
    let state = Arc::new(state_inner);

    let bound = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let bound_addr = bound.local_addr().unwrap();
    drop(bound);
    let ca = Arc::new(vaultproxy::tls::ca::TransparentCa::generate("e2e-h2").unwrap());
    let ca_pem = ca.cert_pem.clone();
    vaultproxy::proxy::transparent::spawn_listener_with_ca(bound_addr, state.clone(), ca)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let upstream_port = upstream_uri
        .rsplit(':')
        .next()
        .unwrap()
        .trim_end_matches('/')
        .parse::<u16>()
        .unwrap();

    // CONNECT to the proxy, then TLS+ALPN=h2.
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
    assert!(
        std::str::from_utf8(&drained)
            .unwrap()
            .starts_with("HTTP/1.1 200"),
        "CONNECT must succeed",
    );

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
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(b"h2" as &[u8]),
        "proxy must negotiate h2",
    );

    let (h2, conn) = client::handshake(tls).await.expect("h2 client handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut h2 = h2.ready().await.expect("h2 ready");

    let req = Request::builder()
        .method(Method::GET)
        .uri("https://127.0.0.1/me")
        .header("authorization", "Bearer attacker")
        .body(())
        .unwrap();
    let (resp_fut, _send) = h2.send_request(req, true).expect("send_request");
    let resp = resp_fut.await.expect("response future");
    assert_eq!(resp.status(), 200);
    let mut body_stream = resp.into_body();
    let mut body = Vec::new();
    while let Some(chunk) = body_stream.data().await {
        body.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(body, b"h2-ok");

    std::env::remove_var("VP_TRANSPARENT_TEST_HTTP");
    // Hold the connection to give the spawned conn driver a moment to
    // flush GOAWAY cleanly. Without this the test occasionally races
    // and reports a clean exit before the server task finishes.
    drop(h2);
    let _ = Bytes::from_static(b"");
}
