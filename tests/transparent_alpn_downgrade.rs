//! Verifies the transparent MITM cert announces ONLY `http/1.1` on ALPN.
//!
//! An h2-capable client that ALPN-negotiates ["h2", "http/1.1"] must end
//! up with "http/1.1" selected (downgrade); a client that asks for ONLY
//! "h2" must fail the handshake (alpn mismatch). Both are safer than
//! letting the agent + proxy end up speaking h2 while the proxy's HTTP/1.1
//! parser silently corrupts the stream.

#![cfg(all(feature = "transparent", feature = "test-utils"))]

use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn alpn_downgrade_to_http1_succeeds() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("alpn-ok"))
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
            name: "test_alpn".into(),
            base_url: upstream_uri.clone(),
            auth: AuthPattern::Bearer {
                vault_item: "alpn-bearer".into(),
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
        .seed_test_password("vault-proxy", "alpn-bearer", "stub")
        .await;
    let state = Arc::new(state_inner);

    let bound = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let bound_addr = bound.local_addr().unwrap();
    drop(bound);
    let ca = Arc::new(vaultproxy::tls::ca::TransparentCa::generate("e2e-alpn").unwrap());
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

    // Build a rustls client that offers BOTH h2 and http/1.1. The proxy
    // should pick http/1.1.
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
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));

    // Send CONNECT to the proxy, then drive inner TLS through the same
    // socket so we can inspect ALPN.
    let mut tcp = TcpStream::connect(bound_addr).await.unwrap();
    let connect = format!(
        "CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\r\n"
    );
    tcp.write_all(connect.as_bytes()).await.unwrap();
    // Drain 200 + headers using a small buffer.
    let mut buf = [0u8; 256];
    let mut drained = Vec::new();
    while !drained.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = tokio::io::AsyncReadExt::read(&mut tcp, &mut buf)
            .await
            .unwrap();
        if n == 0 {
            break;
        }
        drained.extend_from_slice(&buf[..n]);
    }
    let head = String::from_utf8_lossy(&drained);
    assert!(head.starts_with("HTTP/1.1 200"), "CONNECT failed: {head:?}");

    let name = rustls::pki_types::ServerName::try_from("127.0.0.1".to_string()).unwrap();
    let tls = connector.connect(name, tcp).await.expect("inner TLS");
    let (_io, session) = tls.get_ref();
    let selected = session.alpn_protocol();
    assert_eq!(
        selected,
        Some(b"http/1.1" as &[u8]),
        "expected ALPN downgrade to http/1.1, got {selected:?}"
    );

    std::env::remove_var("VP_TRANSPARENT_TEST_HTTP");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn alpn_h2_only_rejected() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
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
            name: "test_alpn_h2".into(),
            base_url: upstream_uri.clone(),
            auth: AuthPattern::Bearer {
                vault_item: "alpn-h2-bearer".into(),
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
        .seed_test_password("vault-proxy", "alpn-h2-bearer", "stub")
        .await;
    let state = Arc::new(state_inner);

    let bound = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let bound_addr = bound.local_addr().unwrap();
    drop(bound);
    let ca = Arc::new(vaultproxy::tls::ca::TransparentCa::generate("e2e-alpn-h2").unwrap());
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

    let mut tcp = TcpStream::connect(bound_addr).await.unwrap();
    let connect = format!(
        "CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\r\n"
    );
    tcp.write_all(connect.as_bytes()).await.unwrap();
    let mut buf = [0u8; 256];
    let mut drained = Vec::new();
    while !drained.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = tokio::io::AsyncReadExt::read(&mut tcp, &mut buf)
            .await
            .unwrap();
        if n == 0 {
            break;
        }
        drained.extend_from_slice(&buf[..n]);
    }

    let name = rustls::pki_types::ServerName::try_from("127.0.0.1".to_string()).unwrap();
    let outcome = connector.connect(name, tcp).await;
    assert!(
        outcome.is_err(),
        "expected ALPN mismatch error when client demands h2 only; got Ok",
    );

    std::env::remove_var("VP_TRANSPARENT_TEST_HTTP");
}
