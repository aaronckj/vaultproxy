//! E2E: transparent UDS listener — proves SO_PEERCRED accept + dispatch
//! through handle_connection actually MITMs the agent's traffic instead of
//! just closing.
//!
//! Same shape as transparent_host_inject_bearer but the agent talks to a
//! Unix socket instead of TCP. The proxy CONNECT path is identical; only
//! the agent-side transport differs.

#![cfg(all(
    feature = "transparent",
    feature = "test-utils",
    target_family = "unix"
))]

use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn uds_listener_mitm_round_trip() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me"))
        .and(header("Authorization", "Bearer vault-stub-token"))
        .respond_with(ResponseTemplate::new(200).set_body_string("uds-ok"))
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
            name: "test_uds".into(),
            base_url: upstream_uri.clone(),
            auth: AuthPattern::Bearer {
                vault_item: "uds-bearer".into(),
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
        .seed_test_password("vault-proxy", "uds-bearer", "vault-stub-token")
        .await;
    let state = Arc::new(state_inner);

    let tmpdir = tempfile::tempdir().unwrap();
    let sock_path = tmpdir.path().join("vp-transparent.sock");
    let ca = Arc::new(vaultproxy::tls::ca::TransparentCa::generate("e2e-uds").unwrap());
    let ca_pem = ca.cert_pem.clone();
    vaultproxy::proxy::transparent::uds_listener::spawn_uds_listener(
        sock_path.clone(),
        state.clone(),
        ca,
        vaultproxy::proxy::transparent::UnregisteredPolicy::Passthrough,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Drive the proxy by hand: connect via UDS, send CONNECT, then run a
    // TLS client (rustls) on top of the UDS stream to do GET /me. reqwest
    // can't proxy through a UDS, so we wire it ourselves.
    let upstream_port = upstream_uri
        .rsplit(':')
        .next()
        .unwrap()
        .trim_end_matches('/')
        .parse::<u16>()
        .unwrap();

    let mut uds = UnixStream::connect(&sock_path).await.expect("connect uds");
    let connect = format!(
        "CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\r\n"
    );
    uds.write_all(connect.as_bytes()).await.unwrap();

    let mut reader = BufReader::new(&mut uds);
    let mut status = String::new();
    reader.read_line(&mut status).await.unwrap();
    assert!(
        status.starts_with("HTTP/1.1 200"),
        "expected 200 from CONNECT, got: {status:?}"
    );
    // Drain header block.
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        if line == "\r\n" || line.is_empty() {
            break;
        }
    }

    // Now run TLS over the same UDS stream, trusting the proxy CA.
    let mut root_store = rustls::RootCertStore::empty();
    let cert = rustls_pemfile::certs(&mut ca_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    for c in cert {
        root_store.add(c).unwrap();
    }
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
    let server_name = rustls::pki_types::ServerName::try_from("127.0.0.1".to_string()).unwrap();
    let mut tls = connector.connect(server_name, uds).await.expect("tls");

    let req = b"GET /me HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer attacker\r\nConnection: close\r\n\r\n";
    tls.write_all(req).await.unwrap();
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await.unwrap();
    let response_str = String::from_utf8_lossy(&response);
    assert!(
        response_str.contains("200 OK") && response_str.ends_with("uds-ok"),
        "expected 200 + uds-ok body, got: {response_str:?}"
    );

    std::env::remove_var("VP_TRANSPARENT_TEST_HTTP");
}
