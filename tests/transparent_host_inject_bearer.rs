//! E2E: transparent host_inject for AuthPattern::Bearer.
//!
//! - wiremock upstream (HTTP, via VP_TRANSPARENT_TEST_HTTP=1) asserts that
//!   the inbound request carried `Authorization: Bearer <stub-token>`.
//! - vault-proxy transparent listener brokers the agent's HTTPS_PROXY
//!   request, signs a leaf cert for the upstream host, decrypts the
//!   plaintext request, strips the agent's Authorization header, injects
//!   the vault credential, forwards to upstream.
//! - reqwest client trusts the vault-proxy CA via add_root_certificate.

#![cfg(all(feature = "transparent", feature = "test-utils"))]

use std::sync::Arc;
use std::time::Duration;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn host_inject_bearer_replaces_agent_auth() {
    // Production main.rs installs rustls's default crypto provider once
    // at startup; integration tests have to do it themselves or rustls
    // returns InvalidContentType on every handshake. Idempotent.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // 1. Upstream wiremock that demands the vault-supplied Bearer.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me"))
        .and(header("Authorization", "Bearer vault-stub-token"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;

    let upstream_uri = server.uri();
    // Tell vault-proxy's transparent forwarder to talk plain HTTP to
    // the upstream so wiremock (which doesn't speak TLS by default) is
    // reachable. Production builds use TLS.
    std::env::set_var("VP_TRANSPARENT_TEST_HTTP", "1");

    // 2. Stub AppState with a registry containing our service. Bypass
    //    from_toml_str (its SSRF guard rejects loopback base_url, which
    //    is exactly what wiremock binds to). Register directly.
    let state_inner = vaultproxy::test_support::stub_app_state().await;
    {
        use vaultproxy::proxy::registry::{
            AuthPattern, ServiceEntry, ServiceRegistry, TransparentMode,
        };
        let mut reg = ServiceRegistry::new();
        reg.register(ServiceEntry {
            name: "test_upstream".into(),
            base_url: upstream_uri.clone(),
            auth: AuthPattern::Bearer {
                vault_item: "test-bearer".into(),
            },
            insecure_tls: false,
            ca_cert_path: None,
            timeout_secs: None,
            transparent_mode: TransparentMode::HostInject,
        });
        *state_inner.registry.write().await = reg;
    }
    // Seed the vault stub with the password the upstream is checking for.
    state_inner
        .vault
        .seed_test_password("vault-proxy", "test-bearer", "vault-stub-token")
        .await;
    let state = Arc::new(state_inner);

    // 3. Spawn transparent listener on ephemeral port.
    let listener_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let bound = std::net::TcpListener::bind(listener_addr).unwrap();
    let bound_addr = bound.local_addr().unwrap();
    drop(bound);

    let ca = Arc::new(vaultproxy::tls::ca::TransparentCa::generate("e2e-test").unwrap());
    let ca_pem = ca.cert_pem.clone();
    vaultproxy::proxy::transparent::spawn_listener_with_ca(bound_addr, state.clone(), ca)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 4. reqwest client through the transparent proxy, trusting our CA.
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .proxy(reqwest::Proxy::all(format!("http://{bound_addr}")).unwrap())
        .build()
        .unwrap();

    // wiremock is on http://127.0.0.1:PORT — but to engage the proxy's
    // CONNECT path (which only fires on HTTPS upstream URLs), tell the
    // reqwest client the URL is https://. The proxy CONNECT lookup
    // matches on host:port, not scheme; the proxy forwards via
    // forward_plaintext (because VP_TRANSPARENT_TEST_HTTP=1) so wiremock
    // sees the request over plain TCP.
    let upstream_port = upstream_uri
        .rsplit(':')
        .next()
        .unwrap()
        .trim_end_matches('/');
    let url = format!("https://127.0.0.1:{upstream_port}/me");
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "ok");

    std::env::remove_var("VP_TRANSPARENT_TEST_HTTP");
}
