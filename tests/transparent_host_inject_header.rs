//! E2E: transparent host_inject for AuthPattern::Header (custom header
//! name, e.g. X-Api-Key). Same shape as the Bearer test but the
//! wiremock matcher asserts the custom header.

#![cfg(all(feature = "transparent", feature = "test-utils"))]

use std::sync::Arc;
use std::time::Duration;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn host_inject_header_replaces_agent_auth() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/items"))
        .and(header("X-Api-Key", "vault-header-token"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
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
            name: "test_upstream".into(),
            base_url: upstream_uri.clone(),
            auth: AuthPattern::Header {
                header_name: "X-Api-Key".into(),
                vault_item: "test-header".into(),
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
        .seed_test_password("vault-proxy", "test-header", "vault-header-token")
        .await;
    let state = Arc::new(state_inner);

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

    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .proxy(reqwest::Proxy::all(format!("http://{bound_addr}")).unwrap())
        .build()
        .unwrap();

    let upstream_port = upstream_uri
        .rsplit(':')
        .next()
        .unwrap()
        .trim_end_matches('/');
    let url = format!("https://127.0.0.1:{upstream_port}/items");
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "ok");

    std::env::remove_var("VP_TRANSPARENT_TEST_HTTP");
}
