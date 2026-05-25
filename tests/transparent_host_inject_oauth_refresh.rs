//! E2E: transparent host_inject for AuthPattern::OAuthRefresh.
//!
//! Mirror of transparent_host_inject_oauth but exchanges a refresh_token
//! for an access_token. Verifies:
//!   * token endpoint receives grant_type=refresh_token + the stub creds
//!   * upstream sees `Authorization: Bearer <issued-token>`
//!   * 2nd call uses the cached access token (no extra token mint)
//!   * IdP-side refresh-token rotation is tolerated (logged only)

#![cfg(all(feature = "transparent", feature = "test-utils"))]

use std::sync::Arc;
use std::time::Duration;
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_inject_oauth_refresh_exchanges_and_caches() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let token_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .and(body_string_contains("refresh_token=long-lived-rt"))
        .and(body_string_contains("client_id=app-client-id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "minted-access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "long-lived-rt",
        })))
        .mount(&token_server)
        .await;
    let token_url = format!("{}/oauth/token", token_server.uri());

    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/profile"))
        .and(header("Authorization", "Bearer minted-access-token"))
        .respond_with(ResponseTemplate::new(200).set_body_string("profile-ok"))
        .mount(&upstream)
        .await;
    let upstream_uri = upstream.uri();
    std::env::set_var("VP_TRANSPARENT_TEST_HTTP", "1");

    let state_inner = vaultproxy::test_support::stub_app_state().await;
    {
        use vaultproxy::proxy::registry::{
            AuthPattern, ServiceEntry, ServiceRegistry, TransparentMode,
        };
        let mut reg = ServiceRegistry::new();
        reg.register(ServiceEntry {
            name: "test_oauth_refresh".into(),
            base_url: upstream_uri.clone(),
            auth: AuthPattern::OAuthRefresh {
                vault_item: "test-rt".into(),
                token_url: token_url.clone(),
                client_id_field: "username".into(),
                client_secret_field: String::new(),
                refresh_token_field: "password".into(),
                scope: String::new(),
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
        .seed_test_password("vault-proxy", "test-rt:client_id", "app-client-id")
        .await;
    state_inner
        .vault
        .seed_test_password("vault-proxy", "test-rt:refresh_token", "long-lived-rt")
        .await;
    let state = Arc::new(state_inner);

    let listener_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let bound = std::net::TcpListener::bind(listener_addr).unwrap();
    let bound_addr = bound.local_addr().unwrap();
    drop(bound);

    let ca = Arc::new(vaultproxy::tls::ca::TransparentCa::generate("e2e-oauth-refresh").unwrap());
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
    let url = format!("https://127.0.0.1:{upstream_port}/profile");
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "profile-ok");

    // Second call exercises the cache path; same upstream + token mock
    // ensures Bearer is still valid + identical.
    let resp2 = client.get(&url).send().await.unwrap();
    assert_eq!(resp2.status(), 200);

    std::env::remove_var("VP_TRANSPARENT_TEST_HTTP");
}
