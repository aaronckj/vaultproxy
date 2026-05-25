//! E2E: transparent host_inject for AuthPattern::OAuthClientCredentials.
//!
//! - wiremock #1 (token endpoint) asserts the client_credentials grant body
//!   carries `client_id` + `client_secret` from the vault stub and returns
//!   `{access_token, expires_in}`.
//! - wiremock #2 (upstream API) asserts the inbound request carries
//!   `Authorization: Bearer <issued-token>`.
//! - vault-proxy transparent listener brokers the agent's HTTPS_PROXY
//!   request, signs a leaf cert for the upstream host, calls the token
//!   endpoint to mint a fresh access token, attaches it as Bearer, forwards
//!   to upstream.

#![cfg(all(feature = "transparent", feature = "test-utils"))]

use std::sync::Arc;
use std::time::Duration;
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_inject_oauth_client_credentials_mints_and_forwards_token() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    // 1. Token endpoint: expects client_credentials grant + creds; returns
    //    a short-lived access token.
    let token_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(body_string_contains("grant_type=client_credentials"))
        .and(body_string_contains("client_id=test-client-id"))
        .and(body_string_contains("client_secret=test-client-secret"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "issued-oauth-token",
            "token_type": "Bearer",
            "expires_in": 3600,
        })))
        .mount(&token_server)
        .await;
    let token_url = format!("{}/oauth/token", token_server.uri());

    // 2. Upstream API: requires the Bearer issued by the token endpoint.
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me"))
        .and(header("Authorization", "Bearer issued-oauth-token"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&upstream)
        .await;
    let upstream_uri = upstream.uri();
    std::env::set_var("VP_TRANSPARENT_TEST_HTTP", "1");

    // 3. Stub AppState with the OAuth service registered.
    let state_inner = vaultproxy::test_support::stub_app_state().await;
    {
        use vaultproxy::proxy::registry::{
            AuthPattern, ServiceEntry, ServiceRegistry, TransparentMode,
        };
        let mut reg = ServiceRegistry::new();
        reg.register(ServiceEntry {
            name: "test_oauth".into(),
            base_url: upstream_uri.clone(),
            auth: AuthPattern::OAuthClientCredentials {
                vault_item: "test-oauth".into(),
                token_url: token_url.clone(),
                client_id_field: "username".into(),
                client_secret_field: "password".into(),
                scope: String::new(),
            },
            insecure_tls: false,
            ca_cert_path: None,
            timeout_secs: None,
            transparent_mode: TransparentMode::HostInject,
        });
        *state_inner.registry.write().await = reg;
    }
    // Seed the vault stub: get_or_refresh_oauth_token short-circuits via
    // test_item_password for `<item>:client_id` and `<item>:client_secret`.
    state_inner
        .vault
        .seed_test_password("vault-proxy", "test-oauth:client_id", "test-client-id")
        .await;
    state_inner
        .vault
        .seed_test_password(
            "vault-proxy",
            "test-oauth:client_secret",
            "test-client-secret",
        )
        .await;
    let state = Arc::new(state_inner);

    // 4. Spawn transparent listener on an ephemeral port.
    let listener_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let bound = std::net::TcpListener::bind(listener_addr).unwrap();
    let bound_addr = bound.local_addr().unwrap();
    drop(bound);

    let ca = Arc::new(vaultproxy::tls::ca::TransparentCa::generate("e2e-oauth").unwrap());
    let ca_pem = ca.cert_pem.clone();
    vaultproxy::proxy::transparent::spawn_listener_with_ca(bound_addr, state.clone(), ca)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 5. reqwest client through the transparent proxy, trusting our CA.
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
    let url = format!("https://127.0.0.1:{upstream_port}/me");
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "ok");

    // Second call hits the same upstream — token should be cached (no new
    // hit on the token endpoint). wiremock's default `Mock::given` does not
    // assert call counts, but if the cache were broken the call would still
    // succeed via a refresh, so this primarily exercises the cache path.
    let resp2 = client.get(&url).send().await.unwrap();
    assert_eq!(resp2.status(), 200);

    std::env::remove_var("VP_TRANSPARENT_TEST_HTTP");
}
