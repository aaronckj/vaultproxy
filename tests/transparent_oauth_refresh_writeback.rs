//! E2E: OAuth refresh-token writeback path.
//!
//! Wiremock IdP rotates the refresh_token on every grant. With
//! writeback enabled, the proxy must:
//!   * mirror the new RT into the test-stub vault map
//!   * use the new RT on the next refresh (forced via force_refresh)
//!
//! Negative leg: a SECOND service with writeback=false sees the same
//! rotated RT but the stub map is NOT updated.

#![cfg(all(feature = "transparent", feature = "test-utils"))]

use std::sync::Arc;
use std::time::Duration;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn writeback_persists_rotated_refresh_token() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let token_server = MockServer::start().await;
    // First-grant response (original RT).
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(body_string_contains("refresh_token=long-lived-rt"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "access-1",
            "token_type": "Bearer",
            "expires_in": 1, // short TTL so force_refresh isn't required
            "refresh_token": "rotated-rt-1",
        })))
        .mount(&token_server)
        .await;
    // Second-grant response (after RT rotation; new RT echoes).
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(body_string_contains("refresh_token=rotated-rt-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "access-2",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "rotated-rt-1",
        })))
        .mount(&token_server)
        .await;
    let token_url = format!("{}/oauth/token", token_server.uri());

    let state_inner = vaultproxy::test_support::stub_app_state().await;
    let state = Arc::new(state_inner);
    state
        .vault
        .seed_test_password("vault-proxy", "rt-writeback:client_id", "app-client-id")
        .await;
    state
        .vault
        .seed_test_password("vault-proxy", "rt-writeback:refresh_token", "long-lived-rt")
        .await;

    // First refresh — IdP returns rotated RT; writeback mirrors it.
    let access = vaultproxy::proxy::get_or_refresh_oauth_refresh_token(
        &state,
        "rt-writeback",
        &token_url,
        "username",
        "",
        "password",
        "",
        true, // writeback ON
        false,
    )
    .await
    .expect("first refresh");
    assert_eq!(access, "access-1");

    // Confirm stub map saw the rotated RT.
    let stubbed = state
        .vault
        .test_item_password("vault-proxy", "rt-writeback:refresh_token")
        .expect("stub map must still hold the RT");
    assert_eq!(stubbed, "rotated-rt-1");

    // Sleep past the 1-second TTL so the cache expires and a fresh
    // refresh runs. The second-grant mock requires the rotated RT in
    // the body, so a successful POST proves the rotated RT was used.
    tokio::time::sleep(Duration::from_millis(1100)).await;

    let access = vaultproxy::proxy::get_or_refresh_oauth_refresh_token(
        &state,
        "rt-writeback",
        &token_url,
        "username",
        "",
        "password",
        "",
        true,
        false,
    )
    .await
    .expect("second refresh uses rotated RT");
    assert_eq!(access, "access-2");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn writeback_disabled_logs_but_does_not_persist() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let token_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "access-x",
            "expires_in": 3600,
            "refresh_token": "different-rotated-rt",
        })))
        .mount(&token_server)
        .await;
    let token_url = format!("{}/oauth/token", token_server.uri());

    let state_inner = vaultproxy::test_support::stub_app_state().await;
    let state = Arc::new(state_inner);
    state
        .vault
        .seed_test_password("vault-proxy", "rt-nowriteback:client_id", "id")
        .await;
    state
        .vault
        .seed_test_password("vault-proxy", "rt-nowriteback:refresh_token", "original-rt")
        .await;

    let access = vaultproxy::proxy::get_or_refresh_oauth_refresh_token(
        &state,
        "rt-nowriteback",
        &token_url,
        "username",
        "",
        "password",
        "",
        false, // writeback OFF
        false,
    )
    .await
    .expect("refresh succeeds");
    assert_eq!(access, "access-x");

    // Stub map must still hold the ORIGINAL RT — writeback was off.
    let stubbed = state
        .vault
        .test_item_password("vault-proxy", "rt-nowriteback:refresh_token")
        .expect("stub map");
    assert_eq!(
        stubbed, "original-rt",
        "writeback=false MUST NOT mutate the vault stub",
    );
}
