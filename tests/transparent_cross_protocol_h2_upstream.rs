//! E2E: agent speaks HTTP/1.1, upstream speaks h2c (v1.9.0+).
//!
//! Verifies the cross-protocol path:
//!   * Reqwest agent (http/1.1) routes through the transparent listener.
//!   * Proxy negotiates the agent side as http/1.1 (ALPN miss vs h2).
//!   * Proxy tries h2 against the upstream first (VP_TRANSPARENT_TEST_FORCE_H2=1
//!     forces h2c).
//!   * Upstream h2c server sees the vault-injected Bearer + per-h2 framing.
//!   * Proxy re-serialises the h2 response as http/1.1 bytes for the agent.
//!   * Agent reads it back as a normal http/1.1 response.

#![cfg(all(feature = "transparent", feature = "test-utils"))]

use bytes::Bytes;
use http::{Response, StatusCode};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;

type CapturedHeaders = Vec<(String, String)>;
type CapturedRequests = Arc<Mutex<Vec<CapturedHeaders>>>;

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
async fn http1_agent_to_h2_upstream() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let captured = Arc::new(Mutex::new(Vec::new()));
    let upstream_port = spawn_h2c_upstream(captured.clone(), b"cross-proto-ok").await;
    std::env::set_var("VP_TRANSPARENT_TEST_FORCE_H2", "1");

    let state_inner = vaultproxy::test_support::stub_app_state().await;
    {
        use vaultproxy::proxy::registry::{
            AuthPattern, ServiceEntry, ServiceRegistry, TransparentMode,
        };
        let mut reg = ServiceRegistry::new();
        reg.register(ServiceEntry {
            name: "test_cross".into(),
            base_url: format!("http://127.0.0.1:{upstream_port}"),
            auth: AuthPattern::Bearer {
                vault_item: "cross-bearer".into(),
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
        .seed_test_password("vault-proxy", "cross-bearer", "vault-cross-token")
        .await;
    let state = Arc::new(state_inner);

    let bound = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let bound_addr = bound.local_addr().unwrap();
    drop(bound);
    let ca = Arc::new(vaultproxy::tls::ca::TransparentCa::generate("e2e-cross").unwrap());
    let ca_pem = ca.cert_pem.clone();
    vaultproxy::proxy::transparent::spawn_listener_with_ca(bound_addr, state.clone(), ca)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Reqwest agent — vanilla http/1.1 client through HTTPS_PROXY.
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).unwrap())
        .proxy(reqwest::Proxy::all(format!("http://{bound_addr}")).unwrap())
        .http1_only()
        .build()
        .unwrap();

    let url = format!("https://127.0.0.1:{upstream_port}/me");
    let resp = client
        .get(&url)
        .header("authorization", "Bearer attacker")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "cross-proto-ok");

    let cap = captured.lock().unwrap().clone();
    assert!(
        !cap.is_empty(),
        "h2c upstream must have received the request",
    );
    let bearer = cap[0]
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    assert_eq!(
        bearer, "Bearer vault-cross-token",
        "upstream must see the vault-injected bearer, not the agent's smuggled one",
    );

    std::env::remove_var("VP_TRANSPARENT_TEST_FORCE_H2");
}
