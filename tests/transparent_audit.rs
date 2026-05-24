//! E2E: transparent host_inject emits an audit log entry with
//! trigger="transparent", correct transparent_mode/host/status/bytes/
//! duration, and never echoes credential values.

#![cfg(all(feature = "transparent", feature = "test-utils"))]

use std::sync::Arc;
use std::time::Duration;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn host_inject_emits_audit_entry() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/audit-probe"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;

    let upstream_uri = server.uri();
    std::env::set_var("VP_TRANSPARENT_TEST_HTTP", "1");

    // Point the audit log at a fresh tempfile per test run.
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let audit_path = tmp.path().to_path_buf();

    let mut state_inner = vaultproxy::test_support::stub_app_state().await;
    state_inner.audit_log = Arc::new(vaultproxy::security::audit_log::AuditLog::new(
        audit_path.to_str().unwrap(),
    ));
    {
        use vaultproxy::proxy::registry::{
            AuthPattern, ServiceEntry, ServiceRegistry, TransparentMode,
        };
        let mut reg = ServiceRegistry::new();
        reg.register(ServiceEntry {
            name: "test_upstream".into(),
            base_url: upstream_uri.clone(),
            auth: AuthPattern::Bearer {
                vault_item: "audit-bearer".into(),
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
        .seed_test_password("vault-proxy", "audit-bearer", "supersecret-vault-value")
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
    let url = format!("https://127.0.0.1:{upstream_port}/audit-probe");
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 200);

    // Force the audit log to flush so the assertions can read it.
    state.audit_log.save();

    let entries = state.audit_log.entries();
    let tx = entries
        .iter()
        .find(|e| e.trigger == "transparent")
        .expect("expected at least one transparent audit entry");

    assert_eq!(tx.transparent_mode.as_deref(), Some("host_inject"));
    assert_eq!(tx.upstream_host.as_deref(), Some("127.0.0.1"));
    assert_eq!(tx.upstream_status, Some(200));
    assert!(tx.bytes_in.unwrap_or(0) > 0);
    assert!(tx.bytes_out.is_some());
    assert!(tx.duration_ms.is_some());

    // The credential value must NEVER appear in any audit field.
    for entry in &entries {
        for field in [&entry.tool_name, &entry.args_summary, &entry.result_summary] {
            assert!(
                !field.contains("supersecret-vault-value"),
                "credential leaked into audit field: {field}"
            );
        }
    }

    std::env::remove_var("VP_TRANSPARENT_TEST_HTTP");
}
