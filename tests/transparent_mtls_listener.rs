//! E2E: transparent mTLS listener — proves the outer TLS jacket requires
//! a valid client cert AND, once authenticated, MITMs the same way the
//! plain TCP listener does.
//!
//! Generates an in-memory mTLS chain (CA + server leaf + client leaf) with
//! rcgen, hand-rolls a rustls client that does TLS+mTLS to the proxy, then
//! sends CONNECT + inner TLS handshake against the wiremock upstream and
//! confirms the Bearer credential was injected from the vault stub.

#![cfg(all(feature = "transparent", feature = "test-utils"))]

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Issue (CA, server leaf, client leaf) — all sharing the same CA.
struct MtlsChain {
    ca_cert_pem: String,
    server_cert_chain_pem: String,
    server_key_pem: String,
    client_cert_chain_pem: String,
    client_key_pem: String,
}

fn issue_mtls_chain() -> MtlsChain {
    use rcgen::{
        CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    };

    let mut ca_params = CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "vp-mtls-test-ca");
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let mut server_params =
        CertificateParams::new(vec!["127.0.0.1".to_string(), "localhost".to_string()]).unwrap();
    server_params
        .distinguished_name
        .push(DnType::CommonName, "vp-mtls-server");
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_key = KeyPair::generate().unwrap();
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .unwrap();

    let mut client_params = CertificateParams::new(vec![]).unwrap();
    client_params
        .distinguished_name
        .push(DnType::CommonName, "vp-mtls-client");
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_key = KeyPair::generate().unwrap();
    let client_cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .unwrap();

    MtlsChain {
        ca_cert_pem: ca_cert.pem(),
        server_cert_chain_pem: format!("{}{}", server_cert.pem(), ca_cert.pem()),
        server_key_pem: server_key.serialize_pem(),
        client_cert_chain_pem: format!("{}{}", client_cert.pem(), ca_cert.pem()),
        client_key_pem: client_key.serialize_pem(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mtls_listener_requires_client_cert_then_mitm() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me"))
        .and(header("Authorization", "Bearer vault-stub-token"))
        .respond_with(ResponseTemplate::new(200).set_body_string("mtls-ok"))
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
            name: "test_mtls".into(),
            base_url: upstream_uri.clone(),
            auth: AuthPattern::Bearer {
                vault_item: "mtls-bearer".into(),
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
        .seed_test_password("vault-proxy", "mtls-bearer", "vault-stub-token")
        .await;
    let state = Arc::new(state_inner);

    let chain = issue_mtls_chain();
    let mitm_ca = Arc::new(vaultproxy::tls::ca::TransparentCa::generate("e2e-mtls-mitm").unwrap());
    let mitm_ca_pem = mitm_ca.cert_pem.clone();
    let mtls = vaultproxy::proxy::transparent::mtls_listener::MtlsMaterial {
        server_cert_pem: chain.server_cert_chain_pem.clone(),
        server_key_pem: chain.server_key_pem.clone(),
        client_ca_pem: chain.ca_cert_pem.clone(),
    };

    let bound = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let bound_addr = bound.local_addr().unwrap();
    drop(bound);

    vaultproxy::proxy::transparent::mtls_listener::spawn_mtls_listener(
        bound_addr,
        state.clone(),
        mitm_ca,
        mtls,
        vaultproxy::proxy::transparent::UnregisteredPolicy::Passthrough,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let upstream_port = upstream_uri
        .rsplit(':')
        .next()
        .unwrap()
        .trim_end_matches('/')
        .parse::<u16>()
        .unwrap();

    // Build the rustls client that does outer mTLS to the proxy.
    let mut outer_roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut chain.ca_cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
    {
        outer_roots.add(c).unwrap();
    }
    let client_certs: Vec<_> = rustls_pemfile::certs(&mut chain.client_cert_chain_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let client_key = rustls_pemfile::pkcs8_private_keys(&mut chain.client_key_pem.as_bytes())
        .next()
        .unwrap()
        .unwrap();
    let outer_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(outer_roots)
        .with_client_auth_cert(
            client_certs,
            rustls::pki_types::PrivateKeyDer::Pkcs8(client_key),
        )
        .unwrap();
    let outer_connector = tokio_rustls::TlsConnector::from(Arc::new(outer_cfg));
    let outer_name = rustls::pki_types::ServerName::try_from("127.0.0.1".to_string()).unwrap();

    let tcp = TcpStream::connect(bound_addr).await.unwrap();
    let mut outer_tls = outer_connector
        .connect(outer_name.clone(), tcp)
        .await
        .expect("outer mTLS handshake");

    let connect = format!(
        "CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\r\n"
    );
    outer_tls.write_all(connect.as_bytes()).await.unwrap();

    let mut reader = BufReader::new(&mut outer_tls);
    let mut status = String::new();
    reader.read_line(&mut status).await.unwrap();
    assert!(
        status.starts_with("HTTP/1.1 200"),
        "expected 200 from CONNECT, got: {status:?}"
    );
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        if line == "\r\n" || line.is_empty() {
            break;
        }
    }

    // Inner TLS to the proxy's MITM leaf (signed by mitm_ca).
    let mut inner_roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut mitm_ca_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
    {
        inner_roots.add(c).unwrap();
    }
    let inner_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(inner_roots)
        .with_no_client_auth();
    let inner_connector = tokio_rustls::TlsConnector::from(Arc::new(inner_cfg));
    let inner_name = rustls::pki_types::ServerName::try_from("127.0.0.1".to_string()).unwrap();
    let mut inner_tls = inner_connector
        .connect(inner_name, outer_tls)
        .await
        .expect("inner TLS handshake (proxy's MITM leaf)");

    let req = b"GET /me HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer attacker\r\nConnection: close\r\n\r\n";
    inner_tls.write_all(req).await.unwrap();
    let mut response = Vec::new();
    inner_tls.read_to_end(&mut response).await.unwrap();
    let response_str = String::from_utf8_lossy(&response);
    assert!(
        response_str.contains("200 OK") && response_str.ends_with("mtls-ok"),
        "expected 200 + mtls-ok body, got: {response_str:?}"
    );

    // Negative check: a client WITHOUT a client cert must be rejected.
    // Some rustls versions complete the TLS handshake successfully and
    // only surface the rejection on the first read/write, so probe by
    // doing a small write+read round-trip.
    let mut neg_roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut chain.ca_cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
    {
        neg_roots.add(c).unwrap();
    }
    let neg_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(neg_roots)
        .with_no_client_auth();
    let neg_connector = tokio_rustls::TlsConnector::from(Arc::new(neg_cfg));
    let neg_tcp = TcpStream::connect(bound_addr).await.unwrap();
    let neg_outcome: anyhow::Result<()> = async {
        let mut neg_tls = neg_connector.connect(outer_name, neg_tcp).await?;
        neg_tls.write_all(b"CONNECT 127.0.0.1:1\r\n\r\n").await?;
        let mut buf = [0u8; 1];
        neg_tls.read_exact(&mut buf).await?;
        Ok(())
    }
    .await;
    assert!(
        neg_outcome.is_err(),
        "transparent mTLS listener MUST reject a client that did not present a client cert; \
         got Ok(()) instead",
    );

    let _ = std::io::stdout().flush();
    std::env::remove_var("VP_TRANSPARENT_TEST_HTTP");
}
