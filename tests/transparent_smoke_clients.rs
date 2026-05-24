//! E2E smoke for the transparent listener using real client tooling:
//! curl, python3 (urllib), node (https). Each test:
//!   - spins up a wiremock HTTP upstream
//!   - spins up the transparent listener with the upstream registered
//!     in host_inject mode
//!   - writes the proxy's CA cert to a tempfile
//!   - shells out to the language tooling with HTTPS_PROXY + per-tool
//!     CA trust env var pointed at the proxy
//!   - asserts the upstream observed the vault-injected Authorization
//!     header and the client got 200
//!
//! These tests are valuable because they catch CA-trust-store
//! integration bugs that the reqwest-based E2Es cannot — every
//! language reads CA bundles slightly differently.

#![cfg(all(feature = "transparent", feature = "test-utils"))]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

struct Harness {
    bound_addr: std::net::SocketAddr,
    upstream_port: String,
    ca_path: PathBuf,
}

async fn spin_up() -> Harness {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/probe"))
        .and(header("Authorization", "Bearer smoke-token"))
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
            name: "smoke".into(),
            base_url: upstream_uri.clone(),
            auth: AuthPattern::Bearer {
                vault_item: "smoke".into(),
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
        .seed_test_password("vault-proxy", "smoke", "smoke-token")
        .await;
    let state = Arc::new(state_inner);

    let listener_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let bound = std::net::TcpListener::bind(listener_addr).unwrap();
    let bound_addr = bound.local_addr().unwrap();
    drop(bound);

    let ca = Arc::new(vaultproxy::tls::ca::TransparentCa::generate("smoke").unwrap());
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
        .to_string();

    // Persist the CA to a tempfile so the shelled-out clients can
    // load it. Leak the NamedTempFile to keep it alive past the
    // function return — the tests are short-lived processes.
    let tmp = tempfile::Builder::new().suffix(".crt").tempfile().unwrap();
    std::fs::write(tmp.path(), ca_pem.as_bytes()).unwrap();
    let ca_path = tmp.path().to_path_buf();
    std::mem::forget(tmp);

    Harness {
        bound_addr,
        upstream_port,
        ca_path,
    }
}

fn curl_available() -> bool {
    std::process::Command::new("curl")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn python3_available() -> bool {
    std::process::Command::new("python3")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn node_available() -> bool {
    std::process::Command::new("node")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smoke_curl() {
    if !curl_available() {
        eprintln!("curl not available; skipping");
        return;
    }
    let h = spin_up().await;
    let url = format!("https://127.0.0.1:{}/probe", h.upstream_port);
    let out = std::process::Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--cacert",
            h.ca_path.to_str().unwrap(),
            "--proxy",
            &format!("http://{}", h.bound_addr),
            "--write-out",
            "%{http_code}",
            "--output",
            "/dev/null",
            &url,
        ])
        .output()
        .expect("run curl");
    let code = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(code, "200", "curl exit={:?} stderr={}", out.status, stderr);
    std::env::remove_var("VP_TRANSPARENT_TEST_HTTP");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smoke_python_urllib() {
    if !python3_available() {
        eprintln!("python3 not available; skipping");
        return;
    }
    let h = spin_up().await;
    let url = format!("https://127.0.0.1:{}/probe", h.upstream_port);
    // Use the proxy via stdlib. Inject our CA bundle through ssl
    // context. Print body + status; test parses stdout.
    let script = r#"
import os, ssl, urllib.request
ctx = ssl.create_default_context(cafile=__CA__)
proxy = urllib.request.ProxyHandler({"https": "http://__ADDR__"})
opener = urllib.request.build_opener(
    proxy,
    urllib.request.HTTPSHandler(context=ctx),
)
with opener.open(__URL__) as r:
    print(r.status, r.read().decode())
"#
    .replace("__CA__", &format!("{:?}", h.ca_path.to_str().unwrap()))
    .replace("__ADDR__", &h.bound_addr.to_string())
    .replace("__URL__", &format!("{:?}", url));
    let out = std::process::Command::new("python3")
        .args(["-c", &script])
        .output()
        .expect("run python3");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && stdout.starts_with("200"),
        "python exit={:?} stdout={} stderr={}",
        out.status,
        stdout,
        stderr
    );
    std::env::remove_var("VP_TRANSPARENT_TEST_HTTP");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smoke_node_https() {
    if !node_available() {
        eprintln!("node not available; skipping");
        return;
    }
    let h = spin_up().await;
    let url = format!("https://127.0.0.1:{}/probe", h.upstream_port);
    // Node's `https` module doesn't honour HTTPS_PROXY natively, so
    // build a CONNECT tunnel by hand: open TCP to our proxy, send
    // CONNECT, then upgrade the socket to TLS using our CA.
    let script = r#"
const fs = require('fs');
const net = require('net');
const tls = require('tls');
const ca = fs.readFileSync(__CA__);

const sock = net.connect(__PORT__, "127.0.0.1", () => {
    sock.write("CONNECT 127.0.0.1:__UPS__ HTTP/1.1\r\nHost: 127.0.0.1:__UPS__\r\n\r\n");
});
let buf = "";
sock.on("data", (chunk) => {
    buf += chunk.toString();
    if (buf.includes("\r\n\r\n")) {
        const head = buf.split("\r\n\r\n", 1)[0];
        if (!head.startsWith("HTTP/1.1 200")) {
            console.error("proxy did not return 200: " + head);
            process.exit(1);
        }
        sock.removeAllListeners("data");
        const tlsSock = tls.connect({
            socket: sock,
            ca: [ca],
            servername: "127.0.0.1",
        }, () => {
            tlsSock.write("GET /probe HTTP/1.1\r\nHost: 127.0.0.1:__UPS__\r\nConnection: close\r\n\r\n");
        });
        let resp = "";
        tlsSock.on("data", (c) => resp += c.toString());
        tlsSock.on("end", () => {
            const status = resp.split(" ", 2)[1];
            console.log(status);
            process.exit(0);
        });
        tlsSock.on("error", (e) => { console.error("tls err " + e); process.exit(1); });
    }
});
sock.on("error", (e) => { console.error("tcp err " + e); process.exit(1); });
setTimeout(() => { console.error("timeout"); process.exit(1); }, 8000);
"#
    .replace("__CA__", &format!("{:?}", h.ca_path.to_str().unwrap()))
    .replace("__PORT__", &h.bound_addr.port().to_string())
    .replace("__UPS__", &h.upstream_port);
    let _ = url; // The script hard-codes /probe; we only need port + CA.
    let out = std::process::Command::new("node")
        .args(["-e", &script])
        .output()
        .expect("run node");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && stdout.trim() == "200",
        "node exit={:?} stdout={} stderr={}",
        out.status,
        stdout,
        stderr
    );
    std::env::remove_var("VP_TRANSPARENT_TEST_HTTP");
}
