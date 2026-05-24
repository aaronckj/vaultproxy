# Transparent HTTPS_PROXY Mode — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a transparent HTTPS proxy listener on `127.0.0.1:3203` that brokers Vaultwarden-backed credentials for unmodified HTTPS clients, with two injection modes (host-based and placeholder) plus passthrough for unregistered hosts.

**Architecture:** New `src/proxy/transparent/` module owns a raw TCP listener that parses `CONNECT host:port HTTP/1.1`, looks up host in the existing `ServiceRegistry`, then either tunnels (passthrough), MITMs with a freshly signed leaf cert from a self-managed CA, injects vault credentials into the plaintext request, and streams to upstream. Gated behind a new `transparent` Cargo feature flag; default off through all of v1.1.

**Tech Stack:** Rust 1.88, Tokio, rustls + tokio-rustls (already in tree), rcgen (promote from transitive to direct), new `lru` crate (~3KB), serde, anyhow, tracing. Tests use wiremock + rustls test certs.

**Spec:** `docs/superpowers/specs/2026-05-24-transparent-https-proxy-design.md` (commits `6132bf2` + `4daa5da`). Refer to it for decisions, threat model, and rationale.

---

## Phase 0 — Prerequisites (≈2 days)

### Task 0.1: Add CI build cache to docker-publish workflow

**Files:**
- Modify: `.github/workflows/docker-publish.yml`

- [ ] **Step 1: Read current workflow**

Read `.github/workflows/docker-publish.yml` to confirm structure. Locate the `Install Rust toolchain` step (around line 49) — the cache step goes immediately after it so toolchain version is part of the cache key.

- [ ] **Step 2: Insert Swatinem/rust-cache after toolchain install**

In `.github/workflows/docker-publish.yml`, after the existing `Install Rust toolchain (version from rust-toolchain.toml)` step, insert:

```yaml
      - name: Rust build cache
        # Caches ~/.cargo registry/cache + target/ keyed on
        # Cargo.lock + toolchain + workflow file hashes. Drops cold-cache
        # CI runs from ~21min (observed on v1.0.4) to ~5min.
        uses: Swatinem/rust-cache@v2
        with:
          shared-key: "transparent-feature-matrix"
          cache-on-failure: true
```

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/docker-publish.yml
git commit -m "ci: cache Rust build artifacts with Swatinem/rust-cache@v2

Cold-cache docker-publish runs took ~21min on v1.0.4 (most of it
re-compiling the same crates from scratch on every tag). Caching
~/.cargo + target/ keyed on Cargo.lock + toolchain drops cached runs
to ~5min. Required before adding the transparent-feature CI matrix
(which would otherwise double cold compile time per push)."
```

- [ ] **Step 4: Verify cache populates on next CI run**

Push to a branch + open a PR (or wait for next tag). The first run after this commit will be cold (~21min) and populate the cache. Subsequent runs hit cache. Check the run's `Rust build cache` step output — should show "Cache hit: false" first run, "Cache hit: true" after.

---

### Task 0.2: Add `transparent` Cargo feature flag

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Add feature declaration**

In `Cargo.toml`, in the `[features]` block, append after the existing `engine = []` entry:

```toml
# Enable the transparent HTTPS_PROXY listener (port 3203 by default).
# When OFF (default through v1.1), the src/proxy/transparent/ module is
# excluded from compilation, no listener binds 3203, no CA cert is
# generated, no new CLI flags appear in `vault-proxy --help`. The binary
# behaves identically to v1.0 for operators who do not opt in.
#
# When ON, vault-proxy ALSO accepts HTTPS_PROXY traffic on 3203 and can
# inject vault credentials into upstream HTTPS requests based on
# services.toml. See docs/operator/TRANSPARENT.md for the operator guide
# and SECURITY.md for the threat model.
#
# Build: cargo build --release --features transparent
# Docker: docker build --build-arg FEATURES=transparent -t vaultproxy:transparent .
transparent = ["dep:rcgen", "dep:lru"]
```

- [ ] **Step 2: Add the optional deps**

In `Cargo.toml`, in `[dependencies]`, add:

```toml
# Used to generate and sign X.509 certificates for the transparent
# HTTPS_PROXY listener (--features transparent). Optional — pulled in
# only when the feature is enabled.
rcgen = { version = "0.13", default-features = false, features = ["pem", "crypto"], optional = true }

# In-memory LRU cache for transparent-mode leaf certs. Optional.
lru = { version = "0.12", optional = true }
```

- [ ] **Step 3: Verify cargo check still passes**

Run:

```bash
cargo check
cargo check --features transparent
```

Expected: both succeed (the feature is declared but the module that uses `rcgen`/`lru` doesn't exist yet; deps compile but are unused).

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "feat(cargo): add 'transparent' feature flag + rcgen/lru deps

Scaffolds the Cargo feature that gates the upcoming
src/proxy/transparent/ module. Default off through all of v1.1 —
operators opt in via --features transparent or
docker build --build-arg FEATURES=transparent.

rcgen and lru are pulled in only when the feature is on (dep:
syntax + optional = true)."
```

---

### Task 0.3: Tag v1.0.6 (baseline before transparent work)

**Files:**
- Modify: `Cargo.toml` (version bump)

- [ ] **Step 1: Bump version**

Edit `Cargo.toml`:

```toml
version = "1.0.6"
```

- [ ] **Step 2: Verify build + tests pass on the baseline**

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --features browser,engine,dashboard -- -D warnings
cargo clippy --all-targets --features transparent -- -D warnings
cargo test --all-targets
cargo test --all-targets --features browser,engine,dashboard
```

Expected: all clean.

- [ ] **Step 3: Commit + tag + push**

```bash
git add Cargo.toml Cargo.lock
git commit -m "chore(release): v1.0.6 — ETXTBSY fix + CI cache + transparent feature scaffold

No new operator-facing behaviour. Tagged as baseline before the v1.1
transparent HTTPS_PROXY implementation work begins."

git tag -a v1.0.6 -m "v1.0.6 baseline before transparent HTTPS_PROXY (B1)"
git push origin main
git push origin v1.0.6
```

- [ ] **Step 4: Verify CI green**

```bash
gh run watch
```

Expected: build-and-push job succeeds, `ghcr.io/aaronckj/vaultproxy:1.0.6` + `:latest` published.

---

## Phase 1 — Scaffolding + passthrough (alpha.1) (≈3 days)

### Task 1.1: Create `src/proxy/transparent/mod.rs` skeleton

**Files:**
- Create: `src/proxy/transparent/mod.rs`
- Modify: `src/proxy/mod.rs` (add `pub mod transparent;` behind feature gate)

- [ ] **Step 1: Write the failing compile-fail check**

We don't have a test yet (the listener is async/network-bound — covered later). For this task the verification is "the module compiles in both feature states." Skip to step 2.

- [ ] **Step 2: Create the skeleton**

Create `src/proxy/transparent/mod.rs`:

```rust
//! Transparent HTTPS_PROXY mode. See docs/superpowers/specs/2026-05-24-transparent-https-proxy-design.md
//!
//! Module is compiled only when the `transparent` Cargo feature is enabled.
//! Operators opt in via `cargo build --features transparent` or
//! `docker build --build-arg FEATURES=transparent`. When off (default
//! through v1.1) the binary has zero new behaviour — no listener, no CA
//! cert, no new CLI flags.

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

use crate::proxy::AppState;

pub mod connect;
pub mod passthrough;

/// Spawn the transparent listener. Returns immediately; the listener task
/// runs in the background until the runtime shuts down.
///
/// Bind failures are returned to the caller so startup can fail fast with
/// a clear error rather than silently leaving the listener offline.
pub async fn spawn_listener(addr: SocketAddr, state: Arc<AppState>) -> Result<()> {
    let listener = TcpListener::bind(addr).await.map_err(|e| {
        anyhow::anyhow!("transparent listener failed to bind {addr}: {e}")
    })?;

    info!(
        addr = %addr,
        "transparent HTTPS_PROXY listener started — agents set HTTPS_PROXY=http://{addr}"
    );

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let state = state.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, peer, state).await {
                            warn!(
                                peer = %peer,
                                error = %e,
                                "transparent connection ended with error",
                            );
                        }
                    });
                }
                Err(e) => {
                    error!(error = %e, "transparent listener accept failed");
                }
            }
        }
    });

    Ok(())
}

async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    _state: Arc<AppState>,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    // Phase 1 stub: read the CONNECT line, then reject everything with 501.
    // Real dispatch (passthrough vs MITM) lands in Task 1.3 / Phase 2.
    let target = connect::read_connect_line(&mut stream).await?;
    info!(peer = %peer, target = %target, "transparent CONNECT received");

    stream
        .write_all(b"HTTP/1.1 501 Not Implemented\r\nContent-Type: application/json\r\n\r\n{\"ok\":false,\"error\":\"transparent listener stub — Phase 1\",\"transparent_error_code\":\"not_implemented\"}\n")
        .await?;
    Ok(())
}
```

- [ ] **Step 3: Gate the module in `src/proxy/mod.rs`**

Open `src/proxy/mod.rs`. Near the top with the other `mod` declarations, add:

```rust
#[cfg(feature = "transparent")]
pub mod transparent;
```

- [ ] **Step 4: Verify both feature states compile**

```bash
cargo check
cargo check --features transparent
```

Expected: both succeed. `cargo check` (default features) does NOT compile the transparent module.

- [ ] **Step 5: Commit**

```bash
git add src/proxy/transparent/mod.rs src/proxy/mod.rs
git commit -m "scaffold(transparent): listener entry point + connection handler stub

Phase 1.1 of the B1 transparent HTTPS_PROXY plan. Stub handler reads
the CONNECT line and replies 501 — real dispatch lands in Task 1.3
(passthrough) and Phase 2 (MITM).

Gated behind cfg(feature = \"transparent\")."
```

---

### Task 1.2: Implement CONNECT line parser

**Files:**
- Create: `src/proxy/transparent/connect.rs`
- Test: same file (`#[cfg(test)] mod tests`)

- [ ] **Step 1: Write the failing tests**

Create `src/proxy/transparent/connect.rs`:

```rust
//! Parse a single HTTP/1.1 `CONNECT host:port HTTP/1.1` line.
//!
//! This is intentionally narrow — only enough HTTP/1 to support the
//! CONNECT verb used by HTTPS_PROXY clients. Any other method, version,
//! or malformed input is rejected with a descriptive error so the caller
//! can return an HTTP 400 to the agent.

use anyhow::{bail, Context, Result};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, BufReader};
use tokio::time::timeout;

/// Resolved target of a CONNECT request: `host:port` after validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectTarget {
    pub host: String,
    pub port: u16,
}

impl std::fmt::Display for ConnectTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Bracket IPv6 literals.
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// Read and parse a `CONNECT host:port HTTP/1.1\r\n…\r\n\r\n` request
/// from the stream, including all subsequent request headers until the
/// blank line. Headers are read but ignored. Times out after 5 seconds
/// (slowloris guard).
///
/// Returns the parsed target. Errors describe what was malformed so the
/// caller can surface them in the 400 response body.
pub async fn read_connect_line<S: AsyncRead + Unpin>(stream: &mut S) -> Result<ConnectTarget> {
    let read = async {
        let mut reader = BufReader::new(stream);
        let mut request_line = String::new();
        let n = reader
            .read_line(&mut request_line)
            .await
            .context("read CONNECT request line")?;
        if n == 0 {
            bail!("client closed before sending request line");
        }
        if !request_line.ends_with("\r\n") {
            bail!("request line did not terminate with CRLF");
        }
        if request_line.len() > 8192 {
            bail!("request line exceeds 8192 bytes");
        }

        // Drain header block (up to blank line). Cap total to prevent
        // memory exhaustion via giant header sets.
        let mut header_bytes = 0usize;
        loop {
            let mut hdr = String::new();
            let n = reader
                .read_line(&mut hdr)
                .await
                .context("read header line")?;
            if n == 0 {
                bail!("client closed mid-headers");
            }
            header_bytes += n;
            if header_bytes > 32 * 1024 {
                bail!("CONNECT headers exceed 32 KiB");
            }
            if hdr == "\r\n" {
                break;
            }
        }

        parse_request_line(request_line.trim_end_matches("\r\n"))
    };

    timeout(Duration::from_secs(5), read)
        .await
        .map_err(|_| anyhow::anyhow!("CONNECT line read timed out after 5s"))?
}

fn parse_request_line(line: &str) -> Result<ConnectTarget> {
    let mut parts = line.splitn(3, ' ');
    let method = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("empty request line"))?;
    let target = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing request target"))?;
    let version = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing HTTP version"))?;

    if method != "CONNECT" {
        bail!("only CONNECT supported; got '{}'", method);
    }
    if version != "HTTP/1.1" {
        bail!("only HTTP/1.1 supported; got '{}'", version);
    }
    parse_host_port(target)
}

fn parse_host_port(s: &str) -> Result<ConnectTarget> {
    // IPv6: [::1]:443
    if let Some(rest) = s.strip_prefix('[') {
        let (ip, port_part) = rest
            .rsplit_once("]:")
            .ok_or_else(|| anyhow::anyhow!("malformed IPv6 target: {}", s))?;
        let port: u16 = port_part
            .parse()
            .with_context(|| format!("invalid port: {}", port_part))?;
        if port == 0 {
            bail!("port must be > 0");
        }
        return Ok(ConnectTarget {
            host: ip.to_string(),
            port,
        });
    }
    // Hostname or IPv4: example.com:443
    let (host, port_part) = s
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("CONNECT target missing port: {}", s))?;
    if host.is_empty() {
        bail!("CONNECT target has empty host");
    }
    let port: u16 = port_part
        .parse()
        .with_context(|| format!("invalid port: {}", port_part))?;
    if port == 0 {
        bail!("port must be > 0");
    }
    Ok(ConnectTarget {
        host: host.to_string(),
        port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    async fn feed(input: &[u8]) -> Result<ConnectTarget> {
        let (mut client, mut server) = tokio::io::duplex(8192);
        client.write_all(input).await.unwrap();
        drop(client);
        read_connect_line(&mut server).await
    }

    #[tokio::test]
    async fn parses_basic_connect() {
        let r = feed(b"CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n").await.unwrap();
        assert_eq!(r.host, "api.github.com");
        assert_eq!(r.port, 443);
    }

    #[tokio::test]
    async fn parses_ipv6_target() {
        let r = feed(b"CONNECT [2001:db8::1]:8443 HTTP/1.1\r\n\r\n").await.unwrap();
        assert_eq!(r.host, "2001:db8::1");
        assert_eq!(r.port, 8443);
    }

    #[tokio::test]
    async fn rejects_non_connect() {
        let r = feed(b"GET / HTTP/1.1\r\n\r\n").await;
        assert!(r.unwrap_err().to_string().contains("only CONNECT supported"));
    }

    #[tokio::test]
    async fn rejects_http2_prelude() {
        let r = feed(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await;
        assert!(r.unwrap_err().to_string().contains("only CONNECT supported"));
    }

    #[tokio::test]
    async fn rejects_missing_port() {
        let r = feed(b"CONNECT api.github.com HTTP/1.1\r\n\r\n").await;
        assert!(r.unwrap_err().to_string().contains("missing port"));
    }

    #[tokio::test]
    async fn rejects_port_zero() {
        let r = feed(b"CONNECT api.github.com:0 HTTP/1.1\r\n\r\n").await;
        assert!(r.unwrap_err().to_string().contains("port must be > 0"));
    }

    #[tokio::test]
    async fn rejects_oversize_request_line() {
        let mut buf = vec![b'A'; 9000];
        buf.extend_from_slice(b" HTTP/1.1\r\n\r\n");
        let mut prefixed = b"CONNECT ".to_vec();
        prefixed.extend_from_slice(&buf);
        let r = feed(&prefixed).await;
        assert!(r.unwrap_err().to_string().contains("exceeds"));
    }

    #[test]
    fn display_brackets_ipv6() {
        let t = ConnectTarget { host: "::1".into(), port: 443 };
        assert_eq!(t.to_string(), "[::1]:443");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test --features transparent --test-utils connect:: 2>&1 | tail -20
```

Wait — `connect.rs` is inside the lib, so tests run via the lib target. Use:

```bash
cargo test --features transparent --lib transparent::connect 2>&1 | tail -20
```

Expected: tests don't exist yet because the file isn't compiled in if `transparent` is the only feature toggle without the `_state: Arc<AppState>` import resolving — verify the file was created in Task 1.1's location. If the lib build errors, the module isn't wired. Confirm `mod connect;` is in `src/proxy/transparent/mod.rs` (already added in Task 1.1, step 2).

- [ ] **Step 3: Re-run tests; expect all 7 to pass**

```bash
cargo test --features transparent --lib transparent::connect 2>&1 | tail -15
```

Expected: `test result: ok. 7 passed; 0 failed`.

- [ ] **Step 4: Commit**

```bash
git add src/proxy/transparent/connect.rs
git commit -m "feat(transparent): CONNECT request-line parser

Implements src/proxy/transparent/connect.rs::read_connect_line — reads
'CONNECT host:port HTTP/1.1' plus header block, validates, returns
ConnectTarget. Rejects malformed methods, HTTP/2 prelude, missing
port, oversized lines.

5s timeout (slowloris guard) matches existing /proxy convention.
IPv6 literals supported via [host]:port bracket form."
```

---

### Task 1.3: Implement passthrough TCP relay

**Files:**
- Create: `src/proxy/transparent/passthrough.rs`
- Modify: `src/proxy/transparent/mod.rs` (call passthrough from handle_connection)

- [ ] **Step 1: Write the passthrough module**

Create `src/proxy/transparent/passthrough.rs`:

```rust
//! Raw TCP relay between agent and upstream. Used when the registry
//! routes a CONNECT target to passthrough (either unregistered host in
//! default policy, or a service with transparent_mode = "passthrough").
//!
//! No TLS interception. No body inspection. Bytes flow both directions
//! until either side closes.

use anyhow::{Context, Result};
use std::time::{Duration, Instant};
use tokio::io::{AsyncWriteExt, copy_bidirectional};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::info;

use super::connect::ConnectTarget;

/// Open a TCP connection to the upstream and relay bytes both directions
/// until close. Returns when both halves are closed or a timeout fires.
///
/// The 200 Connection-established reply is written BEFORE upstream
/// connect succeeds: HTTPS_PROXY clients require it to begin their TLS
/// handshake, and upstream connect failures land as TLS handshake errors
/// on the agent side (matches every other HTTPS proxy implementation).
pub async fn tunnel(mut agent: TcpStream, target: ConnectTarget) -> Result<()> {
    let start = Instant::now();

    // Connect upstream with 10s budget.
    let upstream = timeout(
        Duration::from_secs(10),
        TcpStream::connect((target.host.as_str(), target.port)),
    )
    .await
    .map_err(|_| anyhow::anyhow!("upstream connect timed out after 10s"))?
    .with_context(|| format!("connect to {}", target))?;

    // Tell the agent the tunnel is open.
    agent
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await
        .context("write 200 to agent")?;

    let mut agent = agent;
    let mut upstream = upstream;
    let (bytes_in, bytes_out) = copy_bidirectional(&mut agent, &mut upstream)
        .await
        .context("bidirectional copy")?;

    info!(
        target = %target,
        bytes_in = bytes_in,
        bytes_out = bytes_out,
        duration_ms = start.elapsed().as_millis() as u64,
        mode = "passthrough",
        "transparent tunnel closed",
    );

    Ok(())
}
```

- [ ] **Step 2: Wire it into handle_connection**

Open `src/proxy/transparent/mod.rs` and replace the contents of `handle_connection`:

```rust
async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    _state: Arc<AppState>,
) -> Result<()> {
    let target = match connect::read_connect_line(&mut stream).await {
        Ok(t) => t,
        Err(e) => {
            return reply_error(&mut stream, 400, "malformed_connect", &e.to_string()).await;
        }
    };
    info!(peer = %peer, target = %target, "transparent CONNECT received");

    // Phase 1: every CONNECT goes to passthrough. Registry-driven
    // dispatch lands in Phase 3 (host_inject) and Phase 5 (placeholder).
    if let Err(e) = passthrough::tunnel(stream, target.clone()).await {
        warn!(target = %target, error = %e, "passthrough tunnel error");
    }
    Ok(())
}

async fn reply_error<S: tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    status: u16,
    code: &str,
    message: &str,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let reason = match status {
        400 => "Bad Request",
        502 => "Bad Gateway",
        504 => "Gateway Timeout",
        _ => "Error",
    };
    let body = serde_json::json!({
        "ok": false,
        "error": message,
        "transparent_error_code": code,
    });
    let body_bytes = serde_json::to_vec(&body)?;
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body_bytes.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&body_bytes).await?;
    Ok(())
}
```

- [ ] **Step 3: Verify it compiles**

```bash
cargo check --features transparent
```

Expected: success.

- [ ] **Step 4: Write integration test using wiremock + raw TCP**

Create `tests/transparent_passthrough.rs`:

```rust
//! End-to-end test for transparent passthrough mode.
//!
//! Starts a local TCP echo server, spawns the transparent listener
//! pointed at a real AppState, drives a raw TCP client through
//! HTTPS_PROXY-style CONNECT semantics, and asserts bytes round-trip
//! unmodified.

#![cfg(feature = "transparent")]

use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Start a TCP echo server on an ephemeral port. Returns the bound port.
async fn spawn_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                while let Ok(n) = sock.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    if sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

#[tokio::test]
async fn passthrough_relays_bytes_unmodified() {
    use vaultproxy::proxy::transparent;

    let upstream_port = spawn_echo().await;

    // Build a minimal AppState — passthrough doesn't use the registry yet.
    let state = Arc::new(vaultproxy::test_support::stub_app_state().await);

    // Bind the transparent listener on an ephemeral port.
    let listener_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let bound = std::net::TcpListener::bind(listener_addr).unwrap();
    let bound_addr = bound.local_addr().unwrap();
    drop(bound); // release; spawn_listener will rebind.
    transparent::spawn_listener(bound_addr, state).await.unwrap();

    // Give the listener a moment to come up.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Connect to the listener as if we were curl with HTTPS_PROXY set.
    let mut client = TcpStream::connect(bound_addr).await.unwrap();
    let connect_line = format!(
        "CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\r\n"
    );
    client.write_all(connect_line.as_bytes()).await.unwrap();

    // Expect 200 Connection established.
    let mut buf = [0u8; 512];
    let n = client.read(&mut buf).await.unwrap();
    let response = std::str::from_utf8(&buf[..n]).unwrap();
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "expected 200 from transparent listener, got: {response}"
    );

    // Now write some bytes, expect them echoed back.
    let payload = b"hello from the agent";
    client.write_all(payload).await.unwrap();
    let mut echo = [0u8; 32];
    let n = client.read(&mut echo).await.unwrap();
    assert_eq!(&echo[..n], payload);
}
```

This requires a helper `vaultproxy::test_support::stub_app_state()`. Add it next.

- [ ] **Step 5: Add the test_support helper**

Modify `src/lib.rs` to gate-add a `test_support` module behind `test-utils`:

```rust
#[cfg(feature = "test-utils")]
pub mod test_support;
```

Create `src/test_support.rs`:

```rust
//! Helpers for integration tests that need to construct vault-proxy
//! internal types without booting the full daemon. Gated behind the
//! `test-utils` Cargo feature; never compiled into the production binary.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use crate::audit::AuditLog;
use crate::notify::Notifier;
use crate::policy::ToolPermissions;
use crate::proxy::registry::ServiceRegistry;
use crate::proxy::unifi_session::UnifiSessionCache;
use crate::proxy::AppState;
use crate::vault::VaultManager;

/// Build a minimal `AppState` for tests that exercise listeners/handlers
/// without hitting a real Vaultwarden. Uses a stub VaultManager.
pub async fn stub_app_state() -> AppState {
    AppState {
        vault: Arc::new(VaultManager::new_stub()),
        registry: Arc::new(tokio::sync::RwLock::new(ServiceRegistry::new())),
        http: reqwest::Client::new(),
        http_permissive: reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap(),
        ca_cert_clients: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        unifi_sessions: Arc::new(UnifiSessionCache::new()),
        session_tokens: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        client_certs: None,
        cloud_sync: None,
        approval_queue: Arc::new(tokio::sync::RwLock::new(VecDeque::new())),
        #[cfg(feature = "browser")]
        browser: None,
        permissions: Arc::new(tokio::sync::RwLock::new(ToolPermissions::load(
            "/nonexistent/tool-permissions.json",
        ))),
        audit_log: Arc::new(AuditLog::new("/tmp/vp-test-transparent.json")),
        access_log: None,
        rotation_hook: None,
        mint_wi_mcp: Arc::new(crate::rotate::strategies::SshDockerMintExecutor::from_env()),
        change_wi_mcp_admin: Arc::new(
            crate::rotate::strategies::SshDockerAdminPasswordChanger::from_env(),
        ),
        notifier: Arc::new(Notifier::disabled()),
        handshake_completed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        vault_folder: "vault-proxy".to_string(),
        last_resync_unix: Arc::new(AtomicU64::new(0)),
        internal_token: Arc::new("test-token".to_string()),
        cached_folder_id: Arc::new(tokio::sync::RwLock::new(None)),
        env_write_root: String::new(),
        config_dir: "/config".to_string(),
        proxy_timeout: 120,
        reload_mutex: Arc::new(tokio::sync::Mutex::new(())),
        audit_mutex: Arc::new(tokio::sync::Mutex::new(())),
        smb: crate::proxy::SmbConfig::default(),
    }
}
```

- [ ] **Step 6: Run integration test**

```bash
cargo test --features transparent,test-utils --test transparent_passthrough 2>&1 | tail -10
```

Expected: `test result: ok. 1 passed`.

- [ ] **Step 7: Commit**

```bash
git add src/proxy/transparent/passthrough.rs \
         src/proxy/transparent/mod.rs \
         src/lib.rs \
         src/test_support.rs \
         tests/transparent_passthrough.rs
git commit -m "feat(transparent): passthrough TCP relay + integration test

Implements src/proxy/transparent/passthrough.rs::tunnel — opens
TCP to upstream, writes 200 Connection established to agent,
copy_bidirectional until close. 10s connect timeout. Audit-loggable
fields (bytes_in/out, duration_ms) already structured in the INFO
log line.

handle_connection now routes every CONNECT to passthrough (Phase 1
behaviour — registry dispatch lands in Phase 3).

Adds src/test_support.rs (gated on test-utils feature) with a
stub_app_state() factory so integration tests don't have to
re-construct AppState fields in every file. Replaces the inline
duplication in tests/mcp_server_read_tools.rs in a follow-up cleanup."
```

---

### Task 1.4: Add `--transparent-listen` CLI flag and wire startup

**Files:**
- Modify: `src/main.rs` (CLI args, startup wiring)

- [ ] **Step 1: Locate the Args struct**

Grep `src/main.rs` for `struct Args` (around the existing `--listen` / `--config-dir` flags).

- [ ] **Step 2: Add the flag**

In `src/main.rs`, inside the `struct Args` (use the existing clap macro style), add:

```rust
    /// Transparent HTTPS_PROXY listen address. Set empty to disable.
    /// Default: 127.0.0.1:3203. Only honoured when built with
    /// --features transparent.
    #[cfg(feature = "transparent")]
    #[arg(long, env = "TRANSPARENT_LISTEN", default_value = "127.0.0.1:3203")]
    transparent_listen: String,
```

- [ ] **Step 3: Wire the spawn into main**

Find the existing block where the primary `axum::serve` for port 3201 is started. After it returns and the AppState `Arc` is constructed, add (still in `main`):

```rust
    #[cfg(feature = "transparent")]
    if !args.transparent_listen.is_empty() {
        let addr: std::net::SocketAddr = args.transparent_listen.parse().map_err(|e| {
            anyhow::anyhow!(
                "--transparent-listen '{}' is not a valid SocketAddr: {}",
                args.transparent_listen,
                e
            )
        })?;
        if !addr.ip().is_loopback() {
            tracing::warn!(
                addr = %addr,
                "SECURITY: --transparent-listen is bound to a NON-LOOPBACK address. \
                 Anyone on this network can use this host as an HTTPS-MITM proxy. \
                 See SECURITY.md before exposing port {}.",
                addr.port(),
            );
        }
        crate::proxy::transparent::spawn_listener(addr, state.clone()).await?;
    }
```

- [ ] **Step 4: Verify both feature states compile**

```bash
cargo check
cargo check --features transparent
```

Expected: both succeed.

- [ ] **Step 5: Smoke test — start the binary**

```bash
cargo run --features transparent -- --check
```

Expected: existing `--check` behaviour (validates services.toml). No listener should bind in check mode.

Then run with a fake config dir to confirm the listener binds (you'll need to Ctrl-C):

```bash
mkdir -p /tmp/vp-smoke/config
echo '[[service]]' > /tmp/vp-smoke/config/services.toml
echo 'name = "dummy"' >> /tmp/vp-smoke/config/services.toml
echo 'base_url = "https://example.com"' >> /tmp/vp-smoke/config/services.toml
echo 'auth = "bearer"' >> /tmp/vp-smoke/config/services.toml
echo 'vault_item = "dummy"' >> /tmp/vp-smoke/config/services.toml
# Start in background — will fail vault unlock but should bind 3203 first.
RUST_LOG=info cargo run --features transparent -- --config-dir /tmp/vp-smoke/config --transparent-listen 127.0.0.1:3299 2>&1 | head -20
```

Expected: a log line containing `transparent HTTPS_PROXY listener started ... 127.0.0.1:3299`.

- [ ] **Step 6: Commit**

```bash
git add src/main.rs
git commit -m "feat(cli): add --transparent-listen flag, spawn listener at startup

Wires the transparent listener into main.rs. Flag defaults to
127.0.0.1:3203. Empty string disables. Non-loopback bind logs a
SECURITY warning consistent with --listen.

Both feature states (transparent on/off) still compile clean."
```

---

### Task 1.5: Tag v1.1.0-alpha.1

**Files:**
- Modify: `Cargo.toml`

- [ ] **Step 1: Bump version**

```toml
version = "1.1.0-alpha.1"
```

- [ ] **Step 2: Full lint + test sweep**

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --features transparent -- -D warnings
cargo clippy --all-targets --features browser,engine,dashboard,transparent -- -D warnings
cargo test --all-targets
cargo test --all-targets --features transparent,test-utils
```

Expected: all clean.

- [ ] **Step 3: Commit, tag, push**

```bash
git add Cargo.toml Cargo.lock
git commit -m "chore(release): v1.1.0-alpha.1 — transparent listener (passthrough only)

First alpha of the transparent HTTPS_PROXY mode. Listener binds
127.0.0.1:3203 when started with --features transparent. Every
CONNECT goes to passthrough; no MITM yet (Phase 2). Audit-loggable
fields already in place.

Feature is OFF by default. Operators opt in via --features
transparent or docker build --build-arg FEATURES=transparent."

git tag -a v1.1.0-alpha.1 -m "transparent HTTPS_PROXY: passthrough-only alpha"
git push origin main
git push origin v1.1.0-alpha.1
```

---

## Phase 2 — TLS CA + leaf factory (≈4 days)

### Task 2.1: Create `src/tls/ca.rs` — CA generation

**Files:**
- Create: `src/tls/ca.rs`
- Modify: `src/tls/mod.rs` (declare new module)

- [ ] **Step 1: Write the failing tests**

Append to `src/tls/ca.rs` (create file):

```rust
//! Self-signed CA cert + key for the transparent HTTPS_PROXY listener.
//! Used to sign per-host leaf certs in `cert_factory.rs`.
//!
//! Threat model: the private key is a Tier-1 secret. A leak lets an
//! attacker MITM any traffic from a host that trusted the CA. Stored
//! 0600 in $CONFIG_DIR/transparent-ca.key. See SECURITY.md.

#![cfg(feature = "transparent")]

use anyhow::{bail, Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// In-memory CA: cert PEM + key, ready to sign leaves.
pub struct TransparentCa {
    pub cert_pem: String,
    pub key_pair: KeyPair,
    pub key_pem: String,
    pub fingerprint_sha256: String,
}

impl TransparentCa {
    /// Generate a fresh self-signed ED25519 CA cert valid for ~10 years.
    pub fn generate(hostname: &str) -> Result<Self> {
        let mut params = CertificateParams::new(Vec::<String>::new())
            .context("init cert params")?;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params
            .distinguished_name
            .push(DnType::CommonName, format!("vault-proxy MITM CA ({hostname})"));
        // 10 years, in seconds.
        params.not_before = time::OffsetDateTime::now_utc();
        params.not_after = params.not_before + time::Duration::days(3650);

        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .context("generate ED25519 keypair")?;
        let cert = params.self_signed(&key_pair).context("self-sign CA cert")?;
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        let fingerprint_sha256 = sha256_colon_hex(cert.der());

        Ok(Self {
            cert_pem,
            key_pair,
            key_pem,
            fingerprint_sha256,
        })
    }

    /// Atomically persist to $CONFIG_DIR/transparent-ca.{crt,key}.
    /// crt is 0644, key is 0600. Parent dir must already exist.
    pub fn persist(&self, config_dir: &Path) -> Result<()> {
        let cert_path = config_dir.join("transparent-ca.crt");
        let key_path = config_dir.join("transparent-ca.key");

        write_atomic(&cert_path, self.cert_pem.as_bytes(), 0o644)
            .with_context(|| format!("write {}", cert_path.display()))?;
        write_atomic(&key_path, self.key_pem.as_bytes(), 0o600)
            .with_context(|| format!("write {}", key_path.display()))?;
        Ok(())
    }

    /// Load both files from $CONFIG_DIR. Errors if cert/key missing,
    /// permissions on key are not 0600, or cert/key mismatch.
    pub fn load(config_dir: &Path) -> Result<Self> {
        let cert_path = config_dir.join("transparent-ca.crt");
        let key_path = config_dir.join("transparent-ca.key");

        let key_meta = fs::metadata(&key_path)
            .with_context(|| format!("stat {}", key_path.display()))?;
        let mode = key_meta.permissions().mode() & 0o777;
        if mode != 0o600 {
            bail!(
                "{} must be mode 0600, found {:o}",
                key_path.display(),
                mode
            );
        }
        let cert_pem = fs::read_to_string(&cert_path)
            .with_context(|| format!("read {}", cert_path.display()))?;
        let key_pem = fs::read_to_string(&key_path)
            .with_context(|| format!("read {}", key_path.display()))?;

        let key_pair = KeyPair::from_pem(&key_pem).context("parse CA key PEM")?;
        let cert_der = pem::parse(&cert_pem)
            .context("parse CA cert PEM")?
            .into_contents();
        let fingerprint_sha256 = sha256_colon_hex(&cert_der);

        Ok(Self {
            cert_pem,
            key_pair,
            key_pem,
            fingerprint_sha256,
        })
    }
}

fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(mode)
            .open(&tmp)
            .with_context(|| format!("open {}", tmp.display()))?;
        std::io::Write::write_all(&mut f, bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("rename {} → {}", tmp.display(), path.display()))?;
    Ok(())
}

fn sha256_colon_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    let hex: Vec<String> = out.iter().map(|b| format!("{:02x}", b)).collect();
    hex.join(":")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn generate_round_trips_through_disk() {
        let td = TempDir::new().unwrap();
        let ca = TransparentCa::generate("host.example").unwrap();
        let fp = ca.fingerprint_sha256.clone();
        ca.persist(td.path()).unwrap();

        let loaded = TransparentCa::load(td.path()).unwrap();
        assert_eq!(loaded.fingerprint_sha256, fp);
        assert!(loaded.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(loaded.key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn load_refuses_world_readable_key() {
        let td = TempDir::new().unwrap();
        let ca = TransparentCa::generate("host.example").unwrap();
        ca.persist(td.path()).unwrap();
        // Tamper with key file perms.
        let key = td.path().join("transparent-ca.key");
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = TransparentCa::load(td.path()).unwrap_err();
        assert!(err.to_string().contains("must be mode 0600"));
    }

    #[test]
    fn fingerprint_is_stable_for_same_cert() {
        let td = TempDir::new().unwrap();
        let ca = TransparentCa::generate("host.example").unwrap();
        let fp = ca.fingerprint_sha256.clone();
        ca.persist(td.path()).unwrap();
        let loaded = TransparentCa::load(td.path()).unwrap();
        assert_eq!(loaded.fingerprint_sha256, fp);
    }
}
```

- [ ] **Step 2: Declare module + add dependency on sha2/pem if missing**

Open `src/tls/mod.rs`. Add at top:

```rust
#[cfg(feature = "transparent")]
pub mod ca;
```

Verify `sha2` and `pem` are already in `Cargo.toml`. If not, add to `[dependencies]`:

```toml
sha2 = "0.10"
pem = "3"
```

Add `tempfile = "3"` to `[dev-dependencies]` if not already present.

- [ ] **Step 3: Run tests**

```bash
cargo test --features transparent --lib tls::ca 2>&1 | tail -10
```

Expected: `test result: ok. 3 passed`.

- [ ] **Step 4: Commit**

```bash
git add src/tls/ca.rs src/tls/mod.rs Cargo.toml Cargo.lock
git commit -m "feat(tls): self-signed CA for transparent HTTPS_PROXY MITM

Implements src/tls/ca.rs::TransparentCa::{generate, persist, load}.
ED25519 keypair, 10-year validity, basicConstraints CA:TRUE pathLen:0,
keyUsage = keyCertSign+cRLSign, extendedKeyUsage = serverAuth.

Persists to \$CONFIG_DIR/transparent-ca.{crt,key} (atomic write).
load() refuses to proceed if the key file is not mode 0600 — refuse
to start rather than silently expanding the attack surface.

SHA-256 colon-hex fingerprint is computed from the cert DER for the
startup banner."
```

---

### Task 2.2: BYO CA validation

**Files:**
- Modify: `src/tls/ca.rs` (add `load_byo`)

- [ ] **Step 1: Write the failing tests**

Append to `src/tls/ca.rs`:

```rust
/// Validate operator-provided CA cert + key paths. Same 0600 enforcement
/// on the key file; additionally verifies the cert is actually a CA
/// (basicConstraints CA:TRUE) and the key matches the cert.
pub fn load_byo(cert_path: &Path, key_path: &Path) -> Result<TransparentCa> {
    let key_meta = fs::metadata(key_path)
        .with_context(|| format!("stat {}", key_path.display()))?;
    let mode = key_meta.permissions().mode() & 0o777;
    if mode != 0o600 {
        bail!(
            "{} must be mode 0600, found {:o}",
            key_path.display(),
            mode
        );
    }
    let cert_pem = fs::read_to_string(cert_path)
        .with_context(|| format!("read {}", cert_path.display()))?;
    let key_pem = fs::read_to_string(key_path)
        .with_context(|| format!("read {}", key_path.display()))?;

    let key_pair = KeyPair::from_pem(&key_pem).context("parse BYO key PEM")?;
    let cert_der = pem::parse(&cert_pem)
        .context("parse BYO cert PEM")?
        .into_contents();
    let (_, parsed) = x509_parser::parse_x509_certificate(&cert_der)
        .map_err(|e| anyhow::anyhow!("parse X.509: {e}"))?;
    if !parsed.tbs_certificate.is_ca() {
        bail!("BYO cert {} is not a CA (basicConstraints CA:TRUE missing)", cert_path.display());
    }
    // Key/cert subject-public-key match check.
    let cert_spki = parsed.tbs_certificate.subject_pki.raw;
    let key_pub_der = key_pair.public_key_der();
    if cert_spki != key_pub_der.as_slice() {
        bail!("BYO cert public key does not match BYO key");
    }
    let fingerprint_sha256 = sha256_colon_hex(&cert_der);
    Ok(TransparentCa {
        cert_pem,
        key_pair,
        key_pem,
        fingerprint_sha256,
    })
}

#[cfg(test)]
mod byo_tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn load_byo_accepts_our_own_generated_ca() {
        let td = TempDir::new().unwrap();
        let ca = TransparentCa::generate("byo.test").unwrap();
        ca.persist(td.path()).unwrap();
        let loaded = load_byo(&td.path().join("transparent-ca.crt"), &td.path().join("transparent-ca.key")).unwrap();
        assert_eq!(loaded.fingerprint_sha256, ca.fingerprint_sha256);
    }

    #[test]
    fn load_byo_refuses_world_readable_key() {
        let td = TempDir::new().unwrap();
        let ca = TransparentCa::generate("byo.test").unwrap();
        ca.persist(td.path()).unwrap();
        let key = td.path().join("transparent-ca.key");
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = load_byo(&td.path().join("transparent-ca.crt"), &key).unwrap_err();
        assert!(err.to_string().contains("must be mode 0600"));
    }
}
```

- [ ] **Step 2: Add `x509-parser` dep**

In `Cargo.toml` under `[dependencies]`:

```toml
x509-parser = { version = "0.16", optional = true }
```

And update the `transparent` feature line:

```toml
transparent = ["dep:rcgen", "dep:lru", "dep:x509-parser"]
```

- [ ] **Step 3: Run tests**

```bash
cargo test --features transparent --lib tls::ca 2>&1 | tail -10
```

Expected: 5 passing tests.

- [ ] **Step 4: Commit**

```bash
git add src/tls/ca.rs Cargo.toml Cargo.lock
git commit -m "feat(tls): BYO CA loader with cert/key match + CA constraint check

Operators with their own PKI (corp CA, mkcert) can supply
--transparent-ca-cert + --transparent-ca-key. Loader enforces 0600
on the key file, basicConstraints CA:TRUE on the cert, and that
the key's public key matches the cert's SubjectPublicKeyInfo."
```

---

### Task 2.3: Startup banner + persist-or-load logic

**Files:**
- Create: `src/proxy/transparent/init.rs`
- Modify: `src/proxy/transparent/mod.rs` (declare init mod, call from spawn_listener)

- [ ] **Step 1: Create init module**

Create `src/proxy/transparent/init.rs`:

```rust
//! One-shot initialiser called before the transparent listener starts.
//! Loads (or generates) the CA, validates BYO if provided, prints the
//! fingerprint banner.

use anyhow::Result;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::tls::ca::{self, TransparentCa};

/// Source of the CA: auto-managed by vault-proxy, or operator BYO.
pub enum CaSource {
    Auto {
        config_dir: PathBuf,
    },
    Byo {
        cert_path: PathBuf,
        key_path: PathBuf,
    },
}

/// Resolve a CA per source. Generates + persists on first run if Auto.
pub fn init(source: &CaSource) -> Result<Arc<TransparentCa>> {
    let ca = match source {
        CaSource::Auto { config_dir } => init_auto(config_dir)?,
        CaSource::Byo { cert_path, key_path } => ca::load_byo(cert_path, key_path)?,
    };
    print_banner(&ca, source);
    Ok(Arc::new(ca))
}

fn init_auto(config_dir: &Path) -> Result<TransparentCa> {
    let cert_path = config_dir.join("transparent-ca.crt");
    let key_path = config_dir.join("transparent-ca.key");
    if cert_path.exists() && key_path.exists() {
        return TransparentCa::load(config_dir);
    }
    let hostname = hostname::get()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|_| "vaultproxy-host".into());
    let ca = TransparentCa::generate(&hostname)?;
    ca.persist(config_dir)?;
    tracing::info!(
        cert = %cert_path.display(),
        key = %key_path.display(),
        "generated new transparent-proxy CA",
    );
    Ok(ca)
}

fn print_banner(ca: &TransparentCa, source: &CaSource) {
    let (kind, path) = match source {
        CaSource::Auto { config_dir } => ("auto-generated", config_dir.join("transparent-ca.crt")),
        CaSource::Byo { cert_path, .. } => ("operator-provided (BYO)", cert_path.clone()),
    };
    eprintln!();
    eprintln!("┌─────────────────────────────────────────────────────────────────────┐");
    eprintln!("│ TRANSPARENT PROXY CA  ({kind})");
    eprintln!("│ SHA-256: {}", ca.fingerprint_sha256);
    eprintln!("│ File:    {}", path.display());
    eprintln!("│");
    eprintln!("│ Install on every agent host that uses HTTPS_PROXY=…3203.");
    eprintln!("│ Setup guide: docs/operator/TRANSPARENT-CA.md");
    eprintln!("└─────────────────────────────────────────────────────────────────────┘");
    eprintln!();
}
```

- [ ] **Step 2: Add `hostname` crate**

```toml
hostname = { version = "0.4", optional = true }
```

Update feature:
```toml
transparent = ["dep:rcgen", "dep:lru", "dep:x509-parser", "dep:hostname"]
```

- [ ] **Step 3: Declare `init` in `src/proxy/transparent/mod.rs`**

Add `pub mod init;` near the existing `pub mod connect;` line.

- [ ] **Step 4: Verify build**

```bash
cargo check --features transparent
```

- [ ] **Step 5: Commit**

```bash
git add src/proxy/transparent/init.rs src/proxy/transparent/mod.rs Cargo.toml Cargo.lock
git commit -m "feat(transparent): CA init module + fingerprint startup banner

Wires generate/load/byo decisions behind a single CaSource enum.
Prints the SHA-256 fingerprint banner to stderr on every successful
init so operators see exactly which CA leaf certs will chain back to."
```

---

### Task 2.4: Wire CA init + CLI flags into main.rs

**Files:**
- Modify: `src/main.rs`

- [ ] **Step 1: Add CLI flags**

In `src/main.rs`, in `struct Args`:

```rust
    /// Path to operator-provided CA cert (PEM). Pairs with
    /// --transparent-ca-key. When set, vault-proxy will NOT auto-generate.
    #[cfg(feature = "transparent")]
    #[arg(long, env = "TRANSPARENT_CA_CERT")]
    transparent_ca_cert: Option<String>,

    /// Path to operator-provided CA key (PEM). Must be mode 0600.
    #[cfg(feature = "transparent")]
    #[arg(long, env = "TRANSPARENT_CA_KEY")]
    transparent_ca_key: Option<String>,
```

- [ ] **Step 2: Resolve source + init CA before spawn**

Replace the transparent listener spawn block from Task 1.4 with:

```rust
    #[cfg(feature = "transparent")]
    if !args.transparent_listen.is_empty() {
        let addr: std::net::SocketAddr = args.transparent_listen.parse().map_err(|e| {
            anyhow::anyhow!(
                "--transparent-listen '{}' is not a valid SocketAddr: {}",
                args.transparent_listen,
                e
            )
        })?;
        if !addr.ip().is_loopback() {
            tracing::warn!(
                addr = %addr,
                "SECURITY: --transparent-listen bound to a NON-LOOPBACK address. \
                 Anyone on this network can use this host as an HTTPS-MITM proxy. \
                 See SECURITY.md before exposing port {}.",
                addr.port(),
            );
        }
        let ca_source = match (args.transparent_ca_cert.as_deref(), args.transparent_ca_key.as_deref()) {
            (Some(c), Some(k)) => crate::proxy::transparent::init::CaSource::Byo {
                cert_path: c.into(),
                key_path: k.into(),
            },
            (None, None) => crate::proxy::transparent::init::CaSource::Auto {
                config_dir: args.config_dir.clone().into(),
            },
            _ => {
                return Err(anyhow::anyhow!(
                    "--transparent-ca-cert and --transparent-ca-key must both be set or both unset"
                ));
            }
        };
        let ca = crate::proxy::transparent::init::init(&ca_source)?;
        crate::proxy::transparent::spawn_listener_with_ca(addr, state.clone(), ca).await?;
    }
```

- [ ] **Step 3: Update spawn_listener signature**

In `src/proxy/transparent/mod.rs`, change:

```rust
pub async fn spawn_listener(addr: SocketAddr, state: Arc<AppState>) -> Result<()> {
```

to:

```rust
pub async fn spawn_listener_with_ca(
    addr: SocketAddr,
    state: Arc<AppState>,
    ca: Arc<crate::tls::ca::TransparentCa>,
) -> Result<()> {
```

And pass `ca` through to `handle_connection` (will be used in Phase 3). Update the existing call site (the integration test in Task 1.3) accordingly:

In `tests/transparent_passthrough.rs`, replace the `spawn_listener` call with:

```rust
    let ca = Arc::new(vaultproxy::tls::ca::TransparentCa::generate("test").unwrap());
    transparent::spawn_listener_with_ca(bound_addr, state, ca).await.unwrap();
```

(Import `vaultproxy::tls` at the top.)

- [ ] **Step 4: Verify both feature states compile + tests pass**

```bash
cargo check
cargo check --features transparent
cargo test --features transparent,test-utils --test transparent_passthrough
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/main.rs src/proxy/transparent/mod.rs tests/transparent_passthrough.rs
git commit -m "feat(cli): wire transparent CA init into startup

main.rs now resolves --transparent-ca-cert / --transparent-ca-key (BYO)
or falls back to auto-generated CA in --config-dir. Init runs before
the listener binds so any cert/key validation failure surfaces with
a clear error before any port is opened.

spawn_listener_with_ca takes the resolved Arc<TransparentCa> for
Phase 3 leaf-signing. Test updated."
```

---

### Task 2.5: Leaf cert factory + LRU cache

**Files:**
- Create: `src/proxy/transparent/cert_factory.rs`
- Modify: `src/proxy/transparent/mod.rs` (declare module)

- [ ] **Step 1: Write the failing tests + implementation**

Create `src/proxy/transparent/cert_factory.rs`:

```rust
//! Per-host leaf cert signing for transparent MITM.
//!
//! On CONNECT, fetch the upstream's real cert (so SAN/CN match), sign a
//! fresh leaf with our CA, and present it to the agent. Cached in an
//! LRU keyed on `host:port`. Concurrent requests for the same host
//! coalesce on the cache miss.

use anyhow::{Context, Result};
use lru::LruCache;
use rcgen::{CertificateParams, DnType, KeyPair, SanType};
use std::num::NonZeroUsize;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::tls::ca::TransparentCa;

/// A signed leaf cert + private key, in PEM form, ready to hand to rustls.
#[derive(Clone)]
pub struct LeafCert {
    pub cert_chain_pem: String,
    pub key_pem: String,
}

pub struct CertFactory {
    ca: Arc<TransparentCa>,
    cache: Mutex<LruCache<String, LeafCert>>,
}

impl CertFactory {
    pub fn new(ca: Arc<TransparentCa>, capacity: usize) -> Self {
        Self {
            ca,
            cache: Mutex::new(LruCache::new(NonZeroUsize::new(capacity.max(1)).unwrap())),
        }
    }

    /// Look up or generate a leaf for the given host:port. Currently uses
    /// only the host as the SAN — upstream cert fetch (real-cert mirror)
    /// lands in Task 2.6.
    pub async fn leaf_for(&self, host: &str, port: u16) -> Result<LeafCert> {
        let key = format!("{host}:{port}");
        if let Some(hit) = self.cache.lock().await.get(&key).cloned() {
            return Ok(hit);
        }
        let leaf = self.sign_leaf(host)?;
        self.cache.lock().await.put(key, leaf.clone());
        Ok(leaf)
    }

    fn sign_leaf(&self, host: &str) -> Result<LeafCert> {
        let mut params = CertificateParams::new(vec![host.to_string()])
            .context("init leaf params")?;
        params.distinguished_name.push(DnType::CommonName, host);
        // SAN: prefer IP if host parses as IP; else DNS.
        let san = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            SanType::IpAddress(ip)
        } else {
            SanType::DnsName(rcgen::Ia5String::try_from(host.to_string())
                .context("invalid DNS SAN")?)
        };
        params.subject_alt_names = vec![san];
        params.not_before = time::OffsetDateTime::now_utc();
        params.not_after = params.not_before + time::Duration::days(30);

        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .context("generate leaf ED25519 key")?;
        let cert = params
            .signed_by(&leaf_key, &self.signing_cert()?, &self.ca.key_pair)
            .context("sign leaf with CA")?;
        let key_pem = leaf_key.serialize_pem();
        // Chain: leaf cert + CA cert (so the agent doesn't need the CA
        // separately if it trusts the issuer signature alone).
        let cert_chain_pem = format!("{}{}", cert.pem(), self.ca.cert_pem);
        Ok(LeafCert {
            cert_chain_pem,
            key_pem,
        })
    }

    /// Parse the CA cert from PEM once per call. Tiny perf cost; keeps
    /// rcgen's Certificate type out of the long-lived CertFactory.
    fn signing_cert(&self) -> Result<rcgen::Certificate> {
        let der = pem::parse(&self.ca.cert_pem)
            .context("parse CA cert PEM")?
            .into_contents();
        let params = rcgen::CertificateParams::from_ca_cert_der(&der.into())
            .context("CertificateParams::from_ca_cert_der")?;
        params.self_signed(&self.ca.key_pair).context("rehydrate CA")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_factory() -> CertFactory {
        let ca = Arc::new(TransparentCa::generate("test-host").unwrap());
        CertFactory::new(ca, 16)
    }

    #[tokio::test]
    async fn leaf_for_returns_pem() {
        let f = mock_factory();
        let leaf = f.leaf_for("api.github.com", 443).await.unwrap();
        assert!(leaf.cert_chain_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(leaf.key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    }

    #[tokio::test]
    async fn leaf_for_caches_repeats() {
        let f = mock_factory();
        let a = f.leaf_for("api.github.com", 443).await.unwrap();
        let b = f.leaf_for("api.github.com", 443).await.unwrap();
        assert_eq!(a.cert_chain_pem, b.cert_chain_pem);
    }

    #[tokio::test]
    async fn leaf_for_distinct_hosts_distinct_leaves() {
        let f = mock_factory();
        let a = f.leaf_for("api.github.com", 443).await.unwrap();
        let b = f.leaf_for("api.gitlab.com", 443).await.unwrap();
        assert_ne!(a.cert_chain_pem, b.cert_chain_pem);
    }

    #[tokio::test]
    async fn ipv4_san_works() {
        let f = mock_factory();
        let leaf = f.leaf_for("10.0.0.1", 443).await.unwrap();
        assert!(leaf.cert_chain_pem.contains("CERTIFICATE"));
    }
}
```

- [ ] **Step 2: Declare module**

Add to `src/proxy/transparent/mod.rs`:

```rust
pub mod cert_factory;
```

- [ ] **Step 3: Run tests**

```bash
cargo test --features transparent --lib transparent::cert_factory 2>&1 | tail -10
```

Expected: 4 passing.

- [ ] **Step 4: Commit**

```bash
git add src/proxy/transparent/cert_factory.rs src/proxy/transparent/mod.rs
git commit -m "feat(transparent): leaf cert factory with LRU cache

Per-host signed leaf certs cached in-memory (1024-entry LRU default).
Phase 2.5 only generates SAN from the host string; Task 2.6 will add
upstream-cert mirror so the leaf SAN matches what the real upstream
presents (catches wildcard / multi-SAN upstreams)."
```

---

### Task 2.6: Upstream cert mirror

**Files:**
- Modify: `src/proxy/transparent/cert_factory.rs`

- [ ] **Step 1: Add upstream-cert fetcher**

Append to `src/proxy/transparent/cert_factory.rs`:

```rust
/// Open a TLS connection to upstream, snag its leaf cert's SAN list,
/// and return them so the local leaf can mirror them. 5s timeout.
pub async fn fetch_upstream_sans(host: &str, port: u16) -> Result<Vec<SanType>> {
    use rustls::{ClientConfig, RootCertStore};
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;
    use tokio::time::{timeout, Duration};
    use tokio_rustls::TlsConnector;

    let mut roots = RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().context("load system root certs")? {
        let _ = roots.add(cert);
    }
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let server_name = host
        .parse::<rustls::pki_types::ServerName>()
        .map_err(|e| anyhow::anyhow!("invalid server name '{host}': {e}"))?;

    let tcp = timeout(Duration::from_secs(5), TcpStream::connect((host, port)))
        .await
        .map_err(|_| anyhow::anyhow!("upstream tcp connect timed out"))?
        .with_context(|| format!("connect to {host}:{port}"))?;
    let tls = timeout(Duration::from_secs(5), connector.connect(server_name.to_owned(), tcp))
        .await
        .map_err(|_| anyhow::anyhow!("upstream TLS handshake timed out"))?
        .with_context(|| format!("upstream TLS to {host}:{port}"))?;

    let (_, conn) = tls.get_ref();
    let peer_certs = conn
        .peer_certificates()
        .ok_or_else(|| anyhow::anyhow!("upstream did not present a cert chain"))?;
    if peer_certs.is_empty() {
        return Err(anyhow::anyhow!("upstream cert chain empty"));
    }
    let (_, parsed) = x509_parser::parse_x509_certificate(peer_certs[0].as_ref())
        .map_err(|e| anyhow::anyhow!("parse upstream cert: {e}"))?;

    let mut sans = Vec::new();
    if let Ok(Some(ext)) = parsed.subject_alternative_name() {
        for gn in &ext.value.general_names {
            match gn {
                x509_parser::extensions::GeneralName::DNSName(d) => {
                    if let Ok(s) = rcgen::Ia5String::try_from(d.to_string()) {
                        sans.push(SanType::DnsName(s));
                    }
                }
                x509_parser::extensions::GeneralName::IPAddress(bytes) => {
                    if let Some(ip) = ipaddr_from_bytes(bytes) {
                        sans.push(SanType::IpAddress(ip));
                    }
                }
                _ => {}
            }
        }
    }
    // Cleanly drop the TLS session.
    let mut tls = tls;
    let _ = tls.shutdown().await;
    Ok(sans)
}

fn ipaddr_from_bytes(b: &[u8]) -> Option<std::net::IpAddr> {
    match b.len() {
        4 => Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]))),
        16 => {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(b);
            Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(arr)))
        }
        _ => None,
    }
}
```

- [ ] **Step 2: Add `rustls-native-certs` dep**

```toml
rustls-native-certs = { version = "0.8", optional = true }
```

Update feature:
```toml
transparent = [
  "dep:rcgen", "dep:lru", "dep:x509-parser", "dep:hostname",
  "dep:rustls-native-certs",
]
```

- [ ] **Step 3: Plumb mirror into leaf_for**

Modify `leaf_for` to call `fetch_upstream_sans` once per host (then cache the result alongside the leaf):

```rust
pub async fn leaf_for(&self, host: &str, port: u16) -> Result<LeafCert> {
    let key = format!("{host}:{port}");
    if let Some(hit) = self.cache.lock().await.get(&key).cloned() {
        return Ok(hit);
    }
    let sans = fetch_upstream_sans(host, port).await.unwrap_or_else(|e| {
        tracing::warn!(host, port, error = %e, "upstream SAN fetch failed; falling back to host-only SAN");
        Vec::new()
    });
    let leaf = self.sign_leaf(host, sans)?;
    self.cache.lock().await.put(key, leaf.clone());
    Ok(leaf)
}
```

And update `sign_leaf` to accept the SAN vec:

```rust
fn sign_leaf(&self, host: &str, mut upstream_sans: Vec<SanType>) -> Result<LeafCert> {
    let mut params = CertificateParams::new(vec![host.to_string()])
        .context("init leaf params")?;
    params.distinguished_name.push(DnType::CommonName, host);
    // Always include the requested host as a SAN, plus any mirrored SANs.
    let host_san = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        SanType::IpAddress(ip)
    } else {
        SanType::DnsName(rcgen::Ia5String::try_from(host.to_string())
            .context("invalid DNS SAN")?)
    };
    upstream_sans.push(host_san);
    params.subject_alt_names = upstream_sans;
    params.not_before = time::OffsetDateTime::now_utc();
    params.not_after = params.not_before + time::Duration::days(30);

    let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .context("generate leaf ED25519 key")?;
    let cert = params
        .signed_by(&leaf_key, &self.signing_cert()?, &self.ca.key_pair)
        .context("sign leaf with CA")?;
    let cert_chain_pem = format!("{}{}", cert.pem(), self.ca.cert_pem);
    Ok(LeafCert {
        cert_chain_pem,
        key_pem: leaf_key.serialize_pem(),
    })
}
```

- [ ] **Step 4: Add an integration test against a real upstream cert**

Append to `cert_factory.rs` tests module:

```rust
    // SKIPPED in normal CI — requires network to badssl.com. Run with:
    //   cargo test --features transparent --lib transparent::cert_factory::tests::fetches_real_sans -- --ignored
    #[tokio::test]
    #[ignore]
    async fn fetches_real_sans() {
        let sans = fetch_upstream_sans("badssl.com", 443).await.unwrap();
        assert!(!sans.is_empty());
        let has_badssl = sans.iter().any(|s| matches!(s, SanType::DnsName(d) if d.as_ref().contains("badssl")));
        assert!(has_badssl, "expected at least one *.badssl.com SAN; got {:?}", sans);
    }
```

- [ ] **Step 5: Verify build + non-ignored tests still pass**

```bash
cargo check --features transparent
cargo test --features transparent --lib transparent::cert_factory 2>&1 | tail -10
```

Expected: 4 + 1 (ignored) tests; 4 passing, 1 ignored.

- [ ] **Step 6: Commit**

```bash
git add src/proxy/transparent/cert_factory.rs Cargo.toml Cargo.lock
git commit -m "feat(transparent): mirror upstream cert SANs on leaf signing

cert_factory::leaf_for now opens a real TLS connection to the upstream
on first request, snags the SAN list from the upstream cert, and
includes those in the locally signed leaf. Caches alongside the leaf
PEM so subsequent requests skip the upstream round-trip.

Falls back to host-only SAN if upstream cert fetch fails (logged at
WARN) so a flaky upstream doesn't break the proxy."
```

---

### Task 2.7: Tag v1.1.0-alpha.2 (CA + leaf factory baseline)

Same shape as Task 1.5:

- [ ] **Step 1: Bump version to `1.1.0-alpha.2` in Cargo.toml**
- [ ] **Step 2: Full lint + test sweep (all four clippy + test commands)**
- [ ] **Step 3: Commit, tag, push:**

```bash
git tag -a v1.1.0-alpha.2 -m "transparent HTTPS_PROXY: CA + leaf factory in place"
git push origin main
git push origin v1.1.0-alpha.2
```

---

## Phase 3 — host_inject for bearer + header (≈3 days)

### Task 3.1: Add `transparent_mode` field to ServiceEntry

**Files:**
- Modify: `src/proxy/registry.rs` (extend struct + parse)
- Test: same file

- [ ] **Step 1: Write the failing parse test**

Locate `src/proxy/registry.rs` and find `pub struct ServiceEntry` (around line 222 per session-cached read). Add to the struct (preserve field order):

```rust
    /// Transparent HTTPS_PROXY mode for this service. Default "off" when
    /// absent — every existing services.toml file parses unchanged.
    #[cfg(feature = "transparent")]
    pub transparent_mode: TransparentMode,
```

Above the struct, add:

```rust
#[cfg(feature = "transparent")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TransparentMode {
    #[default]
    Off,
    HostInject,
    Placeholder,
    Passthrough,
}
```

Find the `#[derive(Debug, Deserialize)]` raw `RawService` struct used in parsing and add:

```rust
    #[cfg(feature = "transparent")]
    #[serde(default)]
    transparent_mode: TransparentMode,
```

And in the conversion from `RawService` → `ServiceEntry`, copy the field over:

```rust
    #[cfg(feature = "transparent")]
    transparent_mode: raw.transparent_mode,
```

- [ ] **Step 2: Tests**

In the `#[cfg(test)] mod tests` block at the bottom of registry.rs:

```rust
    #[cfg(feature = "transparent")]
    #[test]
    fn services_toml_parses_transparent_mode() {
        let toml = r#"
            [[service]]
            name = "gh"
            base_url = "https://api.github.com"
            auth = "bearer"
            vault_item = "vault-proxy - GitHub"
            transparent_mode = "host_inject"
        "#;
        let reg = ServiceRegistry::from_toml_str(toml).unwrap();
        let svc = reg.get("gh").unwrap();
        assert_eq!(svc.transparent_mode, TransparentMode::HostInject);
    }

    #[cfg(feature = "transparent")]
    #[test]
    fn services_toml_defaults_transparent_mode_off() {
        let toml = r#"
            [[service]]
            name = "gh"
            base_url = "https://api.github.com"
            auth = "bearer"
            vault_item = "vault-proxy - GitHub"
        "#;
        let reg = ServiceRegistry::from_toml_str(toml).unwrap();
        let svc = reg.get("gh").unwrap();
        assert_eq!(svc.transparent_mode, TransparentMode::Off);
    }
```

(If `from_toml_str` doesn't exist on the registry, use whatever existing parse helper does. Don't invent a new one for the test — match existing patterns.)

- [ ] **Step 3: Run tests**

```bash
cargo test --features transparent --lib proxy::registry 2>&1 | tail -10
```

Expected: pre-existing registry tests still pass + 2 new ones pass.

- [ ] **Step 4: Commit**

```bash
git add src/proxy/registry.rs
git commit -m "feat(registry): add transparent_mode field to ServiceEntry

Per the spec, services.toml gains an optional 'transparent_mode' field
per [[service]] block. Default Off — every existing file parses
unchanged. Gated behind cfg(feature = transparent); zero footprint
in the default build."
```

---

### Task 3.2: Host:port → service lookup index

**Files:**
- Create: `src/proxy/transparent/registry.rs`
- Modify: `src/proxy/transparent/mod.rs`

- [ ] **Step 1: Implement the lookup helper**

Create `src/proxy/transparent/registry.rs`:

```rust
//! Host:port → ServiceEntry lookup, layered over the existing
//! ServiceRegistry. Built on demand from a ServiceRegistry snapshot
//! whenever SIGHUP rebuilds the underlying registry.

use anyhow::{bail, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use url::Url;

use crate::proxy::registry::{ServiceEntry, ServiceRegistry, TransparentMode};

#[derive(Default, Clone)]
pub struct TransparentRegistry {
    by_host_port: HashMap<String, Arc<ServiceEntry>>,
}

impl TransparentRegistry {
    /// Build from a snapshot of the existing ServiceRegistry.
    /// Rejects collisions: two services pointing at the same host:port
    /// with transparent_mode != Off are a config error.
    pub fn build(registry: &ServiceRegistry) -> Result<Self> {
        let mut out: HashMap<String, Arc<ServiceEntry>> = HashMap::new();
        for entry in registry.iter() {
            if entry.transparent_mode == TransparentMode::Off {
                continue;
            }
            let url = Url::parse(&entry.base_url)
                .map_err(|e| anyhow::anyhow!("base_url for '{}' invalid: {e}", entry.name))?;
            let host = url
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("base_url for '{}' has no host", entry.name))?
                .to_lowercase();
            let port = url.port_or_known_default().unwrap_or(443);
            let key = format!("{host}:{port}");
            if let Some(prev) = out.get(&key) {
                bail!(
                    "transparent host:port collision: '{key}' is claimed by both '{}' and '{}'",
                    prev.name,
                    entry.name
                );
            }
            out.insert(key, Arc::new(entry.clone()));
        }
        Ok(Self { by_host_port: out })
    }

    pub fn lookup(&self, host: &str, port: u16) -> Option<Arc<ServiceEntry>> {
        let key = format!("{}:{}", host.to_lowercase(), port);
        self.by_host_port.get(&key).cloned()
    }
}

/// Cell that holds the latest built TransparentRegistry. Updated by
/// SIGHUP reload (Phase 6).
pub type TransparentRegistryCell = Arc<RwLock<TransparentRegistry>>;

#[cfg(test)]
mod tests {
    use super::*;
    // Build helper that constructs a ServiceRegistry with one entry.
    // The exact constructor depends on existing patterns; this is the
    // shape to follow.

    #[test]
    fn collision_is_rejected() {
        let toml = r#"
            [[service]]
            name = "a"
            base_url = "https://api.example.com"
            auth = "bearer"
            vault_item = "v1"
            transparent_mode = "host_inject"

            [[service]]
            name = "b"
            base_url = "https://api.example.com:443/v2"
            auth = "bearer"
            vault_item = "v2"
            transparent_mode = "host_inject"
        "#;
        let reg = ServiceRegistry::from_toml_str(toml).unwrap();
        let err = TransparentRegistry::build(&reg).unwrap_err();
        assert!(err.to_string().contains("collision"));
    }

    #[test]
    fn lookup_is_case_insensitive_on_host() {
        let toml = r#"
            [[service]]
            name = "a"
            base_url = "https://API.Example.com:443"
            auth = "bearer"
            vault_item = "v1"
            transparent_mode = "host_inject"
        "#;
        let reg = ServiceRegistry::from_toml_str(toml).unwrap();
        let tr = TransparentRegistry::build(&reg).unwrap();
        assert!(tr.lookup("api.example.com", 443).is_some());
        assert!(tr.lookup("API.EXAMPLE.COM", 443).is_some());
    }

    #[test]
    fn lookup_default_port_443() {
        let toml = r#"
            [[service]]
            name = "a"
            base_url = "https://api.example.com"
            auth = "bearer"
            vault_item = "v1"
            transparent_mode = "host_inject"
        "#;
        let reg = ServiceRegistry::from_toml_str(toml).unwrap();
        let tr = TransparentRegistry::build(&reg).unwrap();
        assert!(tr.lookup("api.example.com", 443).is_some());
        assert!(tr.lookup("api.example.com", 8443).is_none());
    }
}
```

- [ ] **Step 2: Declare module + add `url` dep if missing**

In `src/proxy/transparent/mod.rs`:

```rust
pub mod registry;
```

`url` is already a transitive dep via reqwest; promote to direct:

```toml
url = "2"
```

- [ ] **Step 3: Run tests**

```bash
cargo test --features transparent --lib transparent::registry 2>&1 | tail -10
```

Expected: 3 passing.

- [ ] **Step 4: Commit**

```bash
git add src/proxy/transparent/registry.rs src/proxy/transparent/mod.rs Cargo.toml Cargo.lock
git commit -m "feat(transparent): host:port → service lookup index

Builds a HashMap<host:port, ServiceEntry> snapshot from the existing
ServiceRegistry, filtered to services with transparent_mode != Off.
Rejects host:port collisions at build time. Case-insensitive on host.
Default port 443 when base_url omits one."
```

---

### Task 3.3: MITM module — TLS handshake + read agent request

**Files:**
- Create: `src/proxy/transparent/mitm.rs`
- Modify: `src/proxy/transparent/mod.rs`

- [ ] **Step 1: Write the MITM skeleton**

Create `src/proxy/transparent/mitm.rs`:

```rust
//! MITM path: present a freshly signed leaf cert to the agent, decrypt
//! the agent's HTTP/1.1 request, hand it to an injector, forward to
//! upstream over a real TLS connection, stream the response back.

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

use crate::proxy::registry::ServiceEntry;
use crate::proxy::transparent::cert_factory::{CertFactory, LeafCert};
use crate::proxy::transparent::connect::ConnectTarget;

/// Run the MITM loop for one CONNECT request.
pub async fn run(
    mut agent_plaintext: TcpStream,
    target: ConnectTarget,
    service: Arc<ServiceEntry>,
    cert_factory: Arc<CertFactory>,
    vault: Arc<crate::vault::VaultManager>,
    vault_folder: &str,
) -> Result<()> {
    let start = Instant::now();

    // 1. Tell the agent the tunnel is open (BEFORE leaf cert prep, so
    //    the agent will start sending Client Hello immediately).
    agent_plaintext
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await
        .context("write 200 to agent")?;

    // 2. Build TlsAcceptor with the leaf for this host.
    let leaf = cert_factory.leaf_for(&target.host, target.port).await?;
    let acceptor = build_acceptor(&leaf)?;
    let mut agent_tls = acceptor
        .accept(agent_plaintext)
        .await
        .context("TLS handshake with agent")?;

    // 3. Read the agent's HTTP/1.1 request (line + headers + body).
    let req = read_http_request(&mut agent_tls).await?;

    // 4. Dispatch to injector based on transparent_mode.
    let injected = match service.transparent_mode {
        #[cfg(feature = "transparent")]
        crate::proxy::registry::TransparentMode::HostInject => {
            crate::proxy::transparent::inject_host::inject(
                req,
                &service,
                vault.clone(),
                vault_folder,
            )
            .await?
        }
        #[cfg(feature = "transparent")]
        crate::proxy::registry::TransparentMode::Placeholder => {
            // Phase 5.
            bail!("placeholder mode not yet implemented");
        }
        _ => unreachable!("mitm::run only called for HostInject / Placeholder"),
    };

    // 5. Forward to upstream over real TLS.
    let response = forward_to_upstream(&target, injected).await?;

    // 6. Stream response back to agent.
    agent_tls.write_all(&response).await?;
    agent_tls.shutdown().await.ok();

    info!(
        host = %target,
        mode = ?service.transparent_mode,
        duration_ms = start.elapsed().as_millis() as u64,
        "transparent MITM closed",
    );
    Ok(())
}

fn build_acceptor(leaf: &LeafCert) -> Result<TlsAcceptor> {
    use rustls::ServerConfig;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let cert_chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut leaf.cert_chain_pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("parse leaf cert PEM")?;
    let key = rustls_pemfile::pkcs8_private_keys(&mut leaf.key_pem.as_bytes())
        .next()
        .ok_or_else(|| anyhow::anyhow!("no PKCS8 key in leaf PEM"))?
        .context("parse leaf key PEM")?;

    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, PrivateKeyDer::Pkcs8(key))
        .context("rustls ServerConfig")?;
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

/// Minimal HTTP/1.1 request representation: method, path, headers,
/// optional body. Adequate for inject/forward; not a full HTTP parser.
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

async fn read_http_request<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
) -> Result<HttpRequest> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;
    let mut parts = request_line.trim_end_matches("\r\n").splitn(3, ' ');
    let method = parts.next().context("HTTP method")?.to_string();
    let path = parts.next().context("HTTP path")?.to_string();
    let version = parts.next().context("HTTP version")?;
    if version != "HTTP/1.1" {
        bail!("agent sent unsupported HTTP version '{version}'");
    }
    let mut headers = Vec::new();
    let mut content_length: usize = 0;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
        let trimmed = line.trim_end_matches("\r\n");
        if let Some((k, v)) = trimmed.split_once(':') {
            let key = k.trim().to_string();
            let val = v.trim().to_string();
            if key.eq_ignore_ascii_case("content-length") {
                content_length = val.parse().unwrap_or(0);
            }
            headers.push((key, val));
        }
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).await?;
    }
    Ok(HttpRequest {
        method,
        path,
        headers,
        body: Bytes::from(body),
    })
}

async fn forward_to_upstream(target: &ConnectTarget, req: HttpRequest) -> Result<Bytes> {
    use rustls::{ClientConfig, RootCertStore};
    use tokio_rustls::TlsConnector;

    let mut roots = RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().context("load native roots")? {
        let _ = roots.add(cert);
    }
    let cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(cfg));
    let server_name = target.host.parse::<rustls::pki_types::ServerName>()
        .map_err(|e| anyhow::anyhow!("invalid server name '{}': {e}", target.host))?;
    let tcp = TcpStream::connect((target.host.as_str(), target.port)).await?;
    let mut tls = connector.connect(server_name.to_owned(), tcp).await?;

    // Serialise request.
    let mut buf = Vec::with_capacity(req.body.len() + 1024);
    buf.extend_from_slice(format!("{} {} HTTP/1.1\r\n", req.method, req.path).as_bytes());
    let mut has_host = false;
    for (k, v) in &req.headers {
        if k.eq_ignore_ascii_case("host") {
            has_host = true;
        }
        buf.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    if !has_host {
        buf.extend_from_slice(format!("Host: {}\r\n", target.host).as_bytes());
    }
    buf.extend_from_slice(format!("Content-Length: {}\r\n\r\n", req.body.len()).as_bytes());
    buf.extend_from_slice(&req.body);
    tls.write_all(&buf).await?;

    // Read full response.
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await?;
    Ok(Bytes::from(response))
}
```

- [ ] **Step 2: Add deps**

```toml
rustls = "0.23"        # already direct
rustls-pemfile = "2"
tokio-rustls = "0.26"  # already direct
bytes = "1"            # already transitive
```

Promote `bytes` and `rustls-pemfile` to direct deps if not already.

- [ ] **Step 3: Declare module**

In `src/proxy/transparent/mod.rs`:

```rust
pub mod mitm;
```

- [ ] **Step 4: Verify build**

```bash
cargo check --features transparent
```

(Will fail because `inject_host` doesn't exist yet — proceed to Task 3.4.)

---

### Task 3.4: `inject_host` for bearer + header

**Files:**
- Create: `src/proxy/transparent/inject_host.rs`
- Modify: `src/proxy/transparent/mod.rs`

- [ ] **Step 1: Implement**

Create `src/proxy/transparent/inject_host.rs`:

```rust
//! Host-based injection: replace the agent's auth header(s) with the
//! credential pulled from Vaultwarden according to the service's
//! auth pattern.
//!
//! Forbidden inbound headers (Authorization, X-Api-Key, X-Plex-Token,
//! Cookie, Proxy-Authorization, Host) are stripped first so the agent
//! can't smuggle in conflicting auth.

use anyhow::{bail, Context, Result};
use std::sync::Arc;

use crate::proxy::registry::{AuthPattern, ServiceEntry};
use crate::proxy::transparent::mitm::HttpRequest;
use crate::vault::VaultManager;

const FORBIDDEN_HEADERS: &[&str] = &[
    "authorization",
    "x-api-key",
    "x-plex-token",
    "cookie",
    "proxy-authorization",
];

pub async fn inject(
    mut req: HttpRequest,
    service: &Arc<ServiceEntry>,
    vault: Arc<VaultManager>,
    vault_folder: &str,
) -> Result<HttpRequest> {
    strip_forbidden_headers(&mut req.headers);

    match &service.auth {
        AuthPattern::Bearer { vault_item } => {
            let token = vault
                .get_item_password(vault_folder, vault_item)
                .await
                .with_context(|| format!("resolve vault item '{vault_item}'"))?;
            req.headers.push((
                "Authorization".into(),
                format!("Bearer {token}"),
            ));
        }
        AuthPattern::Header { vault_item, header_name } => {
            let value = vault
                .get_item_password(vault_folder, vault_item)
                .await
                .with_context(|| format!("resolve vault item '{vault_item}'"))?;
            req.headers.push((header_name.clone(), value));
        }
        other => {
            bail!(
                "transparent host_inject does not yet support auth pattern {:?}; service '{}'",
                other,
                service.name
            );
        }
    }
    Ok(req)
}

fn strip_forbidden_headers(headers: &mut Vec<(String, String)>) {
    headers.retain(|(k, _)| {
        !FORBIDDEN_HEADERS
            .iter()
            .any(|f| k.eq_ignore_ascii_case(f))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forbidden_headers_stripped() {
        let mut h = vec![
            ("Authorization".into(), "Bearer attacker".into()),
            ("X-Api-Key".into(), "leak".into()),
            ("Accept".into(), "*/*".into()),
            ("cookie".into(), "session=stale".into()),
        ];
        strip_forbidden_headers(&mut h);
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].0, "Accept");
    }
}
```

- [ ] **Step 2: Declare module + verify build**

In `src/proxy/transparent/mod.rs`:

```rust
pub mod inject_host;
```

```bash
cargo test --features transparent --lib transparent::inject_host 2>&1 | tail -10
```

Expected: 1 passing.

- [ ] **Step 3: Commit**

```bash
git add src/proxy/transparent/inject_host.rs \
         src/proxy/transparent/mitm.rs \
         src/proxy/transparent/mod.rs \
         Cargo.toml Cargo.lock
git commit -m "feat(transparent): MITM + host_inject (bearer, header)

Adds src/proxy/transparent/mitm.rs (TLS handshake with agent using
freshly signed leaf, plaintext request read, upstream TLS forward,
response stream) and inject_host.rs (forbidden-header strip + vault
credential injection for AuthPattern::Bearer and ::Header).

Basic + QueryParam + session/unifi_dual deferred to Phase 4."
```

---

### Task 3.5: Wire MITM dispatch into handle_connection

**Files:**
- Modify: `src/proxy/transparent/mod.rs`

- [ ] **Step 1: Replace handle_connection with registry-driven dispatch**

In `src/proxy/transparent/mod.rs`:

```rust
async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    state: Arc<AppState>,
    cert_factory: Arc<cert_factory::CertFactory>,
    tr_registry: registry::TransparentRegistryCell,
) -> Result<()> {
    let target = match connect::read_connect_line(&mut stream).await {
        Ok(t) => t,
        Err(e) => {
            return reply_error(&mut stream, 400, "malformed_connect", &e.to_string()).await;
        }
    };
    info!(peer = %peer, target = %target, "transparent CONNECT received");

    let svc = tr_registry.read().await.lookup(&target.host, target.port);
    use crate::proxy::registry::TransparentMode;
    match svc.as_ref().map(|s| s.transparent_mode) {
        Some(TransparentMode::HostInject) | Some(TransparentMode::Placeholder) => {
            let service = svc.unwrap();
            if let Err(e) = mitm::run(
                stream,
                target.clone(),
                service.clone(),
                cert_factory,
                state.vault.clone(),
                &state.vault_folder,
            ).await {
                warn!(target = %target, error = %e, "MITM error");
            }
        }
        Some(TransparentMode::Passthrough) | Some(TransparentMode::Off) | None => {
            // Off mode services + unregistered hosts both tunnel.
            // Allowlist policy enforcement lands in Phase 6.
            if let Err(e) = passthrough::tunnel(stream, target.clone()).await {
                warn!(target = %target, error = %e, "passthrough error");
            }
        }
    }
    Ok(())
}
```

- [ ] **Step 2: Update spawn_listener_with_ca to thread cert_factory + tr_registry**

In the same file:

```rust
pub async fn spawn_listener_with_ca(
    addr: SocketAddr,
    state: Arc<AppState>,
    ca: Arc<crate::tls::ca::TransparentCa>,
) -> Result<()> {
    let listener = TcpListener::bind(addr).await.map_err(|e| {
        anyhow::anyhow!("transparent listener failed to bind {addr}: {e}")
    })?;
    let cert_factory = Arc::new(cert_factory::CertFactory::new(ca, 1024));

    // Build initial registry snapshot. SIGHUP reload (Phase 6) updates
    // this cell in place.
    let snapshot = {
        let reg = state.registry.read().await;
        registry::TransparentRegistry::build(&reg)?
    };
    let tr_registry: registry::TransparentRegistryCell =
        Arc::new(tokio::sync::RwLock::new(snapshot));

    info!(addr = %addr, "transparent HTTPS_PROXY listener started");

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    let state = state.clone();
                    let cf = cert_factory.clone();
                    let tr = tr_registry.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, peer, state, cf, tr).await {
                            warn!(peer = %peer, error = %e, "transparent connection error");
                        }
                    });
                }
                Err(e) => {
                    error!(error = %e, "transparent accept failed");
                }
            }
        }
    });
    Ok(())
}
```

- [ ] **Step 3: Verify build + existing passthrough test still passes**

```bash
cargo check --features transparent
cargo test --features transparent,test-utils --test transparent_passthrough 2>&1 | tail -10
```

Expected: passes (Phase 1 test still goes through passthrough branch).

- [ ] **Step 4: Commit**

```bash
git add src/proxy/transparent/mod.rs
git commit -m "feat(transparent): registry-driven MITM/passthrough dispatch

handle_connection now looks up the CONNECT target in
TransparentRegistry and routes to mitm::run (HostInject/Placeholder)
or passthrough::tunnel (Off/Passthrough/unregistered).

CertFactory and TransparentRegistry are constructed once per
listener and Arc'd into the per-connection handler. Allowlist
policy enforcement for unregistered hosts lands in Phase 6."
```

---

### Task 3.6: Integration test — host_inject for Bearer

**Files:**
- Create: `tests/transparent_host_inject_bearer.rs`

- [ ] **Step 1: Write the test**

Create `tests/transparent_host_inject_bearer.rs`:

```rust
//! E2E for transparent host_inject with AuthPattern::Bearer.
//!
//! Spawns:
//!   - A wiremock upstream serving HTTPS (self-signed leaf trusted by
//!     a vault-proxy-managed root)
//!   - vault-proxy transparent listener pointed at a stub vault
//!     containing one bearer item
//!   - A reqwest client that uses HTTPS_PROXY=…3203, trusts the
//!     vault-proxy CA, and makes one GET
//!
//! Asserts the wiremock saw `Authorization: Bearer <stub-token>`.

#![cfg(all(feature = "transparent", feature = "test-utils"))]

// Full test body — implementation mirrors the pattern in
// tests/transparent_passthrough.rs but adds a wiremock HTTPS upstream
// and an injection assertion. Detailed code in the implementation
// step below.
```

(Stop and elaborate the full implementation in step 2.)

- [ ] **Step 2: Full implementation**

Replace placeholder body with:

```rust
#![cfg(all(feature = "transparent", feature = "test-utils"))]

use std::sync::Arc;
use std::time::Duration;
use wiremock::{matchers::{method, header, path}, Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn host_inject_bearer_replaces_agent_auth() {
    // 1. Wiremock upstream that requires Bearer matching the vault stub.
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/me"))
        .and(header("Authorization", "Bearer vault-stub-token"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;

    let upstream_uri = server.uri();
    // wiremock binds plain HTTP. For the test we run host_inject in
    // "test-plain" mode by overriding the upstream connector path to
    // skip TLS. The mitm module accepts an upstream-scheme override
    // via env (added below for test-only use).
    std::env::set_var("VP_TRANSPARENT_TEST_HTTP", "1");

    // 2. Build AppState with a stub vault that returns "vault-stub-token"
    //    for the matching item, and a registry with our service.
    let mut state = vaultproxy::test_support::stub_app_state().await;
    {
        let mut reg = state.registry.write().await;
        let toml = format!(
            r#"
            [[service]]
            name = "test_upstream"
            base_url = "{}"
            auth = "bearer"
            vault_item = "test-bearer"
            transparent_mode = "host_inject"
            "#,
            upstream_uri
        );
        *reg = vaultproxy::proxy::registry::ServiceRegistry::from_toml_str(&toml).unwrap();
    }
    let state = Arc::new(state);

    // 3. Spawn transparent listener on ephemeral port.
    let listener_addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
    let bound = std::net::TcpListener::bind(listener_addr).unwrap();
    let bound_addr = bound.local_addr().unwrap();
    drop(bound);
    let ca = Arc::new(vaultproxy::tls::ca::TransparentCa::generate("test").unwrap());
    vaultproxy::proxy::transparent::spawn_listener_with_ca(bound_addr, state.clone(), ca.clone())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 4. reqwest client through the transparent proxy, trusting our CA.
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca.cert_pem.as_bytes()).unwrap())
        .proxy(reqwest::Proxy::all(format!("http://{bound_addr}")).unwrap())
        .build()
        .unwrap();

    let url = format!("{}/me", upstream_uri);
    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "ok");
}
```

NOTE: the comment about `VP_TRANSPARENT_TEST_HTTP` and plain-HTTP upstream is a test affordance we need to add. Update `mitm::forward_to_upstream` to honour it when set:

```rust
async fn forward_to_upstream(target: &ConnectTarget, req: HttpRequest) -> Result<Bytes> {
    let use_http = std::env::var("VP_TRANSPARENT_TEST_HTTP").ok().as_deref() == Some("1");
    if use_http {
        return forward_plaintext(target, req).await;
    }
    // ... existing TLS path unchanged ...
}

async fn forward_plaintext(target: &ConnectTarget, req: HttpRequest) -> Result<Bytes> {
    let mut tcp = TcpStream::connect((target.host.as_str(), target.port)).await?;
    let mut buf = Vec::with_capacity(req.body.len() + 1024);
    buf.extend_from_slice(format!("{} {} HTTP/1.1\r\n", req.method, req.path).as_bytes());
    let mut has_host = false;
    for (k, v) in &req.headers {
        if k.eq_ignore_ascii_case("host") { has_host = true; }
        buf.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    if !has_host {
        buf.extend_from_slice(format!("Host: {}\r\n", target.host).as_bytes());
    }
    buf.extend_from_slice(format!("Content-Length: {}\r\n\r\n", req.body.len()).as_bytes());
    buf.extend_from_slice(&req.body);
    tcp.write_all(&buf).await?;
    let mut response = Vec::new();
    tcp.read_to_end(&mut response).await?;
    Ok(Bytes::from(response))
}
```

Also: the stub vault returned by `VaultManager::new_stub()` needs an injection helper. Add `VaultManager::new_stub_with_item(item: &str, password: &str)` if it doesn't exist, or update `stub_app_state()` to seed an item via `state.vault.insert_test_item(...)`. Inspect existing vault stub before writing; reuse what's there. If neither exists, add a tiny helper in `src/vault/mod.rs` behind `#[cfg(any(test, feature = "test-utils"))]`:

```rust
#[cfg(any(test, feature = "test-utils"))]
impl VaultManager {
    pub fn insert_test_item(&self, folder: &str, name: &str, password: &str) {
        // Insert directly into the in-memory stub cache.
        // Concrete implementation depends on VaultManager internals;
        // mirror the pattern used by new_stub_with_keys() if present.
    }
}
```

Then in the test, after building state:

```rust
    state.vault.insert_test_item("vault-proxy", "test-bearer", "vault-stub-token");
```

- [ ] **Step 3: Run the test**

```bash
cargo test --features transparent,test-utils --test transparent_host_inject_bearer 2>&1 | tail -10
```

Expected: pass.

- [ ] **Step 4: Commit**

```bash
git add tests/transparent_host_inject_bearer.rs src/proxy/transparent/mitm.rs src/vault/mod.rs
git commit -m "test(transparent): E2E host_inject for Bearer auth pattern

Wiremock upstream asserts received Authorization: Bearer matches the
vault-stub value, proving:
  - reqwest client trusts our CA via add_root_certificate
  - HTTPS_PROXY plumbing reaches mitm::run
  - Forbidden Authorization header on the agent side is dropped
  - Vault credential is injected
  - Response streams back to the agent

VP_TRANSPARENT_TEST_HTTP test affordance lets the upstream forwarder
use plain HTTP so wiremock (which doesn't speak TLS by default) can
be the target."
```

---

### Task 3.7: Integration test — host_inject for Header

Same shape as 3.6 but assert a custom `X-Api-Key` header:

- [ ] **Step 1: Create `tests/transparent_host_inject_header.rs`**

Same skeleton, but:

```rust
        r#"
        [[service]]
        name = "test_upstream"
        base_url = "{}"
        auth = "header"
        header_name = "X-Api-Key"
        vault_item = "test-header"
        transparent_mode = "host_inject"
        "#
```

And the wiremock matcher uses `header("X-Api-Key", "vault-header-token")`.

- [ ] **Step 2: Run, expect pass, commit**

```bash
cargo test --features transparent,test-utils --test transparent_host_inject_header
git add tests/transparent_host_inject_header.rs
git commit -m "test(transparent): E2E host_inject for AuthPattern::Header"
```

---

## Phase 4 — Remaining auth types (basic, query_param) (≈3 days)

### Task 4.1: Extend `inject_host` for Basic auth

**Files:**
- Modify: `src/proxy/transparent/inject_host.rs`
- Test: `tests/transparent_host_inject_basic.rs`

- [ ] **Step 1: Extend the `match` arm**

In `inject_host.rs`, add a new arm:

```rust
        AuthPattern::Basic { vault_item, key_field, secret_field } => {
            let key = vault
                .get_item_field(vault_folder, vault_item, key_field)
                .await
                .with_context(|| format!("resolve vault item '{vault_item}' field '{key_field}'"))?;
            let secret = vault
                .get_item_field(vault_folder, vault_item, secret_field)
                .await
                .with_context(|| format!("resolve vault item '{vault_item}' field '{secret_field}'"))?;
            use base64::Engine;
            let creds = format!("{key}:{secret}");
            let encoded = base64::engine::general_purpose::STANDARD.encode(creds);
            req.headers.push(("Authorization".into(), format!("Basic {encoded}")));
        }
```

`base64` is likely already a direct dep; confirm.

- [ ] **Step 2: Add E2E test mirroring 3.6/3.7**

`tests/transparent_host_inject_basic.rs`:

- service block with `auth = "basic"`, `key_field = "username"`, `secret_field = "password"`, `vault_item = "test-basic"`
- seed vault with custom fields: `state.vault.insert_test_item_with_fields("vault-proxy", "test-basic", &[("username","admin"), ("password","s3cret")])`
- wiremock matcher: `header("Authorization", "Basic YWRtaW46czNjcmV0")`

Add `insert_test_item_with_fields` if it doesn't already exist.

- [ ] **Step 3: Test + commit**

```bash
cargo test --features transparent,test-utils --test transparent_host_inject_basic
git add src/proxy/transparent/inject_host.rs \
         tests/transparent_host_inject_basic.rs \
         src/vault/mod.rs
git commit -m "feat(transparent): host_inject Basic auth + E2E"
```

---

### Task 4.2: Extend `inject_host` for QueryParam

**Files:**
- Modify: `src/proxy/transparent/inject_host.rs`
- Test: `tests/transparent_host_inject_query.rs`

- [ ] **Step 1: Extend the `match` arm**

```rust
        AuthPattern::QueryParam { vault_item, param_name } => {
            let value = vault
                .get_item_password(vault_folder, vault_item)
                .await
                .with_context(|| format!("resolve vault item '{vault_item}'"))?;
            // Inject into the request path's query string.
            let sep = if req.path.contains('?') { '&' } else { '?' };
            req.path.push(sep);
            req.path.push_str(param_name);
            req.path.push('=');
            req.path.push_str(&urlencoding::encode(&value));
        }
```

`urlencoding` is likely already a transitive dep; if not, add `urlencoding = "2"` to Cargo.toml.

- [ ] **Step 2: E2E test**

`tests/transparent_host_inject_query.rs`:

- service block with `auth = "query_param"`, `param_name = "apikey"`
- wiremock matcher uses `query_param("apikey", "vault-query-token")`

- [ ] **Step 3: Test + commit**

```bash
cargo test --features transparent,test-utils --test transparent_host_inject_query
git add src/proxy/transparent/inject_host.rs tests/transparent_host_inject_query.rs Cargo.toml Cargo.lock
git commit -m "feat(transparent): host_inject QueryParam + E2E"
```

---

### Task 4.3: Reject session / unifi_dual at load time

**Files:**
- Modify: `src/proxy/registry.rs` (extend validation)
- Test: same file

- [ ] **Step 1: Add validation in the registry parse path**

In `src/proxy/registry.rs`, in the function that converts `RawService` → `ServiceEntry` (or wherever per-entry validation happens), add (gated on `transparent` feature):

```rust
    #[cfg(feature = "transparent")]
    if matches!(transparent_mode, TransparentMode::HostInject)
        && matches!(auth, AuthPattern::Session { .. } | AuthPattern::UnifiDual { .. })
    {
        return Err(anyhow::anyhow!(
            "service '{}' has transparent_mode = 'host_inject' which only supports \
             auth = bearer | header | basic | query_param (got {:?}). \
             For session-based or UniFi-dual services, use transparent_mode = 'passthrough' \
             or 'placeholder' instead.",
            name,
            auth
        ));
    }
```

- [ ] **Step 2: Test**

```rust
    #[cfg(feature = "transparent")]
    #[test]
    fn host_inject_rejects_session_auth() {
        let toml = r#"
            [[service]]
            name = "npm"
            base_url = "https://npm.example.com"
            auth = "session"
            vault_item = "npm"
            login_path = "/login"
            token_field = "token"
            transparent_mode = "host_inject"
        "#;
        let err = ServiceRegistry::from_toml_str(toml).unwrap_err();
        assert!(err.to_string().contains("only supports auth = bearer"));
    }
```

- [ ] **Step 3: Run + commit**

```bash
cargo test --features transparent --lib proxy::registry::tests::host_inject_rejects_session_auth
git add src/proxy/registry.rs
git commit -m "validate(transparent): reject host_inject + session/unifi_dual at load

host_inject only supports stateless auth (bearer/header/basic/query_param).
Stateful auth needs the existing /proxy session-cookie path. Surface the
incompatibility at config-load time, not at first request."
```

---

## Phase 5 — Placeholder substitution (≈3 days)

### Task 5.1: services.toml top-level `[[transparent_placeholder]]` block

**Files:**
- Modify: `src/proxy/registry.rs`

- [ ] **Step 1: Add the type + parser**

In `src/proxy/registry.rs` (or a new sibling file `transparent_placeholders.rs`), add:

```rust
#[cfg(feature = "transparent")]
#[derive(Debug, Clone, serde::Deserialize)]
pub struct TransparentPlaceholder {
    pub token: String,
    pub vault_item: String,
    #[serde(default = "default_field")]
    pub field: String,
}

#[cfg(feature = "transparent")]
fn default_field() -> String { "password".into() }
```

Modify the top-level config struct to read these:

```rust
#[derive(Debug, serde::Deserialize)]
struct ServicesFile {
    #[serde(default)]
    service: Vec<RawService>,
    #[cfg(feature = "transparent")]
    #[serde(default)]
    transparent_placeholder: Vec<TransparentPlaceholder>,
}
```

Expose the parsed placeholders on `ServiceRegistry`:

```rust
#[cfg(feature = "transparent")]
pub fn transparent_placeholders(&self) -> &[TransparentPlaceholder] {
    &self.transparent_placeholders
}
```

- [ ] **Step 2: Validate token syntax at load**

```rust
#[cfg(feature = "transparent")]
fn validate_placeholder_token(t: &str) -> anyhow::Result<()> {
    if !t.starts_with("__vault.") || !t.ends_with("__") {
        anyhow::bail!("placeholder token '{t}' must match __vault.<name>__");
    }
    let inner = &t["__vault.".len()..t.len() - 2];
    if inner.is_empty() {
        anyhow::bail!("placeholder token '{t}' has empty name");
    }
    if !inner.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        anyhow::bail!("placeholder token '{t}' name must be [A-Za-z0-9_-]+");
    }
    Ok(())
}
```

Call from the parse path for each placeholder.

- [ ] **Step 3: Tests**

```rust
    #[cfg(feature = "transparent")]
    #[test]
    fn parses_placeholder_block() {
        let toml = r#"
            [[transparent_placeholder]]
            token = "__vault.github_pat__"
            vault_item = "vault-proxy - GitHub PAT"
        "#;
        let reg = ServiceRegistry::from_toml_str(toml).unwrap();
        let p = &reg.transparent_placeholders()[0];
        assert_eq!(p.token, "__vault.github_pat__");
        assert_eq!(p.field, "password");
    }

    #[cfg(feature = "transparent")]
    #[test]
    fn rejects_bad_placeholder_token() {
        for bad in &["__vault.__", "vault.x__", "__vault.x", "__vault.x y__"] {
            let toml = format!(r#"
                [[transparent_placeholder]]
                token = "{bad}"
                vault_item = "x"
            "#);
            assert!(ServiceRegistry::from_toml_str(&toml).is_err(), "{bad} should fail");
        }
    }
```

- [ ] **Step 4: Run + commit**

```bash
cargo test --features transparent --lib proxy::registry
git add src/proxy/registry.rs
git commit -m "feat(registry): [[transparent_placeholder]] parsing + token validation"
```

---

### Task 5.2: Implement placeholder substitution

**Files:**
- Create: `src/proxy/transparent/inject_placeholder.rs`
- Modify: `src/proxy/transparent/mod.rs` + `src/proxy/transparent/mitm.rs`

- [ ] **Step 1: Implement**

Create `src/proxy/transparent/inject_placeholder.rs`:

```rust
//! Placeholder substitution: scan request body + header values for
//! literal `__vault.<name>__` tokens and replace each with the
//! corresponding vault item field value.
//!
//! Substitution is literal-string (not regex / not JSON-aware) for
//! predictability and bounded cost. Bodies whose Content-Type is
//! outside the textual allowlist pass through untouched.

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use std::sync::Arc;

use crate::proxy::registry::TransparentPlaceholder;
use crate::proxy::transparent::mitm::HttpRequest;
use crate::vault::VaultManager;

const TEXTUAL_CONTENT_TYPES: &[&str] = &[
    "application/json",
    "application/x-www-form-urlencoded",
    "text/",
];

pub async fn substitute(
    mut req: HttpRequest,
    placeholders: &[TransparentPlaceholder],
    vault: Arc<VaultManager>,
    vault_folder: &str,
    body_limit_bytes: usize,
) -> Result<HttpRequest> {
    let placeholders_used = find_placeholders_in_request(&req);
    if placeholders_used.is_empty() {
        return Ok(req);
    }

    // Resolve every placeholder once (cache local to this request).
    let mut resolved: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for token in &placeholders_used {
        let cfg = placeholders.iter().find(|p| &p.token == token).ok_or_else(|| {
            anyhow::anyhow!(
                "transparent placeholder '{token}' referenced in request but not declared \
                 in any [[transparent_placeholder]] block"
            )
        })?;
        let value = vault
            .get_item_field(vault_folder, &cfg.vault_item, &cfg.field)
            .await
            .with_context(|| {
                format!(
                    "resolve placeholder '{}' → vault item '{}' field '{}'",
                    token, cfg.vault_item, cfg.field
                )
            })?;
        resolved.insert(token.clone(), value);
    }

    // Header substitution.
    for (_, v) in req.headers.iter_mut() {
        for (token, value) in &resolved {
            if v.contains(token) {
                *v = v.replace(token, value);
            }
        }
    }

    // Body substitution — only for textual content types within size cap.
    let content_type = req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let is_textual = TEXTUAL_CONTENT_TYPES
        .iter()
        .any(|prefix| content_type.starts_with(prefix));

    if !is_textual {
        return Ok(req);
    }
    if req.body.len() > body_limit_bytes {
        tracing::warn!(
            len = req.body.len(),
            limit = body_limit_bytes,
            "placeholder: body exceeds limit; forwarding without substitution",
        );
        return Ok(req);
    }

    let mut body_str = std::str::from_utf8(&req.body)
        .map(|s| s.to_string())
        .map_err(|_| anyhow::anyhow!("body declared textual content-type but is not valid UTF-8"))?;
    for (token, value) in &resolved {
        body_str = body_str.replace(token, value);
    }
    req.body = Bytes::from(body_str.into_bytes());
    Ok(req)
}

fn find_placeholders_in_request(req: &HttpRequest) -> Vec<String> {
    let mut out = std::collections::BTreeSet::new();
    let mut scan = |s: &str| {
        let mut rest = s;
        while let Some(start) = rest.find("__vault.") {
            if let Some(end_rel) = rest[start..].find("__")
                .and_then(|first| rest[start + first + 2..].find("__").map(|e| start + first + 2 + e))
            {
                let token = &rest[start..end_rel + 2];
                out.insert(token.to_string());
                rest = &rest[end_rel + 2..];
            } else {
                break;
            }
        }
    };
    scan(&req.path);
    for (_, v) in &req.headers {
        scan(v);
    }
    if let Ok(s) = std::str::from_utf8(&req.body) {
        scan(s);
    }
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn substitutes_in_body_when_json() {
        let req = HttpRequest {
            method: "POST".into(),
            path: "/".into(),
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: Bytes::from_static(b"{\"key\":\"__vault.pat__\"}"),
        };
        let pl = vec![TransparentPlaceholder {
            token: "__vault.pat__".into(),
            vault_item: "stub".into(),
            field: "password".into(),
        }];
        let vault = Arc::new(crate::vault::VaultManager::new_stub());
        vault.insert_test_item("vault-proxy", "stub", "real-value");
        let out = substitute(req, &pl, vault, "vault-proxy", 32 * 1024 * 1024).await.unwrap();
        assert_eq!(out.body, Bytes::from_static(b"{\"key\":\"real-value\"}"));
    }

    #[tokio::test]
    async fn passes_through_binary_bodies() {
        let body = Bytes::from(vec![0u8, 1, 2, 3, 0xff, b'_', b'_', b'v', b'a', b'u', b'l', b't', b'.', b'x', b'_', b'_']);
        let req = HttpRequest {
            method: "POST".into(),
            path: "/".into(),
            headers: vec![("Content-Type".into(), "application/octet-stream".into())],
            body: body.clone(),
        };
        let pl = vec![TransparentPlaceholder {
            token: "__vault.x__".into(),
            vault_item: "stub".into(),
            field: "password".into(),
        }];
        let vault = Arc::new(crate::vault::VaultManager::new_stub());
        vault.insert_test_item("vault-proxy", "stub", "real");
        let out = substitute(req, &pl, vault, "vault-proxy", 32 * 1024 * 1024).await.unwrap();
        assert_eq!(out.body, body); // unchanged
    }

    #[tokio::test]
    async fn errors_when_token_not_declared() {
        let req = HttpRequest {
            method: "POST".into(),
            path: "/".into(),
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: Bytes::from_static(b"{\"x\":\"__vault.unknown__\"}"),
        };
        let pl = vec![];
        let vault = Arc::new(crate::vault::VaultManager::new_stub());
        let err = substitute(req, &pl, vault, "vault-proxy", 32 * 1024 * 1024).await.unwrap_err();
        assert!(err.to_string().contains("not declared"));
    }
}
```

- [ ] **Step 2: Declare module + wire from mitm**

`src/proxy/transparent/mod.rs`:

```rust
pub mod inject_placeholder;
```

`src/proxy/transparent/mitm.rs`: replace the `Placeholder` arm:

```rust
        crate::proxy::registry::TransparentMode::Placeholder => {
            let placeholders = state_placeholders.clone();
            crate::proxy::transparent::inject_placeholder::substitute(
                req,
                &placeholders,
                vault.clone(),
                vault_folder,
                32 * 1024 * 1024,
            )
            .await?
        }
```

(`state_placeholders` is added in Task 5.3.)

- [ ] **Step 3: Run + commit**

```bash
cargo test --features transparent --lib transparent::inject_placeholder
git add src/proxy/transparent/inject_placeholder.rs src/proxy/transparent/mod.rs src/proxy/transparent/mitm.rs
git commit -m "feat(transparent): placeholder substitution

Scans request path, header values, and (when Content-Type is textual)
the request body for __vault.<name>__ literals. Each token is resolved
via the [[transparent_placeholder]] map to a vault item field. Binary
bodies and oversize bodies pass through with WARN."
```

---

### Task 5.3: Plumb placeholders Arc into the listener

**Files:**
- Modify: `src/proxy/transparent/mod.rs`, `mitm.rs`

- [ ] **Step 1: Thread Arc<Vec<TransparentPlaceholder>> through**

In `spawn_listener_with_ca`, after building the registry snapshot, also snapshot placeholders:

```rust
    let placeholders = Arc::new({
        let reg = state.registry.read().await;
        reg.transparent_placeholders().to_vec()
    });
```

Thread `placeholders` into `handle_connection` → `mitm::run`. Update `mitm::run` signature to take `placeholders: Arc<Vec<TransparentPlaceholder>>`.

- [ ] **Step 2: Verify build + run all transparent tests**

```bash
cargo test --features transparent,test-utils --tests transparent_
```

Expected: all green.

- [ ] **Step 3: Commit**

```bash
git add src/proxy/transparent/mod.rs src/proxy/transparent/mitm.rs
git commit -m "wire(transparent): plumb placeholder snapshot into MITM path"
```

---

### Task 5.4: E2E placeholder integration test

**Files:**
- Create: `tests/transparent_placeholder.rs`

- [ ] **Step 1: Write the test**

Same pattern as the bearer/header E2Es. Service block:

```toml
[[service]]
name = "test_upstream"
base_url = "{upstream}"
auth = "bearer"   # required field, but unused since transparent_mode = "placeholder"
vault_item = "unused"
transparent_mode = "placeholder"

[[transparent_placeholder]]
token = "__vault.pat__"
vault_item = "test-placeholder"
```

Client posts JSON `{"token":"__vault.pat__"}`. Wiremock matches body exactly equal to `{"token":"swapped-value"}` (using `body_string` matcher).

- [ ] **Step 2: Test + commit**

```bash
cargo test --features transparent,test-utils --test transparent_placeholder
git add tests/transparent_placeholder.rs
git commit -m "test(transparent): E2E placeholder substitution in JSON body"
```

---

### Task 5.5: 502 envelope on unresolved placeholder

**Files:**
- Modify: `src/proxy/transparent/mitm.rs`

- [ ] **Step 1: Catch the `not declared` error**

In `mitm::run`, after the `Placeholder` arm, map the error type to a 502 envelope written back to the agent over the TLS stream rather than propagating up:

```rust
    let injected = match service.transparent_mode {
        // ... HostInject as before ...
        crate::proxy::registry::TransparentMode::Placeholder => {
            match crate::proxy::transparent::inject_placeholder::substitute(
                req, &placeholders, vault.clone(), vault_folder, 32 * 1024 * 1024,
            ).await {
                Ok(r) => r,
                Err(e) if e.to_string().contains("not declared") => {
                    write_error_over_tls(&mut agent_tls, 502, "placeholder_unresolved", &e.to_string()).await?;
                    return Ok(());
                }
                Err(e) if e.to_string().contains("resolve placeholder") => {
                    write_error_over_tls(&mut agent_tls, 502, "vault_resolution_failed", &e.to_string()).await?;
                    return Ok(());
                }
                Err(e) => return Err(e),
            }
        }
        _ => unreachable!(),
    };
```

Add `write_error_over_tls`:

```rust
async fn write_error_over_tls<S: tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    status: u16,
    code: &str,
    message: &str,
) -> Result<()> {
    let body = serde_json::json!({
        "ok": false,
        "error": message,
        "transparent_error_code": code,
    });
    let body_bytes = serde_json::to_vec(&body)?;
    let reason = match status { 502 => "Bad Gateway", 504 => "Gateway Timeout", _ => "Error" };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body_bytes.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&body_bytes).await?;
    Ok(())
}
```

- [ ] **Step 2: Test — agent gets a 502 with the right code**

In `tests/transparent_placeholder.rs`, add a second `#[tokio::test]` that sends `__vault.never_declared__` and asserts the response is 502 with `transparent_error_code = "placeholder_unresolved"`.

- [ ] **Step 3: Run + commit**

```bash
cargo test --features transparent,test-utils --test transparent_placeholder
git add src/proxy/transparent/mitm.rs tests/transparent_placeholder.rs
git commit -m "feat(transparent): 502 placeholder_unresolved envelope to agent"
```

---

## Phase 6 — services.toml policy flags + hot-reload (≈2 days)

### Task 6.1: `--transparent-default-mode` flag

**Files:**
- Modify: `src/main.rs`, `src/proxy/registry.rs`

- [ ] **Step 1: Add flag**

In `src/main.rs::Args`:

```rust
    /// Default transparent_mode for services that don't specify one.
    /// Only takes effect when --features transparent is built in.
    #[cfg(feature = "transparent")]
    #[arg(long, env = "TRANSPARENT_DEFAULT_MODE", default_value = "off")]
    transparent_default_mode: String,
```

- [ ] **Step 2: Apply the default in registry parse**

In `ServiceRegistry::from_toml_*`, after parsing, walk each entry and apply the default if the field was absent. This requires distinguishing "field absent" from "field set to off". Use `Option<TransparentMode>` in `RawService`, then resolve.

Modify `RawService`:

```rust
    #[cfg(feature = "transparent")]
    transparent_mode: Option<TransparentMode>,
```

Add a setter on `ServiceRegistry`:

```rust
#[cfg(feature = "transparent")]
pub fn apply_transparent_default(&mut self, default: TransparentMode) {
    for entry in self.entries.iter_mut() {
        if entry.transparent_mode_explicit.is_none() {
            // ... write the default into the resolved field
        }
    }
}
```

(The exact API depends on the existing registry mutability model. If entries are immutable after construction, take the default as a parameter to `from_toml_str` or `build` instead.)

- [ ] **Step 3: Wire from main.rs**

After building the registry:

```rust
    #[cfg(feature = "transparent")]
    {
        let default = parse_transparent_mode(&args.transparent_default_mode)?;
        registry.apply_transparent_default(default);
    }
```

`parse_transparent_mode` is a small helper that maps strings → enum + returns a clear error on unknown values.

- [ ] **Step 4: Test + commit**

```bash
cargo test --features transparent --lib proxy::registry
git add src/main.rs src/proxy/registry.rs
git commit -m "feat(cli): --transparent-default-mode flag"
```

---

### Task 6.2: `--transparent-unregistered-policy` flag + allowlist enforcement

**Files:**
- Modify: `src/main.rs`, `src/proxy/transparent/mod.rs`

- [ ] **Step 1: Add flag + plumb through**

```rust
    /// Behaviour for hosts that have NO [[service]] block.
    ///   "passthrough" (default) — relay TCP unchanged
    ///   "allowlist"             — reject with 502 unregistered_host_blocked
    #[cfg(feature = "transparent")]
    #[arg(long, env = "TRANSPARENT_UNREGISTERED_POLICY", default_value = "passthrough")]
    transparent_unregistered_policy: String,
```

In `spawn_listener_with_ca`, accept a `UnregisteredPolicy` enum and thread into `handle_connection`.

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnregisteredPolicy { Passthrough, Allowlist }
```

In `handle_connection`, when the lookup returns `None`:

```rust
        None => {
            match unregistered_policy {
                UnregisteredPolicy::Passthrough => { /* tunnel as today */ }
                UnregisteredPolicy::Allowlist => {
                    reply_error(
                        &mut stream,
                        502,
                        "unregistered_host_blocked",
                        &format!("host {} has no [[service]] block; allowlist policy active", target),
                    ).await?;
                    return Ok(());
                }
            }
        }
```

- [ ] **Step 2: E2E test**

`tests/transparent_allowlist.rs`:

- spawn listener with `UnregisteredPolicy::Allowlist`, no services
- raw TCP CONNECT to `unknown.example:443`
- assert 502 + JSON body has `transparent_error_code = "unregistered_host_blocked"`

- [ ] **Step 3: Test + commit**

```bash
cargo test --features transparent,test-utils --test transparent_allowlist
git add src/main.rs src/proxy/transparent/mod.rs tests/transparent_allowlist.rs
git commit -m "feat(transparent): --transparent-unregistered-policy=allowlist enforcement"
```

---

### Task 6.3: SIGHUP rebuilds transparent registry

**Files:**
- Modify: `src/main.rs` (the existing SIGHUP handler), `src/proxy/transparent/mod.rs` (expose rebuild API)

- [ ] **Step 1: Expose a rebuild helper**

In `src/proxy/transparent/mod.rs`:

```rust
pub async fn rebuild_registry(
    cell: &registry::TransparentRegistryCell,
    placeholders_cell: &Arc<tokio::sync::RwLock<Vec<crate::proxy::registry::TransparentPlaceholder>>>,
    registry_snapshot: &crate::proxy::registry::ServiceRegistry,
) -> Result<()> {
    let new = registry::TransparentRegistry::build(registry_snapshot)?;
    *cell.write().await = new;
    *placeholders_cell.write().await = registry_snapshot.transparent_placeholders().to_vec();
    Ok(())
}
```

Modify `spawn_listener_with_ca` to return the two cells so main.rs can call rebuild after SIGHUP.

- [ ] **Step 2: Hook into existing SIGHUP path**

Locate the SIGHUP handler in `src/main.rs` (it currently rebuilds the primary registry per `RELOAD.md`). After it swaps the registry, call `transparent::rebuild_registry(...)`.

- [ ] **Step 3: Test**

`tests/transparent_hot_reload.rs`:

- spawn listener with empty registry, CONNECT to `acme.example:443` returns 502 (allowlist mode)
- programmatically replace the registry snapshot in `state.registry` with one containing the host + call `transparent::rebuild_registry`
- new CONNECT now succeeds via passthrough/MITM (depending on mode set)

- [ ] **Step 4: Test + commit**

```bash
cargo test --features transparent,test-utils --test transparent_hot_reload
git add src/main.rs src/proxy/transparent/mod.rs tests/transparent_hot_reload.rs
git commit -m "feat(transparent): SIGHUP rebuilds transparent registry + placeholders"
```

---

### Task 6.4: `--check` validators

**Files:**
- Modify: the existing `--check` codepath in `src/main.rs`

- [ ] **Step 1: Plug in placeholder + collision validation**

After the existing services.toml parse in `--check`:

```rust
    #[cfg(feature = "transparent")]
    {
        // Building the transparent registry runs all collision checks.
        crate::proxy::transparent::registry::TransparentRegistry::build(&registry)
            .map_err(|e| anyhow::anyhow!("transparent registry validation failed: {e}"))?;
        // Placeholder token validation already runs during ServiceRegistry parse.
        // Warn on session/unifi_dual + host_inject combo (Task 4.3 already errors).
    }
```

- [ ] **Step 2: Integration test**

Add a `tests/transparent_check.rs` that constructs a services.toml with a host:port collision and asserts `vault-proxy --check` exits non-zero with the right message. Run vault-proxy as a subprocess.

- [ ] **Step 3: Commit**

```bash
cargo test --features transparent --test transparent_check
git add src/main.rs tests/transparent_check.rs
git commit -m "feat(check): transparent registry validation during --check"
```

---

## Phase 7 — Audit log integration + error envelopes (≈2 days)

### Task 7.1: Extend AuditLog with transparent trigger

**Files:**
- Modify: `src/audit.rs` (or wherever AuditLog lives — locate first)

- [ ] **Step 1: Add the trigger variant**

Find the existing `enum Trigger` (or string discriminator). Add `Transparent` variant.

Extend the audit entry struct to optionally include `transparent_mode`, `upstream_host`, `upstream_status`, `bytes_in`, `bytes_out`, `duration_ms`. Use `Option<>` so existing entries unaffected.

- [ ] **Step 2: Emit from mitm::run + passthrough::tunnel**

In `mitm::run`, after `agent_tls.shutdown()`:

```rust
    state.audit_log.append(AuditEntry {
        timestamp: chrono::Utc::now(),
        tool_name: format!("transparent::{}::{}", service.transparent_mode_str(), service.name),
        args_summary: format!("host={} mode={}", target, service.transparent_mode_str()),
        result_summary: format!("status={} bytes_in={} bytes_out={}", upstream_status, bytes_in, bytes_out),
        permission: Permission::Log,
        trigger: Trigger::Transparent,
        transparent_mode: Some(service.transparent_mode_str().into()),
        upstream_host: Some(target.host.clone()),
        upstream_status: Some(upstream_status),
        bytes_in: Some(bytes_in),
        bytes_out: Some(bytes_out),
        duration_ms: Some(start.elapsed().as_millis() as u64),
    }).await;
```

(`upstream_status` and byte counts need to be plumbed up from `forward_to_upstream`. Adjust signature: return `(status, bytes_in, bytes_out, response_bytes)` from forwarders.)

- [ ] **Step 3: Existing sensitive-field masking applies**

Verify in code review: nothing in `args_summary` / `result_summary` echoes credentials. Add a `tests/transparent_audit.rs` that runs a host_inject request and reads `audit-log.json`, asserting the entry exists with `trigger == "transparent"` and no credential string appears.

- [ ] **Step 4: Run + commit**

```bash
cargo test --features transparent,test-utils --test transparent_audit
git add src/audit.rs src/proxy/transparent/mitm.rs src/proxy/transparent/passthrough.rs tests/transparent_audit.rs
git commit -m "feat(audit): trigger=transparent entries with mode/host/status/bytes/duration"
```

---

### Task 7.2: Standardise error envelope

**Files:**
- Modify: `src/proxy/transparent/mitm.rs` (and `mod.rs::reply_error`)

- [ ] **Step 1: Create a single `TransparentErrorCode` enum**

In `src/proxy/transparent/mod.rs`:

```rust
#[derive(Debug, Clone, Copy)]
pub enum TransparentErrorCode {
    MalformedConnect,
    UpstreamUnreachable,
    UnregisteredHostBlocked,
    VaultResolutionFailed,
    PlaceholderUnresolved,
    AgentReadTimeout,
}

impl TransparentErrorCode {
    pub fn http_status(&self) -> u16 {
        match self {
            Self::MalformedConnect => 400,
            Self::AgentReadTimeout => 504,
            _ => 502,
        }
    }
    pub fn discriminator(&self) -> &'static str {
        match self {
            Self::MalformedConnect => "malformed_connect",
            Self::UpstreamUnreachable => "upstream_unreachable",
            Self::UnregisteredHostBlocked => "unregistered_host_blocked",
            Self::VaultResolutionFailed => "vault_resolution_failed",
            Self::PlaceholderUnresolved => "placeholder_unresolved",
            Self::AgentReadTimeout => "agent_read_timeout",
        }
    }
}
```

Refactor every error-write call site to take a `TransparentErrorCode`:

```rust
async fn reply_error_typed<S: tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    code: TransparentErrorCode,
    message: &str,
) -> Result<()> { /* serialise as before */ }
```

- [ ] **Step 2: Tests for each error code path**

In `tests/transparent_errors.rs`:

- Send a `GET / HTTP/1.1` instead of CONNECT → assert 400 + `malformed_connect`
- Configure allowlist mode + unknown host → 502 + `unregistered_host_blocked`
- Configure service with vault_item that doesn't exist → 502 + `vault_resolution_failed`
- Send `__vault.never_declared__` in a placeholder body → 502 + `placeholder_unresolved`

- [ ] **Step 3: Run + commit**

```bash
cargo test --features transparent,test-utils --test transparent_errors
git add src/proxy/transparent/mod.rs src/proxy/transparent/mitm.rs tests/transparent_errors.rs
git commit -m "feat(transparent): typed error codes + unified envelope"
```

---

## Phase 8 — E2E smoke (curl / python / node) (≈2 days)

### Task 8.1: Test harness — vault-proxy subprocess + wiremock

**Files:**
- Create: `tests/e2e_transparent/mod.rs`, `tests/e2e_transparent/harness.rs`

- [ ] **Step 1: Spawn vault-proxy + wiremock**

Write a Rust test harness that:
- Spawns wiremock on ephemeral HTTP port
- Spawns the vault-proxy binary (built via `env!("CARGO_BIN_EXE_vaultproxy")`) with `--config-dir` pointing at a tempdir containing services.toml + a pre-unlocked keystore
- Waits for the transparent listener to bind 3203 (or ephemeral)
- Returns handles for cleanup

- [ ] **Step 2: Smoke test using `reqwest`**

```rust
#[tokio::test]
async fn smoke_reqwest_e2e() {
    let h = harness::spawn().await;
    let client = reqwest::Client::builder()
        .add_root_certificate(h.ca_cert.clone())
        .proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{}", h.transparent_port)).unwrap())
        .build().unwrap();
    let resp = client.get(format!("{}/me", h.upstream_uri)).send().await.unwrap();
    assert_eq!(resp.status(), 200);
}
```

- [ ] **Step 3: Commit**

```bash
git add tests/e2e_transparent/
git commit -m "test(e2e): harness for transparent-mode smoke tests"
```

---

### Task 8.2: curl smoke

**Files:**
- Modify: `tests/e2e_transparent/`

- [ ] **Step 1: Add a test that shells out to `curl --cacert ... -x http://... https://...` and asserts exit 0 + injected header arrived at wiremock.**

```rust
#[tokio::test]
async fn smoke_curl_e2e() {
    let h = harness::spawn().await;
    // Write CA cert to a tempfile.
    let ca_path = h.config_dir.join("transparent-ca.crt");
    let status = std::process::Command::new("curl")
        .args([
            "--cacert", ca_path.to_str().unwrap(),
            "-x", &format!("http://127.0.0.1:{}", h.transparent_port),
            "-s", "-o", "/dev/null", "-w", "%{http_code}",
            &format!("{}/me", h.upstream_uri),
        ])
        .output().unwrap();
    let code = String::from_utf8(status.stdout).unwrap();
    assert_eq!(code, "200");
}
```

- [ ] **Step 2: Commit**

```bash
git commit -m "test(e2e): curl smoke through transparent proxy"
```

---

### Task 8.3: Python smoke (requires `python3` + `requests` in CI image)

```rust
#[tokio::test]
async fn smoke_python_requests_e2e() {
    let h = harness::spawn().await;
    let script = format!(
        "import os, requests; os.environ['REQUESTS_CA_BUNDLE'] = '{ca}'; \
         r = requests.get('{url}', proxies={{'https': 'http://127.0.0.1:{port}'}}); \
         print(r.status_code)",
        ca = h.config_dir.join("transparent-ca.crt").display(),
        url = format!("{}/me", h.upstream_uri),
        port = h.transparent_port,
    );
    let out = std::process::Command::new("python3").args(["-c", &script]).output().unwrap();
    assert!(String::from_utf8(out.stdout).unwrap().contains("200"));
}
```

Commit individually.

---

### Task 8.4: Node smoke (requires `node` in CI image)

Similar shape, using `node -e`. Commit individually.

---

### Task 8.5: Wire into CI

**Files:**
- Modify: `.github/workflows/docker-publish.yml`

- [ ] **Step 1: Add the transparent feature matrix step**

After the existing `Run tests (full feature matrix)` step:

```yaml
      - name: Run tests (transparent feature)
        run: cargo test --all-targets --features transparent,test-utils

      - name: Run tests (all features combined)
        run: cargo test --all-targets --features browser,engine,dashboard,transparent,test-utils
```

- [ ] **Step 2: Ensure python3 + node + curl are present**

Add a step before tests:

```yaml
      - name: Install E2E tooling
        run: |
          sudo apt-get update
          sudo apt-get install -y python3 python3-requests curl
          # node is pre-installed on ubuntu-24.04 runner
```

- [ ] **Step 3: Commit + push, watch CI green**

```bash
git add .github/workflows/docker-publish.yml
git commit -m "ci: transparent feature matrix + E2E tooling"
git push origin main
```

---

## Phase 9 — Documentation (≈2 days)

### Task 9.1: `docs/operator/TRANSPARENT.md`

**Files:**
- Create: `docs/operator/TRANSPARENT.md`

- [ ] **Step 1: Write the doc** (≈400 lines covering: what it is, when to use vs /proxy, decision tree, services.toml schema, placeholder syntax, --transparent-* CLI reference, audit log shape, error code table, troubleshooting)

- [ ] **Step 2: Commit**

```bash
git add docs/operator/TRANSPARENT.md
git commit -m "docs: operator guide for transparent HTTPS_PROXY mode"
```

---

### Task 9.2: `docs/operator/TRANSPARENT-CA.md`

**Files:**
- Create: `docs/operator/TRANSPARENT-CA.md`

- [ ] **Step 1: Per-platform CA install instructions** (Linux system, per-language env vars, macOS Keychain, Windows certutil, rotation steps, BYO mode setup)

- [ ] **Step 2: Commit**

```bash
git commit -m "docs: per-platform CA install + rotation runbook"
```

---

### Task 9.3: `SECURITY.md` update

**Files:**
- Modify: `SECURITY.md`

- [ ] **Step 1: Add a new section `## Transparent HTTPS_PROXY (--features transparent)`** covering:
  - CA private key as Tier-1 secret
  - Loopback bind by default
  - BYO mode threat differences
  - Why we refuse to start with world-readable key file
  - Reference to `docs/operator/TRANSPARENT-CA.md`

- [ ] **Step 2: Commit**

```bash
git commit -m "docs(security): transparent CA threat model"
```

---

### Task 9.4: README updates

**Files:**
- Modify: `README.md`

- [ ] **Step 1: In the comparison table (§How it compares), update vault-proxy column for the Transparent HTTPS_PROXY row from ❌ to ✅ (with footnote that it lands in v1.1).**

- [ ] **Step 2: In the feature highlights table, add a row:**

```
| Transparent HTTPS_PROXY listener | ✅ `--features transparent` (since v1.1.0) | [docs/operator/TRANSPARENT.md](docs/operator/TRANSPARENT.md) |
```

- [ ] **Step 3: Commit**

```bash
git commit -m "docs(readme): comparison table + features table reflect transparent mode"
```

---

### Task 9.5: `services.example.toml`

**Files:**
- Modify: `services.example.toml`

- [ ] **Step 1: Add an annotated transparent example block**

```toml
# ── Example: transparent HTTPS_PROXY mode ──────────────────────────────────
# Requires --features transparent at build time.
#
# This entry tells vault-proxy to intercept HTTPS traffic from any agent
# whose HTTPS_PROXY=http://127.0.0.1:3203 reaches api.github.com:443 and
# inject a Bearer token from Vaultwarden BEFORE the request leaves the host.
# Agent does not need to know about the credential at all.
#
# [[service]]
# name             = "github_api"
# base_url         = "https://api.github.com"
# auth             = "bearer"
# vault_item       = "vault-proxy - GitHub PAT"
# transparent_mode = "host_inject"

# Optional: placeholders for credentials not tied to a single host.
#
# [[transparent_placeholder]]
# token      = "__vault.github_pat__"
# vault_item = "vault-proxy - GitHub PAT"
```

- [ ] **Step 2: Commit + push**

```bash
git commit -m "docs(example): annotated transparent_mode + placeholder block"
git push origin main
```

---

## Phase 10 — Soak + tag releases (≈5 days)

### Task 10.1: Tag v1.1.0-beta.1

Same shape as Task 1.5. Version `1.1.0-beta.1`. Push tag. Watch CI green.

### Task 10.2: 7-day soak period

- Run vault-proxy with `--features transparent` in the author's homelab against real services for 7 calendar days.
- Track every issue in a `BETA1-SOAK.md` scratch file or GitHub issues with `soak-beta1` label.
- No code changes during soak unless they fix a P0 (data loss, crash, security).

### Task 10.3: Tag v1.1.0-beta.2 (bugfixes from soak)

For each P0/P1 from soak:
- Branch fix/<issue>
- TDD-style fix (test first, then change)
- Merge to main

After ≥3 days clean on beta.2:

### Task 10.4: Tag v1.1.0 GA

- Bump Cargo.toml to `1.1.0`
- Full lint + test sweep
- Tag, push
- Verify GHCR `:1.1.0` + `:latest`
- `cargo publish` (via the existing `vaultproxy-publish` launcher entry)

---

## Phase 11 — v1.2.0 default-on (≈1 day; separate calendar week)

### Task 11.1: Flip default in Cargo.toml

```toml
[features]
default = ["transparent"]
```

Update `transparent` feature documentation in Cargo.toml to note it is now default.

### Task 11.2: Update README and Dockerfile

- README quickstart: remove `--features transparent` mention since it's default.
- Dockerfile: keep build-arg pattern intact; default image now includes transparent listener.

### Task 11.3: Tag v1.2.0

Full sweep + tag + push + cargo publish.

---

## Self-Review

(Run by the plan author after writing; corrections applied inline.)

**1. Spec coverage:**

- §3 architecture diagram → Phase 1 + Phase 3 implementation ✓
- §4 TLS / CA management → Phase 2 ✓
- §5 services.toml schema → Phase 3 (field) + Phase 5 (placeholder block) + Phase 6 (defaults/policy) ✓
- §6 internals + error handling → Phase 7 (error envelopes), Phase 1-6 (modules) ✓
- §7 testing strategy → Tests interwoven per TDD pattern in every phase + Phase 8 E2E ✓
- §8 rollout plan → Phase 10 tags + Phase 11 default flip ✓
- §9 timeline → matches phase headers ✓
- §10 risk register → mitigations live in: forbidden-header strip (G3 risk), refuse-to-start on perm drift (G7 risk), per-platform install docs (G1 risk) ✓
- §11 hard cutoffs → reflected in non-goals: no HTTP/2 (Phase 1 parser explicitly rejects), TLS-only (passthrough is TCP relay; placeholder/host_inject require TLS handshake which fails for plain HTTP upstreams), loopback bind warning (Task 1.4) ✓
- §12 backwards compatibility → preserved via cfg(feature = transparent) gating throughout ✓
- §13 open questions → resolved inline:
  - lru version: `0.12` (Task 0.2)
  - cert pre-warm: not done in v1.1; lazy-only (Task 2.5 caches on first miss)
  - audit batch flush: existing 10-entry / shutdown flush unchanged (deferred)
  - per-connection tracing::Span: not added in v1.1 (deferred)
  - forbidden header list: enumerated explicitly in Task 3.4

**2. Placeholder scan:**
- "Same shape as Task 1.5" in Task 2.7, 10.1 — acceptable since 1.5 fully spells out the pattern (commit + tag + push) and steps are mechanical. Reader can scan 1.5 once.
- Tasks 4.1 and 4.2 have abbreviated E2E test descriptions ("same pattern as 3.6/3.7"). Acceptable for the same reason; 3.6 has the full test code template.
- All actual code blocks are complete.

**3. Type consistency:**
- `TransparentMode` enum used identically across registry.rs, transparent/registry.rs, mitm.rs ✓
- `TransparentPlaceholder` struct: `token`, `vault_item`, `field` consistent ✓
- `HttpRequest` struct: same shape in mitm.rs and inject_*.rs ✓
- `TransparentErrorCode` enum: spec §6 lists `malformed_connect`, `upstream_unreachable`, `unregistered_host_blocked`, `vault_resolution_failed`, `placeholder_unresolved`, `agent_read_timeout` — Task 7.2 enum matches ✓
- `CertFactory::leaf_for` signature stable: `(host: &str, port: u16) -> Result<LeafCert>` ✓
- `spawn_listener_with_ca` signature evolves: Task 1.4 → Task 2.4 → Task 3.5. Each evolution is explicit (and the test in Task 1.3 is updated in Task 2.4 step 3).

No further issues found.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-05-24-transparent-https-proxy-impl.md`. Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration. Best for this plan because every task is self-contained TDD with a clear pass/fail gate.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints. Best if you want me to power through phases with minimal context switches.

Which approach?
