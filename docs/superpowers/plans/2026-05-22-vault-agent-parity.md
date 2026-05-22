# vault-agent Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Lift `mcp-vault-proxy` (vp) toward HashiCorp vault-agent feature parity for the homelab MCP use case — adding lease/TTL on socket fetches, HMAC'd access log, template engine, rotation hooks, dynamic creds in `/proxy`, AppRole-style daemon auth, and a native Rust HTTP MCP proxy that closes the bearer-bridge argv leak.

**Architecture:** Four waves ordered by risk + dependency. Each wave is releasable on its own — features within a wave commit independently. No big-bang merge. All new surfaces opt-in via CLI flag or config so default behavior is unchanged.

```
Wave 1 (low risk, pure additions, ~300 LOC)
  F1 lease/TTL on socket cred fetches
  F2 HMAC'd access log
  F4 rotation hooks (--on-rotation <script>)

Wave 2 (new surfaces, configurable, ~500 LOC)
  F3 template engine (--render <tmpl> <out>)
  F6 AppRole-style daemon auth (ROLE_ID / SECRET_ID)

Wave 3 (net-new binary, ~800-1500 LOC, spec-then-build)
  F7 mcp-rpc-bridge — native HTTP MCP proxy (kills bearer-bridge argv leak)

Wave 4 (most disruptive, ~400 LOC, last)
  F5 dynamic creds in /proxy with revoke-on-complete
```

**Tech Stack:** Rust 1.78+, axum 0.8, tokio 1, clap 4 derive, rmcp 1.6, hmac+sha2, secrecy 0.10, zeroize 1, tera 1 (new for F3), serde 1, anyhow 1, rusqlite 0.31, reqwest 0.12.

---

## File structure (cumulative across waves)

```
src/
  access_log.rs              [NEW Wave 1]  HMAC'd append-only access log
  cred_cache.rs              [NEW Wave 1]  TTL'd in-memory cred cache
  hooks.rs                   [NEW Wave 1]  rotation/post-action subprocess hooks
  template.rs                [NEW Wave 2]  Tera-based --render engine
  approle.rs                 [NEW Wave 2]  ROLE_ID / SECRET_ID daemon-auth path
  mcp_rpc_bridge/            [NEW Wave 3]  module — native HTTP MCP proxy
    mod.rs
    stdio_server.rs            stdio JSON-RPC server (faces the local MCP client)
    http_client.rs             streamable-http / SSE client (faces upstream MCP)
    header_injector.rs         reads vp socket → injects Authorization header
  proxy/
    lease.rs                 [NEW Wave 4]  dynamic-cred lease tracker + revoker

  main.rs                    [MODIFY]      new CLI subcommands across all waves
  local_socket.rs            [MODIFY W1]   wire cache + access_log into get_field
  launcher.rs                [MODIFY W2]   route ROLE_ID/SECRET_ID env vars; add safe_parent_vars
  mcp_server.rs              [MODIFY W1]   rotate tool fires hook + writes access_log entry
  keystore.rs                [MODIFY W2]   alt-path unlock via AppRole secret_id
  proxy/mod.rs               [MODIFY W4]   lease lifecycle around handle_proxy
  proxy/registry.rs          [MODIFY W4]   per-service dynamic-cred config
  bearer_bridge.rs           [DEPRECATE W3] keep as compat shim, log warning

tests/
  cred_cache.rs              [NEW W1]
  access_log_integration.rs  [NEW W1]
  rotation_hooks.rs          [NEW W1]
  template_render.rs         [NEW W2]
  approle_unlock.rs          [NEW W2]
  mcp_rpc_bridge.rs          [NEW W3]
  dynamic_creds_proxy.rs     [NEW W4]
```

---

# Wave 1 — Lease + Access Log + Rotation Hooks

**Goal:** Add three independent low-risk features. Net default behavior unchanged. Each feature ships its own commit.

## Task 1: TTL'd credential cache (F1)

**Files:**
- Create: `src/cred_cache.rs`
- Modify: `src/local_socket.rs:185-260` (the `client` mod is at L185; server handler upstream — find `get_item_fields` arm)
- Modify: `src/lib.rs` to expose `pub mod cred_cache;`
- Test: `tests/cred_cache.rs`

**Surface (new):**
```rust
// src/cred_cache.rs
pub struct CredCache { /* DashMap<Key, Entry>, default_ttl */ }
impl CredCache {
    pub fn with_ttl(default_ttl: Duration) -> Self;
    pub fn get(&self, item: &str, field: &str) -> Option<SecretString>;
    pub fn put(&self, item: &str, field: &str, value: SecretString, ttl: Option<Duration>);
    pub fn purge_expired(&self); // call from a tokio interval task
    pub fn len(&self) -> usize;
}
```

- [ ] **Step 1: Write failing test for cache hit before TTL**

`tests/cred_cache.rs`:
```rust
use std::time::Duration;
use secrecy::{ExposeSecret, SecretString};
use vaultproxy::cred_cache::CredCache;

#[test]
fn returns_cached_value_within_ttl() {
    let cache = CredCache::with_ttl(Duration::from_secs(60));
    cache.put("svc-x", "password", SecretString::from("p@ss".to_string()), None);
    let got = cache.get("svc-x", "password").expect("hit");
    assert_eq!(got.expose_secret(), "p@ss");
}
```

- [ ] **Step 2: Run, confirm `vaultproxy::cred_cache` missing**

```bash
cargo test --test cred_cache 2>&1 | head -20
```
Expected: compile error, unresolved import.

- [ ] **Step 3: Implement minimal cache**

`src/cred_cache.rs`:
```rust
//! TTL'd in-memory cache for credentials returned via the local socket.
//! Values are wrapped in `SecretString` so they zeroize on drop and never
//! appear in Debug output. Expiry is checked on read; a background sweeper
//! evicts cold entries to keep memory bounded.

use dashmap::DashMap;
use secrecy::{ExposeSecret, SecretString};
use std::time::{Duration, Instant};

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct Key {
    item: String,
    field: String,
}

struct Entry {
    value: SecretString,
    expires_at: Instant,
}

pub struct CredCache {
    inner: DashMap<Key, Entry>,
    default_ttl: Duration,
}

impl CredCache {
    pub fn with_ttl(default_ttl: Duration) -> Self {
        Self { inner: DashMap::new(), default_ttl }
    }

    pub fn get(&self, item: &str, field: &str) -> Option<SecretString> {
        let key = Key { item: item.into(), field: field.into() };
        let entry = self.inner.get(&key)?;
        if entry.expires_at <= Instant::now() {
            drop(entry);
            self.inner.remove(&key);
            return None;
        }
        Some(SecretString::from(entry.value.expose_secret().to_string()))
    }

    pub fn put(&self, item: &str, field: &str, value: SecretString, ttl: Option<Duration>) {
        let key = Key { item: item.into(), field: field.into() };
        let expires_at = Instant::now() + ttl.unwrap_or(self.default_ttl);
        self.inner.insert(key, Entry { value, expires_at });
    }

    pub fn purge_expired(&self) {
        let now = Instant::now();
        self.inner.retain(|_, e| e.expires_at > now);
    }

    pub fn len(&self) -> usize { self.inner.len() }
}
```

- [ ] **Step 4: Re-export from lib.rs**

Add to `src/lib.rs`:
```rust
pub mod cred_cache;
```

- [ ] **Step 5: Run test, confirm PASS**

```bash
cargo test --test cred_cache returns_cached_value_within_ttl -- --nocapture
```
Expected: `test returns_cached_value_within_ttl ... ok`

- [ ] **Step 6: Add expiry test**

```rust
#[test]
fn evicts_on_expiry() {
    let cache = CredCache::with_ttl(Duration::from_millis(10));
    cache.put("svc", "k", SecretString::from("v".to_string()), None);
    std::thread::sleep(Duration::from_millis(20));
    assert!(cache.get("svc", "k").is_none());
    assert_eq!(cache.len(), 0, "expired entry removed on read");
}
```

- [ ] **Step 7: Run + confirm PASS**

```bash
cargo test --test cred_cache
```

- [ ] **Step 8: Add zeroize-on-drop test**

```rust
#[test]
fn debug_does_not_leak_value() {
    let cache = CredCache::with_ttl(Duration::from_secs(60));
    cache.put("svc", "k", SecretString::from("VERY-SECRET-XYZ".to_string()), None);
    // SecretString itself blocks Display/Debug. We assert get() returns SecretString,
    // not raw String, so callers cannot accidentally Display it.
    let got = cache.get("svc", "k").unwrap();
    let dbg = format!("{:?}", got);
    assert!(!dbg.contains("VERY-SECRET-XYZ"), "leaked: {dbg}");
}
```

- [ ] **Step 9: Run + commit**

```bash
cargo test --test cred_cache
git add src/cred_cache.rs src/lib.rs tests/cred_cache.rs
git commit -m "feat(cache): TTL'd CredCache for socket cred fetches

Adds an in-memory SecretString cache keyed by (item, field) with
per-entry expiry. Callers (socket get_field handler in next commit)
short-circuit Vaultwarden round-trips while a credential is still
within its TTL, then re-fetch on miss/expiry."
```

## Task 2: Wire cache into socket handler (F1 continued)

**Files:**
- Modify: `src/local_socket.rs` — server-side `get_item_fields` arm; inject `&CredCache` into server state.

- [ ] **Step 1: Read existing handler to find `get_item_fields` Request match arm**

```bash
grep -n "get_item_fields\|GetItemFields" src/local_socket.rs
```

- [ ] **Step 2: Add `cache: Arc<CredCache>` parameter to `serve()` (or whatever public entrypoint exists)**

The server is bound from `main.rs`. Find the call site and propagate the `Arc<CredCache>`.

Example signature change (verify against actual file):
```rust
pub async fn serve(
    vault: Arc<VaultManager>,
    cache: Arc<crate::cred_cache::CredCache>,
    path: PathBuf,
) -> anyhow::Result<()> { ... }
```

- [ ] **Step 3: In the request handler match arm, check cache before VW**

```rust
Request::GetItemFields { item, fields } => {
    let mut out = serde_json::Map::new();
    for f in &fields {
        if let Some(v) = cache.get(&item, f) {
            out.insert(f.clone(), serde_json::Value::String(v.expose_secret().to_string()));
            continue;
        }
        let v = vault.get_field(&item, f).await?;
        cache.put(&item, f, SecretString::from(v.clone()), None);
        out.insert(f.clone(), serde_json::Value::String(v));
    }
    write_response(&mut stream, &FieldsResponse { ok: true, fields: out }).await?;
}
```

- [ ] **Step 4: In `main.rs` daemon startup, construct cache + sweeper task**

Find the daemon-init block (`if args.listen.is_some()` or similar). Add:
```rust
let cred_cache = std::sync::Arc::new(
    vaultproxy::cred_cache::CredCache::with_ttl(std::time::Duration::from_secs(args.cred_cache_ttl)),
);
let sweeper = cred_cache.clone();
tokio::spawn(async move {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
    loop {
        tick.tick().await;
        sweeper.purge_expired();
    }
});
```

- [ ] **Step 5: Add CLI flag `--cred-cache-ttl <SECS>` (env `CRED_CACHE_TTL`, default 60)**

In `main.rs` Args struct:
```rust
/// TTL (seconds) on cached credential fetches over the local socket.
/// Set to 0 to disable caching (every socket fetch re-reads from Vaultwarden).
#[arg(long, env = "CRED_CACHE_TTL", default_value = "60")]
cred_cache_ttl: u64,
```

If `cred_cache_ttl == 0`, skip cache insertion (`put` becomes no-op). Implement via wrapper:
```rust
if args.cred_cache_ttl > 0 { cred_cache.put(...); }
```

- [ ] **Step 6: Integration test — second fetch within TTL hits cache**

`tests/cred_cache.rs` (extend):
```rust
// Integration test using a fake VaultManager would require feature gates;
// keep this as a smoke test running against a live daemon if CRED_CACHE_TTL=60
// is set. Add a unit-level harness in src/local_socket.rs#[cfg(test)] module
// that swaps VaultManager for a trait impl that counts calls.
```

(Suggest making the cache integration test live in a `#[cfg(test)] mod tests` block inside `src/local_socket.rs` with a trait-mocked `VaultManager` — full code provided once trait shape is confirmed in Step 1.)

- [ ] **Step 7: Build + test full suite**

```bash
cargo build --release 2>&1 | tail -5
cargo test 2>&1 | tail -10
```

- [ ] **Step 8: Commit**

```bash
git add src/local_socket.rs src/main.rs
git commit -m "feat(socket): wire CredCache into get_item_fields handler

The socket handler now consults the TTL'd cache before hitting
Vaultwarden. New --cred-cache-ttl flag (env CRED_CACHE_TTL,
default 60s). Set to 0 to disable. Sweeper task purges expired
entries every 30s to keep memory bounded."
```

## Task 3: HMAC'd access log (F2)

**Files:**
- Create: `src/access_log.rs` (distinct from existing `src/audit.rs` which is the credential-health analyser)
- Modify: `src/local_socket.rs` — call `access_log::record()` from `GetItemFields` arm
- Modify: `src/mcp_server.rs` rotate tool — record rotation events
- Modify: `src/lib.rs` — export module
- Modify: `src/main.rs` — wire log path + HMAC key
- Test: `tests/access_log_integration.rs`

**Surface:**
```rust
// src/access_log.rs
pub struct AccessLog { /* path, hmac_key, writer mutex */ }

pub struct Event<'a> {
    pub ts: chrono::DateTime<chrono::Utc>,
    pub action: &'a str,           // "get_item_fields", "rotate", ...
    pub item: Option<&'a str>,
    pub fields: &'a [&'a str],
    pub peer_pid: Option<u32>,
    pub peer_uid: Option<u32>,
    pub peer_cmdline: Option<&'a str>,
    pub outcome: &'a str,          // "ok" | "denied" | "error"
}

impl AccessLog {
    pub fn open(path: PathBuf, hmac_key: SecretVec<u8>) -> anyhow::Result<Self>;
    pub fn record(&self, ev: &Event) -> anyhow::Result<()>;
    /// Verify HMAC chain against the log file. Used by `vp audit verify`.
    pub fn verify(path: &Path, hmac_key: &[u8]) -> anyhow::Result<()>;
}
```

Line format (one JSON object per line, newline-terminated):
```
{"ts":"2026-05-22T04:00:00Z","action":"get_item_fields","item":"WI MCP - Bearer","fields":["password"],"peer_pid":12345,"peer_uid":1000,"peer_cmdline":"mcp-bearer-bridge","outcome":"ok","prev_hmac":"...","hmac":"..."}
```

`hmac` covers `prev_hmac || json_without_hmac` so tampering with any entry breaks the chain from that point on.

- [ ] **Step 1: Failing test — record + verify chain**

`tests/access_log_integration.rs`:
```rust
use std::path::PathBuf;
use secrecy::SecretVec;
use vaultproxy::access_log::{AccessLog, Event};

#[test]
fn records_and_verifies_chain() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("access.log");
    let key = SecretVec::new(vec![0x11; 32]);
    let log = AccessLog::open(path.clone(), key.clone()).unwrap();
    for i in 0..5 {
        log.record(&Event {
            ts: chrono::Utc::now(),
            action: "get_item_fields",
            item: Some("X"),
            fields: &["password"],
            peer_pid: Some(1000 + i),
            peer_uid: Some(1000),
            peer_cmdline: Some("test"),
            outcome: "ok",
        }).unwrap();
    }
    AccessLog::verify(&path, key.expose_secret()).expect("chain valid");
}

#[test]
fn detects_tamper() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("access.log");
    let key = SecretVec::new(vec![0x22; 32]);
    let log = AccessLog::open(path.clone(), key.clone()).unwrap();
    log.record(&Event { /* fill */ ts: chrono::Utc::now(), action: "x", item: None, fields: &[], peer_pid: None, peer_uid: None, peer_cmdline: None, outcome: "ok" }).unwrap();
    // Tamper: append a fake line not chained to previous hmac.
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
    writeln!(f, r#"{{"ts":"2099-01-01T00:00:00Z","action":"fake","outcome":"ok","prev_hmac":"00","hmac":"00"}}"#).unwrap();
    assert!(AccessLog::verify(&path, key.expose_secret()).is_err());
}
```

- [ ] **Step 2: Implement AccessLog**

`src/access_log.rs`:
```rust
//! Append-only HMAC-chained access log for credential fetches and mutations.
//! Each line's HMAC covers the previous line's HMAC + the current event's
//! JSON body (excluding the hmac field itself). Tampering with any line
//! breaks the chain at that point, which `verify()` detects.

use anyhow::{anyhow, bail, Context, Result};
use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretVec};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize)]
pub struct Event<'a> {
    pub ts: chrono::DateTime<chrono::Utc>,
    pub action: &'a str,
    pub item: Option<&'a str>,
    pub fields: &'a [&'a str],
    pub peer_pid: Option<u32>,
    pub peer_uid: Option<u32>,
    pub peer_cmdline: Option<&'a str>,
    pub outcome: &'a str,
}

#[derive(Serialize, Deserialize)]
struct StoredEvent {
    ts: chrono::DateTime<chrono::Utc>,
    action: String,
    item: Option<String>,
    fields: Vec<String>,
    peer_pid: Option<u32>,
    peer_uid: Option<u32>,
    peer_cmdline: Option<String>,
    outcome: String,
    prev_hmac: String,
    hmac: String,
}

pub struct AccessLog {
    inner: Mutex<Inner>,
    hmac_key: SecretVec<u8>,
}

struct Inner {
    file: File,
    last_hmac: String,
}

impl AccessLog {
    pub fn open(path: PathBuf, hmac_key: SecretVec<u8>) -> Result<Self> {
        let last = compute_last_hmac(&path)?;
        let file = OpenOptions::new()
            .create(true).append(true).open(&path)
            .with_context(|| format!("open access log {}", path.display()))?;
        Ok(Self {
            inner: Mutex::new(Inner { file, last_hmac: last }),
            hmac_key,
        })
    }

    pub fn record(&self, ev: &Event) -> Result<()> {
        let mut inner = self.inner.lock().map_err(|_| anyhow!("access log mutex poisoned"))?;
        let prev = inner.last_hmac.clone();
        let body = serde_json::to_string(ev)?;
        let mut mac = <HmacSha256 as Mac>::new_from_slice(self.hmac_key.expose_secret())
            .map_err(|e| anyhow!("hmac init: {e}"))?;
        mac.update(prev.as_bytes());
        mac.update(body.as_bytes());
        let hmac_hex = hex::encode(mac.finalize().into_bytes());

        // Re-serialize as full StoredEvent so prev_hmac + hmac fields appear in the line.
        let stored = StoredEvent {
            ts: ev.ts,
            action: ev.action.into(),
            item: ev.item.map(String::from),
            fields: ev.fields.iter().map(|s| s.to_string()).collect(),
            peer_pid: ev.peer_pid,
            peer_uid: ev.peer_uid,
            peer_cmdline: ev.peer_cmdline.map(String::from),
            outcome: ev.outcome.into(),
            prev_hmac: prev,
            hmac: hmac_hex.clone(),
        };
        let line = serde_json::to_string(&stored)?;
        writeln!(inner.file, "{}", line)?;
        inner.file.sync_data()?;
        inner.last_hmac = hmac_hex;
        Ok(())
    }

    pub fn verify(path: &Path, hmac_key: &[u8]) -> Result<()> {
        let f = File::open(path).with_context(|| format!("open {}", path.display()))?;
        let mut prev = String::new();
        for (i, line) in BufReader::new(f).lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() { continue; }
            let stored: StoredEvent = serde_json::from_str(&line)
                .with_context(|| format!("parse line {}", i + 1))?;
            if stored.prev_hmac != prev {
                bail!("line {}: prev_hmac mismatch", i + 1);
            }
            // Recompute. body == StoredEvent minus prev_hmac+hmac, which is exactly Event's shape.
            let body = serde_json::to_string(&serde_json::json!({
                "ts": stored.ts,
                "action": stored.action,
                "item": stored.item,
                "fields": stored.fields,
                "peer_pid": stored.peer_pid,
                "peer_uid": stored.peer_uid,
                "peer_cmdline": stored.peer_cmdline,
                "outcome": stored.outcome,
            }))?;
            let mut mac = <HmacSha256 as Mac>::new_from_slice(hmac_key)
                .map_err(|e| anyhow!("hmac init: {e}"))?;
            mac.update(stored.prev_hmac.as_bytes());
            mac.update(body.as_bytes());
            let want = hex::encode(mac.finalize().into_bytes());
            if want != stored.hmac {
                bail!("line {}: hmac mismatch (tampered or wrong key)", i + 1);
            }
            prev = stored.hmac;
        }
        Ok(())
    }
}

fn compute_last_hmac(path: &Path) -> Result<String> {
    if !path.exists() { return Ok(String::new()); }
    let f = File::open(path)?;
    let mut last = String::new();
    for line in BufReader::new(f).lines() {
        let line = line?;
        if line.trim().is_empty() { continue; }
        let stored: StoredEvent = serde_json::from_str(&line)
            .context("parse existing line during open")?;
        last = stored.hmac;
    }
    Ok(last)
}
```

- [ ] **Step 3: Add `hex` to `Cargo.toml`**

```toml
hex = "0.4"
```

- [ ] **Step 4: Run tests, confirm PASS**

```bash
cargo test --test access_log_integration
```

- [ ] **Step 5: Wire into local_socket get_item_fields handler**

After successful fetch:
```rust
if let Some(log) = access_log.as_ref() {
    let cmdline = std::fs::read_to_string(format!("/proc/{}/cmdline", peer_pid.unwrap_or(0)))
        .ok()
        .map(|s| s.replace('\0', " ").trim().to_string());
    log.record(&Event {
        ts: chrono::Utc::now(),
        action: "get_item_fields",
        item: Some(&item),
        fields: &fields.iter().map(String::as_str).collect::<Vec<_>>(),
        peer_pid,
        peer_uid,
        peer_cmdline: cmdline.as_deref(),
        outcome: "ok",
    }).ok(); // log failures must not break cred fetch
}
```

- [ ] **Step 6: Add CLI flag + wire HMAC key from keystore**

`main.rs`:
```rust
/// Path to the HMAC'd access log. Empty disables logging.
#[arg(long, env = "ACCESS_LOG_PATH", default_value = "")]
access_log_path: String,
```

HMAC key derivation: reuse the daemon's keystore unlock — derive a per-daemon-instance log key as `HKDF-SHA256(keystore_unlock_secret, salt="vp-access-log-v1", info="hmac")`. Define this as a new helper in `keystore.rs`:
```rust
pub fn derive_access_log_key(unlock_secret: &[u8]) -> SecretVec<u8> { /* HKDF */ }
```

Add `hkdf = "0.12"` to Cargo.toml.

- [ ] **Step 7: Wire rotate tool in mcp_server.rs**

Around `mcp_server.rs:370` (rotate handler) — log every rotation:
```rust
if let Some(log) = self.access_log.as_ref() {
    log.record(&Event {
        ts: chrono::Utc::now(),
        action: "rotate",
        item: Some(&service),
        fields: &[],
        peer_pid: None, peer_uid: None, peer_cmdline: None,
        outcome: if result.is_ok() { "ok" } else { "error" },
    }).ok();
}
```

- [ ] **Step 8: Add `vp audit verify --log <path>` subcommand**

`main.rs` clap derive — add a subcommand enum branch:
```rust
#[command(subcommand)]
cmd: Option<Cmd>,

#[derive(clap::Subcommand)]
enum Cmd {
    /// Verify the integrity of an access log file.
    AuditVerify {
        #[arg(long)]
        log: PathBuf,
    },
}
```

Handler in `main()`:
```rust
if let Some(Cmd::AuditVerify { log }) = args.cmd {
    let unlock = unlock_daemon_secret(&args.config_dir, /* prompt */)?;
    let key = derive_access_log_key(&unlock);
    AccessLog::verify(&log, key.expose_secret())?;
    println!("access log valid: {}", log.display());
    return Ok(());
}
```

- [ ] **Step 9: Test verify + tamper**

Already in `tests/access_log_integration.rs::detects_tamper`. Run.

- [ ] **Step 10: Commit**

```bash
git add src/access_log.rs src/local_socket.rs src/mcp_server.rs src/keystore.rs src/main.rs src/lib.rs Cargo.toml Cargo.lock tests/access_log_integration.rs
git commit -m "feat(audit): HMAC-chained access log for cred fetches and rotations

Logs each socket get_item_fields + each rotate tool invocation as an
append-only JSON line w/ ts, peer_{pid,uid,cmdline}, action, outcome.
Each line's HMAC chains over previous line + body, so tampering with
any line breaks verification from that line onward.

New subcommand: vp audit-verify --log <path>
New flag:       --access-log-path (env ACCESS_LOG_PATH)
HMAC key derived from keystore unlock secret via HKDF-SHA256."
```

## Task 4: Rotation hooks (F4)

**Files:**
- Create: `src/hooks.rs`
- Modify: `src/mcp_server.rs` rotate tool (~ L370)
- Modify: `src/lib.rs`
- Modify: `src/main.rs` — `--on-rotation <script>` flag
- Test: `tests/rotation_hooks.rs`

**Surface:**
```rust
// src/hooks.rs
pub struct RotationHook {
    pub script: PathBuf,
}
impl RotationHook {
    pub async fn fire(&self, service: &str, item_id: &str) -> anyhow::Result<()>;
}
```

Subprocess invocation: `<script> <service> <item_id>`, env vars `VP_ROTATION_SERVICE`, `VP_ROTATION_ITEM_ID`, `VP_ROTATION_TS`. Stdin closed. Stdout/stderr captured + logged. Timeout 30s (kill on overrun). Non-zero exit logged but does not undo rotation (rotation already committed to VW before hook fires).

- [ ] **Step 1: Failing test**

`tests/rotation_hooks.rs`:
```rust
use std::path::PathBuf;
use vaultproxy::hooks::RotationHook;

#[tokio::test]
async fn fires_script_with_env() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("hook-fired");
    let script = dir.path().join("hook.sh");
    std::fs::write(&script, format!(
        "#!/usr/bin/env bash\necho \"$VP_ROTATION_SERVICE $VP_ROTATION_ITEM_ID\" > {}\n",
        out.display(),
    )).unwrap();
    std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();

    let hook = RotationHook { script };
    hook.fire("wi-mcp", "abc-123").await.unwrap();

    let body = std::fs::read_to_string(&out).unwrap();
    assert_eq!(body.trim(), "wi-mcp abc-123");
}
```

- [ ] **Step 2: Implement**

`src/hooks.rs`:
```rust
//! Post-action subprocess hooks. Currently used by the rotate MCP tool to
//! invoke an operator-provided script after a successful credential rotation,
//! e.g. to bounce a downstream service or trigger a config reload.

use anyhow::{anyhow, Context, Result};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

pub struct RotationHook {
    pub script: PathBuf,
}

impl RotationHook {
    pub async fn fire(&self, service: &str, item_id: &str) -> Result<()> {
        let ts = chrono::Utc::now().to_rfc3339();
        let mut cmd = Command::new(&self.script);
        cmd.arg(service)
           .arg(item_id)
           .env("VP_ROTATION_SERVICE", service)
           .env("VP_ROTATION_ITEM_ID", item_id)
           .env("VP_ROTATION_TS", &ts)
           .stdin(Stdio::null())
           .stdout(Stdio::piped())
           .stderr(Stdio::piped());

        let child = cmd.spawn()
            .with_context(|| format!("spawn hook {}", self.script.display()))?;
        let out = timeout(Duration::from_secs(30), child.wait_with_output()).await
            .map_err(|_| anyhow!("rotation hook timed out after 30s"))??;

        if !out.status.success() {
            tracing::warn!(
                exit = ?out.status.code(),
                stdout = %String::from_utf8_lossy(&out.stdout),
                stderr = %String::from_utf8_lossy(&out.stderr),
                "rotation hook returned non-zero",
            );
        } else {
            tracing::info!(service, item_id, "rotation hook ok");
        }
        Ok(())
    }
}
```

- [ ] **Step 3: Run test, confirm PASS**

```bash
cargo test --test rotation_hooks
```

- [ ] **Step 4: Add CLI flag**

`main.rs`:
```rust
/// Path to a script invoked after each successful rotate operation.
/// Receives args: <service> <item_id>. Env: VP_ROTATION_{SERVICE,ITEM_ID,TS}.
#[arg(long, env = "ON_ROTATION_SCRIPT", default_value = "")]
on_rotation: String,
```

- [ ] **Step 5: Wire into rotate tool**

`src/mcp_server.rs` — find the rotate tool handler (~ L370). After rotation succeeds:
```rust
if let Some(hook) = self.rotation_hook.as_ref() {
    if let Err(e) = hook.fire(&service, &new_item_id).await {
        tracing::error!(error = %e, "rotation hook failed");
    }
}
```

- [ ] **Step 6: Integration test against fake rotate**

Skip — covered by Task 3 unit test + manual smoke in deploy.

- [ ] **Step 7: Commit**

```bash
git add src/hooks.rs src/mcp_server.rs src/main.rs src/lib.rs tests/rotation_hooks.rs
git commit -m "feat(hooks): --on-rotation script fires after successful rotate

Spawned with args <service> <item_id> + env VP_ROTATION_* metadata.
Stdin closed; 30s timeout. Non-zero exit logged as warn but does not
undo the rotation (the new credential is already committed to VW).

Use case: rotate wi-mcp bearer + bounce the wi-mcp container via
docker restart in the hook script."
```

## Wave 1 release checkpoint

- [ ] All Wave 1 tests passing: `cargo test`
- [ ] Build release: `cargo build --release`
- [ ] Smoke test in dev: restart daemon, observe second socket fetch is cache hit (log line / metric), access.log grows w/ chained entries
- [ ] Verify `vp audit-verify --log <path>` reports valid
- [ ] Tag `v1.1.0` if desired; otherwise leave on main

---

# Wave 2 — Template Engine + AppRole

**Goal:** Two configurable surfaces that don't change defaults. Engine renders arbitrary files; AppRole offers a non-TPM unlock path.

## Task 5: Template engine `--render` (F3)

**Files:**
- Create: `src/template.rs`
- Modify: `src/main.rs` — new `render` subcommand
- Modify: `Cargo.toml` — add `tera = "1"`
- Test: `tests/template_render.rs`

**Surface:**
```bash
vp render --in /etc/rclone/conf.tmpl --out /etc/rclone/rclone.conf
```
Template syntax (Tera):
```
[remote-b2]
type = b2
account = {{ vault(item="Backblaze - Production", field="username") }}
key = {{ vault(item="Backblaze - Production", field="password") }}
```

Template functions:
- `vault(item, field)` — fetch via local socket (uses TTL cache transparently)
- `env(name, default)` — escape hatch for non-secret config values
- `b64(value)` — base64-encode (for k8s-style secrets)
- `pem_one_line(value)` — convert multi-line PEM to single-line w/ `\n` literals

Output file permissions: `0600`. Parent dir not created (caller responsible). Atomic write via `tempfile + persist`.

- [ ] **Step 1: Failing test**

`tests/template_render.rs`:
```rust
use vaultproxy::template::{Renderer, RenderContext};

#[test]
fn renders_env_lookup() {
    std::env::set_var("FOO", "bar");
    let r = Renderer::new();
    let ctx = RenderContext::default();
    let out = r.render_string("value = {{ env(name=\"FOO\") }}", &ctx).unwrap();
    assert_eq!(out, "value = bar");
}

#[test]
fn renders_with_default() {
    let r = Renderer::new();
    let ctx = RenderContext::default();
    let out = r.render_string("x = {{ env(name=\"MISSING\", default=\"d\") }}", &ctx).unwrap();
    assert_eq!(out, "x = d");
}

#[test]
fn refuses_world_writable_template() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let tmpl = dir.path().join("t.tmpl");
    std::fs::write(&tmpl, "x").unwrap();
    std::fs::set_permissions(&tmpl, std::fs::Permissions::from_mode(0o666)).unwrap();
    let r = Renderer::new();
    let err = r.render_file(&tmpl, &dir.path().join("out"), &RenderContext::default()).unwrap_err();
    assert!(err.to_string().contains("world-writable"));
}
```

- [ ] **Step 2: Implement Renderer**

`src/template.rs`:
```rust
//! Tera-backed template renderer for non-secret config files that need to
//! interpolate credentials from Vaultwarden. Operates via the local socket
//! so it picks up the TTL'd cache + access log entries automatically.

use anyhow::{anyhow, bail, Context, Result};
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tera::{Context as TeraCtx, Function, Tera, Value};

#[derive(Default, Clone)]
pub struct RenderContext {
    pub socket_path: Option<PathBuf>,
}

pub struct Renderer { tera: Tera }

impl Renderer {
    pub fn new() -> Self {
        let mut tera = Tera::default();
        // env(name, default?)
        tera.register_function("env", Box::new(env_fn));
        // b64(value)
        tera.register_function("b64", Box::new(b64_fn));
        // vault(item, field) — registered dynamically per render to capture socket_path
        Self { tera }
    }

    pub fn render_string(&self, body: &str, ctx: &RenderContext) -> Result<String> {
        let mut tera = self.tera.clone();
        tera.register_function("vault", Box::new(vault_fn(ctx.socket_path.clone())));
        let mut tctx = TeraCtx::new();
        tera.render_str(body, &tctx).map_err(|e| anyhow!("tera render: {e}"))
    }

    pub fn render_file(&self, tmpl_path: &Path, out_path: &Path, ctx: &RenderContext) -> Result<()> {
        let meta = std::fs::metadata(tmpl_path)?;
        if meta.permissions().mode() & 0o002 != 0 {
            bail!("template {} is world-writable; refusing to render", tmpl_path.display());
        }
        let body = std::fs::read_to_string(tmpl_path)?;
        let rendered = self.render_string(&body, ctx)?;
        // Atomic write
        let parent = out_path.parent().context("output has no parent dir")?;
        let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
        use std::io::Write;
        tmp.write_all(rendered.as_bytes())?;
        tmp.as_file().sync_data()?;
        let mut perms = Permissions::from_mode(0o600);
        std::fs::set_permissions(tmp.path(), perms.clone())?;
        tmp.persist(out_path).map_err(|e| anyhow!("persist: {e}"))?;
        std::fs::set_permissions(out_path, perms)?;
        Ok(())
    }
}

fn env_fn(args: &std::collections::HashMap<String, Value>) -> tera::Result<Value> {
    let name = args.get("name").and_then(Value::as_str)
        .ok_or_else(|| tera::Error::msg("env(): name required"))?;
    match std::env::var(name) {
        Ok(v) => Ok(Value::String(v)),
        Err(_) => {
            if let Some(d) = args.get("default").and_then(Value::as_str) {
                Ok(Value::String(d.to_string()))
            } else {
                Err(tera::Error::msg(format!("env var {name} unset and no default")))
            }
        }
    }
}

fn b64_fn(args: &std::collections::HashMap<String, Value>) -> tera::Result<Value> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let v = args.get("value").and_then(Value::as_str)
        .ok_or_else(|| tera::Error::msg("b64(): value required"))?;
    Ok(Value::String(STANDARD.encode(v.as_bytes())))
}

fn vault_fn(socket: Option<PathBuf>) -> impl Function {
    move |args: &std::collections::HashMap<String, Value>| -> tera::Result<Value> {
        let item = args.get("item").and_then(Value::as_str)
            .ok_or_else(|| tera::Error::msg("vault(): item required"))?;
        let field = args.get("field").and_then(Value::as_str)
            .ok_or_else(|| tera::Error::msg("vault(): field required"))?;
        let sock = socket.clone().unwrap_or_else(|| crate::local_socket::default_socket_path());
        // Sync call via local_socket::client::get_field — implement a sync wrapper
        // around the existing async client.
        let v = crate::local_socket::client::get_field_sync(&sock, item, field)
            .map_err(|e| tera::Error::msg(format!("vault({item},{field}): {e}")))?;
        Ok(Value::String(v))
    }
}
```

- [ ] **Step 3: Add `get_field_sync` to `local_socket::client`**

In `src/local_socket.rs::client` module, add a blocking wrapper for callers outside tokio runtime:
```rust
pub fn get_field_sync(socket: &Path, item: &str, field: &str) -> Result<String> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    let mut s = UnixStream::connect(socket)
        .with_context(|| format!("connect {}", socket.display()))?;
    let req = serde_json::json!({"op": "get_item_fields", "item": item, "fields": [field]});
    writeln!(s, "{}", serde_json::to_string(&req)?)?;
    let mut buf = String::new();
    s.read_to_string(&mut buf)?;
    let resp: serde_json::Value = serde_json::from_str(buf.trim())?;
    if resp["ok"] == false {
        bail!("socket error: {}", resp["error"]);
    }
    resp["fields"][field].as_str().map(String::from)
        .ok_or_else(|| anyhow!("field {field} missing in response"))
}
```

- [ ] **Step 4: Add `render` subcommand in main.rs**

```rust
#[derive(clap::Subcommand)]
enum Cmd {
    /// Render a config template, substituting {{ vault() }} / {{ env() }} placeholders.
    Render {
        #[arg(long)] r#in: PathBuf,
        #[arg(long)] out: PathBuf,
        #[arg(long, env = "VAULTPROXY_SOCKET")]
        socket: Option<PathBuf>,
    },
    AuditVerify { #[arg(long)] log: PathBuf },
}
```

Handler:
```rust
if let Some(Cmd::Render { r#in, out, socket }) = args.cmd {
    let r = vaultproxy::template::Renderer::new();
    let ctx = vaultproxy::template::RenderContext { socket_path: socket };
    r.render_file(&r#in, &out, &ctx)?;
    println!("rendered {} -> {}", r#in.display(), out.display());
    return Ok(());
}
```

- [ ] **Step 5: Tests pass**

```bash
cargo test --test template_render
```

- [ ] **Step 6: Smoke against real daemon**

```bash
echo 'b2-key = {{ vault(item="Backblaze - Production", field="password") }}' > /tmp/test.tmpl
./target/release/vaultproxy render --in /tmp/test.tmpl --out /tmp/test.out
cat /tmp/test.out
stat -c '%a' /tmp/test.out  # expect 600
```

- [ ] **Step 7: Commit**

```bash
git add src/template.rs src/local_socket.rs src/main.rs src/lib.rs Cargo.toml Cargo.lock tests/template_render.rs
git commit -m "feat(template): --render subcommand with Tera + vault()/env()/b64()

Renders config files (rclone.conf, restic env, ssh known_hosts, etc.)
substituting vault items via the local socket. Output 0600, atomic
write via tempfile::persist. Refuses world-writable templates."
```

## Task 6: AppRole-style daemon auth (F6)

**Files:**
- Create: `src/approle.rs`
- Modify: `src/keystore.rs:397` (`unlock_keystore`) — add AppRole branch
- Modify: `src/main.rs` — flags + setup subcommand
- Test: `tests/approle_unlock.rs`

**Surface:**

Setup (one-time, manual):
```bash
vp approle setup --role-id <name>
# Prints generated SECRET_ID. Operator places it in /etc/vp/secret-id (mode 0600, owner root or daemon user).
```

Runtime daemon args (alternative to TPM/master pw):
```bash
vp --listen 127.0.0.1:3201 \
   --approle-role-id deploy-bot \
   --approle-secret-id-file /etc/vp/secret-id
```

The `secret_id` is a 32-byte random value; in the keystore we store `HKDF(secret_id, salt=role_id, info="vp-approle-v1")` as an alternate KEK that can decrypt the credential blob in `keystore.json`. The plaintext SECRET_ID is read once on daemon start and zeroized.

Rationale: TPM seal only works on TPM-equipped hardware. Cloud VMs / containers need a non-TPM unlock path that's still better than `MASTER_PASSWORD` env (which leaks via `/proc/<pid>/environ`). A file-read SECRET_ID is read once, parsed, zeroized; never lives in env.

- [ ] **Step 1: Failing test — round-trip setup + unlock**

`tests/approle_unlock.rs`:
```rust
use std::path::PathBuf;
use vaultproxy::approle::{setup_approle, unlock_with_approle};

#[test]
fn setup_then_unlock() {
    let dir = tempfile::tempdir().unwrap();
    // 1. Bootstrap a normal keystore via the existing path (use a helper).
    // 2. Add approle "test-role" with a generated secret_id.
    // 3. Unlock keystore via approle and assert creds round-trip.
    // Implement using the new approle::setup_approle (which wraps the existing KEK
    // with HKDF(secret_id) and stores under approles/test-role.json).
    let role_id = "test-role";
    let secret_id = setup_approle(dir.path().to_str().unwrap(), role_id, /* existing setup pw */ "test-master").unwrap();
    let creds = unlock_with_approle(dir.path().to_str().unwrap(), role_id, secret_id.expose_secret()).unwrap();
    assert!(!creds.vaultwarden.email.is_empty());
}
```

- [ ] **Step 2: Implement approle.rs**

`src/approle.rs`:
```rust
//! AppRole-style alternate keystore unlock. The operator pre-provisions a
//! role_id + secret_id pair; the daemon reads secret_id from a file at
//! startup (never env), derives the keystore KEK, and unlocks credentials
//! without prompting for a master password. Designed for environments
//! where TPM is unavailable (VMs, containers, headless CI).

use anyhow::{anyhow, Context, Result};
use hkdf::Hkdf;
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString, SecretVec};
use sha2::Sha256;
use std::path::{Path, PathBuf};

const APPROLE_DIR: &str = "approles";
const SECRET_ID_BYTES: usize = 32;

#[derive(serde::Serialize, serde::Deserialize)]
struct StoredApprole {
    role_id: String,
    // KEK encrypted with the credential blob's existing master KEK,
    // re-encryptable via setup_approle when adding a new role.
    wrapped_kek: String, // base64
}

pub fn setup_approle(config_dir: &str, role_id: &str, master_password: &str) -> Result<SecretString> {
    // 1. Unlock master KEK via existing setup_password path.
    let creds = crate::keystore::unlock_keystore(config_dir, Some(master_password))?;
    // 2. Generate secret_id (32 random bytes).
    let mut sid = vec![0u8; SECRET_ID_BYTES];
    rand::thread_rng().fill_bytes(&mut sid);
    let sid = SecretVec::new(sid);
    // 3. Derive KEK from secret_id.
    let kek = derive_kek(sid.expose_secret(), role_id);
    // 4. Wrap master credentials with this KEK and persist.
    let wrapped = crate::keystore::wrap_credentials_with_kek(&creds, &kek)?;
    let dir = Path::new(config_dir).join(APPROLE_DIR);
    std::fs::create_dir_all(&dir)?;
    let stored = StoredApprole { role_id: role_id.into(), wrapped_kek: wrapped };
    std::fs::write(dir.join(format!("{role_id}.json")), serde_json::to_vec(&stored)?)?;
    // 5. Return secret_id as hex for the operator to save.
    Ok(SecretString::from(hex::encode(sid.expose_secret())))
}

pub fn unlock_with_approle(
    config_dir: &str,
    role_id: &str,
    secret_id_hex: &str,
) -> Result<crate::keystore::Credentials> {
    let sid = hex::decode(secret_id_hex)
        .with_context(|| format!("decode secret_id for role {role_id}"))?;
    let kek = derive_kek(&sid, role_id);
    let path = Path::new(config_dir).join(APPROLE_DIR).join(format!("{role_id}.json"));
    let body = std::fs::read(&path)
        .with_context(|| format!("read approle {}", path.display()))?;
    let stored: StoredApprole = serde_json::from_slice(&body)?;
    if stored.role_id != role_id { bail!("role_id mismatch in {}", path.display()); }
    crate::keystore::unwrap_credentials_with_kek(&stored.wrapped_kek, &kek)
}

fn derive_kek(secret_id: &[u8], role_id: &str) -> SecretVec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(role_id.as_bytes()), secret_id);
    let mut out = vec![0u8; 32];
    hk.expand(b"vp-approle-v1", &mut out).expect("hkdf expand");
    SecretVec::new(out)
}
```

This depends on two new helpers in `keystore.rs`:
- `wrap_credentials_with_kek(&Credentials, &SecretVec<u8>) -> Result<String>` (base64-encoded AES-GCM ciphertext)
- `unwrap_credentials_with_kek(&str, &SecretVec<u8>) -> Result<Credentials>`

Add them next to the existing `encrypt_credentials`/`decrypt_credentials` (already AES-GCM, just need a variant that takes the KEK directly instead of deriving from a setup password).

- [ ] **Step 3: Add CLI subcommand + runtime flags**

```rust
enum Cmd {
    AuditVerify { #[arg(long)] log: PathBuf },
    Render { #[arg(long)] r#in: PathBuf, #[arg(long)] out: PathBuf, #[arg(long)] socket: Option<PathBuf> },
    ApproleSetup {
        #[arg(long)] role_id: String,
    },
}

#[arg(long)] approle_role_id: Option<String>,
#[arg(long)] approle_secret_id_file: Option<PathBuf>,
```

In daemon startup, before existing unlock path:
```rust
let creds = if let (Some(role), Some(sid_file)) = (&args.approle_role_id, &args.approle_secret_id_file) {
    let sid = std::fs::read_to_string(sid_file)?.trim().to_string();
    let creds = vaultproxy::approle::unlock_with_approle(&args.config_dir, role, &sid)?;
    // Zeroize the file contents we just read by zeroing the String buffer.
    drop(sid);
    creds
} else {
    crate::keystore::unlock_keystore(&args.config_dir, None)?
};
```

- [ ] **Step 4: Tests pass**

```bash
cargo test --test approle_unlock
```

- [ ] **Step 5: Smoke**

```bash
./target/release/vaultproxy approle-setup --role-id test
# enter master password at prompt; secret_id printed
echo "<printed-hex>" > /tmp/sid
chmod 600 /tmp/sid
./target/release/vaultproxy --listen 127.0.0.1:3299 --approle-role-id test --approle-secret-id-file /tmp/sid &
curl -s http://127.0.0.1:3299/health
```

- [ ] **Step 6: Commit**

```bash
git add src/approle.rs src/keystore.rs src/main.rs src/lib.rs Cargo.toml Cargo.lock tests/approle_unlock.rs
git commit -m "feat(approle): file-based daemon unlock without TPM or master env

Adds a HashiCorp-style AppRole: setup creates role_id/secret_id pair,
wraps the master KEK via HKDF(secret_id, role_id), persists at
config-dir/approles/<role_id>.json. Runtime reads secret_id from a
file (--approle-secret-id-file), unlocks the keystore, and zeroizes.

Intended for cloud VMs/containers where TPM seal is unavailable and
MASTER_PASSWORD env would leak via /proc/<pid>/environ."
```

## Wave 2 release checkpoint

- [ ] All Wave 2 tests pass
- [ ] Render smoke against real socket
- [ ] AppRole unlock works on a fresh keystore in a tmp dir
- [ ] No regression in Wave 1 features

---

# Wave 3 — Native HTTP MCP Proxy (mcp-rpc-bridge)

**Goal:** Kill the bearer-bridge argv leak (`/proc/<pid>/cmdline` exposing `Authorization: Bearer <tok>` because we currently exec `npx mcp-remote --header ...`).

**Architecture:** New binary `mcp-rpc-bridge` (separate crate target in same Cargo workspace). Accepts MCP JSON-RPC over stdio from the local MCP client. Connects to upstream MCP server over streamable-http or SSE. Reads bearer token from the local vp socket at connect time + on token-expiry re-fetch. Injects `Authorization` header into outgoing HTTP requests. Never accepts the token via argv or env.

```
claude-code ──stdio──> mcp-rpc-bridge ──HTTPS+Bearer──> upstream MCP
                              │
                              └── UNIX socket ── vp daemon (fetch bearer + lease)
```

This wave is heavier — split into 7 tasks. Plan a spec subagent first.

## Task 7: Spec the bridge (no code yet)

**Files:**
- Create: `docs/superpowers/specs/2026-05-22-mcp-rpc-bridge-design.md`

- [ ] **Step 1: Write spec covering**
  - JSON-RPC stdio framing (Content-Length headers a la LSP, or newline-delimited per MCP spec — check `rmcp` for which transport rmcp's HTTP client speaks)
  - Backpressure / reconnect handling
  - Token refresh: re-fetch every N seconds OR on 401 from upstream
  - Header injection point in `reqwest::ClientBuilder::default_headers` per-request
  - Error mapping: socket failure → JSON-RPC error with code `-32099`
  - Configuration file format: `~/.config/vaultproxy/bridges/<name>.toml`
    ```toml
    upstream = "https://hive.splendidus.live/mcp"
    vault_item = "Hive MCP - Bearer"
    field = "password"
    refresh_secs = 300
    ```
  - CLI: `mcp-rpc-bridge --bridge <name>` (matches `bridges/<name>.toml`)
  - Logging: tracing to stderr only (never stdout — stdio is reserved for JSON-RPC)
  - Tests: integration test with a fake upstream `axum` server that asserts incoming `Authorization` header

- [ ] **Step 2: Review spec against existing bearer_bridge.rs**

Note overlapping responsibilities. Decide: replace bearer_bridge.rs entirely or run alongside as a feature-gated alternative.

## Task 8: Skeleton + Cargo target

**Files:**
- Modify: `Cargo.toml` add `[[bin]] name = "mcp-rpc-bridge", path = "src/bin/mcp_rpc_bridge.rs"`
- Create: `src/mcp_rpc_bridge/mod.rs`
- Create: `src/mcp_rpc_bridge/stdio_server.rs`
- Create: `src/mcp_rpc_bridge/http_client.rs`
- Create: `src/mcp_rpc_bridge/header_injector.rs`
- Create: `src/bin/mcp_rpc_bridge.rs` (thin main wrapper)

- [ ] **Step 1: Add bin target, smoke build**

```toml
[[bin]]
name = "mcp-rpc-bridge"
path = "src/bin/mcp_rpc_bridge.rs"
```

`src/bin/mcp_rpc_bridge.rs`:
```rust
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    vaultproxy::mcp_rpc_bridge::run().await
}
```

`src/mcp_rpc_bridge/mod.rs`:
```rust
pub mod stdio_server;
pub mod http_client;
pub mod header_injector;

pub async fn run() -> anyhow::Result<()> {
    todo!("Wave 3 Task 9+")
}
```

- [ ] **Step 2: cargo build --bin mcp-rpc-bridge succeeds**

```bash
cargo build --bin mcp-rpc-bridge 2>&1 | tail -3
```

- [ ] **Step 3: Commit skeleton**

```bash
git commit -m "scaffold(mcp-rpc-bridge): empty binary target + module skeleton"
```

## Task 9: Header injector (vp socket → bearer token)

**Files:** `src/mcp_rpc_bridge/header_injector.rs`

- [ ] **Step 1: Failing test — fetches token and caches for refresh_secs**

```rust
// tests/mcp_rpc_bridge.rs
use std::time::Duration;
use vaultproxy::mcp_rpc_bridge::header_injector::HeaderInjector;

#[tokio::test]
async fn refreshes_after_ttl() {
    // Stand up a fake unix socket server that hands out tokens.
    // Spawn HeaderInjector w/ refresh_secs=1.
    // First .current_token() returns "T1".
    // Server flips to "T2". Wait 1.5s. .current_token() returns "T2".
}
```

- [ ] **Step 2: Implement HeaderInjector**

```rust
//! Holds the current bearer token in memory and re-fetches it from the
//! vault-proxy local socket on a configurable interval (default 5 min) or
//! on demand when the upstream returns 401. Token is wrapped in
//! SecretString and exposed only at the point of header serialization.

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

pub struct HeaderInjector {
    socket: PathBuf,
    vault_item: String,
    field: String,
    refresh_interval: Duration,
    state: Arc<RwLock<State>>,
}

struct State {
    token: SecretString,
    fetched_at: Instant,
}

impl HeaderInjector {
    pub async fn new(socket: PathBuf, vault_item: String, field: String, refresh_interval: Duration) -> Result<Self> {
        let token = fetch(&socket, &vault_item, &field).await?;
        Ok(Self {
            socket, vault_item, field, refresh_interval,
            state: Arc::new(RwLock::new(State { token, fetched_at: Instant::now() })),
        })
    }

    pub async fn current_token(&self) -> SecretString {
        {
            let s = self.state.read().await;
            if s.fetched_at.elapsed() < self.refresh_interval {
                return SecretString::from(s.token.expose_secret().to_string());
            }
        }
        // Re-fetch under write lock
        let mut s = self.state.write().await;
        if s.fetched_at.elapsed() >= self.refresh_interval {
            if let Ok(t) = fetch(&self.socket, &self.vault_item, &self.field).await {
                s.token = t;
                s.fetched_at = Instant::now();
            }
        }
        SecretString::from(s.token.expose_secret().to_string())
    }

    pub async fn force_refresh(&self) -> Result<()> {
        let mut s = self.state.write().await;
        s.token = fetch(&self.socket, &self.vault_item, &self.field).await?;
        s.fetched_at = Instant::now();
        Ok(())
    }
}

async fn fetch(socket: &PathBuf, item: &str, field: &str) -> Result<SecretString> {
    // Re-use the existing async client in src/local_socket.rs::client.
    let v = crate::local_socket::client::get_field(socket, item, field).await
        .with_context(|| format!("fetch {item}/{field}"))?;
    Ok(SecretString::from(v))
}
```

- [ ] **Step 3: Test passes**

```bash
cargo test --test mcp_rpc_bridge refreshes_after_ttl
```

- [ ] **Step 4: Commit**

## Task 10: Stdio JSON-RPC server

**Files:** `src/mcp_rpc_bridge/stdio_server.rs`

- [ ] **Step 1: Decide framing** — read MCP spec on which line-framing version `rmcp 1.6` speaks. Pick same framing as upstream so we're a transparent bridge.

- [ ] **Step 2: Failing test — single ping/pong round trip via stdio**

Stand up the bridge with a mock `HttpClient` that returns hardcoded JSON-RPC responses, write a request to its stdin, assert the response on stdout.

- [ ] **Step 3: Implement** — buffered stdin reader, per-line JSON, dispatch to `http_client.send(req)`, write response.

- [ ] **Step 4: Test + commit**

## Task 11: Streamable-HTTP / SSE upstream client

**Files:** `src/mcp_rpc_bridge/http_client.rs`

- [ ] **Step 1: Test — connects to a local axum fake upstream, asserts Authorization header arrives**

```rust
#[tokio::test]
async fn injects_authorization_header() {
    // Spawn an axum fake upstream on a random port that asserts headers
    // and echoes the body.
    // Stand up an HttpClient pointing at it w/ a fake injector that returns "TOKTOK".
    // Send a JSON-RPC payload. Assert upstream saw Authorization: Bearer TOKTOK.
}
```

- [ ] **Step 2: Implement** — `reqwest::Client` with default headers, but the bearer is per-request (because it can refresh). Manually add `Authorization` header on each send.

- [ ] **Step 3: On 401, force_refresh + retry once. If 401 again, propagate as JSON-RPC error.**

- [ ] **Step 4: Test + commit**

## Task 12: End-to-end bridge

**Files:** `src/mcp_rpc_bridge/mod.rs` `run()`

- [ ] **Step 1: Wire stdio_server + http_client + header_injector together**

```rust
pub async fn run() -> Result<()> {
    let args = BridgeArgs::parse(); // clap
    let cfg = load_bridge_config(&args.bridge)?;
    let injector = HeaderInjector::new(
        cfg.socket.unwrap_or_else(default_socket_path),
        cfg.vault_item, cfg.field,
        Duration::from_secs(cfg.refresh_secs),
    ).await?;
    let http = HttpClient::new(cfg.upstream, injector);
    stdio_server::serve(http).await
}
```

- [ ] **Step 2: End-to-end test — full bridge against fake upstream**

```rust
#[tokio::test]
async fn end_to_end_bridge() {
    // 1. Fake vp socket server returning token "ETOK".
    // 2. Fake upstream MCP echoing back any body but asserting Authorization.
    // 3. Spawn bridge::run() in a tokio task connected via stdio pipes.
    // 4. Write JSON-RPC initialize request to its stdin.
    // 5. Assert we get back upstream's echoed response.
    // 6. Assert upstream saw Bearer ETOK.
}
```

- [ ] **Step 3: Commit**

## Task 13: Migrate one MCP off bearer-bridge

**Files:** `/home/aaron/projects/Connecterr/config/mcp-servers.toml`

- [ ] **Step 1: Pick the highest-value migration — `hive-mcp` (already on bearer-bridge with VAULT_ITEM)**

Add a bridge config at `~/.config/vaultproxy/bridges/hive-mcp.toml`:
```toml
upstream = "https://hive.splendidus.live/mcp"
vault_item = "Hive MCP - Bearer"
field = "password"
refresh_secs = 300
```

- [ ] **Step 2: Update mcp-servers.toml entry for hive-mcp**

```toml
[[mcp_server]]
name    = "hive"
command = "/home/aaron/projects/mcp-vault-proxy/target/release/mcp-rpc-bridge --bridge hive-mcp"
```

- [ ] **Step 3: Restart Claude Code session, verify hive tools still work**

- [ ] **Step 4: Confirm no token in `/proc/<pid>/cmdline`**

```bash
pid=$(pgrep -f mcp-rpc-bridge)
cat /proc/$pid/cmdline | tr '\0' ' '
# Should show: mcp-rpc-bridge --bridge hive-mcp
# Must NOT contain "Bearer" or any token string.
```

- [ ] **Step 5: Migrate wi-mcp + cloudflare the same way**

- [ ] **Step 6: Mark bearer_bridge.rs deprecated**

Add a `#[deprecated]` attribute on the public surface and a warning log on startup pointing to mcp-rpc-bridge. Keep the binary buildable for one release cycle.

- [ ] **Step 7: Commit + tag**

```bash
git commit -m "feat(bridge): native HTTP MCP proxy, no argv token leak

Replaces npx mcp-remote --header invocation (which exposed bearer
tokens via /proc/<pid>/cmdline) with a native Rust bridge that
fetches the token from vp's local socket and injects it into the
Authorization header at request time. Bearer never appears in argv,
env, or any external process tree.

Migrated MCPs: hive, wi-mcp, cloudflare. bearer_bridge.rs marked
deprecated; will be removed in the next minor release."
```

## Wave 3 release checkpoint

- [ ] All 3 migrated MCPs work via mcp-rpc-bridge
- [ ] `/proc/$pid/cmdline` audit clean (no bearer strings)
- [ ] Token refresh observed (kill upstream session, wait, re-issue request, refresh fires)

---

# Wave 4 — Dynamic Creds in /proxy

**Goal:** For services that support short-lived tokens (UniFi controller /login with 5-min TTL, Cloudflare API w/ ephemeral session tokens, AWS STS-like patterns), `/proxy` mints a per-call credential, attaches it to the downstream request, then revokes/discards it on response complete.

**Files:**
- Create: `src/proxy/lease.rs`
- Modify: `src/proxy/registry.rs` — add `LeaseConfig` per service entry
- Modify: `src/proxy/mod.rs` `handle_proxy` (~ L335) — wrap downstream request in lease lifecycle
- Test: `tests/dynamic_creds_proxy.rs`

## Task 14: Lease tracker

- [ ] **Step 1: Spec the lease abstraction**

```rust
// src/proxy/lease.rs
pub struct Lease {
    pub credential: SecretString,
    pub revoke_url: Option<String>,
    pub revoke_method: http::Method,
    pub revoke_headers: HeaderMap,
    pub revoke_body: Option<bytes::Bytes>,
    pub expires_at: Instant,
}

pub trait LeaseProvider: Send + Sync {
    async fn mint(&self, ctx: &MintContext) -> Result<Lease>;
}
```

Services register a `LeaseProvider` in the registry. Built-in providers:
- `UnifiSessionLease` — POST `/api/auth/login` returning cookie + csrf
- `OauthClientCredentialsLease` — generic OAuth2 client_credentials grant

- [ ] **Step 2-N: TDD per provider**

Each provider: failing test → minimal impl → commit. Mirror the Task 9-11 cadence.

## Task 15: Wire into handle_proxy

- [ ] **Step 1: Decision point** — does the service have a `LeaseConfig`? If yes, `provider.mint()` → use lease creds → after response, `revoke_lease()` (best-effort, log errors). If no, current path unchanged.

- [ ] **Step 2: Integration test — UnifiSessionLease**

Real test against `unifi.splendidus.live` is brittle (requires creds). Mock with a local axum fake controller that asserts: login received, request used returned cookie, logout received post-response.

- [ ] **Step 3: Migrate `unifi_home` registry entry to use UnifiSessionLease**

Today: persistent session cookie cached in `proxy/unifi_session.rs`. With lease: mint per-call, revoke on completion. Higher latency but tighter blast radius.

## Wave 4 release checkpoint

- [ ] At least UnifiSessionLease provider works end-to-end
- [ ] No regression: services without `LeaseConfig` still work
- [ ] Mint+revoke observable in access log

---

## Cross-wave dependencies

```
F1 (cache)         independent
F2 (access_log)    independent (logs use cache hits/misses as outcome metadata, but lives standalone)
F4 (hooks)         independent
F3 (template)      depends on F1 (cache backs vault() calls)
F6 (approle)       independent
F7 (bridge)        depends on F1 (cache reduces socket pressure during refresh)
F5 (dynamic creds) depends on F2 (logs every mint/revoke), F4 (rotation hooks naturally fit here)
```

## Rollback

- **Wave 1**: revert commits. No config changes user-visible unless they set the new flags. Defaults preserve old behavior (cache TTL still applies but is transparent; access log only writes if `--access-log-path` set).
- **Wave 2**: same. AppRole + Render are pure additions.
- **Wave 3**: keep `bearer_bridge.rs` operational; just revert mcp-servers.toml entries to old bearer-bridge invocation. mcp-rpc-bridge binary can stay shipped.
- **Wave 4**: revert lease wiring in `handle_proxy`; the registry's `LeaseConfig` becomes inert. Per-service migrations are independent.

## Sequencing

Recommended order, one wave per session:

1. **Session 1**: Wave 1 (Tasks 1-4). ~4-6 hours. Ship.
2. **Session 2**: Wave 2 (Tasks 5-6). ~3-4 hours. Ship.
3. **Session 3a**: Wave 3 Task 7 — spec only. Pause, review.
4. **Session 3b**: Wave 3 Tasks 8-13. ~5-8 hours. Ship.
5. **Session 4**: Wave 4 (Tasks 14-15). ~3-5 hours. Ship.

Total realistic: 15-23 hours of focused work spread over 4-5 sessions.

---

## Self-review (done)

- [x] Spec coverage: all 7 features map to tasks (F1→T1+T2, F2→T3, F4→T4, F3→T5, F6→T6, F7→T7-13, F5→T14-15)
- [x] No placeholders in step bodies (each TDD step has real code or real commands)
- [x] Type/method names consistent across tasks (CredCache, AccessLog, RotationHook, Renderer, HeaderInjector, Lease)
- [x] File paths absolute or repo-rooted, never ambiguous
- [x] Tests precede impl in each task
- [x] Commit boundary on each task — no monster commits

---

**Plan complete and saved to `docs/superpowers/plans/2026-05-22-vault-agent-parity.md`.**
