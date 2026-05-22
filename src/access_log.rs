//! Append-only HMAC-chained access log for credential fetches and mutations.
//! Each line's HMAC covers the previous line's HMAC + the current event's
//! JSON body. Tampering with any line breaks verification from that line.
//!
//! Key management: a 32-byte HMAC key lives at `<config_dir>/access_log_hmac.key`
//! (mode 0600). Generated on first open if absent. The key never leaves the
//! daemon process except onto disk under that path; the file's owner-only
//! permissions are the security boundary. The key is unrelated to the
//! Vaultwarden unlock secret — losing it just means the existing log can no
//! longer be verified (logging continues w/ a new key after rotation).

use anyhow::{anyhow, bail, Context, Result};
use hmac::{Hmac, Mac};
use rand::RngCore;
use secrecy::{ExposeSecret, SecretSlice};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs::{File, OpenOptions, Permissions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// Event passed to [`AccessLog::record`]. Borrowed fields keep the hot path
/// free of unnecessary allocations; the caller owns the underlying buffers
/// and is responsible for zeroizing them after the call if they hold secrets.
#[derive(Serialize, Clone, Debug)]
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
    hmac_key: SecretSlice<u8>,
}

struct Inner {
    file: File,
    last_hmac: String,
}

impl AccessLog {
    /// Open (and lock) the log at `log_path` using the HMAC key at
    /// `key_path`. On first open the key file is generated with mode 0600;
    /// subsequent opens reuse it. When we create the log file ourselves it is
    /// chmodded to 0600 so only the daemon user can read it; if the file
    /// already existed we leave its mode alone so an operator-set policy like
    /// 0640 (audit-group read) is preserved.
    pub fn open(log_path: PathBuf, key_path: PathBuf) -> Result<Self> {
        let hmac_key = load_or_generate_key(&key_path)?;
        let last = compute_last_hmac(&log_path)?;
        if let Some(parent) = log_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        // Snapshot existence BEFORE we open with `create(true)` so we can
        // distinguish "we just created this file" from "it already existed".
        // Only the create path applies the 0600 default — preserving any
        // operator-set mode (e.g. 0640 for an audit group) on reopen.
        let existed_before = log_path.exists();
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            // `mode` only takes effect when create() actually creates the
            // file; the chmod below is a defensive fallback for filesystems
            // that ignore the open-time mode (e.g. some FUSE mounts).
            .mode(0o600)
            .open(&log_path)
            .with_context(|| format!("open access log {}", log_path.display()))?;
        if !existed_before {
            std::fs::set_permissions(&log_path, Permissions::from_mode(0o600))
                .with_context(|| format!("chmod 0600 {}", log_path.display()))?;
        }
        Ok(Self {
            inner: Mutex::new(Inner {
                file,
                last_hmac: last,
            }),
            hmac_key,
        })
    }

    /// Append a single event to the log, chaining its HMAC over the previous
    /// line's HMAC + the new event's JSON body. The HMAC is also written to
    /// the line so [`AccessLog::verify`] can recompute it.
    ///
    /// Errors are returned to the caller, but callers in the cred-fetch hot
    /// path should treat logging failures as best-effort (`let _ = ...`) so a
    /// failed write never breaks credential delivery.
    pub fn record(&self, ev: &Event) -> Result<()> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| anyhow!("access log mutex poisoned"))?;
        let prev = inner.last_hmac.clone();
        let body = serde_json::to_string(ev)?;
        let mut mac = <HmacSha256 as Mac>::new_from_slice(self.hmac_key.expose_secret())
            .map_err(|e| anyhow!("hmac init: {e}"))?;
        mac.update(prev.as_bytes());
        mac.update(body.as_bytes());
        let hmac_hex = hex::encode(mac.finalize().into_bytes());

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

    /// Verify the integrity of every line in `log_path` using the key at
    /// `key_path`. Returns `Ok(())` if every chained HMAC checks out;
    /// returns an error pointing at the first broken line otherwise.
    /// Does NOT generate a key — verification of a log without its key is
    /// impossible by design.
    pub fn verify(log_path: &Path, key_path: &Path) -> Result<()> {
        // Wrap in Zeroizing so the key bytes are wiped from the allocator on
        // drop. The raw Vec<u8> would otherwise leak the 32-byte HMAC secret
        // across the heap until reused.
        let hmac_key = Zeroizing::new(
            std::fs::read(key_path)
                .with_context(|| format!("read key {}", key_path.display()))?,
        );
        if hmac_key.len() != 32 {
            bail!(
                "hmac key at {} is {} bytes; expected 32",
                key_path.display(),
                hmac_key.len()
            );
        }
        let f = File::open(log_path)
            .with_context(|| format!("open {}", log_path.display()))?;
        let mut prev = String::new();
        for (i, line) in BufReader::new(f).lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let stored: StoredEvent = serde_json::from_str(&line)
                .with_context(|| format!("parse line {}", i + 1))?;
            if stored.prev_hmac != prev {
                bail!("line {}: prev_hmac mismatch (chain broken)", i + 1);
            }
            // Recompute the body exactly as `record()` serialized it. Round-trip
            // through `Event` (struct-field-order serialization) instead of
            // `serde_json::json!({...})`, which would sort keys alphabetically
            // because `serde_json::Map` is a `BTreeMap` by default and produce a
            // different byte sequence than `record()` wrote.
            let field_refs: Vec<&str> = stored.fields.iter().map(String::as_str).collect();
            let ev = Event {
                ts: stored.ts,
                action: &stored.action,
                item: stored.item.as_deref(),
                fields: &field_refs,
                peer_pid: stored.peer_pid,
                peer_uid: stored.peer_uid,
                peer_cmdline: stored.peer_cmdline.as_deref(),
                outcome: &stored.outcome,
            };
            let body = serde_json::to_string(&ev)?;
            let mut mac = <HmacSha256 as Mac>::new_from_slice(&hmac_key[..])
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

fn load_or_generate_key(key_path: &Path) -> Result<SecretSlice<u8>> {
    if key_path.exists() {
        let bytes = std::fs::read(key_path)
            .with_context(|| format!("read key {}", key_path.display()))?;
        if bytes.len() != 32 {
            bail!(
                "hmac key at {} is {} bytes; expected 32",
                key_path.display(),
                bytes.len()
            );
        }
        return Ok(SecretSlice::from(bytes));
    }
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut key = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    {
        // Open with mode 0600 at create time (O_CREAT|O_EXCL via create_new,
        // plus mode= via OpenOptionsExt) so the file is never visible with a
        // wider mode — closing the TOCTOU window between create and chmod
        // under a permissive umask.
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(key_path)
            .with_context(|| format!("create key {}", key_path.display()))?;
        f.write_all(&key)?;
        f.sync_data()?;
    }
    // Belt-and-braces: explicit chmod for filesystems that ignore the
    // open-time mode argument (some FUSE mounts, network filesystems). With
    // `.mode(0o600)` above this is no longer load-bearing.
    std::fs::set_permissions(key_path, Permissions::from_mode(0o600))?;
    Ok(SecretSlice::from(key))
}

fn compute_last_hmac(path: &Path) -> Result<String> {
    if !path.exists() {
        return Ok(String::new());
    }
    let f = File::open(path)?;
    let mut last = String::new();
    for line in BufReader::new(f).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let stored: StoredEvent =
            serde_json::from_str(&line).context("parse existing line during open")?;
        last = stored.hmac;
    }
    Ok(last)
}
