//! TTL'd in-memory cache for credentials returned via the local socket.
//! Values are wrapped in `SecretString` so they zeroize on drop and never
//! appear in Debug output. Expiry is checked on read; `purge_expired()` is
//! provided for callers (e.g. an interval task in a future commit) to invoke
//! when they want to evict cold entries proactively.
//!
//! **Zero-TTL semantics:** constructing a cache with
//! `with_ttl(Duration::ZERO)` disables caching for the common call path —
//! `put(item, field, value, None)` becomes a no-op so the map never grows.
//! This lets `CRED_CACHE_TTL=0` cleanly disable caching at the daemon level
//! without forcing every call-site to branch on a separate flag. Callers
//! that want to opt back in for a single entry can still pass an explicit
//! `Some(ttl)` to `put()` — that path is honoured regardless of the
//! default.

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
        Self {
            inner: DashMap::new(),
            default_ttl,
        }
    }

    pub fn get(&self, item: &str, field: &str) -> Option<SecretString> {
        let key = Key {
            item: item.into(),
            field: field.into(),
        };
        // Atomic: only remove if the entry we're looking at is actually expired.
        // If a concurrent put() replaces the value between our get and remove,
        // remove_if's predicate sees the new value and bails out.
        self.inner
            .remove_if(&key, |_, e| e.expires_at <= Instant::now());
        let entry = self.inner.get(&key)?;
        Some(SecretString::from(entry.value.expose_secret().to_string()))
    }

    pub fn put(&self, item: &str, field: &str, value: SecretString, ttl: Option<Duration>) {
        // Zero default TTL + no per-entry override = caching disabled. Skip
        // the insert so the map doesn't accumulate entries that would be
        // evicted on the next read anyway.
        if self.default_ttl.is_zero() && ttl.is_none() {
            return;
        }
        let key = Key {
            item: item.into(),
            field: field.into(),
        };
        let expires_at = Instant::now() + ttl.unwrap_or(self.default_ttl);
        self.inner.insert(key, Entry { value, expires_at });
    }

    pub fn purge_expired(&self) {
        let now = Instant::now();
        self.inner.retain(|_, e| e.expires_at > now);
    }

    // Used by integration tests (compiled against the lib crate). The binary
    // crate also declares `mod cred_cache;`, where this method is unused at
    // compile time — silence the resulting dead_code warning there without
    // hiding it from the lib copy.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}
