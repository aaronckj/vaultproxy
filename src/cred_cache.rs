//! TTL'd in-memory cache for credentials returned via the local socket.
//! Values are wrapped in `SecretString` so they zeroize on drop and never
//! appear in Debug output. Expiry is checked on read; `purge_expired()` is
//! provided for callers (e.g. an interval task in a future commit) to invoke
//! when they want to evict cold entries proactively.

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
        // Atomic: only remove if the entry we're looking at is actually expired.
        // If a concurrent put() replaces the value between our get and remove,
        // remove_if's predicate sees the new value and bails out.
        self.inner.remove_if(&key, |_, e| e.expires_at <= Instant::now());
        let entry = self.inner.get(&key)?;
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
