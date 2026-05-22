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
