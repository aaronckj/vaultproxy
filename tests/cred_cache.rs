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

#[test]
fn evicts_on_expiry() {
    let cache = CredCache::with_ttl(Duration::from_millis(10));
    cache.put("svc", "k", SecretString::from("v".to_string()), None);
    std::thread::sleep(Duration::from_millis(20));
    assert!(cache.get("svc", "k").is_none());
    assert_eq!(cache.len(), 0, "expired entry removed on read");
}

#[test]
fn debug_does_not_leak_value() {
    let cache = CredCache::with_ttl(Duration::from_secs(60));
    cache.put("svc", "k", SecretString::from("VERY-SECRET-XYZ".to_string()), None);
    let got = cache.get("svc", "k").unwrap();
    let dbg = format!("{:?}", got);
    assert!(!dbg.contains("VERY-SECRET-XYZ"), "leaked: {dbg}");
}
