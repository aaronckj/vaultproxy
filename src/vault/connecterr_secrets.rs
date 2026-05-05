//! Aggregate VW items in folder "Connecterr" into the ConnecterrSecrets JSON shape.
//!
//! Item names and custom field names are treated as **non-sensitive metadata**
//! (they're config keys like "unifi/home" / "username", not secret values), so
//! they are intentionally surfaced in error messages and tracing logs to keep
//! operator debugging tractable. Field *values* never appear in logs.

use std::sync::Arc;
use anyhow::{Context, Result};
use serde_json::{Map, Value};

use super::VaultManager;

pub const DEFAULT_VAULT_FOLDER: &str = "vault-proxy";

/// Pure helper — build the nested JSON object from a list of
/// (item_name, fields_map) pairs where item_name is `/`-delimited.
pub fn build_secrets_json(pairs: Vec<(String, Map<String, Value>)>) -> Value {
    let mut root = Map::new();
    for (item_name, fields) in pairs {
        let parts: Vec<&str> = item_name.split('/').collect();
        let leaf = walk_path(&mut root, &parts);
        for (k, v) in fields { leaf.insert(k, v); }
    }
    Value::Object(root)
}

fn walk_path<'a>(root: &'a mut Map<String, Value>, parts: &[&str]) -> &'a mut Map<String, Value> {
    let (head, tail) = parts.split_first().expect("non-empty path");
    if tail.is_empty() {
        // Leaf — ensure key exists as object, return mut ref.
        let entry = root.entry(head.to_string()).or_insert_with(|| Value::Object(Map::new()));
        if !entry.is_object() { *entry = Value::Object(Map::new()); }
        entry.as_object_mut().unwrap()
    } else {
        let entry = root.entry(head.to_string()).or_insert_with(|| Value::Object(Map::new()));
        if !entry.is_object() { *entry = Value::Object(Map::new()); }
        walk_path(entry.as_object_mut().unwrap(), tail)
    }
}

/// Aggregator entry point — used by the HTTP handler.
///
/// Validates item-name well-formedness before walking fields:
/// names with empty path segments (leading/trailing/double slashes) are
/// skipped with a warning rather than silently producing `""` keys in the
/// output JSON. Duplicate item names also produce a warning; per
/// `build_secrets_json`'s contract the second occurrence's fields will
/// overwrite the first's at any colliding leaf key.
//
// TODO(perf): the current loop calls list_field_names (decrypts every field
// name) and then decrypt_field per name (which walks fields and decrypts
// each name again to compare) — O(n²) in fields per item. Acceptable at
// expected sizes (boot-time, ~10 items, 2-5 fields each). Refactor to a
// single VaultManager::list_field_pairs(item) -> Vec<(name, SecureBuffer)>
// pass if profiling shows a real cost or if folder ever grows.
pub async fn aggregate(vault: &Arc<VaultManager>, folder_name: &str) -> Result<Value> {
    let items = vault.list_items_in_folder(folder_name).await;
    let mut pairs: Vec<(String, Map<String, Value>)> = Vec::with_capacity(items.len());
    let mut seen_names: std::collections::HashSet<String> =
        std::collections::HashSet::with_capacity(items.len());

    for (name, _cipher) in items {
        // Reject malformed item names: empty path segments would silently
        // create "" keys in the output JSON.
        if name.is_empty() || name.split('/').any(|p| p.is_empty()) {
            tracing::warn!(item = %name, "skipping item with empty path segment");
            continue;
        }
        if !seen_names.insert(name.clone()) {
            tracing::warn!(item = %name, "duplicate item name in folder; later fields overwrite earlier");
        }

        let field_names = vault.list_field_names(&name).await
            .with_context(|| format!("list fields for '{}'", name))?;

        let mut field_map = Map::new();
        for fname in field_names {
            let buf = vault.decrypt_field(&name, &fname)
                .with_context(|| format!("decrypt field '{}' on '{}'", fname, name))?;
            let s = buf.as_str()
                .map_err(|_| anyhow::anyhow!("field '{}' on '{}' is not valid UTF-8", fname, name))?
                .to_string();
            field_map.insert(fname, Value::String(s));
        }
        pairs.push((name, field_map));
    }

    Ok(build_secrets_json(pairs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fields(pairs: &[(&str, &str)]) -> Map<String, Value> {
        pairs.iter().map(|(k, v)| (k.to_string(), Value::String(v.to_string()))).collect()
    }

    #[test]
    fn build_secrets_json_handles_flat_and_nested_paths() {
        let pairs = vec![
            ("apiKey".into(), fields(&[("apiKey", "ABC")])),
            ("unifi/home".into(), fields(&[("username", "admin"), ("password", "pw")])),
            ("media/plex".into(), fields(&[("apiKey", "PLEX")])),
            ("media/sonarr".into(), fields(&[("apiKey", "SON")])),
        ];

        let v = build_secrets_json(pairs);
        let expected = json!({
            "apiKey": { "apiKey": "ABC" },
            "unifi": { "home": { "username": "admin", "password": "pw" } },
            "media": {
                "plex":   { "apiKey": "PLEX" },
                "sonarr": { "apiKey": "SON"  },
            },
        });
        assert_eq!(v, expected);
    }

    #[test]
    #[allow(non_snake_case)] // camelCase mirrors the connecterr-side schema key
    fn build_secrets_json_collapses_apiKey_when_consumer_expects_string() {
        // The aggregator emits {"apiKey": {"apiKey": "ABC"}} for an item named
        // "apiKey" with field "apiKey". The connecterr-side schema unwraps that
        // (handled in TS — see migrate-secrets.test.mjs golden test).
        let v = build_secrets_json(vec![("apiKey".into(), fields(&[("apiKey", "ABC")]))]);
        assert_eq!(v["apiKey"]["apiKey"], "ABC");
    }

    #[test]
    fn build_secrets_json_with_empty_path_segments_creates_empty_keys() {
        // Documents the raw helper's behavior: it does NOT validate names — that's
        // the aggregate() guard's job. A leading "/" produces a "" leaf key. This
        // test pins the contract so a future refactor of either layer doesn't
        // accidentally drop the validation responsibility on the floor.
        let v = build_secrets_json(vec![("/apiKey".into(), fields(&[("apiKey", "ABC")]))]);
        assert!(v.get("").is_some(), "empty leading segment should produce '' key");
    }
}
