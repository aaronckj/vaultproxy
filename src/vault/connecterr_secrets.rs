//! Aggregate VW items in folder "Connecterr" into the ConnecterrSecrets JSON shape.
//!
//! Item names and custom field names are treated as **non-sensitive metadata**
//! (they're config keys like "unifi/home" / "username", not secret values), so
//! they are intentionally surfaced in error messages and tracing logs to keep
//! operator debugging tractable. Field *values* never appear in logs.

use anyhow::{Context, Result};
use serde_json::{Map, Value};
use std::sync::Arc;

use super::VaultManager;

/// Default Vaultwarden folder name that vault-proxy uses when `--vault-folder`
/// is not specified. The live value at runtime comes from `AppState::vault_folder`
/// (set from the CLI flag / env var), so this constant is kept for reference and
/// documentation only — it is intentionally not wired into runtime code paths
/// to avoid the constant silently overriding the operator-configured value.
#[allow(dead_code)]
pub const DEFAULT_VAULT_FOLDER: &str = "vault-proxy";

/// Pure helper — build the nested JSON object from a list of
/// (item_name, fields_map) pairs where item_name is `/`-delimited.
pub fn build_secrets_json(pairs: Vec<(String, Map<String, Value>)>) -> Value {
    let mut root = Map::new();
    for (item_name, fields) in pairs {
        let parts: Vec<&str> = item_name.split('/').collect();
        let leaf = walk_path(&mut root, &parts);
        for (k, v) in fields {
            leaf.insert(k, v);
        }
    }
    Value::Object(root)
}

/// Maximum depth of a vault item name path (slash-separated segments).
/// Each recursive call to `walk_path` consumes one stack frame; the default
/// Rust stack is 8 MiB and each frame is ~200 bytes, giving ~40 000 safe
/// frames. We cap at 64 as a generous-but-safe limit: no legitimate service
/// credential hierarchy needs more than a handful of levels, and any deeper
/// name is almost certainly a misconfiguration or an attempted attack.
pub const WALK_PATH_MAX_DEPTH: usize = 64;

fn walk_path<'a>(root: &'a mut Map<String, Value>, parts: &[&str]) -> &'a mut Map<String, Value> {
    walk_path_inner(root, parts, 0)
}

fn walk_path_inner<'a>(
    root: &'a mut Map<String, Value>,
    parts: &[&str],
    depth: usize,
) -> &'a mut Map<String, Value> {
    // Safety: callers must pass a non-empty slice. `build_secrets_json` splits
    // on '/' so the minimum is one element. Return root unchanged for empty
    // slices instead of panicking — callers validate item names before calling.
    //
    // Depth guard: `aggregate()` already rejects names with more than
    // `WALK_PATH_MAX_DEPTH` segments before calling `build_secrets_json`, so
    // this check is a belt-and-suspenders defence for direct callers of
    // `build_secrets_json`. Returning root at the depth cap is safe: the
    // offending item's fields will be merged into the parent node rather than
    // discarded, which is a tolerable semantic degradation vs. a stack overflow.
    if depth >= WALK_PATH_MAX_DEPTH {
        tracing::warn!(
            "walk_path: depth cap {} reached — truncating nested path. \
             This should not happen in production; check vault item names.",
            WALK_PATH_MAX_DEPTH
        );
        return root;
    }
    let (head, tail) = match parts.split_first() {
        Some(pair) => pair,
        None => return root,
    };
    if tail.is_empty() {
        // Leaf — ensure key exists as object, return mut ref.
        let entry = root
            .entry(head.to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        if !entry.is_object() {
            *entry = Value::Object(Map::new());
        }
        // SAFETY: we just ensured the entry is an Object above.
        entry.as_object_mut().expect("entry is Object")
    } else {
        let entry = root
            .entry(head.to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        if !entry.is_object() {
            *entry = Value::Object(Map::new());
        }
        // SAFETY: we just ensured the entry is an Object above.
        walk_path_inner(
            entry.as_object_mut().expect("entry is Object"),
            tail,
            depth + 1,
        )
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
///
/// Performance: uses `VaultManager::list_field_pairs` which locks the vault
/// items map once and decrypts both field names and values in a single pass —
/// O(n) in fields per item. The previous O(n²) pattern (list_field_names +
/// decrypt_field per name) that was deferred in iter-36 is now eliminated.
pub async fn aggregate(vault: &Arc<VaultManager>, folder_name: &str) -> Result<Value> {
    // Issue-7 (iter-4): Distinguish "folder does not exist" from "folder
    // exists but is empty". `list_items_in_folder` returns an empty Vec for
    // both cases (it resolves folder_name → folder_id, and returns Vec::new()
    // when the folder_id is not found). An empty result from a non-existent
    // folder means every downstream service appears unconfigured — silent and
    // confusing. Log a warning so operators see it in logs.
    //
    // We deliberately do NOT hard-error here (returning Ok({})) because the
    // caller (GET /vault/connecterr-secrets) should still return a valid empty
    // JSON object — returning an HTTP error would break the MCP server's
    // startup health check. The warning in logs is sufficient for diagnosis.
    let folder_exists = vault
        .find_folder_id_by_name_async(folder_name)
        .await
        .is_some();
    if !folder_exists {
        tracing::warn!(
            "vault folder '{}' not found — no items will be aggregated. \
             Create the folder in Vaultwarden and populate it with service credentials.",
            folder_name
        );
    }

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
        // Reject deeply nested names that would recurse past the stack-safe
        // limit in walk_path. A 65-segment path is not a real credential name.
        let segment_count = name.split('/').count();
        if segment_count > WALK_PATH_MAX_DEPTH {
            tracing::warn!(
                item = %name,
                segments = segment_count,
                max = WALK_PATH_MAX_DEPTH,
                "skipping item: path too deep (would risk stack overflow in walk_path)"
            );
            continue;
        }
        if !seen_names.insert(name.clone()) {
            tracing::warn!(item = %name, "duplicate item name in folder; later fields overwrite earlier");
        }

        // Single-pass O(n): decrypt all field names and values together.
        let field_pairs = vault
            .list_field_pairs(&name)
            .await
            .with_context(|| format!("list field pairs for '{}'", name))?;

        let mut field_map = Map::new();
        for (fname, buf) in field_pairs {
            let s = buf
                .as_str()
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
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), Value::String(v.to_string())))
            .collect()
    }

    #[test]
    fn build_secrets_json_handles_flat_and_nested_paths() {
        let pairs = vec![
            ("apiKey".into(), fields(&[("apiKey", "ABC")])),
            (
                "unifi/home".into(),
                fields(&[("username", "admin"), ("password", "pw")]),
            ),
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
        assert!(
            v.get("").is_some(),
            "empty leading segment should produce '' key"
        );
    }

    #[test]
    fn walk_path_empty_slice_returns_root_without_panic() {
        // Regression test for the `expect("non-empty path")` panic fix.
        // walk_path is an internal helper; passing an empty slice previously
        // would panic. After the fix it must return root unchanged.
        let mut root = Map::new();
        root.insert("existing".to_string(), Value::String("val".to_string()));
        let result = walk_path(&mut root, &[]);
        // Root is returned as-is; the existing key is preserved.
        assert!(result.contains_key("existing"));
    }
}
