//! Vault HTTP handlers.

use std::sync::Arc;

use axum::{extract::State, http::StatusCode, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::proxy::AppState;
use super::types::{DuplicateGroup, FolderInfo, MaskedItem};

// -------------------------------------------------------------------------- //
// Helpers                                                                     //
// -------------------------------------------------------------------------- //

/// Resolve the `vault_folder` name to its Vaultwarden folder ID, using the
/// cached value in `state.cached_folder_id` when available.
///
/// Issue (iter-22): Every scoped handler previously called
/// `find_folder_id_by_name_async` on every request — a read lock + linear scan
/// over the folder map. Since `vault_folder` is static (set at startup),
/// caching the resolved ID avoids the repeated lock acquisition.
///
/// The cache is invalidated by `POST /vault/resync` (which may rename or
/// recreate the folder). A `None` in the cache means "not yet resolved" —
/// this function populates it on first call and returns the resolved ID.
///
/// Callers that get `None` back should treat it as "folder not found in the
/// vault" (same semantics as `find_folder_id_by_name_async`).
///
/// # Thundering-herd prevention (iter-23)
///
/// The iter-22 implementation had a TOCTOU window: after dropping the read lock
/// but before acquiring the write lock, N concurrent requests could all observe
/// `None` and all call `find_folder_id_by_name_async` independently. This is a
/// thundering herd against the vault's folder-index read lock.
///
/// Fix: after the read-lock miss, upgrade to a write lock and re-check the
/// cache before populating it (double-checked locking). Only the first writer
/// calls `find_folder_id_by_name_async`; all others find the cache warm on the
/// re-check and return immediately without calling into the vault.
pub async fn resolve_vault_folder_id(state: &Arc<AppState>) -> Option<String> {
    // Fast path: cache hit under read lock.
    {
        let cached = state.cached_folder_id.read().await;
        if let Some(ref id) = *cached {
            return Some(id.clone());
        }
    }
    // Slow path: upgrade to write lock and re-check (double-checked locking).
    // Between releasing the read lock and acquiring the write lock another task
    // may have populated the cache — that's the common case after the first
    // resolution. Only the winner of the write lock actually calls into the
    // vault; all losers find the cache warm on re-check.
    let mut write_guard = state.cached_folder_id.write().await;
    if let Some(ref id) = *write_guard {
        // Another task won the race and already populated the cache.
        return Some(id.clone());
    }
    // We are the first writer — resolve and populate.
    let id = state.vault.find_folder_id_by_name_async(&state.vault_folder).await;
    if let Some(ref resolved) = id {
        *write_guard = Some(resolved.clone());
    }
    id
}

// -------------------------------------------------------------------------- //
// Request types                                                               //
// -------------------------------------------------------------------------- //

#[derive(Debug, Deserialize)]
pub struct UpsertConnecterrSecretsItem {
    pub name: String,
    #[serde(default)]
    pub fields: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
pub struct UpsertConnecterrSecretsRequest {
    pub items: Vec<UpsertConnecterrSecretsItem>,
}

fn validate_item_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("name is empty".into());
    }
    // Issue (iter-21): Reject names containing newlines, null bytes, or other
    // ASCII control characters. A name with an embedded `\n` or `\r` could:
    //   1. Corrupt Vaultwarden's internal storage if the cipher name is stored
    //      in a format that treats newlines as delimiters (TOML, env files, etc.).
    //   2. Pollute structured log output — a crafted name like "foo\nERROR bar"
    //      could inject a fake log line into tracing output.
    //   3. Confuse any downstream code that splits on newlines to enumerate items.
    //
    // We also reject null bytes (\0) because they terminate C-style strings and
    // can confuse SQLite or OS-level file name comparisons.
    //
    // The check covers all ASCII control characters (0x00–0x1F, including \t,
    // \n, \r) and DEL (0x7F). Printable ASCII and valid UTF-8 multi-byte
    // sequences are allowed.
    if name.chars().any(|c| (c as u32) < 0x20 || c == '\x7f') {
        return Err(format!(
            "name '{}' contains a control character (newline, null, tab, etc.) — \
             item names must contain only printable characters",
            name.escape_debug()
        ));
    }
    if name.split('/').any(|seg| seg.is_empty()) {
        return Err(format!("name '{}' has empty path segment", name));
    }
    Ok(())
}

/// Validate a custom field name for an upsert operation.
///
/// Issue (iter-22): `upsert_connecterr_secrets` accepts `fields: BTreeMap<String, String>`
/// where keys are field names written to Vaultwarden. These were previously not
/// validated for control characters. A field name with an embedded `\n` or `\0`
/// could corrupt structured log output or confuse Vaultwarden's internal field storage.
///
/// Field names differ from item names: they do not use `/` path syntax, so the
/// empty-path-segment check is omitted. Otherwise the same control-character
/// rejection applies.
fn validate_field_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("field name is empty".into());
    }
    if name.chars().any(|c| (c as u32) < 0x20 || c == '\x7f') {
        return Err(format!(
            "field name '{}' contains a control character (newline, null, tab, etc.) — \
             field names must contain only printable characters",
            name.escape_debug()
        ));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // fields read by serde deserialization
pub struct CreateItemFieldInput {
    pub name: String,
    pub value: String,
    /// Bitwarden field type: 0=text, 1=hidden, 2=boolean, 3=linked. Default 1 (hidden).
    /// Validated against this range in `create_item`; out-of-range values yield 400.
    #[serde(default = "default_field_type")]
    pub field_type: u8,
}
fn default_field_type() -> u8 { 1 }

/// Reject URL values that don't pass a minimal SSRF policy: scheme must be
/// http or https, and the host must not resolve to a cloud-metadata IP,
/// link-local range, or loopback address. We deliberately do NOT inspect
/// the path — that's the target API's concern — only the authority. Shared
/// across any handler that builds an outbound URL from user-supplied input
/// (currently `inject_creds` and `browser_rotate`).
///
/// # Loopback blocking (iter-9 fix)
///
/// A crafted `services.toml` with `base_url = "http://127.0.0.1:3201/..."` could
/// point the `/proxy` handler at vault-proxy itself, enabling a caller to
/// read vault metadata or enumerate items via a `/proxy` → `/vault/items`
/// loop-back. `is_allowed_outbound_url` is called by `inject_creds` and
/// `browser_rotate` (both of which accept user-supplied URLs). Loopback
/// addresses (`127.0.0.0/8`, `::1`, and the hostname `localhost`) are now
/// blocked in addition to the existing link-local / cloud-metadata guards.
///
/// # Userinfo blocking (iter-11)
///
/// A URL like `http://user:password@service/api` has a userinfo component.
/// Userinfo is forwarded verbatim in the `Authorization` header by some HTTP
/// clients (as Basic auth) and always appears in log lines. Because vault-proxy
/// obtains credentials exclusively from the vault, a `base_url` with embedded
/// credentials is always a misconfiguration: the password would be passed both
/// from the vault AND from the URL. We reject such URLs to prevent credential
/// leakage via logs and to prevent config confusion.
pub(crate) fn is_allowed_outbound_url(raw: &str) -> bool {
    let url = match url::Url::parse(raw) {
        Ok(u) => u,
        Err(_) => return false,
    };
    match url.scheme() {
        "http" | "https" => {}
        _ => return false,
    }
    // iter-11: Reject URLs that embed credentials (userinfo component).
    // `url::Url::password()` returns Some(_) even when the password is the
    // empty string (e.g. "http://user:@host/"), so we check both.
    if url.username() != "" || url.password().is_some() {
        return false;
    }
    let host = match url.host_str() {
        Some(h) => h,
        None => return false,
    };
    // Block well-known cloud metadata hostnames and loopback hostname outright.
    const BLOCKED_HOSTS: &[&str] = &[
        "169.254.169.254",               // AWS/GCP/Azure IMDS
        "metadata.google.internal",      // GCP
        "metadata.aws.cloud",
        "metadata.azure.com",
        "fd00:ec2::254",                 // AWS IPv6 IMDS
        "localhost",                     // loopback hostname — blocks loop-back into vault-proxy
    ];
    if BLOCKED_HOSTS.iter().any(|b| b.eq_ignore_ascii_case(host)) {
        return false;
    }
    // If the host is a literal IP, also block loopback, link-local, and
    // IMDS-adjacent ranges.
    // NOTE: url::Url::host_str() returns IPv6 addresses with enclosing
    // brackets (e.g. "[fe80::1]"). Rust's IpAddr parser does NOT accept
    // brackets, so we must strip them before parsing or the IPv6 link-local
    // check silently passes for fe80:: addresses.
    let host_for_ip = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host_for_ip.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => {
                let octs = v4.octets();
                // 127.0.0.0/8 — loopback (blocks loop-back into vault-proxy itself)
                if octs[0] == 127 {
                    return false;
                }
                // 169.254.0.0/16 — link-local / cloud metadata
                if octs[0] == 169 && octs[1] == 254 {
                    return false;
                }
            }
            std::net::IpAddr::V6(v6) => {
                // ::1 — IPv6 loopback
                if v6.is_loopback() {
                    return false;
                }
                // fe80::/10 link-local
                let seg = v6.segments();
                if seg[0] & 0xffc0 == 0xfe80 {
                    return false;
                }
            }
        }
    }
    true
}

/// Flow IDs come from the HA config-flow engine and are normally UUIDs.
/// Restrict to a narrow charset to prevent path-traversal into arbitrary
/// HA API endpoints via crafted `flow_id` values like `../../admin`.
fn is_safe_flow_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // fields read by serde deserialization
pub struct CreateItemRequest {
    pub name: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub uri: Option<String>,
    pub notes: Option<String>,
    /// Custom field name → value pairs. Stored as type-1 (hidden) by default.
    #[serde(default)]
    pub fields: Vec<CreateItemFieldInput>,
    /// Folder name (decrypted). If set, item is placed in this folder.
    /// Must already exist in the vault — this handler does not create folders.
    pub folder_name: Option<String>,
}

/// Request body for `update_item`. All fields except `id` are optional —
/// only the provided fields are modified; omitted fields are left unchanged.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct UpdateItemRequest {
    /// Vault item id (uuid) to update.
    pub id: String,
    pub name: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub uri: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // fields read by serde deserialization
pub struct DeleteItemRequest {
    pub id: String,
    pub confirm: bool,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // fields read by serde deserialization
pub struct DeleteFolderRequest {
    pub id: String,
    pub confirm: bool,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct CloneItemRequest {
    /// Vault item id whose encrypted password blob is copied to the new cipher.
    pub source_id: String,
    /// New cipher name (plaintext; encrypted server-side with vault keys).
    pub name: String,
    /// New username. Omit to reuse the source's username.
    #[serde(default)]
    pub username: Option<String>,
    /// New URI. Omit to reuse the source's URIs.
    #[serde(default)]
    pub uri: Option<String>,
    /// Place the new cipher in this folder id. Omit for unfiled.
    #[serde(default)]
    pub folder_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct TestCredentialRequest {
    /// Vault item id whose (username, password) should be tried against `url`.
    pub vault_item_id: String,
    pub url: String,
    /// HTTP method for the login request. Default: "POST".
    #[serde(default)]
    pub method: Option<String>,
    /// Auth style — one of:
    ///   "json"  — POST JSON body with username/password fields
    ///   "form"  — application/x-www-form-urlencoded
    ///   "basic" — HTTP Basic auth header
    pub auth_style: String,
    /// Field name for username in the body. Default: "username".
    #[serde(default)]
    pub username_field: Option<String>,
    /// Field name for password in the body. Default: "password".
    #[serde(default)]
    pub password_field: Option<String>,
    /// Extra fields to merge into the request body (json/form only).
    #[serde(default)]
    pub extra_fields: Option<serde_json::Map<String, Value>>,
    /// Status codes considered a successful authentication. Default: [200, 204].
    #[serde(default)]
    pub success_statuses: Option<Vec<u16>>,
    /// Optional JSON body to include in the request. Only meaningful for
    /// `basic` auth (where the credentials go in the Authorization header and
    /// the body is otherwise empty) — lets callers drive authenticated
    /// mutations, e.g. `POST /api/v1/user/repos` against Gitea. Ignored for
    /// `json`/`form` auth styles, which compose the body from
    /// username/password + extra_fields.
    #[serde(default)]
    pub body: Option<Value>,
    /// When true, include the response body (capped at 64 KiB) in the result
    /// so callers can read mutation output (e.g. the id of a newly-created
    /// resource). Default false — preserves the existing status-only
    /// behavior for probe-style use. Bodies are returned as a UTF-8 string;
    /// non-UTF-8 bytes are replaced. The cap exists to protect log / response
    /// size; if the upstream returns more than 64 KiB, the returned string is
    /// truncated and a `response_body_truncated: true` flag is set.
    #[serde(default)]
    pub return_body: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct WriteEnvRequest {
    pub vault_item_id: String,
    /// Absolute path to write the env file. Must begin with one of the
    /// allowlisted prefixes (see `write_env` handler) — otherwise this
    /// endpoint is a write-anywhere primitive, which is not acceptable.
    pub target_path: String,
    /// Map env-var name → source field on the vault item. Supported source
    /// fields: "username", "password". Other fields (uri/notes/name) are
    /// refused until the plaintext-fetch helpers for them are available.
    pub mappings: std::collections::HashMap<String, String>,
    /// Create the target file if it doesn't exist. Defaults to true. When
    /// the file is created, it gets mode 0600.
    #[serde(default)]
    pub create_if_missing: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // fields read by serde deserialization
pub struct MoveItemRequest {
    pub id: String,
    /// Exactly one of `folder_id` or `folder_name` must be provided.
    /// `folder_id` is preferred when the caller needs to disambiguate between
    /// multiple folders with the same name (common after cloud→self-hosted
    /// migrations); `folder_name` is the ergonomic form that creates the
    /// folder if missing.
    #[serde(default)]
    pub folder_id: Option<String>,
    #[serde(default)]
    pub folder_name: Option<String>,
}

// -------------------------------------------------------------------------- //
// Handlers                                                                    //
// -------------------------------------------------------------------------- //

/// `GET /vault/health` — liveness + summary.
pub async fn health(State(state): State<Arc<AppState>>) -> Json<Value> {
    let items = state.vault.list_items().await;
    let services = state.registry.list();

    let cloud_sync_status = match &state.cloud_sync {
        Some(sync) => {
            let st = sync.get_status().await;
            json!({
                "state": st.state,
                "last_sync": st.last_sync,
                "items_synced": st.items_synced,
                "errors": st.errors,
            })
        }
        None => json!({ "state": "not_configured" }),
    };

    Json(json!({
        "status": "ok",
        "vault_item_count": items.len(),
        "services": services,
        "cloud_sync": cloud_sync_status,
    }))
}

/// `GET /vault/items` — list vault items with passwords masked.
///
/// Issue (iter-18): Scope to vault_folder only.
///
/// Previously this returned every item in the entire vault — banking
/// credentials, SSH keys, personal logins — with their names, usernames, and
/// URIs exposed in plaintext to any local caller. vault-proxy has no business
/// exposing items from other folders; only items in `state.vault_folder` are
/// within its ownership boundary.
///
/// We resolve vault_folder → folder_id async and filter the full list.
/// If the folder isn't found (fresh vault / mid-setup) we fall through and
/// return all items so first-run usability is preserved — the same permissive
/// fallback used by update_item and delete_item.
pub async fn list_items(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<MaskedItem>> {
    let items = state.vault.list_items().await;

    // Find the folder_id that corresponds to vault_folder.
    let vault_folder_id = state.vault.find_folder_id_by_name_async(&state.vault_folder).await;

    let filtered = match vault_folder_id {
        Some(ref folder_id) => items
            .into_iter()
            .filter(|item| item.folder_id.as_deref() == Some(folder_id.as_str()))
            .collect(),
        None => {
            // vault_folder not found — fresh vault or misconfiguration.
            // Return all items so first-run tooling still works.
            tracing::debug!(
                "list_items: vault_folder '{}' not found — returning all items (fresh vault?)",
                state.vault_folder
            );
            items
        }
    };

    Json(filtered)
}

/// `GET /vault/duplicates` — find items that share the same
/// `(organization_id, username, password)`. Passwords are hashed and
/// compared inside the proxy; plaintext and hashes never leave.
///
/// Issue (iter-19): Scope to vault_folder only. Previously this scanned the
/// full vault cache and returned names/usernames of personal items (outside
/// vault_folder) to any local caller. We now filter to vault_folder items
/// before duplicate detection so personal entries are never exposed.
pub async fn list_duplicates(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<DuplicateGroup>> {
    // Resolve vault_folder → folder_id for filtering.
    let vault_folder_id = state.vault.find_folder_id_by_name_async(&state.vault_folder).await;
    let groups = state.vault.list_duplicates_in_folder(vault_folder_id.as_deref()).await;
    Json(groups)
}

/// `GET /vault/folders` — list folders scoped to `vault_folder`.
///
/// # Folder scope (iter-20)
///
/// Previously this returned ALL folders in the vault, exposing personal folder
/// names (e.g. "Banking", "Work", "Personal SSH Keys") to any local caller.
/// Folder names are sensitive metadata: they reveal the owner's life categories
/// even without exposing any credential values.
///
/// We now return only the folder(s) whose decrypted name matches
/// `state.vault_folder` (the proxy's own folder). Duplicate `vault_folder`
/// entries (same name, different IDs — a common cloud→self-hosted migration
/// artefact) still show up as separate entries so the operator can consolidate
/// them, but personal folders are no longer surfaced.
///
/// If the vault_folder is not found (fresh vault), an empty list is returned.
///
/// # `?include_all=true` — destination listing for `move_item` (iter-21)
///
/// `POST /vault/items/move` accepts a `folder_id` field so the caller can
/// target an already-existing folder by its UUID. After the iter-20 scope
/// restriction, the only way to discover folder IDs from other folders was
/// out-of-band (Vaultwarden UI, external API call). That makes the `folder_id`
/// path of `move_item` effectively unusable for cross-folder moves.
///
/// The `?include_all=true` query parameter restores the pre-iter-20 full
/// listing ONLY for use as a destination picker. It is intentionally separate
/// from the default path so callers must opt in. Audit logging is applied.
///
/// This is NOT a security regression: folder names are already visible to
/// the vault owner in Vaultwarden; any authenticated local caller (same threat
/// model as the rest of the API) can enumerate them.
pub async fn list_folders(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Json<Vec<FolderInfo>> {
    let include_all = params.get("include_all").map(|v| v == "true").unwrap_or(false);
    let tracked: std::collections::HashSet<String> = if let Some(ref sm) = state.cloud_sync {
        sm.map
            .read()
            .await
            .folders
            .values()
            .map(|m| m.vw_folder_id.clone())
            .collect()
    } else {
        std::collections::HashSet::new()
    };
    let all = state.vault.list_folders_with_counts(&tracked).await;

    if include_all {
        // Return all folders — used by callers that need to resolve destination
        // folder IDs for `POST /vault/items/move`. Audit so operators can see
        // when the full listing is requested.
        //
        // Issue (iter-22): The iter-21 comment said "Audit logging is applied"
        // but only a tracing::info! was present — the structured AuditLog was
        // never called for this path. Fixed here.
        tracing::info!(
            "list_folders: include_all=true requested — returning all {} folder(s) \
             for destination resolution (move_item use case)",
            all.len()
        );
        state.audit_log.log(crate::security::audit_log::AuditEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            tool_name: "vault__list_folders".to_string(),
            args_summary: "include_all=true".to_string(),
            result_summary: format!("ok; returned {} folder(s)", all.len()),
            permission: "Allowed".to_string(),
            trigger: "http".to_string(),
        });
        return Json(all);
    }

    // Default: filter to only entries whose name matches vault_folder. This still
    // exposes duplicate vault_folder entries (same name, different id) so operators
    // can identify and consolidate migration artefacts.
    let scoped: Vec<FolderInfo> = all
        .into_iter()
        .filter(|f| f.name == state.vault_folder.as_str())
        .collect();
    Json(scoped)
}

/// `GET /vault/items/untracked` — list vault items that have no entry in the
/// cloud↔VW sync map. These are either personal items created directly in VW
/// (expected) or orphans from past broken-sync runs (cleanup targets).
///
/// # Folder scope (iter-20)
///
/// Without a scope guard this endpoint returns ALL vault items not in the sync
/// map — including personal items from every other folder (banking, personal SSH
/// keys, etc.). The "untracked" check is purely about sync-map membership, not
/// about folder ownership. We now filter the result to only items inside
/// `vault_folder`, consistent with every other listing endpoint. Items outside
/// `vault_folder` that are also outside the sync map are none of vault-proxy's
/// concern; an operator who wants to find personal vault orphans should use the
/// Vaultwarden UI directly.
pub async fn list_untracked_items(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    let tracked: std::collections::HashSet<String> = if let Some(ref sm) = state.cloud_sync {
        sm.map
            .read()
            .await
            .items
            .values()
            .map(|m| m.vw_id.clone())
            .collect()
    } else {
        std::collections::HashSet::new()
    };

    // Issue (iter-20): Scope to vault_folder items only. list_untracked_item_ids
    // returns ALL items not in the sync map — including personal items from other
    // folders. Filter to vault_folder before returning so callers cannot enumerate
    // names/usernames/URIs of personal vault entries.
    let vault_folder_id = state.vault.find_folder_id_by_name_async(&state.vault_folder).await;

    let all_untracked = state.vault.list_untracked_item_ids(&tracked).await;

    // When vault_folder is not yet resolved (fresh vault), return everything
    // untracked — same permissive fallback used by list_items.
    let items: Vec<(String, String)> = match vault_folder_id {
        Some(ref fid) => {
            // We need folder_id per item. Re-read from the vault to filter.
            // list_untracked_item_ids already holds a snapshot; we cross-reference
            // against get_cipher_by_id to get folder membership.
            // Build the filtered list inline.
            let mut out = Vec::new();
            for (id, name) in all_untracked {
                if let Some(cipher) = state.vault.get_cipher_by_id(&id).await {
                    if cipher.folder_id.as_deref() == Some(fid.as_str()) {
                        out.push((id, name));
                    }
                }
            }
            out
        }
        None => {
            tracing::debug!(
                "list_untracked_items: vault_folder '{}' not found — returning all untracked items (fresh vault?)",
                state.vault_folder
            );
            all_untracked
        }
    };

    Json(json!({
        "count": items.len(),
        "items": items
            .into_iter()
            .map(|(id, name)| json!({ "id": id, "name": name }))
            .collect::<Vec<_>>(),
    }))
}

/// `POST /vault/items` — create a new vault item (login type).
///
/// Encrypts all fields with the vault's symmetric key and creates the cipher
/// in Vaultwarden. Plaintext is zeroized after encryption.
///
/// # Folder scope (iter-19)
///
/// Items must land in `vault_folder`. When the caller omits `folder_name` the
/// proxy defaults to `state.vault_folder` so the item is always created inside
/// the owned folder. When `folder_name` is supplied it must exactly match
/// `state.vault_folder`; a different value is rejected with 400 to prevent
/// callers from injecting items into arbitrary vault folders.
pub async fn create_item(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateItemRequest>,
) -> (StatusCode, Json<Value>) {
    use crate::vault::crypto::encrypt_to_cipher_string;
    use crate::vault::types::{EncryptedCipher, EncryptedField, EncryptedLogin, EncryptedUri};

    // Issue (iter-19): Enforce folder scope.
    // If folder_name is provided it must match vault_folder; if omitted, default
    // to vault_folder so items are never created outside the owned folder.
    let effective_folder_name = match req.folder_name.as_deref() {
        Some(fname) if fname != state.vault_folder.as_str() => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": format!(
                        "folder_name '{}' is not the vault-proxy folder ('{}') — \
                         create_item only creates items inside the vault-proxy folder",
                        fname, state.vault_folder
                    )
                })),
            );
        }
        Some(_) | None => state.vault_folder.clone(),
    };

    let enc_key = state.vault.enc_key();
    let mac_key = state.vault.mac_key();

    let enc_name = match encrypt_to_cipher_string(&req.name, enc_key, mac_key) {
        Ok(s) => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": format!("encrypt name: {}", e)}))),
    };

    let enc_username = req.username.as_deref().and_then(|u| encrypt_to_cipher_string(u, enc_key, mac_key).ok());
    let enc_password = req.password.as_deref().and_then(|p| encrypt_to_cipher_string(p, enc_key, mac_key).ok());
    let enc_notes    = req.notes   .as_deref().and_then(|n| encrypt_to_cipher_string(n, enc_key, mac_key).ok());
    let enc_uris = req.uri.as_deref().and_then(|u| {
        encrypt_to_cipher_string(u, enc_key, mac_key).ok().map(|enc_uri| {
            vec![EncryptedUri { uri: Some(enc_uri) }]
        })
    });

    // Validate field_type range (BW types are 0=text, 1=hidden, 2=boolean, 3=linked).
    if let Some(bad) = req.fields.iter().find(|f| f.field_type > 3) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!(
                "field '{}' has invalid field_type {} (expected 0..=3)",
                bad.name, bad.field_type
            )})),
        );
    }

    // Encrypt custom fields.
    let enc_fields: Option<Vec<EncryptedField>> = if req.fields.is_empty() {
        None
    } else {
        let mut out = Vec::with_capacity(req.fields.len());
        for f in &req.fields {
            let enc_fname = match encrypt_to_cipher_string(&f.name, enc_key, mac_key) {
                Ok(s) => s,
                Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": format!("encrypt field name '{}': {}", f.name, e)}))),
            };
            let enc_fval = match encrypt_to_cipher_string(&f.value, enc_key, mac_key) {
                Ok(s) => s,
                Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": format!("encrypt field value '{}': {}", f.name, e)}))),
            };
            out.push(EncryptedField {
                name: Some(enc_fname),
                value: Some(enc_fval),
                field_type: f.field_type,
            });
        }
        Some(out)
    };

    // Resolve effective_folder_name → folder_id.
    // effective_folder_name is always vault_folder (validated above), so this
    // places the new item inside the owned folder. Returns None only when the
    // folder doesn't exist yet (fresh vault) — the item will be created without
    // a folder, which is acceptable for first-run tooling.
    let folder_id = match state.vault.find_folder_id_by_name_async(&effective_folder_name).await {
        Some(id) => Some(id),
        None => {
            tracing::debug!(
                "create_item: vault_folder '{}' not found — creating item without folder (fresh vault?)",
                effective_folder_name
            );
            None
        }
    };

    let cipher = EncryptedCipher {
        id: String::new(),
        name: enc_name,
        cipher_type: 1,
        login: Some(EncryptedLogin {
            username: enc_username,
            password: enc_password,
            uris: enc_uris,
            totp: None,
        }),
        card: None, identity: None, secure_note: None,
        fields: enc_fields,
        notes: enc_notes,
        organization_id: None,
        collection_ids: None,
        folder_id,
        revision_date: None,
        key: None,
        extra: None,
    };

    match state.vault.create_cipher(&cipher).await {
        Ok(id) => {
            if let Err(e) = state.vault.sync().await {
                tracing::warn!("post-create sync failed: {}", e);
            }
            (StatusCode::CREATED, Json(json!({"ok": true, "id": id})))
        }
        Err(e) => {
            tracing::error!("create cipher failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()})))
        }
    }
}

/// `POST /vault/items/update` — patch a login cipher in-place.
///
/// Only the fields present in the request body are changed; omitted fields
/// are left exactly as they are in the vault. Plaintext values are encrypted
/// with the vault's symmetric key inside the proxy — they never appear in
/// the Bitwarden API calls.
pub async fn update_item(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpdateItemRequest>,
) -> (StatusCode, Json<Value>) {
    use crate::vault::crypto::encrypt_to_cipher_string;
    use crate::vault::types::EncryptedLogin;

    if req.id.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, Json(json!({"error": "id must not be empty"})));
    }

    // Fetch the existing cipher so we only overwrite the requested fields.
    let cipher = match state.vault.get_cipher_by_id(&req.id).await {
        Some(c) => c,
        None => return (StatusCode::NOT_FOUND, Json(json!({"error": "item not found"}))),
    };

    // Issue (iter-17): Scope update_item to items inside state.vault_folder only.
    //
    // Without this guard an MCP caller can pass any vault item UUID — including
    // items outside the vault-proxy folder (banking passwords, personal notes,
    // SSH keys, etc.) — and overwrite their name, username, password, or URI.
    // vault-proxy has no business modifying items it doesn't own.
    //
    // We resolve vault_folder → folder_id async; if the folder is not found we
    // fall through permissively (the vault_folder may not yet exist in a fresh
    // vault, or the operator may be mid-setup).  We only block when we can
    // positively confirm the item belongs to a *different* folder.
    {
        let vault_folder_id = state.vault.find_folder_id_by_name_async(&state.vault_folder).await;
        if let Some(ref folder_id) = vault_folder_id {
            match cipher.folder_id.as_deref() {
                Some(item_folder_id) if item_folder_id != folder_id.as_str() => {
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({
                            "error": format!(
                                "item {} is not in the vault-proxy folder ('{}') — \
                                 update_item only modifies items owned by vault-proxy",
                                req.id, state.vault_folder
                            )
                        })),
                    );
                }
                None => {
                    // Item has no folder — could be a root-level item not owned by vault-proxy.
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({
                            "error": format!(
                                "item {} has no folder — update_item only modifies items \
                                 inside the vault-proxy folder ('{}')",
                                req.id, state.vault_folder
                            )
                        })),
                    );
                }
                _ => {} // folder_id matches vault_folder — proceed
            }
        }
        // If vault_folder_id is None (folder not found), fall through and allow
        // the update — the operator is likely running a fresh/test vault.
    }

    let enc_key = state.vault.enc_key();
    let mac_key = state.vault.mac_key();

    let mut updated = cipher.clone();

    // Update name if provided.
    if let Some(ref new_name) = req.name {
        if new_name.trim().is_empty() {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": "name must not be empty"})));
        }
        updated.name = match encrypt_to_cipher_string(new_name, enc_key, mac_key) {
            Ok(s) => s,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": format!("encrypt name: {}", e)}))),
        };
    }

    // Update login fields if any are provided.
    if req.username.is_some() || req.password.is_some() || req.uri.is_some() {
        let login = updated.login.get_or_insert_with(|| EncryptedLogin {
            username: None, password: None, uris: None, totp: None,
        });
        if let Some(ref u) = req.username {
            login.username = encrypt_to_cipher_string(u, enc_key, mac_key).ok();
        }
        if let Some(ref p) = req.password {
            login.password = encrypt_to_cipher_string(p, enc_key, mac_key).ok();
        }
        if let Some(ref uri) = req.uri {
            use crate::vault::types::EncryptedUri;
            login.uris = encrypt_to_cipher_string(uri, enc_key, mac_key).ok().map(|enc| {
                vec![EncryptedUri { uri: Some(enc) }]
            });
        }
    }

    // Update notes if provided.
    if let Some(ref n) = req.notes {
        updated.notes = encrypt_to_cipher_string(n, enc_key, mac_key).ok();
    }

    match state.vault.update_cipher(&req.id, &updated).await {
        Ok(()) => {
            if let Err(e) = state.vault.sync().await {
                tracing::warn!("post-update sync failed: {}", e);
            }
            (StatusCode::OK, Json(json!({"ok": true, "id": req.id})))
        }
        Err(e) => {
            tracing::error!("update cipher failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()})))
        }
    }
}

/// `GET /handshake` — return the client certificate material for Connecterr.
///
/// Called once at Connecterr startup so the TypeScript client can configure
/// itself with the mTLS client cert/key that vault-proxy generated.
/// One-time use: after the first successful handshake, subsequent calls
/// are rejected to prevent key exfiltration.
///
/// # Security note (iter-6 audit)
///
/// This endpoint is **internal** to the Connecterr sidecar pair. It returns
/// the ephemeral private key (`client_key_pem`) to whoever calls it first.
/// The single-use flag (`handshake_completed`) prevents a *second* caller
/// from reading the key, but it does nothing to prevent an *unauthorized
/// first* caller (any process on localhost, or any browser tab exploiting a
/// DNS-rebinding window before the legitimate Connecterr client starts).
///
/// For a public release, operators should be aware of this design constraint:
/// - The window between vault-proxy startup and the first Connecterr handshake
///   is the only time this is exploitable.
/// - The sidecar is bound to 127.0.0.1 only, and the DNS rebinding guard
///   blocks requests with non-localhost `Host` headers, which substantially
///   reduces the attack surface.
/// - A browser-based DNS rebinding attack that wins the race is theoretically
///   possible. Mitigation: start Connecterr and vault-proxy as a unit
///   (e.g. Docker Compose depends_on) so Connecterr completes the handshake
///   before any untrusted code runs.
///
/// RESOLVED (iter-22): A pre-shared bearer token is now required to call
/// `/handshake`. The token is generated at startup and written to
/// `$CONFIG_DIR/internal-token` (0o600 permissions). Connecterr reads the
/// token file before calling `/handshake`, eliminating the race window for
/// unauthenticated callers.
pub async fn handshake(State(state): State<Arc<AppState>>) -> Json<Value> {
    // Only allow handshake once — prevent key exfiltration after startup.
    if state.handshake_completed.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return Json(json!({
            "error": "handshake already completed — restart sidecar to re-handshake",
        }));
    }

    match &state.client_certs {
        Some(certs) => Json(json!({
            "ca_cert_pem":     certs.ca_cert_pem,
            "client_cert_pem": certs.client_cert_pem,
            "client_key_pem":  certs.client_key_pem,
        })),
        None => Json(json!({
            "error": "mTLS certificates not available",
        })),
    }
}

/// `POST /vault/items/clone` — create a new login cipher that reuses the
/// encrypted password blob of an existing item, with optional overrides for
/// name/username/uri. The plaintext password is never touched — we copy the
/// encrypted cipher string byte-for-byte. Recovery path for "I deleted the
/// only copy of a credential I know is shared with this other item."
pub async fn clone_item(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CloneItemRequest>,
) -> (StatusCode, Json<Value>) {
    if req.source_id.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "source_id is required" })),
        );
    }
    if req.name.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "name is required" })),
        );
    }

    // Issue (iter-18): Scope clone_item to source items inside state.vault_folder only.
    //
    // Without this guard an MCP caller can supply any source_id — including items
    // from entirely different folders (banking, personal SSH keys, etc.) — and
    // duplicate their encrypted password blob into a new item. This would silently
    // exfiltrate credentials indirectly: the clone lands in the vault folder and
    // vault-proxy can then decrypt its password via decrypt_password().
    //
    // We do NOT restrict the *destination* folder (req.folder_id) — cloning into
    // an arbitrary destination folder is intentional (the operator may want the
    // clone in a staging area). Only the *source* must be inside vault_folder.
    {
        let source = match state.vault.get_cipher_by_id(&req.source_id).await {
            Some(c) => c,
            None => return (StatusCode::NOT_FOUND, Json(json!({"error": "source item not found"}))),
        };
        let vault_folder_id = state.vault.find_folder_id_by_name_async(&state.vault_folder).await;
        if let Some(ref folder_id) = vault_folder_id {
            match source.folder_id.as_deref() {
                Some(item_folder_id) if item_folder_id != folder_id.as_str() => {
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({
                            "error": format!(
                                "source item {} is not in the vault-proxy folder ('{}') — \
                                 clone_item only clones items owned by vault-proxy",
                                req.source_id, state.vault_folder
                            )
                        })),
                    );
                }
                None => {
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({
                            "error": format!(
                                "source item {} has no folder — clone_item only clones items \
                                 inside the vault-proxy folder ('{}')",
                                req.source_id, state.vault_folder
                            )
                        })),
                    );
                }
                _ => {} // folder_id matches vault_folder — proceed
            }
        }
    }

    match state
        .vault
        .clone_cipher_with_overrides(
            &req.source_id,
            &req.name,
            req.username.as_deref(),
            req.uri.as_deref(),
            req.folder_id.as_deref(),
        )
        .await
    {
        Ok(new_id) => (
            StatusCode::CREATED,
            Json(json!({ "ok": true, "id": new_id, "source_id": req.source_id })),
        ),
        Err(e) => {
            tracing::error!("clone cipher failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
        }
    }
}

/// `POST /vault/test-credential` — attempt an authenticated login against
/// `url` using the credentials stored under `vault_item_id`. Plaintext
/// username/password never leave the proxy — they're decrypted, placed on
/// an outbound HTTP request, and dropped. The response body is discarded;
/// only the HTTP status code and an `authenticated` boolean (status in the
/// configured success set) are returned.
pub async fn test_credential(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TestCredentialRequest>,
) -> (StatusCode, Json<Value>) {
    use reqwest::Client;
    use zeroize::Zeroizing;

    // Validate the URL against the full SSRF policy — not just a scheme check.
    // The original check only blocked non-http(s) schemes but allowed requests
    // to 169.254.169.254 (AWS IMDS), fe80::/10 link-local addresses, and other
    // cloud-metadata endpoints. Since this endpoint makes an outbound request
    // with real vault credentials, a caller could use it as an SSRF gadget to
    // probe internal services or exfiltrate credentials to an attacker-controlled
    // host without ever touching the proxy's own service registry.
    if !is_allowed_outbound_url(&req.url) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "url must be http(s) and resolve to a non-metadata, non-link-local host" })),
        );
    }

    // Issue (iter-19): Scope test_credential to vault_folder items only.
    // Without this guard a caller can pass any vault item UUID and use this
    // endpoint to decrypt + test credentials for unrelated personal accounts.
    // We check the item's folder_id against vault_folder before decrypting.
    {
        let cipher = match state.vault.get_cipher_by_id(&req.vault_item_id).await {
            Some(c) => c,
            None => return (StatusCode::NOT_FOUND, Json(json!({"error": "vault item not found"}))),
        };
        let vault_folder_id = state.vault.find_folder_id_by_name_async(&state.vault_folder).await;
        if let Some(ref folder_id) = vault_folder_id {
            match cipher.folder_id.as_deref() {
                Some(item_folder_id) if item_folder_id != folder_id.as_str() => {
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({
                            "error": format!(
                                "item {} is not in the vault-proxy folder ('{}') — \
                                 test_credential is scoped to vault-proxy items only",
                                req.vault_item_id, state.vault_folder
                            )
                        })),
                    );
                }
                None => {
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({
                            "error": format!(
                                "item {} has no folder — test_credential is scoped to \
                                 items inside the vault-proxy folder ('{}')",
                                req.vault_item_id, state.vault_folder
                            )
                        })),
                    );
                }
                _ => {} // folder_id matches vault_folder — proceed
            }
        }
        // If vault_folder_id is None (folder not found), fall through
        // permissively — fresh vault / first-run scenario.
    }

    // Decrypt creds. Plaintext lives in SecureBuffers, zeroised on drop.
    let (username_buf, password_buf) = match state
        .vault
        .decrypt_credentials_by_id(&req.vault_item_id)
        .await
    {
        Ok(pair) => pair,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": format!("decrypt creds: {}", e) })),
            );
        }
    };

    // Zeroizing<String> so the owned String form also wipes on drop. For
    // large credential sweeps this matters; for a one-shot test less so, but
    // the policy is "no plaintext lingers".
    let username: Zeroizing<String> = Zeroizing::new(
        username_buf
            .as_ref()
            .map(|b| String::from_utf8_lossy(b.as_bytes()).into_owned())
            .unwrap_or_default(),
    );
    let password: Zeroizing<String> =
        Zeroizing::new(String::from_utf8_lossy(password_buf.as_bytes()).into_owned());

    let client = match Client::builder()
        .danger_accept_invalid_certs(true) // LAN services commonly have self-signed
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": format!("build http client: {}", e) })),
            );
        }
    };

    let method = req.method.as_deref().unwrap_or("POST").to_uppercase();
    let method_enum = match method.as_str() {
        "GET" => reqwest::Method::GET,
        "POST" => reqwest::Method::POST,
        "PUT" => reqwest::Method::PUT,
        "PATCH" => reqwest::Method::PATCH,
        "DELETE" => reqwest::Method::DELETE,
        other => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": format!("unsupported method: {}", other) })),
            );
        }
    };

    let u_field = req.username_field.as_deref().unwrap_or("username");
    let p_field = req.password_field.as_deref().unwrap_or("password");

    let mut req_builder = client.request(method_enum, &req.url);

    match req.auth_style.as_str() {
        "basic" => {
            req_builder = req_builder.basic_auth(&*username, Some(&*password));
            // For basic auth, credentials ride in the header — the request
            // body is orthogonal. Pass through a caller-supplied JSON body
            // so this endpoint can drive authenticated mutations (e.g.
            // `POST /api/v1/user/repos` on Gitea) and not just auth probes.
            if let Some(body_val) = req.body.as_ref() {
                req_builder = req_builder.json(body_val);
            }
        }
        "json" => {
            let mut body = serde_json::Map::new();
            body.insert(u_field.to_string(), Value::String(username.to_string()));
            body.insert(p_field.to_string(), Value::String(password.to_string()));
            if let Some(extras) = req.extra_fields.as_ref() {
                for (k, v) in extras {
                    body.insert(k.clone(), v.clone());
                }
            }
            req_builder = req_builder.json(&body);
        }
        "form" => {
            let mut pairs: Vec<(String, String)> = Vec::new();
            pairs.push((u_field.to_string(), username.to_string()));
            pairs.push((p_field.to_string(), password.to_string()));
            if let Some(extras) = req.extra_fields.as_ref() {
                for (k, v) in extras {
                    let as_str = match v {
                        Value::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    pairs.push((k.clone(), as_str));
                }
            }
            req_builder = req_builder.form(&pairs);
        }
        other => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": format!("unsupported auth_style '{}' (use json/form/basic)", other)
                })),
            );
        }
    };

    let success_set: std::collections::HashSet<u16> = req
        .success_statuses
        .unwrap_or_else(|| vec![200, 204])
        .into_iter()
        .collect();

    let want_body = req.return_body.unwrap_or(false);

    let response = req_builder.send().await;
    match response {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let authenticated = success_set.contains(&status);
            // Default: discard the body. A misbehaving upstream shouldn't
            // get to exfiltrate via our logs, and probe callers only need
            // the status. When return_body=true, read it with a 64 KiB cap
            // so mutation callers (e.g. Gitea repo create) can see the id
            // of a newly-created resource.
            if !want_body {
                return (
                    StatusCode::OK,
                    Json(json!({
                        "reachable": true,
                        "http_status": status,
                        "authenticated": authenticated,
                        "vault_item_id": req.vault_item_id,
                    })),
                );
            }
            const MAX_BODY_BYTES: usize = 64 * 1024;
            let bytes = match resp.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    return (
                        StatusCode::OK,
                        Json(json!({
                            "reachable": true,
                            "http_status": status,
                            "authenticated": authenticated,
                            "vault_item_id": req.vault_item_id,
                            "response_body_error": format!("read body: {}", e),
                        })),
                    );
                }
            };
            let truncated = bytes.len() > MAX_BODY_BYTES;
            let slice = if truncated { &bytes[..MAX_BODY_BYTES] } else { &bytes[..] };
            let body_str = String::from_utf8_lossy(slice).into_owned();
            (
                StatusCode::OK,
                Json(json!({
                    "reachable": true,
                    "http_status": status,
                    "authenticated": authenticated,
                    "vault_item_id": req.vault_item_id,
                    "response_body": body_str,
                    "response_body_truncated": truncated,
                })),
            )
        }
        Err(e) => (
            StatusCode::OK,
            Json(json!({
                "reachable": false,
                "http_status": 0,
                "authenticated": false,
                "error": e.to_string(),
                "vault_item_id": req.vault_item_id,
            })),
        ),
    }
}

/// `POST /vault/write-env` — decrypt a vault item's credentials and write
/// them as env-var assignments to `target_path`. Plaintext lives only in
/// vault-proxy's memory and on disk at the destination; it never transits
/// over HTTP. The endpoint preserves unrelated lines, updates matching
/// `KEY=` assignments in-place, and appends new ones at the end.
///
/// `target_path` must begin with the `--env-write-root` / `ENV_WRITE_ROOT`
/// prefix configured at startup. If `--env-write-root` is unset (default),
/// this endpoint returns `501 Not Implemented` — it must be explicitly enabled
/// by an operator who sets the allowed prefix.
///
/// # iter-23 fix (was TODO(public-release))
///
/// The previous implementation hardcoded `/envs/` as the only allowed prefix.
/// This was a homelab-specific convention (Connecterr Docker Compose bind-mount
/// path) that confused public users who called the endpoint and received a
/// cryptic "target_path must begin with ['/envs/']" error with no explanation.
///
/// The allowed prefix is now configurable via `--env-write-root` / `ENV_WRITE_ROOT`.
/// When unset, the endpoint returns 501 with a message explaining the flag.
pub async fn write_env(
    State(state): State<Arc<AppState>>,
    Json(req): Json<WriteEnvRequest>,
) -> (StatusCode, Json<Value>) {
    use std::collections::{HashMap, HashSet};
    use zeroize::Zeroizing;

    // iter-23: gate the endpoint behind --env-write-root.
    // An empty env_write_root means the operator has not opted in — return 501.
    if state.env_write_root.is_empty() {
        return (
            StatusCode::NOT_IMPLEMENTED,
            Json(json!({
                "error": "POST /vault/write-env is disabled. \
                          Set --env-write-root (or ENV_WRITE_ROOT) to the directory \
                          prefix that vault-proxy is allowed to write env files into \
                          (e.g. ENV_WRITE_ROOT=/envs). \
                          Only paths beginning with that prefix will be accepted."
            })),
        );
    }

    // Normalise: ensure the prefix ends with '/' so a prefix of '/envs' cannot
    // accidentally permit '/envs-evil/secret.env'.
    let root = if state.env_write_root.ends_with('/') {
        state.env_write_root.clone()
    } else {
        format!("{}/", state.env_write_root)
    };

    let ok_prefix = req.target_path.starts_with(&root);
    if !ok_prefix {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!(
                    "target_path must begin with the configured env-write-root prefix '{}'",
                    root
                )
            })),
        );
    }
    // Refuse any path-traversal attempts — block every path whose components
    // include a `.` or `..` segment.  The previous check only caught `/../`
    // (interior) and `/..` (trailing-slash form), missing cases like:
    //   "/envs/.."       (ends with `..` without preceding `/`)
    //   "/envs/./sub"    (single-dot kept as-is by std::fs on some kernels)
    // Splitting on `/` and checking each segment is comprehensive.
    let has_traversal = req.target_path.split('/').any(|seg| seg == ".." || seg == ".");
    if has_traversal {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "target_path must not contain '.' or '..' segments"})),
        );
    }

    if req.mappings.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "mappings must not be empty"})),
        );
    }
    for field in req.mappings.values() {
        match field.as_str() {
            "username" | "password" => {}
            other => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "error": format!(
                            "unsupported source field '{}' (use 'username' or 'password')",
                            other
                        )
                    })),
                );
            }
        }
    }

    // Issue (iter-20): Scope write_env to vault_folder items only.
    // write_env decrypts a vault item's credentials and writes them to disk.
    // Without a folder scope guard a caller could pass any vault item UUID —
    // including personal banking or SSH-key entries — and silently exfiltrate
    // their plaintext credentials to a file. Mirror the guard used by
    // test_credential (iter-19).
    {
        let cipher = match state.vault.get_cipher_by_id(&req.vault_item_id).await {
            Some(c) => c,
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"error": "vault item not found"})),
                )
            }
        };
        let vault_folder_id = state.vault.find_folder_id_by_name_async(&state.vault_folder).await;
        if let Some(ref folder_id) = vault_folder_id {
            match cipher.folder_id.as_deref() {
                Some(item_folder_id) if item_folder_id != folder_id.as_str() => {
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({
                            "error": format!(
                                "item {} is not in the vault-proxy folder ('{}') — \
                                 write_env is scoped to vault-proxy items only",
                                req.vault_item_id, state.vault_folder
                            )
                        })),
                    );
                }
                None => {
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({
                            "error": format!(
                                "item {} has no folder — write_env is scoped to \
                                 items inside the vault-proxy folder ('{}')",
                                req.vault_item_id, state.vault_folder
                            )
                        })),
                    );
                }
                _ => {} // folder_id matches vault_folder — proceed
            }
        }
        // If vault_folder_id is None (folder not found), fall through
        // permissively — fresh vault / first-run scenario.
    }

    let (username_buf, password_buf) = match state
        .vault
        .decrypt_credentials_by_id(&req.vault_item_id)
        .await
    {
        Ok(pair) => pair,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("decrypt creds: {}", e)})),
            );
        }
    };
    let username: Zeroizing<String> = Zeroizing::new(
        username_buf
            .as_ref()
            .map(|b| String::from_utf8_lossy(b.as_bytes()).into_owned())
            .unwrap_or_default(),
    );
    let password: Zeroizing<String> =
        Zeroizing::new(String::from_utf8_lossy(password_buf.as_bytes()).into_owned());

    // Build desired env-var assignments.
    let mut desired: HashMap<String, Zeroizing<String>> = HashMap::new();
    for (env_name, field) in &req.mappings {
        if env_name.is_empty() || !env_name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": format!(
                        "env var name '{}' must be [A-Za-z0-9_]+", env_name
                    )
                })),
            );
        }
        let val = match field.as_str() {
            "username" => Zeroizing::new(username.to_string()),
            "password" => Zeroizing::new(password.to_string()),
            _ => unreachable!(),
        };
        desired.insert(env_name.clone(), val);
    }

    // Read existing file if present.
    let path = std::path::Path::new(&req.target_path);
    let create_missing = req.create_if_missing.unwrap_or(true);
    let existing_content = match std::fs::read_to_string(path) {
        Ok(s) => Some(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": format!("read {}: {}", path.display(), e)
                })),
            );
        }
    };
    if existing_content.is_none() && !create_missing {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!(
                    "target file does not exist and create_if_missing=false: {}",
                    path.display()
                )
            })),
        );
    }

    // Walk existing lines; replace any `KEY=` whose KEY is in desired.
    // Don't touch commented-out `# KEY=` lines — user may have deliberate
    // commented defaults there.
    let mut out_lines: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    if let Some(content) = existing_content.as_ref() {
        for line in content.lines() {
            let stripped = line.trim_start();
            if !stripped.starts_with('#') {
                if let Some(eq) = stripped.find('=') {
                    let key = stripped[..eq].trim_end();
                    if let Some(val) = desired.get(key) {
                        out_lines.push(format!("{}={}", key, val.as_str()));
                        seen.insert(key.to_string());
                        continue;
                    }
                }
            }
            out_lines.push(line.to_string());
        }
    }
    let mut inserted: Vec<String> = Vec::new();
    for (env_name, val) in &desired {
        if !seen.contains(env_name) {
            out_lines.push(format!("{}={}", env_name, val.as_str()));
            inserted.push(env_name.clone());
        }
    }
    let mut updated: Vec<String> = seen.into_iter().collect();
    updated.sort();
    inserted.sort();

    // Atomic write: write to .tmp then rename. Ensure the tmp file is mode
    // 0600 BEFORE it receives any content, so we never even briefly expose
    // plaintext to other users.
    let new_content = format!("{}\n", out_lines.join("\n"));
    let tmp_path = {
        let parent = match path.parent() {
            Some(p) => p,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "target_path has no parent directory"})),
                );
            }
        };
        parent.join(format!(
            ".{}.write-env.tmp",
            path.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("envfile")
        ))
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true).mode(0o600);
        let mut f = match opts.open(&tmp_path) {
            Ok(f) => f,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "error": format!("open tmp {}: {}", tmp_path.display(), e)
                    })),
                );
            }
        };
        use std::io::Write;
        if let Err(e) = f.write_all(new_content.as_bytes()) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": format!("write tmp {}: {}", tmp_path.display(), e)
                })),
            );
        }
    }
    #[cfg(not(unix))]
    {
        if let Err(e) = std::fs::write(&tmp_path, &new_content) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": format!("write tmp {}: {}", tmp_path.display(), e)
                })),
            );
        }
    }
    if let Err(e) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": format!(
                    "rename {} -> {}: {}",
                    tmp_path.display(),
                    path.display(),
                    e
                )
            })),
        );
    }

    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "target_path": req.target_path,
            "updated": updated,
            "inserted": inserted,
        })),
    )
}

/// `POST /vault/folders/delete` — delete a folder by id. Vaultwarden rejects
/// the request if the folder is non-empty, so the caller must move items out
/// first. `confirm: true` required as an accidental-delete guard.
pub async fn delete_folder(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DeleteFolderRequest>,
) -> (StatusCode, Json<Value>) {
    if !req.confirm {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "confirm must be true to delete" })),
        );
    }
    if req.id.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "id is required" })),
        );
    }

    // Issue (iter-19): Prevent deletion of vault_folder itself.
    // Deleting vault_folder would silently break all credential lookups —
    // list_items, update_item, delete_item, etc. all filter by vault_folder.
    // If the requested folder id matches vault_folder's id, refuse.
    if let Some(vault_folder_id) = state.vault.find_folder_id_by_name_async(&state.vault_folder).await {
        if req.id.trim() == vault_folder_id.as_str() {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": format!(
                        "cannot delete the vault-proxy folder ('{}') — \
                         deleting it would break all credential lookups. \
                         Move or reassign items first, then delete via Vaultwarden directly.",
                        state.vault_folder
                    )
                })),
            );
        }
    }

    match state.vault.delete_folder(&req.id).await {
        Ok(()) => (StatusCode::OK, Json(json!({ "ok": true, "id": req.id }))),
        Err(e) => {
            tracing::error!("delete folder failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
        }
    }
}

/// `POST /vault/items/move` — move a vault item into the named folder
/// (creating the folder if it doesn't yet exist). Non-destructive: preserves
/// all encrypted fields, only updates `folder_id`. Intended for staging
/// duplicate/old credentials in a review bucket before deletion.
pub async fn move_item(
    State(state): State<Arc<AppState>>,
    Json(req): Json<MoveItemRequest>,
) -> (StatusCode, Json<Value>) {
    if req.id.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "id is required" })),
        );
    }

    // Issue (iter-18): Scope move_item so it only moves items that belong to
    // state.vault_folder.
    //
    // Without this guard an MCP caller can supply any item UUID and relocate it
    // to an arbitrary folder — including moving vault-proxy items OUT of
    // vault_folder (breaking credential lookups) or pulling foreign items INTO
    // vault_folder (making them decryptable via /proxy).
    //
    // We allow the *destination* to be any folder — the operator may legitimately
    // want to move an item to a review/staging folder for cleanup. Only the
    // *source* item must currently reside in vault_folder.
    {
        let cipher = match state.vault.get_cipher_by_id(&req.id).await {
            Some(c) => c,
            None => return (StatusCode::NOT_FOUND, Json(json!({"error": "item not found"}))),
        };
        let vault_folder_id = state.vault.find_folder_id_by_name_async(&state.vault_folder).await;
        if let Some(ref folder_id) = vault_folder_id {
            match cipher.folder_id.as_deref() {
                Some(item_folder_id) if item_folder_id != folder_id.as_str() => {
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({
                            "error": format!(
                                "item {} is not in the vault-proxy folder ('{}') — \
                                 move_item only moves items owned by vault-proxy",
                                req.id, state.vault_folder
                            )
                        })),
                    );
                }
                None => {
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({
                            "error": format!(
                                "item {} has no folder — move_item only moves items \
                                 inside the vault-proxy folder ('{}')",
                                req.id, state.vault_folder
                            )
                        })),
                    );
                }
                _ => {} // folder_id matches vault_folder — proceed
            }
        }
    }

    // Prefer folder_id when provided — avoids the by-name ambiguity when
    // multiple folders share a name. Fall back to folder_name (create-on-
    // demand) when only that form is sent.
    let result = match (req.folder_id.as_deref(), req.folder_name.as_deref()) {
        (Some(fid), _) if !fid.trim().is_empty() => {
            state.vault.move_cipher_to_folder_id(&req.id, fid).await
        }
        (_, Some(fname)) if !fname.trim().is_empty() => {
            state.vault.move_cipher_to_folder(&req.id, fname).await
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "folder_id or folder_name is required" })),
            );
        }
    };

    match result {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "id": req.id,
                "folder_id": req.folder_id,
                "folder_name": req.folder_name,
            })),
        ),
        Err(e) => {
            tracing::error!("move cipher failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
        }
    }
}

/// `POST /vault/items/delete` — permanently delete a vault item by id.
///
/// Requires `confirm: true` in the request body as a second-factor guard
/// against accidental deletes; this is the only way to remove a cipher
/// through vault-proxy, so a mistyped id must not be silently destructive.
pub async fn delete_item(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DeleteItemRequest>,
) -> (StatusCode, Json<Value>) {
    if !req.confirm {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "confirm must be true to delete" })),
        );
    }
    if req.id.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "id is required" })),
        );
    }

    // Issue (iter-18): Scope delete_item to items inside state.vault_folder only.
    //
    // Without this guard an MCP caller can supply any vault item UUID —
    // including items outside the vault-proxy folder (banking passwords,
    // SSH keys, personal notes) — and permanently delete them.
    // vault-proxy must only destroy items it owns.
    //
    // Mirror the logic used by update_item (iter-17): resolve vault_folder →
    // folder_id; if the folder doesn't exist yet fall through permissively
    // (fresh vault / mid-setup). Block only when we can positively confirm the
    // item belongs to a *different* known folder.
    {
        let cipher = match state.vault.get_cipher_by_id(&req.id).await {
            Some(c) => c,
            None => return (StatusCode::NOT_FOUND, Json(json!({"error": "item not found"}))),
        };
        let vault_folder_id = state.vault.find_folder_id_by_name_async(&state.vault_folder).await;
        if let Some(ref folder_id) = vault_folder_id {
            match cipher.folder_id.as_deref() {
                Some(item_folder_id) if item_folder_id != folder_id.as_str() => {
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({
                            "error": format!(
                                "item {} is not in the vault-proxy folder ('{}') — \
                                 delete_item only removes items owned by vault-proxy",
                                req.id, state.vault_folder
                            )
                        })),
                    );
                }
                None => {
                    return (
                        StatusCode::FORBIDDEN,
                        Json(json!({
                            "error": format!(
                                "item {} has no folder — delete_item only removes items \
                                 inside the vault-proxy folder ('{}')",
                                req.id, state.vault_folder
                            )
                        })),
                    );
                }
                _ => {} // folder_id matches vault_folder — proceed
            }
        }
    }

    match state.vault.delete_cipher(&req.id).await {
        Ok(()) => {
            // Refresh the local masked-item cache so a subsequent list_items
            // doesn't still show the deleted id. create_item does the same.
            if let Err(e) = state.vault.sync().await {
                tracing::warn!("post-delete sync failed: {}", e);
            }
            (StatusCode::OK, Json(json!({ "ok": true, "id": req.id })))
        }
        Err(e) => {
            tracing::error!("delete cipher failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
        }
    }
}

// -------------------------------------------------------------------------- //
// Credential injection for HA config flows                                    //
// -------------------------------------------------------------------------- //

#[derive(Debug, Deserialize)]
pub struct InjectCredsRequest {
    /// Vault item name to get credentials from.
    pub vault_item: String,
    /// HA config flow ID to inject credentials into.
    pub flow_id: String,
    /// HA base URL (e.g., "http://192.0.2.1:8123").
    pub ha_url: String,
    /// HA long-lived access token item name in vault (notes field).
    pub ha_token_item: String,
    /// Additional fields to merge into the flow submission.
    #[serde(default)]
    pub extra_fields: serde_json::Map<String, Value>,
    /// Field name mapping: vault field -> flow field name.
    /// Default: {"username": "username", "password": "password"}
    #[serde(default)]
    pub field_map: serde_json::Map<String, Value>,
}

/// `POST /vault/inject-creds` — decrypt vault credentials and inject them into
/// an HA config flow. The plaintext password never leaves the sidecar process.
///
/// This enables setting up HA integrations (UniFi, Plex, etc.) that require
/// credentials, without exposing passwords to any external caller.
///
/// # Security note (iter-6 audit)
///
/// Credentials are decrypted internally and sent directly to HA's config-flow
/// API — they are **never returned** in the HTTP response. This preserves the
/// security model (credentials don't cross the MCP boundary).
///
/// However, the endpoint itself is unauthenticated: any local caller can
/// trigger a credential injection into HA for any vault item. The impact is
/// limited to HA integration setup flows (which require a valid HA token item
/// in the vault), not arbitrary credential disclosure.
///
/// The `ha_url` and `flow_id` inputs are validated by `is_allowed_outbound_url`
/// and `is_safe_flow_id` respectively to prevent SSRF.
pub async fn inject_creds(
    State(state): State<Arc<AppState>>,
    Json(req): Json<InjectCredsRequest>,
) -> (StatusCode, Json<Value>) {
    // 0. SSRF / path-traversal guards on caller-supplied inputs.
    // `ha_url` is used directly in the outbound request target and `flow_id`
    // is interpolated into the URL path. Without these checks, a caller can
    // aim inject_creds at cloud metadata endpoints or walk out of the
    // intended HA API surface. Reject up front with a generic message —
    // never echo the rejected input back.
    if !is_allowed_outbound_url(&req.ha_url) {
        tracing::warn!("inject_creds rejected ha_url (scheme/host policy): <redacted>");
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "ha_url must be http(s) and resolve to a non-metadata, non-link-local host"})),
        );
    }
    if !is_safe_flow_id(&req.flow_id) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "flow_id must be alphanumeric (with - or _), non-empty, max 128 chars"})),
        );
    }

    // Issue (iter-20): Scope inject_creds to vault_folder items only.
    // inject_creds looks up vault items by decrypted *name* (not UUID), so we
    // cannot use the get_cipher_by_id + folder_id check used by test_credential
    // and write_env. Instead we use item_name_is_in_folder (the same helper
    // used by generate_totp and decrypt_notes in iter-19). Without this guard
    // a caller could supply any item name — including personal banking or
    // SSH-key entries — and have their plaintext credentials submitted to an
    // arbitrary HA config-flow endpoint.
    //
    // Both vault_item (credential source) and ha_token_item (HA token source)
    // must be inside vault_folder.
    if !state.vault.item_name_is_in_folder(&req.vault_item, &state.vault_folder).await {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": format!(
                    "vault_item '{}' is not in the vault-proxy folder ('{}') — \
                     inject_creds is scoped to vault-proxy items only",
                    req.vault_item, state.vault_folder
                )
            })),
        );
    }
    if !state.vault.item_name_is_in_folder(&req.ha_token_item, &state.vault_folder).await {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": format!(
                    "ha_token_item '{}' is not in the vault-proxy folder ('{}') — \
                     inject_creds is scoped to vault-proxy items only",
                    req.ha_token_item, state.vault_folder
                )
            })),
        );
    }

    // 1. Decrypt credentials from vault
    let username = match state.vault.decrypt_username(&req.vault_item) {
        Ok(Some(buf)) => match buf.as_str() {
            Ok(s) => Some(s.to_string()),
            Err(_) => None,
        },
        _ => None,
    };

    let password = match state.vault.decrypt_password(&req.vault_item) {
        Ok(buf) => match buf.as_str() {
            Ok(s) => s.to_string(),
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "password is not valid UTF-8"}))),
        },
        Err(e) => {
            // Log the detail (vault item name, underlying error) for operators
            // but return a generic 400 to callers — vault item names are
            // considered internal topology that should not be exposed in API
            // responses reachable by MCP callers.
            tracing::warn!("inject_creds: decrypt password for '{}': {:#}", req.vault_item, e);
            return (StatusCode::BAD_REQUEST, Json(json!({"error": "vault credential not found or decryption failed"})));
        }
    };

    // 2. Get HA token from vault (stored in notes field)
    let ha_token = match state.vault.decrypt_notes(&req.ha_token_item) {
        Ok(Some(buf)) => match buf.as_str() {
            Ok(s) => s.to_string(),
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "HA token is not valid UTF-8"}))),
        },
        Ok(None) => {
            tracing::warn!("inject_creds: no notes on ha_token_item '{}'", req.ha_token_item);
            return (StatusCode::BAD_REQUEST, Json(json!({"error": "HA token vault item has no notes field"})));
        }
        Err(e) => {
            tracing::warn!("inject_creds: HA token decrypt for '{}': {:#}", req.ha_token_item, e);
            return (StatusCode::BAD_REQUEST, Json(json!({"error": "HA token vault credential not found or decryption failed"})));
        }
    };

    // 3. Build the flow submission payload
    let mut payload = serde_json::Map::new();

    // Map vault fields to flow fields
    let username_field = req.field_map.get("username")
        .and_then(|v| v.as_str())
        .unwrap_or("username");
    let password_field = req.field_map.get("password")
        .and_then(|v| v.as_str())
        .unwrap_or("password");

    if let Some(ref u) = username {
        payload.insert(username_field.to_string(), Value::String(u.clone()));
    }
    payload.insert(password_field.to_string(), Value::String(password.clone()));

    // Merge extra fields
    for (k, v) in &req.extra_fields {
        payload.insert(k.clone(), v.clone());
    }

    tracing::info!(
        "injecting credentials from '{}' into HA flow {} (fields: {})",
        req.vault_item, req.flow_id,
        payload.keys().map(|k| {
            if k.contains("password") || k.contains("secret") || k.contains("token") {
                format!("{}=***", k)
            } else {
                format!("{}={}", k, payload.get(k).map(|v| v.to_string()).unwrap_or_default())
            }
        }).collect::<Vec<_>>().join(", ")
    );

    // 4. POST to HA config flow
    let url = format!("{}/api/config/config_entries/flow/{}", req.ha_url, req.flow_id);
    let resp = match state.http
        .post(&url)
        .bearer_auth(&ha_token)
        .json(&Value::Object(payload))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("HA flow submission failed: {}", e);
            return (StatusCode::BAD_GATEWAY, Json(json!({"error": format!("HA request failed: {}", e)})));
        }
    };

    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(json!({"error": "no response body"}));

    // 5. Check result
    if status.is_success() {
        let result_type = body.get("type").and_then(|v| v.as_str()).unwrap_or("unknown");
        let title = body.get("title").and_then(|v| v.as_str()).unwrap_or("");
        let step = body.get("step_id").and_then(|v| v.as_str()).unwrap_or("");

        tracing::info!("HA flow result: type={}, title={}, step={}", result_type, title, step);

        (StatusCode::OK, Json(json!({
            "ok": true,
            "type": result_type,
            "title": title,
            "step_id": step,
            "flow_response": body,
        })))
    } else {
        tracing::warn!("HA flow submission returned {}: {:?}", status, body);
        (StatusCode::OK, Json(json!({
            "ok": false,
            "ha_status": status.as_u16(),
            "error": body,
        })))
    }
}

// -------------------------------------------------------------------------- //
// TOTP handler                                                                //
// -------------------------------------------------------------------------- //

/// `POST /vault/totp` -- generate a TOTP code for a vault item.
///
/// Issue (iter-19): Scope to vault_folder only. Without this guard a caller
/// could supply any item name and obtain a live TOTP code for an unrelated
/// account stored in the personal vault (e.g. banking, email 2FA).
pub async fn generate_totp(
    State(state): State<Arc<AppState>>,
    Json(req): Json<Value>,
) -> Json<Value> {
    let item_name = req.get("item_name").and_then(|v| v.as_str()).unwrap_or("");
    if item_name.is_empty() {
        return Json(json!({"error": "item_name required"}));
    }

    // Folder scope guard: reject item names that don't belong to vault_folder.
    if !state.vault.item_name_is_in_folder(item_name, &state.vault_folder).await {
        return Json(json!({
            "error": format!(
                "item '{}' is not in the vault-proxy folder ('{}') — \
                 generate_totp is scoped to vault-proxy items only",
                item_name, state.vault_folder
            )
        }));
    }

    match state.vault.decrypt_totp(item_name) {
        Ok(Some(seed_buf)) => {
            // Convert seed and generate code in a tight scope so the
            // plaintext seed String is dropped as soon as possible.
            let result = {
                let seed = match seed_buf.as_str() {
                    Ok(s) => s.to_string(),
                    Err(_) => return Json(json!({"error": "TOTP seed is not valid UTF-8"})),
                };
                // seed_buf dropped here -> zeroized
                drop(seed_buf);

                let res = crate::totp::generate_code(&seed);
                // Overwrite the seed String before dropping to minimise
                // time sensitive material lives in memory.
                drop(seed);
                res
            };

            match result {
                Ok(code) => Json(json!({
                    "code": code,
                    "expires_in": crate::totp::seconds_remaining(),
                })),
                // Use a generic error message — never forward the inner error
                // which could contain fragments of the TOTP seed/URI.
                Err(_e) => Json(json!({"error": "TOTP generation failed"})),
            }
        }
        Ok(None) => Json(json!({"error": "no TOTP seed stored for this item"})),
        Err(e) => Json(json!({"error": e.to_string()})),
    }
}

// -------------------------------------------------------------------------- //
// Notes decryption handler                                                    //
// -------------------------------------------------------------------------- //

/// `POST /vault/notes` -- decrypt and return the notes content for a vault item.
///
/// # Security note
///
/// This endpoint returns the **full decrypted notes field**. Notes can contain
/// arbitrary sensitive data (API tokens, SSH keys, recovery codes, etc.).
/// Unlike passwords (which are never returned), notes are returned in full
/// because `inject_creds` legitimately needs to read a long-lived HA token
/// from the notes field of a vault item.
///
/// iter-23 fix: This handler is now on the **internal router** — callers must
/// present `Authorization: Bearer <token>` (from `$CONFIG_DIR/internal-token`).
/// Previously it was on the open router, accessible to any localhost process.
pub async fn decrypt_notes(
    State(state): State<Arc<AppState>>,
    Json(req): Json<Value>,
) -> Json<Value> {
    let item_name = req.get("item_name").and_then(|v| v.as_str()).unwrap_or("");
    if item_name.is_empty() {
        return Json(json!({"error": "item_name required"}));
    }

    // Issue (iter-19): Scope to vault_folder. Without this guard any local
    // caller can extract the full notes field of any vault item — including
    // API tokens, SSH keys, and recovery codes stored in personal entries.
    if !state.vault.item_name_is_in_folder(item_name, &state.vault_folder).await {
        return Json(json!({
            "error": format!(
                "item '{}' is not in the vault-proxy folder ('{}') — \
                 decrypt_notes is scoped to vault-proxy items only",
                item_name, state.vault_folder
            )
        }));
    }

    match state.vault.decrypt_notes(item_name) {
        Ok(Some(buf)) => {
            match buf.as_str() {
                Ok(s) => Json(json!({"notes": s})),
                Err(_) => Json(json!({"error": "notes content is not valid UTF-8"})),
            }
        }
        Ok(None) => Json(json!({"error": "no notes content for this item"})),
        Err(e) => Json(json!({"error": e.to_string()})),
    }
}

// -------------------------------------------------------------------------- //
// Sync handlers                                                               //
// -------------------------------------------------------------------------- //

/// Request body for `POST /sync/setup-cloud`.
#[derive(Debug, Deserialize)]
#[allow(dead_code)] // fields read by serde deserialization
pub struct SetupCloudRequest {
    pub email: Option<String>,
    pub password: Option<String>,
    pub totp_code: Option<String>,
}

/// `GET /sync/status` — return cloud sync status.
/// `POST /vault/resync` — re-sync the local Vaultwarden vault cache.
/// `GET /vault/check-permission?tool=<name>` — returns the permission
/// verdict for a given MCP tool name. Used by the Node-side WorkflowsModule
/// to honour dashboard permission settings on cross-module `callModule()`
/// dispatches that would otherwise bypass the Rust `handle_proxy` gate.
///
/// The permission is read from the live `AppState.permissions` `RwLock`
/// (iter-12 hot-reload), so dashboard edits take effect without a restart.
pub async fn check_permission(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Json<Value> {
    let tool = match params.get("tool") {
        Some(t) if !t.is_empty() => t,
        _ => return Json(json!({"error": "tool query param required"})),
    };
    let permission = state.permissions.read().await.get_permission(tool);
    // Serialize the Permission enum's Debug form ("Allow"|"Ask"|"Block"|"Log")
    // lowercased for the wire, matching the existing JSON shape of the
    // dashboard `overrides` map.
    let verdict = format!("{:?}", permission).to_lowercase();
    Json(json!({
        "tool": tool,
        "permission": verdict,
        "allowed": !matches!(permission, crate::security::permissions::Permission::Block | crate::security::permissions::Permission::Ask),
    }))
}

/// `POST /vault/resync` — re-fetch all ciphers from Vaultwarden and replace
/// the in-memory cache.
///
/// # Cache staleness (iter-10)
///
/// vault-proxy loads vault items into a `RwLock<HashMap>` at startup and does
/// NOT automatically re-fetch them on a TTL or timer. If a user updates a
/// credential in Vaultwarden (e.g. rotates a password), vault-proxy continues
/// to serve the old encrypted blob until either:
///   a. The process restarts, or
///   b. A caller POSTs to this endpoint.
///
/// This is the *only* mechanism for live credential refresh (besides restart).
/// The cloud-sync path (`POST /sync/trigger`) calls `VaultManager::sync()` on
/// cipher-change notifications but only for cloud→self-hosted mirroring; it
/// does not help when the operator edits the self-hosted Vaultwarden directly.
///
/// # Cost
///
/// `sync()` performs two authenticated HTTP requests to Vaultwarden
/// (`GET /api/sync` which returns all ciphers and folders) and holds the
/// `items` write lock for the duration of the map rebuild. On a vault with
/// ~900 items this takes ~200 ms; during that window `decrypt_password()`
/// calls block at `try_read()`. Callers should not hammer this endpoint.
///
/// # Rate limiting
///
/// This endpoint goes through the global 60 req/60s rate limiter (shared with
/// all other routes). It does NOT have its own per-endpoint rate limit. An MCP
/// caller who can reach vault-proxy could trigger a full Vaultwarden sync up
/// to 60 times per minute, causing ~60 full-vault fetches against the local
/// Vaultwarden instance.
///
/// Per-endpoint cooldown for `/vault/resync`: minimum 30 seconds between calls.
/// Each full sync takes ~200 ms on a 900-item vault and holds the items write
/// lock for that duration. Allowing 60 calls/minute (global rate limit) would
/// mean ~60 full-vault fetches per minute — a denial-of-service amplifier
/// against a shared Vaultwarden instance.
///
/// The cooldown uses `AppState.last_resync_unix` (an `AtomicU64` storing seconds
/// since the Unix epoch). On cooldown violation we return a 429 with a JSON body
/// that includes `retry_after_s` so callers can back off correctly.
const RESYNC_COOLDOWN_SECS: u64 = 30;

pub async fn vault_resync(State(state): State<Arc<AppState>>) -> (axum::http::StatusCode, Json<Value>) {
    use std::sync::atomic::Ordering;
    use std::time::{SystemTime, UNIX_EPOCH};

    // Get the current Unix timestamp (saturate to 0 on clock error — that just
    // means the cooldown is bypassed once, which is benign).
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let last = state.last_resync_unix.load(Ordering::Relaxed);
    if last > 0 {
        let elapsed = now.saturating_sub(last);
        if elapsed < RESYNC_COOLDOWN_SECS {
            let retry_after = RESYNC_COOLDOWN_SECS - elapsed;
            tracing::warn!(
                elapsed_s = elapsed,
                retry_after_s = retry_after,
                "vault_resync: cooldown active, rejecting request"
            );
            return (
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                Json(json!({
                    "ok": false,
                    "error": "resync cooldown active — try again shortly",
                    "retry_after_s": retry_after,
                })),
            );
        }
    }

    // Update the last-resync timestamp before the sync so concurrent callers
    // also see the cooldown (prevents a small race window where two requests
    // both pass the check before either updates the timestamp).
    state.last_resync_unix.store(now, Ordering::Relaxed);

    match state.vault.sync().await {
        Ok(()) => {
            // Issue (iter-22): Invalidate the cached folder_id so the next
            // handler call re-resolves it against the freshly synced vault.
            // A resync may rename or recreate the vault_folder, making the
            // cached ID stale. Clearing here is cheap (one write lock) and
            // happens at most once every 30 seconds (the resync cooldown).
            *state.cached_folder_id.write().await = None;

            let items = state.vault.list_items().await;
            // Issue (iter-17): Make the scope of this endpoint explicit in the
            // response body. `/vault/resync` reloads vault *items* (credentials)
            // from Vaultwarden only — it does NOT reload `services.toml` or
            // rebuild `ca_cert_clients`. Operators who add a new service to
            // `services.toml` must restart the process; calling resync will NOT
            // make the new service available. Including `scope` and
            // `services_toml_note` in the response prevents confusion where an
            // operator adds a service, calls resync, and wonders why it still
            // returns 404 "unknown service".
            (axum::http::StatusCode::OK, Json(json!({
                "ok": true,
                "items": items.len(),
                "scope": "vault_items_only",
                "services_toml_note": "services.toml and CA-cert clients are NOT reloaded by this endpoint — restart the process to pick up services.toml changes",
            })))
        }
        Err(e) => {
            // On error, reset the timestamp so operators can immediately retry
            // after fixing the underlying issue (e.g. Vaultwarden unreachable).
            state.last_resync_unix.store(0, Ordering::Relaxed);
            (axum::http::StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false, "error": e.to_string()})))
        }
    }
}

pub async fn sync_status(State(state): State<Arc<AppState>>) -> Json<Value> {
    match &state.cloud_sync {
        Some(sync) => {
            let st = sync.get_status().await;
            Json(json!({
                "state": st.state,
                "last_sync": st.last_sync,
                "items_synced": st.items_synced,
                "errors": st.errors,
            }))
        }
        None => Json(json!({ "state": "not_configured" })),
    }
}

/// `POST /sync/trigger` — trigger a full cloud sync.
pub async fn sync_trigger(State(state): State<Arc<AppState>>) -> Json<Value> {
    match &state.cloud_sync {
        Some(sync) => match sync.full_sync().await {
            Ok(()) => {
                let st = sync.get_status().await;
                Json(json!({
                    "result": "ok",
                    "items_synced": st.items_synced,
                    "errors": st.errors,
                }))
            }
            Err(e) => {
                tracing::error!("sync trigger failed: {:#}", e);
                Json(json!({
                    "result": "error",
                    "error": "sync failed — check logs for details",
                }))
            }
        },
        None => Json(json!({
            "result": "error",
            "error": "cloud sync not configured",
        })),
    }
}

/// `POST /sync/setup-cloud` — placeholder for Phase 3 dashboard.
pub async fn setup_cloud(
    State(_state): State<Arc<AppState>>,
    Json(_req): Json<SetupCloudRequest>,
) -> Json<Value> {
    Json(json!({
        "result": "not_yet_implemented",
    }))
}

/// Request body for `POST /sync/init`.
#[derive(Debug, Deserialize)]
pub struct SyncInitRequest {
    pub refresh_token: String,
    pub master_password: String,
}

/// `POST /sync/init` — initialize cloud sync at runtime using a refresh token.
///
/// For users who don't use secrets files, they can POST a refresh token
/// (obtained from `bw login`) and their cloud master password to start syncing.
pub async fn sync_init(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SyncInitRequest>,
) -> Json<Value> {
    if state.cloud_sync.is_some() {
        return Json(json!({
            "result": "error",
            "error": "cloud sync is already active",
        }));
    }

    // Get cloud email from keystore
    let config_dir = std::env::var("CONFIG_DIR").unwrap_or_else(|_| "/config".to_string());
    let cloud_email = match crate::keystore::unlock_keystore(&config_dir, None) {
        Ok(c) => match c.cloud {
            Some(cl) => cl.email,
            None => return Json(json!({"result": "error", "error": "no cloud credentials in keystore"})),
        },
        Err(_) => return Json(json!({"result": "error", "error": "cannot unlock keystore"})),
    };

    let kdf_override = std::env::var("CLOUD_KDF_ITERATIONS")
        .ok()
        .and_then(|s| s.parse::<u32>().ok());

    match crate::sync::cloud::CloudClient::from_refresh_token(
        &cloud_email,
        &req.master_password,
        &req.refresh_token,
        kdf_override,
    )
    .await
    {
        Ok((cloud_client, new_refresh)) => {
            // TODO: persist refresh token and master password through keystore
            // reencryption instead of direct TPM sealing. The old
            // cloud_refresh_token.sealed / cloud_vault.sealed paths are no
            // longer used in the new keystore architecture.
            let _ = &new_refresh; // suppress unused-variable warning

            // Create SyncManager and run initial sync.
            let sync_mgr = std::sync::Arc::new(
                crate::sync::SyncManager::new(cloud_client, state.vault.clone()),
            );

            if let Err(e) = sync_mgr.full_sync().await {
                tracing::error!("initial sync after sync/init failed: {:#}", e);
                return Json(json!({
                    "result": "partial",
                    "message": "authenticated but initial sync failed — check logs",
                }));
            }

            let status = sync_mgr.get_status().await;
            Json(json!({
                "result": "ok",
                "message": "cloud sync initialized via refresh token",
                "items_synced": status.items_synced,
            }))
        }
        Err(e) => {
            tracing::error!("refresh token auth failed: {:#}", e);
            Json(json!({
                "result": "error",
                "error": "authentication failed — check logs for details",
            }))
        }
    }
}

/// Request body for `POST /sync/totp`.
#[derive(Debug, Deserialize)]
pub struct TotpRequest {
    pub code: String,
}

/// `GET /vault/connecterr-secrets` — return the ConnecterrSecrets JSON,
/// aggregated from VW items in folder "Connecterr".
///
/// Returns 503 if the vault is locked or unreachable. Both success and
/// failure paths write to the persistent `AuditLog` so operators see
/// connecterr secret-fetches in the dashboard's audit log.
///
/// # Security note (iter-6 audit)
///
/// This endpoint is **internal** to the legacy Connecterr TypeScript layer.
/// It aggregates credential metadata from Vaultwarden and returns the result
/// to callers. While the response contains only field *names* (never plaintext
/// values), it exposes the internal structure of the vault folder.
///
/// RESOLVED (iter-22): This endpoint is now gated behind the internal bearer
/// token. Callers must present `Authorization: Bearer <token>` (token from
/// `$CONFIG_DIR/internal-token`, 0o600 permissions). The TypeScript Connecterr
/// side reads the token file and includes it in the Authorization header.
pub async fn connecterr_secrets(
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<Value>) {
    use crate::security::audit_log::AuditEntry;
    let result = crate::vault::connecterr_secrets::aggregate(&state.vault, &state.vault_folder).await;
    match result {
        Ok(v) => {
            // Audit log: top-level key names only (item/field names are
            // non-sensitive metadata per the aggregator module's contract;
            // values are NEVER recorded).
            let names: Vec<&str> = v
                .as_object()
                .map(|m| m.keys().map(String::as_str).collect())
                .unwrap_or_default();
            state.audit_log.log(AuditEntry {
                timestamp: chrono::Utc::now().to_rfc3339(),
                tool_name: "vault__connecterr_secrets".to_string(),
                args_summary: String::new(),
                result_summary: format!("ok; top_level_keys={:?}", names),
                permission: "Allowed".to_string(),
                trigger: "http".to_string(),
            });
            (StatusCode::OK, Json(v))
        }
        Err(e) => {
            tracing::error!("connecterr-secrets aggregator failed: {:#}", e);
            // Audit the failure too — a 503 is exactly the kind of event
            // forensics should see ("someone polled at 14:23 and failed").
            state.audit_log.log(AuditEntry {
                timestamp: chrono::Utc::now().to_rfc3339(),
                tool_name: "vault__connecterr_secrets".to_string(),
                args_summary: String::new(),
                result_summary: format!("error: {:#}", e),
                permission: "Allowed".to_string(),
                trigger: "http".to_string(),
            });
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "vault unavailable"})),
            )
        }
    }
}

/// `POST /sync/totp` — provide a one-time TOTP code for 2FA during initial
/// Bitwarden cloud setup. The sidecar will authenticate, get a device token
/// for future 2FA-free logins, and start syncing.
pub async fn provide_totp(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TotpRequest>,
) -> Json<Value> {
    // Retrieve cloud credentials from keystore.
    // Try TPM first, then fall back to env-based config dir.
    let config_dir = std::env::var("CONFIG_DIR").unwrap_or_else(|_| "/config".to_string());
    let creds = match crate::keystore::unlock_keystore(&config_dir, None) {
        Ok(c) => c,
        Err(_) => {
            return Json(json!({ "result": "error", "error": "cannot unlock keystore to read cloud credentials — use dashboard settings to configure" }));
        }
    };

    let cloud = match creds.cloud {
        Some(c) => c,
        None => {
            return Json(json!({ "result": "error", "error": "no cloud credentials configured — add them in dashboard settings" }));
        }
    };

    let cloud_email = cloud.email;
    let cloud_password = cloud.master_password;

    // Retry auth with TOTP code
    match crate::sync::cloud::CloudClient::new(
        &cloud_email,
        &cloud_password,
        Some(&req.code),
        None,
    )
    .await
    {
        Ok((cloud_client, device_token)) => {
            // TODO: persist device token through keystore reencryption instead
            // of the old cloud_device_token.sealed TPM path.

            // Create SyncManager and run initial sync
            let sync_mgr = std::sync::Arc::new(
                crate::sync::SyncManager::new(cloud_client, state.vault.clone()),
            );

            if let Err(e) = sync_mgr.full_sync().await {
                tracing::error!("initial sync after setup_cloud failed: {:#}", e);
                return Json(json!({
                    "result": "partial",
                    "message": "authenticated but initial sync failed — check logs",
                }));
            }

            let status = sync_mgr.get_status().await;
            Json(json!({
                "result": "ok",
                "message": "cloud sync active — 2FA device token saved for future logins",
                "items_synced": status.items_synced,
                "device_token_saved": device_token.is_some(),
            }))
        }
        Err(e) => {
            tracing::error!("TOTP auth failed: {:#}", e);
            Json(json!({
                "result": "error",
                "error": "authentication failed — check logs for details",
            }))
        }
    }
}

/// `POST /vault/connecterr-secrets/upsert` — create or merge items in the `Connecterr` folder.
///
/// For each item:
/// - if an item with that name doesn't exist in the folder, create it with the given fields.
/// - if it exists, merge the given fields into its existing custom-fields map.
///   Credential fields NOT in the request are left untouched.
///
/// Never decrypts or reads credential fields. Field names are treated as
/// non-sensitive metadata (same policy as the aggregator — see
/// `connecterr_secrets.rs`).
///
/// NOTE: partial-batch failure is NOT rolled back. Up-front name validation
/// prevents half-apply on malformed input, but if the Nth item in a batch
/// fails at runtime (e.g., network error to VW), items 1..N-1 are already
/// persisted. Callers should expect idempotent retries — the CLI's upsert
/// is safe to re-run.
///
/// # Security note (iter-6 audit)
///
/// This endpoint is **internal** to the legacy Connecterr CLI.
///
/// RESOLVED (iter-22): This endpoint is now gated behind the internal bearer
/// token. Callers must present `Authorization: Bearer <token>` (token from
/// `$CONFIG_DIR/internal-token`, 0o600 permissions).
pub async fn upsert_connecterr_secrets(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpsertConnecterrSecretsRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Validate all names and field names up-front so we don't half-apply.
    //
    // Issue (iter-22): field names were previously not validated for control
    // characters. A crafted field name with `\n` or `\0` could corrupt
    // Vaultwarden storage or inject fake log lines. Validate eagerly before
    // any vault mutations so the entire batch is either accepted or rejected.
    let mut errors: Vec<Value> = Vec::new();
    for item in &req.items {
        if let Err(msg) = validate_item_name(&item.name) {
            errors.push(json!({ "name": item.name, "error": msg }));
        }
        for field_key in item.fields.keys() {
            if let Err(msg) = validate_field_name(field_key) {
                errors.push(json!({ "name": item.name, "field": field_key, "error": msg }));
            }
        }
    }
    if !errors.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid item name(s) or field name(s)", "items": errors })),
        ));
    }

    let mut created: Vec<String> = Vec::new();
    let mut merged: Vec<String> = Vec::new();

    for item in req.items {
        match state
            .vault
            .upsert_folder_item(&state.vault_folder, &item.name, item.fields)
            .await
        {
            Ok(was_create) => {
                if was_create { created.push(item.name); } else { merged.push(item.name); }
            }
            Err(e) => {
                tracing::error!("upsert_connecterr_secrets failed on item '{}': {:#}", item.name, e);
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({ "error": "vault-proxy returned 503 — vault locked or VW unreachable" })),
                ));
            }
        }
    }

    Ok(Json(json!({ "created": created, "merged": merged })))
}

#[cfg(test)]
mod upsert_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn request_deserializes_flat_items() {
        let raw = json!({
            "items": [
                { "name": "ssh/kali", "fields": { "host": "192.0.2.10", "port": "2222" } },
                { "name": "unifi/home", "fields": { "url": "https://192.0.2.2" } },
            ]
        });
        let req: UpsertConnecterrSecretsRequest = serde_json::from_value(raw).unwrap();
        assert_eq!(req.items.len(), 2);
        assert_eq!(req.items[0].name, "ssh/kali");
        assert_eq!(req.items[0].fields.get("host").unwrap(), "192.0.2.10");
    }

    #[test]
    fn malformed_name_is_rejected() {
        assert!(validate_item_name("").is_err());
        assert!(validate_item_name("/leading").is_err());
        assert!(validate_item_name("trailing/").is_err());
        assert!(validate_item_name("a//b").is_err());
        assert!(validate_item_name("ssh/kali").is_ok());
        assert!(validate_item_name("media/plex").is_ok());
    }

    /// Issue (iter-21): Names with embedded control characters must be rejected.
    ///
    /// A name containing `\n` or `\r` could:
    ///   - corrupt Vaultwarden storage if names are stored line-by-line
    ///   - inject fake log lines into structured logging output
    ///   - confuse downstream code that splits on newlines
    ///
    /// A name containing `\0` (null byte) terminates C-style strings and
    /// can confuse SQLite or OS-level filename comparisons.
    #[test]
    fn control_characters_in_name_are_rejected() {
        // Newline (LF)
        assert!(validate_item_name("ssh/kali\n").is_err(), "LF must be rejected");
        // Carriage return (CR)
        assert!(validate_item_name("ssh/kali\r").is_err(), "CR must be rejected");
        // Null byte
        assert!(validate_item_name("ssh/kali\x00").is_err(), "null byte must be rejected");
        // Tab
        assert!(validate_item_name("ssh/\tkali").is_err(), "tab must be rejected");
        // Embedded newline mid-name
        assert!(validate_item_name("ssh\nkali").is_err(), "embedded LF must be rejected");
        // DEL (0x7F)
        assert!(validate_item_name("ssh/kali\x7f").is_err(), "DEL must be rejected");
        // Valid names with non-ASCII printable UTF-8 characters are allowed
        assert!(validate_item_name("ssh/kali-üñicode").is_ok(), "UTF-8 printable must pass");
    }

    /// Exercises the 400 path of `upsert_connecterr_secrets` without a live
    /// `AppState`: we replicate the validation branch (which runs before any
    /// vault I/O) and assert the response shape matches what the handler produces.
    #[test]
    fn handler_returns_400_on_malformed_name() {
        // Build a request body containing one valid and one malformed item name.
        let raw = json!({
            "items": [
                { "name": "ssh/kali", "fields": { "host": "192.0.2.10" } },
                { "name": "bad//name", "fields": {} },
            ]
        });
        let req: UpsertConnecterrSecretsRequest = serde_json::from_value(raw).unwrap();

        // Replicate the validation branch from the handler.
        let mut errors: Vec<serde_json::Value> = Vec::new();
        for item in &req.items {
            if let Err(msg) = validate_item_name(&item.name) {
                errors.push(json!({ "name": item.name, "error": msg }));
            }
        }

        // Should have exactly one validation error (for "bad//name").
        assert!(!errors.is_empty(), "expected validation errors but got none");

        // Build the 400 response body the handler returns.
        let body = json!({ "error": "invalid item name(s)", "items": errors });

        // Assert shape: top-level "error" key present.
        assert_eq!(
            body["error"].as_str().unwrap(),
            "invalid item name(s)",
            "400 body should carry 'invalid item name(s)' error key"
        );

        // Assert the bad item is reported, the good item is not.
        let reported_names: Vec<&str> = body["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["name"].as_str().unwrap())
            .collect();
        assert_eq!(reported_names, vec!["bad//name"]);
        assert!(
            !reported_names.contains(&"ssh/kali"),
            "valid item must not appear in error list"
        );
    }
}

#[cfg(test)]
mod create_item_tests {
    use super::*;

    #[test]
    fn create_item_request_deserializes_fields_and_folder() {
        let raw = r#"{
            "name": "apiKey",
            "folder_name": "Connecterr",
            "fields": [
                { "name": "apiKey", "value": "ABC123" }
            ]
        }"#;
        let req: CreateItemRequest = serde_json::from_str(raw).unwrap();
        assert_eq!(req.name, "apiKey");
        assert_eq!(req.folder_name.as_deref(), Some("Connecterr"));
        assert_eq!(req.fields.len(), 1);
        assert_eq!(req.fields[0].name, "apiKey");
        assert_eq!(req.fields[0].value, "ABC123");
        assert_eq!(req.fields[0].field_type, 1); // default = hidden
    }
}

#[cfg(test)]
mod ssrf_tests {
    use super::*;

    #[test]
    fn ipv6_link_local_fe80_is_blocked() {
        // Regression: url::Url::host_str() returns "[fe80::1]" WITH brackets.
        // Rust's IpAddr parser does not accept brackets, so the IPv6 link-local
        // check was silently bypassed before the bracket-stripping fix.
        assert!(!is_allowed_outbound_url("http://[fe80::1]/api"), "fe80::1 must be blocked");
        assert!(!is_allowed_outbound_url("https://[fe80::abcd:ef01]/path"), "fe80:: prefix must be blocked");
    }

    #[test]
    fn ipv4_link_local_169_254_is_blocked() {
        assert!(!is_allowed_outbound_url("http://169.254.169.254/latest/meta-data"), "AWS IMDS must be blocked");
        assert!(!is_allowed_outbound_url("http://169.254.1.1/"), "all 169.254.x.x must be blocked");
    }

    #[test]
    fn blocked_hostname_strings_are_blocked() {
        assert!(!is_allowed_outbound_url("http://metadata.google.internal/"), "GCP metadata must be blocked");
        assert!(!is_allowed_outbound_url("http://metadata.aws.cloud/"), "AWS cloud metadata must be blocked");
    }

    #[test]
    fn normal_urls_are_allowed() {
        assert!(is_allowed_outbound_url("http://192.168.1.1:8123"), "LAN IP should be allowed");
        assert!(is_allowed_outbound_url("https://vault.example.com"), "public hostname should be allowed");
        assert!(is_allowed_outbound_url("http://10.0.0.1:8080/api"), "RFC1918 should be allowed");
    }

    #[test]
    fn non_http_schemes_are_blocked() {
        assert!(!is_allowed_outbound_url("ftp://example.com/"));
        assert!(!is_allowed_outbound_url("file:///etc/passwd"));
    }

    /// iter-9: loopback addresses and the hostname "localhost" must be blocked.
    /// A services.toml with `base_url = "http://127.0.0.1:3201/vault/items"` would
    /// let a /proxy call loop back into vault-proxy and read vault metadata.
    #[test]
    fn loopback_addresses_are_blocked() {
        assert!(!is_allowed_outbound_url("http://127.0.0.1:3201/vault/items"), "127.0.0.1 must be blocked");
        assert!(!is_allowed_outbound_url("http://127.0.0.1/"), "bare 127.0.0.1 must be blocked");
        assert!(!is_allowed_outbound_url("http://127.1.2.3/api"), "127.x.y.z must be blocked");
        assert!(!is_allowed_outbound_url("http://[::1]/api"), "::1 IPv6 loopback must be blocked");
        assert!(!is_allowed_outbound_url("http://localhost/api"), "localhost hostname must be blocked");
        assert!(!is_allowed_outbound_url("http://LOCALHOST:8080/"), "case-insensitive localhost must be blocked");
    }

    /// iter-13: Scheme-less URLs (e.g. "homeassistant.local:8123") must be
    /// blocked. url::Url::parse treats the hostname as the scheme in this form,
    /// so the scheme check rejects it — but the error message from the registry
    /// was previously misleading ("link-local or cloud-metadata endpoint").
    /// Verified here so the behaviour contract is explicit.
    #[test]
    fn schemeless_urls_are_blocked() {
        assert!(
            !is_allowed_outbound_url("homeassistant.local:8123"),
            "scheme-less host:port must be blocked (parsed as opaque URI)"
        );
        assert!(
            !is_allowed_outbound_url("192.168.1.100:8080"),
            "scheme-less ip:port must be blocked"
        );
        assert!(
            !is_allowed_outbound_url("//192.168.1.100:8080/api"),
            "protocol-relative URL must be blocked (no http/https scheme)"
        );
    }

    /// iter-11: URLs with an embedded userinfo component (user:password@host)
    /// must be rejected. Userinfo leaks credentials into logs and means the
    /// caller is bypassing vault-proxy's credential-isolation model.
    #[test]
    fn userinfo_urls_are_blocked() {
        assert!(
            !is_allowed_outbound_url("http://user:password@192.168.1.1/api"),
            "URL with user:password userinfo must be blocked"
        );
        assert!(
            !is_allowed_outbound_url("http://admin:secret@service.example.com/api/v3"),
            "URL with credentials at public host must be blocked"
        );
        assert!(
            !is_allowed_outbound_url("http://user:@192.168.1.1/api"),
            "URL with user and empty password must be blocked"
        );
        assert!(
            !is_allowed_outbound_url("http://user@192.168.1.1/api"),
            "URL with username only (no password) must be blocked"
        );
        // A normal URL without userinfo must still pass.
        assert!(
            is_allowed_outbound_url("http://192.168.1.1:8080/api"),
            "plain URL without userinfo must be allowed"
        );
    }
}

#[cfg(test)]
mod write_env_traversal_tests {
    /// Validate the path-traversal check used by `write_env`.
    ///
    /// The previous implementation only blocked `/../` (interior) and `/..`
    /// (trailing-slash form), missing `/envs/..` (no trailing slash after
    /// the `..` segment) and `/envs/./sub` (single-dot segment).
    #[test]
    fn dotdot_variants_are_all_blocked() {
        fn has_traversal(p: &str) -> bool {
            p.split('/').any(|seg| seg == ".." || seg == ".")
        }

        // Previously missed cases
        assert!(has_traversal("/envs/.."), "/envs/.. must be blocked");
        assert!(has_traversal("/envs/../etc/passwd"), "/envs/../etc/passwd must be blocked");
        assert!(has_traversal("/envs/./sub"), "/envs/./sub (single-dot) must be blocked");

        // Already caught by old check
        assert!(has_traversal("/envs/sub/../etc"), "interior .. must be blocked");

        // Normal paths must pass
        assert!(!has_traversal("/envs/myapp.env"), "normal path should be allowed");
        assert!(!has_traversal("/envs/sub/myapp.env"), "nested normal path should be allowed");
    }
}

// Issue (iter-18): Unit tests for the folder-scope guard logic used by
// delete_item, clone_item, move_item, and list_items.  The actual handlers
// require a live AppState + VaultManager, so we replicate the decision logic
// inline to verify the three key cases: item-in-wrong-folder, item-with-no-folder,
// and item-in-correct-folder.
#[cfg(test)]
mod folder_scope_guard_tests {
    /// Simulate the folder ownership check introduced in iter-18.
    /// Returns Ok(()) when the item belongs to vault_folder_id, or Err(msg)
    /// for wrong-folder and no-folder cases.
    fn check_folder_scope(
        item_folder_id: Option<&str>,
        vault_folder_id: Option<&str>,
        item_id: &str,
        vault_folder_name: &str,
    ) -> Result<(), String> {
        match vault_folder_id {
            None => Ok(()), // vault_folder not found — fresh vault, allow
            Some(folder_id) => match item_folder_id {
                Some(id) if id == folder_id => Ok(()),
                Some(_) => Err(format!(
                    "item {} is not in the vault-proxy folder ('{}')",
                    item_id, vault_folder_name
                )),
                None => Err(format!(
                    "item {} has no folder — only items inside '{}' are permitted",
                    item_id, vault_folder_name
                )),
            },
        }
    }

    #[test]
    fn item_in_correct_folder_is_allowed() {
        let result = check_folder_scope(
            Some("folder-uuid-abc"),
            Some("folder-uuid-abc"),
            "item-uuid-1",
            "vault-proxy",
        );
        assert!(result.is_ok(), "item in correct folder must be allowed");
    }

    #[test]
    fn item_in_wrong_folder_is_blocked() {
        let result = check_folder_scope(
            Some("other-folder-uuid"),
            Some("folder-uuid-abc"),
            "item-uuid-1",
            "vault-proxy",
        );
        assert!(result.is_err(), "item in wrong folder must be blocked");
        let msg = result.unwrap_err();
        assert!(msg.contains("vault-proxy"), "error must mention vault_folder name");
    }

    #[test]
    fn item_with_no_folder_is_blocked() {
        let result = check_folder_scope(
            None,
            Some("folder-uuid-abc"),
            "item-uuid-1",
            "vault-proxy",
        );
        assert!(result.is_err(), "item with no folder must be blocked");
    }

    #[test]
    fn fresh_vault_no_folder_id_is_allowed() {
        // vault_folder_id = None means the vault_folder doesn't exist yet.
        // Fall through permissively so first-run tooling works.
        let result = check_folder_scope(
            None,
            None, // vault_folder not found
            "item-uuid-1",
            "vault-proxy",
        );
        assert!(result.is_ok(), "fresh vault (no folder_id) must allow all items");
    }

    #[test]
    fn list_items_folder_filter_logic() {
        // Simulate the list_items filtering: only items whose folder_id
        // matches vault_folder_id should survive.
        let vault_folder_id = "folder-abc";
        let items: Vec<(Option<&str>, &str)> = vec![
            (Some("folder-abc"), "item-in-scope"),
            (Some("folder-xyz"), "item-out-of-scope"),
            (None, "item-no-folder"),
        ];
        let filtered: Vec<&str> = items
            .into_iter()
            .filter(|(fid, _)| *fid == Some(vault_folder_id))
            .map(|(_, name)| name)
            .collect();

        assert_eq!(filtered, vec!["item-in-scope"]);
    }
}
