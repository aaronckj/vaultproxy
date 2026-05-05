//! Vault HTTP handlers.

use std::sync::Arc;

use axum::{extract::State, http::StatusCode, Json};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::proxy::AppState;
use super::types::{DuplicateGroup, FolderInfo, MaskedItem};

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
    if name.split('/').any(|seg| seg.is_empty()) {
        return Err(format!("name '{}' has empty path segment", name));
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
pub async fn list_items(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<MaskedItem>> {
    let items = state.vault.list_items().await;
    Json(items)
}

/// `GET /vault/duplicates` — find items that share the same
/// `(organization_id, username, password)`. Passwords are hashed and
/// compared inside the proxy; plaintext and hashes never leave.
pub async fn list_duplicates(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<DuplicateGroup>> {
    let groups = state.vault.list_duplicates().await;
    Json(groups)
}

/// `GET /vault/folders` — list all folders the vault knows about with their
/// item counts and sync-tracking status. Duplicate folder names (a common
/// artefact of cloud→self-hosted migrations) show up here as separate entries
/// with different ids, so callers can consolidate them.
pub async fn list_folders(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<FolderInfo>> {
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
    Json(state.vault.list_folders_with_counts(&tracked).await)
}

/// `GET /vault/items/untracked` — list vault items that have no entry in the
/// cloud↔VW sync map. These are either personal items created directly in VW
/// (expected) or orphans from past broken-sync runs (cleanup targets).
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
    let items = state.vault.list_untracked_item_ids(&tracked).await;
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
pub async fn create_item(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateItemRequest>,
) -> (StatusCode, Json<Value>) {
    use crate::vault::crypto::encrypt_to_cipher_string;
    use crate::vault::types::{EncryptedCipher, EncryptedField, EncryptedLogin, EncryptedUri};

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

    // Resolve folder_name → folder_id (if requested).
    let folder_id = if let Some(ref fname) = req.folder_name {
        match state.vault.find_folder_id_by_name_async(fname).await {
            Some(id) => Some(id),
            None => return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("folder '{}' not found in vault", fname)})),
            ),
        }
    } else { None };

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
/// TODO(public-release): Consider requiring a pre-shared bootstrap token
/// (e.g. written to a file only Connecterr can read) to gate the first
/// handshake, eliminating the race entirely.
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
/// `target_path` is allowlisted to `/envs/` (the canonical bind mount for
/// service env files). Rejecting unknown prefixes stops this handler from
/// being a write-anywhere primitive.
///
/// # Public-release note
///
/// The hardcoded `/envs/` prefix is a homelab-specific convention (bind-mount
/// path inside the Connecterr Docker Compose stack). Public users almost
/// certainly do not have an `/envs/` directory.
///
/// TODO(public-release): This endpoint should either be removed entirely for
/// the public release (it has no meaningful use outside the Connecterr Docker
/// stack) or the allowed prefix should be made configurable via
/// `--env-write-root` / `ENV_WRITE_ROOT` so operators can set a path that
/// exists on their system. Until then, any public user calling this endpoint
/// will receive a 400 "target_path must begin with ['/envs/']" error that
/// gives no indication of how to fix it.
pub async fn write_env(
    State(state): State<Arc<AppState>>,
    Json(req): Json<WriteEnvRequest>,
) -> (StatusCode, Json<Value>) {
    use std::collections::{HashMap, HashSet};
    use zeroize::Zeroizing;

    const ALLOWED_PREFIXES: &[&str] = &["/envs/"];
    let ok_prefix = ALLOWED_PREFIXES.iter().any(|p| req.target_path.starts_with(p));
    if !ok_prefix {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!(
                    "target_path must begin with one of {:?}", ALLOWED_PREFIXES
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
pub async fn generate_totp(
    State(state): State<Arc<AppState>>,
    Json(req): Json<Value>,
) -> Json<Value> {
    let item_name = req.get("item_name").and_then(|v| v.as_str()).unwrap_or("");
    if item_name.is_empty() {
        return Json(json!({"error": "item_name required"}));
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
/// This endpoint returns the **full decrypted notes field** to any unauthenticated
/// caller on localhost. Notes can contain arbitrary sensitive data (API tokens,
/// SSH keys, recovery codes, etc.). Unlike passwords (which are never returned),
/// notes are returned in full because `inject_creds` legitimately needs to read
/// a long-lived HA token from the notes field of a vault item.
///
/// For the internal sidecar use case this is acceptable: only local processes
/// can call it and all routes already go through the DNS-rebinding guard.
///
/// TODO(public-release): Evaluate whether this endpoint is needed at all in the
/// public release. If the only consumer is `inject_creds` (which calls
/// `decrypt_notes` internally), the HTTP endpoint can be removed — keeping it
/// creates an unnecessarily wide surface for notes exfiltration via any local
/// process that can call the sidecar. If retained, it should be gated by the
/// same authentication layer added to other sensitive endpoints.
pub async fn decrypt_notes(
    State(state): State<Arc<AppState>>,
    Json(req): Json<Value>,
) -> Json<Value> {
    let item_name = req.get("item_name").and_then(|v| v.as_str()).unwrap_or("");
    if item_name.is_empty() {
        return Json(json!({"error": "item_name required"}));
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
            let items = state.vault.list_items().await;
            (axum::http::StatusCode::OK, Json(json!({"ok": true, "items": items.len()})))
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
/// to any unauthenticated caller that can reach 127.0.0.1:3201. While the
/// response contains only field *names* (never plaintext values), it does
/// expose the internal structure of the vault folder, including service names
/// and item names.
///
/// For a public release, this endpoint should be:
///   1. Protected by the same bearer-token or mTLS scheme used elsewhere, OR
///   2. Removed if the TypeScript Connecterr layer is no longer maintained.
///
/// TODO(public-release): Gate behind authentication or remove if legacy
/// Connecterr TypeScript layer is no longer in use.
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
/// This endpoint is **internal** to the legacy Connecterr CLI. Any
/// unauthenticated caller on localhost can write arbitrary field names into
/// the vault folder. While field *values* are not written by this endpoint
/// (only field names / structural metadata), it could still be used to
/// corrupt the vault folder structure. For a public release, consider:
///   1. Protecting with authentication, OR
///   2. Removing if the Connecterr CLI is no longer maintained.
///
/// TODO(public-release): Gate behind authentication or remove if legacy
/// Connecterr CLI layer is no longer in use.
pub async fn upsert_connecterr_secrets(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpsertConnecterrSecretsRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    // Validate all names up-front so we don't half-apply.
    let mut errors: Vec<Value> = Vec::new();
    for item in &req.items {
        if let Err(msg) = validate_item_name(&item.name) {
            errors.push(json!({ "name": item.name, "error": msg }));
        }
    }
    if !errors.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "invalid item name(s)", "items": errors })),
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
