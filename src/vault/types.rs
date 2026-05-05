use serde::{Deserialize, Serialize};

// -------------------------------------------------------------------------- //
// Vaultwarden API response types                                              //
// -------------------------------------------------------------------------- //

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreloginResponse {
    pub kdf_iterations: u32,
}

#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    /// Refresh token for re-authentication when the access token expires.
    pub refresh_token: Option<String>,
    /// Encrypted symmetric key returned by the identity endpoint.
    #[serde(rename = "Key")]
    pub key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedCipher {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub cipher_type: u8,
    pub login: Option<EncryptedLogin>,
    pub card: Option<serde_json::Value>,
    pub identity: Option<serde_json::Value>,
    pub secure_note: Option<serde_json::Value>,
    pub fields: Option<Vec<EncryptedField>>,
    pub notes: Option<String>,
    pub organization_id: Option<String>,
    pub collection_ids: Option<Vec<String>>,
    pub folder_id: Option<String>,
    pub revision_date: Option<String>,
    /// Per-item encryption key (encrypted with org/personal key).
    /// Present on org-shared ciphers; must be decrypted to get real field keys.
    pub key: Option<String>,
    /// Catch-all for fields we don't explicitly model (reprompt, favorite, etc.)
    #[serde(flatten)]
    pub extra: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedLogin {
    pub username: Option<String>,
    pub password: Option<String>,
    pub uris: Option<Vec<EncryptedUri>>,
    pub totp: Option<String>, // encrypted TOTP seed
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedUri {
    pub uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedField {
    pub name: Option<String>,
    pub value: Option<String>,
    #[serde(rename = "type")]
    pub field_type: u8,
}

// -------------------------------------------------------------------------- //
// Bitwarden cloud sync types                                                  //
// -------------------------------------------------------------------------- //

/// Full sync response from Bitwarden cloud /api/sync endpoint.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncResponse {
    pub profile: SyncProfile,
    pub ciphers: Vec<EncryptedCipher>,
    pub folders: Vec<SyncFolder>,
    pub collections: Vec<SyncCollection>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)] // fields read by serde deserialization
pub struct SyncProfile {
    pub id: String,
    pub email: String,
    pub organizations: Option<Vec<SyncOrganization>>,
    /// RSA private key encrypted with the user's symmetric key.
    /// Used to decrypt organization keys (type 4 cipher strings).
    pub private_key: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncOrganization {
    pub id: String,
    pub name: String,
    pub key: String, // org encryption key, encrypted with user's personal key
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)] // fields read by serde deserialization
pub struct SyncFolder {
    pub id: String,
    pub name: String,
    pub revision_date: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncCollection {
    pub id: String,
    pub organization_id: String,
    pub name: String, // encrypted with org key
}

// -------------------------------------------------------------------------- //
// Response types for the proxy API                                            //
// -------------------------------------------------------------------------- //

/// A vault item returned by the list endpoint — passwords are masked.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MaskedItem {
    pub id: String,
    pub name: String,
    pub item_type: String,
    pub username: Option<String>,
    pub password: &'static str,
    pub uris: Vec<String>,
    /// Organization id if the item is shared via an org; `None` means personal
    /// vault. Exposed so callers can disambiguate same-looking items that live
    /// in different orgs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    /// Folder id the item belongs to, or `None` if unfiled. Useful for
    /// segmenting review buckets ("items in Duplicates Review", etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder_id: Option<String>,
}

/// A single entry inside a `DuplicateGroup`. Minimal payload for the caller to
/// pick which to keep — no passwords or hashes leave the proxy.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DuplicateMember {
    pub id: String,
    pub name: String,
    pub uris: Vec<String>,
    /// ISO-8601 revision date from the cipher record, when available. Useful
    /// for "keep the newest" heuristics — callers don't have to re-fetch.
    pub revision_date: Option<String>,
}

/// One folder as seen by the proxy. Returned by `GET /vault/folders` so callers
/// can spot duplicate folder names (the same decrypted name on multiple folder
/// ids, usually a migration artefact) and consolidate them.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderInfo {
    pub id: String,
    pub name: String,
    /// Number of ciphers currently assigned to this folder.
    pub item_count: usize,
    /// `true` if the folder is mapped in the cloud↔VW sync map (one of the
    /// folders produced by the sync pipeline), `false` if it exists only in
    /// VW (personal/manual folder or an unmapped historical artefact).
    pub tracked: bool,
}

/// A set of items that share the same `(organization_id, username, password)` —
/// i.e. the same credential stored more than once. Returned by
/// `GET /vault/duplicates`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DuplicateGroup {
    /// Organization id the creds belong to, or "personal" for the user's
    /// personal vault. Items in different orgs are never merged into the same
    /// group even if creds match.
    pub organization_id: String,
    pub username: String,
    pub count: usize,
    pub items: Vec<DuplicateMember>,
}
