pub mod cloud;
pub mod mapping;
pub mod websocket;

use std::sync::Arc;

use anyhow::{Context, Result};
use serde::Serialize;
use tokio::sync::{RwLock, Semaphore};

use crate::secure::SecureBuffer;
use serde_json::Value;

use crate::vault::crypto::{decrypt_cipher_string, encrypt_to_cipher_string};
use crate::vault::types::*;
use crate::vault::VaultManager;

/// Sanitize a vault item/collection name for safe use in logs.
/// Strips control characters and truncates to prevent log injection.
fn sanitize_name_for_log(name: &str) -> String {
    let sanitized: String = name.chars().filter(|c| !c.is_control()).take(128).collect();
    sanitized
}

use cloud::CloudClient;
use mapping::SyncMap;

const SYNC_MAP_PATH: &str = "/config/sync-map.json";

// -------------------------------------------------------------------------- //
// SyncStatus                                                                  //
// -------------------------------------------------------------------------- //

#[derive(Debug, Clone, Serialize)]
pub struct SyncStatus {
    pub state: String,
    pub last_sync: Option<String>,
    pub items_synced: usize,
    pub errors: Vec<String>,
}

impl Default for SyncStatus {
    fn default() -> Self {
        Self {
            state: "idle".into(),
            last_sync: None,
            items_synced: 0,
            errors: Vec::new(),
        }
    }
}

// -------------------------------------------------------------------------- //
// SyncManager                                                                 //
// -------------------------------------------------------------------------- //

pub struct SyncManager {
    pub cloud: RwLock<CloudClient>,
    pub vw: Arc<VaultManager>,
    pub map: RwLock<SyncMap>,
    pub status: RwLock<SyncStatus>,
    /// Single-permit semaphore that serializes `full_sync` calls. Three
    /// independent callers (WebSocket VaultSync notification, the 300s
    /// polling task, dashboard `/sync/trigger`) could previously enter
    /// `full_sync_inner` concurrently and race on the `map` write lock,
    /// producing duplicate VW writes and arbitrary final `status` state.
    sync_permit: Semaphore,
}

impl SyncManager {
    /// Create a new SyncManager, loading the sync map from disk (or defaulting).
    pub fn new(cloud: CloudClient, vw: Arc<VaultManager>) -> Self {
        let map = SyncMap::load(SYNC_MAP_PATH).unwrap_or_else(|e| {
            tracing::warn!("failed to load sync map, using empty: {}", e);
            SyncMap::default()
        });

        SyncManager {
            cloud: RwLock::new(cloud),
            vw,
            map: RwLock::new(map),
            status: RwLock::new(SyncStatus::default()),
            sync_permit: Semaphore::new(1),
        }
    }

    /// Perform a full sync: pull all ciphers from Bitwarden cloud, re-encrypt
    /// them, and push into the local Vaultwarden instance.
    pub async fn full_sync(&self) -> Result<()> {
        // Single-permit gate — if another full_sync is in flight, log and
        // return Ok(()) rather than queuing. Dedup is the correct semantics
        // here: running two syncs back-to-back does not produce better data
        // than running one, and queuing could exhaust resources if callers
        // fire in a tight loop.
        let _permit = match self.sync_permit.try_acquire() {
            Ok(p) => p,
            Err(_) => {
                tracing::debug!("full_sync already in progress — skipping duplicate call");
                return Ok(());
            }
        };

        // Mark status as syncing.
        {
            let mut st = self.status.write().await;
            st.state = "syncing".into();
            st.errors.clear();
        }

        let sync_result = self.full_sync_inner().await;

        // Update status based on result.
        let mut st = self.status.write().await;
        st.last_sync = Some(chrono::Utc::now().to_rfc3339());

        match sync_result {
            Ok(count) => {
                st.items_synced = count;
                if st.errors.is_empty() {
                    st.state = "idle".into();
                } else {
                    st.state = "idle_with_errors".into();
                }
                tracing::info!(
                    items = count,
                    errors = st.errors.len(),
                    "full sync complete"
                );
                Ok(())
            }
            Err(e) => {
                st.state = "error".into();
                st.errors.push(format!("{:#}", e));
                tracing::error!("full sync failed: {:#}", e);
                Err(e)
            }
        }
    }

    /// Inner sync logic — returns the count of successfully synced items.
    async fn full_sync_inner(&self) -> Result<usize> {
        // Step 1: Full sync from cloud.
        let sync_resp = {
            let mut cloud = self.cloud.write().await;
            cloud.full_sync().await.context("cloud full_sync failed")?
        };

        let cloud = self.cloud.read().await;
        let mut map = self.map.write().await;

        // Step 2: Sync collections → VW folders.
        for collection in &sync_resp.collections {
            if map.get_folder_id(&collection.id).is_some() {
                continue; // Already mapped.
            }

            // Decrypt collection name using org keys, then re-encrypt with VW keys.
            match self
                .sync_collection_to_vw(&cloud, collection, &mut map)
                .await
            {
                Ok(()) => {}
                Err(e) => {
                    let msg = format!("failed to sync collection '{}': {:#}", collection.id, e);
                    tracing::warn!("{}", msg);
                    self.status.write().await.errors.push(msg);
                }
            }
        }

        // Step 3: Sync ciphers.
        let mut synced = 0usize;
        for cipher in &sync_resp.ciphers {
            match self.sync_cipher_to_vw(&cloud, cipher, &mut map).await {
                Ok(()) => synced += 1,
                Err(e) => {
                    let msg = format!("failed to sync cipher '{}': {:#}", cipher.id, e);
                    tracing::warn!("{}", msg);
                    self.status.write().await.errors.push(msg);
                }
            }
        }

        // Step 4: Save mapping.
        map.save(SYNC_MAP_PATH).context("failed to save sync map")?;

        // Drop locks before calling vw.sync().
        drop(map);
        drop(cloud);

        // Step 5: Refresh VaultManager's local cache.
        self.vw.sync().await.context("VW re-sync failed")?;

        Ok(synced)
    }

    /// Sync a single collection → VW folder.
    async fn sync_collection_to_vw(
        &self,
        cloud: &CloudClient,
        collection: &SyncCollection,
        map: &mut SyncMap,
    ) -> Result<()> {
        // To decrypt the collection name we need the org's keys.
        // Build a dummy cipher with the collection's org_id so keys_for_cipher works.
        let dummy = EncryptedCipher {
            id: String::new(),
            name: String::new(),
            cipher_type: 1,
            login: None,
            card: None,
            identity: None,
            secure_note: None,
            fields: None,
            notes: None,
            organization_id: Some(collection.organization_id.clone()),
            collection_ids: None,
            folder_id: None,
            revision_date: None,
            key: None,
            extra: None,
        };
        let (src_enc, src_mac) = cloud.keys_for_cipher(&dummy)?;

        // Decrypt collection name.
        let name_buf = decrypt_cipher_string(&collection.name, src_enc, src_mac)
            .context("failed to decrypt collection name")?;
        let name_str = std::str::from_utf8(name_buf.as_bytes())
            .context("collection name is not valid UTF-8")?
            .to_string();

        // Re-encrypt name with VW keys.
        let vw_encrypted_name =
            encrypt_to_cipher_string(&name_str, self.vw.enc_key(), self.vw.mac_key())
                .context("failed to encrypt folder name for VW")?;

        // Create folder in VW.
        let folder_id = self
            .vw
            .create_folder(&vw_encrypted_name)
            .await
            .context("failed to create folder in VW")?;

        tracing::info!(
            collection_id = %collection.id,
            folder_id = %folder_id,
            name = %sanitize_name_for_log(&name_str),
            "mapped collection to VW folder"
        );

        map.set_folder(
            &collection.id,
            &collection.organization_id,
            &folder_id,
            &name_str,
        );

        Ok(())
    }

    /// Re-encrypt and sync a single cipher from cloud to VW.
    pub async fn sync_cipher_to_vw(
        &self,
        cloud: &CloudClient,
        cipher: &EncryptedCipher,
        map: &mut SyncMap,
    ) -> Result<()> {
        // Get source (cloud) keys, resolving per-item key if present.
        let (src_enc, src_mac) = cloud
            .resolve_cipher_keys(cipher)
            .context("failed to get cloud keys for cipher")?;

        // Get destination (VW) keys.
        let dst_enc = self.vw.enc_key();
        let dst_mac = self.vw.mac_key();

        // Re-encrypt all fields.
        let mut vw_cipher = re_encrypt_cipher(cipher, &src_enc, &src_mac, dst_enc, dst_mac)
            .with_context(|| format!("re-encrypt failed for cipher '{}'", cipher.id))?;

        // Map folder_id from first collection if applicable.
        if let Some(ref collections) = cipher.collection_ids {
            for cid in collections {
                if let Some(folder_id) = map.get_folder_id(cid) {
                    vw_cipher.folder_id = Some(folder_id.to_string());
                    break;
                }
            }
        }

        // VW stores as personal items — clear org fields.
        vw_cipher.organization_id = None;
        vw_cipher.collection_ids = None;

        // Drop any folder id that VW doesn't know about. re_encrypt_cipher
        // carries over the cloud-side folder_id, which is meaningless on the VW
        // instance — pushing it makes VW reject the cipher with 400 "Invalid
        // folder". Collection-mapped items already had folder_id rewritten to a
        // real VW folder above; everything else lands unfiled.
        if let Some(ref fid) = vw_cipher.folder_id {
            if !self.vw.folder_id_exists(fid).await {
                vw_cipher.folder_id = None;
            }
        }

        // Create or update in VW.
        if let Some(vw_id) = map.get_vw_id(&cipher.id).map(|s| s.to_string()) {
            // Update existing.
            vw_cipher.id = vw_id.clone();
            self.vw
                .update_cipher(&vw_id, &vw_cipher)
                .await
                .with_context(|| format!("update cipher in VW failed for '{}'", cipher.id))?;

            map.set_item(
                &cipher.id,
                &vw_id,
                cipher.revision_date.as_deref(),
                Option::<&str>::None,
            );
        } else {
            // Create new.
            let vw_id = self
                .vw
                .create_cipher(&vw_cipher)
                .await
                .with_context(|| format!("create cipher in VW failed for '{}'", cipher.id))?;

            map.set_item(
                &cipher.id,
                &vw_id,
                cipher.revision_date.as_deref(),
                Option::<&str>::None,
            );
        }

        Ok(())
    }

    /// Sync a cipher from VW back to Bitwarden cloud.
    #[allow(dead_code)] // needed for future VW→cloud reverse sync
    pub async fn sync_cipher_to_cloud(&self, vw_cipher: &EncryptedCipher) -> Result<()> {
        let src_enc = self.vw.enc_key();
        let src_mac = self.vw.mac_key();

        let cloud = self.cloud.read().await;
        let dst_enc = cloud.enc_key();
        let dst_mac = cloud.mac_key();

        let mut cloud_cipher = re_encrypt_cipher(vw_cipher, src_enc, src_mac, dst_enc, dst_mac)
            .context("re-encrypt from VW to cloud failed")?;

        let mut map = self.map.write().await;

        if let Some(cloud_id) = map.get_cloud_id(&vw_cipher.id).map(|s| s.to_string()) {
            // Update existing.
            cloud_cipher.id = cloud_id.clone();
            cloud
                .update_cipher(&cloud_id, &cloud_cipher)
                .await
                .context("update cipher in cloud failed")?;

            map.set_item(
                &cloud_id,
                &vw_cipher.id,
                Option::<&str>::None,
                vw_cipher.revision_date.as_deref(),
            );
        } else {
            // Create new.
            let cloud_id = cloud
                .create_cipher(&cloud_cipher)
                .await
                .context("create cipher in cloud failed")?;

            map.set_item(
                &cloud_id,
                &vw_cipher.id,
                Option::<&str>::None,
                vw_cipher.revision_date.as_deref(),
            );
        }

        map.save(SYNC_MAP_PATH)
            .context("failed to save sync map after cloud push")?;

        Ok(())
    }

    /// Durably change ONLY the password of a cipher in Bitwarden cloud
    /// (the source of truth), given its VW-side id.
    ///
    /// Edits made to the VW mirror alone are reverted on the next cloud→VW
    /// reconcile, so credential changes must be written upstream. This does a
    /// minimal field-preserving edit: fetch the live cloud cipher, re-encrypt
    /// just the password with that cipher's resolved keys, and PUT it back —
    /// leaving folder/org/all other fields exactly as cloud has them (avoids
    /// the "Invalid folder" rejection a re-encrypted whole-cipher push hits).
    pub async fn update_password_in_cloud(&self, vw_id: &str, new_password: &str) -> Result<()> {
        let cloud_id = {
            let map = self.map.read().await;
            map.get_cloud_id(vw_id)
                .map(|s| s.to_string())
                .ok_or_else(|| anyhow::anyhow!("no cloud mapping for VW item '{}'", vw_id))?
        };

        let mut cloud = self.cloud.write().await;
        let mut cloud_cipher = cloud
            .get_cipher(&cloud_id)
            .await
            .with_context(|| format!("fetch cloud cipher '{}'", cloud_id))?;

        let (enc, mac) = cloud
            .resolve_cipher_keys(&cloud_cipher)
            .context("resolve cloud cipher keys")?;
        let enc_pw = encrypt_to_cipher_string(new_password, &enc, &mac)
            .context("encrypt new password with cloud keys")?;

        let login = cloud_cipher
            .login
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("cloud cipher '{}' has no login", cloud_id))?;
        login.password = Some(enc_pw);

        cloud
            .update_cipher(&cloud_id, &cloud_cipher)
            .await
            .with_context(|| format!("update cloud cipher '{}'", cloud_id))?;

        Ok(())
    }

    /// Return the current sync status.
    pub async fn get_status(&self) -> SyncStatus {
        self.status.read().await.clone()
    }
}

// -------------------------------------------------------------------------- //
// Re-encryption                                                               //
// -------------------------------------------------------------------------- //

/// Re-encrypt a cipher's fields from one key set to another.
///
/// All plaintext exists only in `SecureBuffer`s during re-encryption and is
/// zeroized when dropped.
pub fn re_encrypt_cipher(
    cipher: &EncryptedCipher,
    src_enc: &[u8],
    src_mac: &[u8],
    dst_enc: &[u8],
    dst_mac: &[u8],
) -> Result<EncryptedCipher> {
    // Helper: re-encrypt a required field.
    let reencrypt = |cs: &str| -> Result<String> {
        let plain: SecureBuffer = decrypt_cipher_string(cs, src_enc, src_mac)?;
        let plain_str =
            std::str::from_utf8(plain.as_bytes()).context("decrypted field is not valid UTF-8")?;
        let result = encrypt_to_cipher_string(plain_str, dst_enc, dst_mac)?;
        // `plain` (SecureBuffer) is dropped and zeroized here.
        Ok(result)
    };

    // Helper: re-encrypt an optional field.
    let reencrypt_opt = |cs: &Option<String>| -> Result<Option<String>> {
        match cs {
            Some(ref s) => Ok(Some(reencrypt(s)?)),
            None => Ok(None),
        }
    };

    // Name (required).
    let name = reencrypt(&cipher.name).context("failed to re-encrypt name")?;

    // Notes (optional).
    let notes = reencrypt_opt(&cipher.notes).context("failed to re-encrypt notes")?;

    // Login fields.
    let login = match &cipher.login {
        Some(l) => {
            let username =
                reencrypt_opt(&l.username).context("failed to re-encrypt login.username")?;
            let password =
                reencrypt_opt(&l.password).context("failed to re-encrypt login.password")?;
            let uris = match &l.uris {
                Some(uris) => {
                    let mut out = Vec::with_capacity(uris.len());
                    for u in uris {
                        let uri =
                            reencrypt_opt(&u.uri).context("failed to re-encrypt login.uri")?;
                        out.push(EncryptedUri { uri });
                    }
                    Some(out)
                }
                None => None,
            };
            let totp = reencrypt_opt(&l.totp).context("failed to re-encrypt login.totp")?;
            Some(EncryptedLogin {
                username,
                password,
                uris,
                totp,
            })
        }
        None => None,
    };

    // Custom fields.
    let fields = match &cipher.fields {
        Some(fields) => {
            let mut out = Vec::with_capacity(fields.len());
            for f in fields {
                let field_name =
                    reencrypt_opt(&f.name).context("failed to re-encrypt field.name")?;
                let field_value =
                    reencrypt_opt(&f.value).context("failed to re-encrypt field.value")?;
                out.push(EncryptedField {
                    name: field_name,
                    value: field_value,
                    field_type: f.field_type,
                });
            }
            Some(out)
        }
        None => None,
    };

    // Re-encrypt card, identity, and secure_note JSON blobs.
    let card = match &cipher.card {
        Some(v) => Some(
            re_encrypt_json_value(v, src_enc, src_mac, dst_enc, dst_mac)
                .context("failed to re-encrypt card")?,
        ),
        None => None,
    };
    let identity = match &cipher.identity {
        Some(v) => Some(
            re_encrypt_json_value(v, src_enc, src_mac, dst_enc, dst_mac)
                .context("failed to re-encrypt identity")?,
        ),
        None => None,
    };
    let secure_note = match &cipher.secure_note {
        Some(v) => Some(
            re_encrypt_json_value(v, src_enc, src_mac, dst_enc, dst_mac)
                .context("failed to re-encrypt secure_note")?,
        ),
        None => None,
    };

    Ok(EncryptedCipher {
        id: String::new(), // Server assigns ID.
        cipher_type: cipher.cipher_type,
        name,
        login,
        card,
        identity,
        secure_note,
        fields,
        notes,
        organization_id: cipher.organization_id.clone(),
        collection_ids: cipher.collection_ids.clone(),
        folder_id: cipher.folder_id.clone(),
        revision_date: cipher.revision_date.clone(),
        key: None, // Personal items don't need per-item keys.
        extra: cipher.extra.clone(),
    })
}

/// Re-encrypt all cipher string values within a JSON Value.
fn re_encrypt_json_value(
    value: &Value,
    src_enc: &[u8],
    src_mac: &[u8],
    dst_enc: &[u8],
    dst_mac: &[u8],
) -> Result<Value> {
    match value {
        Value::String(s) => {
            // Check if it looks like a cipher string (starts with "2." or "0." or "1.")
            if s.starts_with("2.") || s.starts_with("0.") || s.starts_with("1.") {
                match decrypt_cipher_string(s, src_enc, src_mac) {
                    Ok(plain) => {
                        let plain_str = std::str::from_utf8(plain.as_bytes()).unwrap_or("");
                        let encrypted = encrypt_to_cipher_string(plain_str, dst_enc, dst_mac)?;
                        Ok(Value::String(encrypted))
                    }
                    Err(_) => Ok(Value::String(s.clone())), // Can't decrypt, pass through
                }
            } else {
                Ok(Value::String(s.clone()))
            }
        }
        Value::Object(map) => {
            let mut new_map = serde_json::Map::new();
            for (k, v) in map {
                new_map.insert(
                    k.clone(),
                    re_encrypt_json_value(v, src_enc, src_mac, dst_enc, dst_mac)?,
                );
            }
            Ok(Value::Object(new_map))
        }
        Value::Array(arr) => {
            let new_arr: Result<Vec<Value>> = arr
                .iter()
                .map(|v| re_encrypt_json_value(v, src_enc, src_mac, dst_enc, dst_mac))
                .collect();
            Ok(Value::Array(new_arr?))
        }
        other => Ok(other.clone()),
    }
}
