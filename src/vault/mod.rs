//! Vault management module — authentication, key derivation, and cipher access.

pub mod connecterr_secrets;
pub mod crypto;
pub mod handlers;
pub mod smb;
pub mod types;

use anyhow::{anyhow, bail, Context, Result};
use reqwest::Client;
use std::collections::HashMap;
use tokio::sync::{Mutex, RwLock};

use crate::secure::SecureBuffer;
use crypto::{
    decrypt_cipher_string, decrypt_symmetric_key, decrypt_to_string, derive_master_key,
    hash_master_password,
};
use types::{
    DuplicateGroup, DuplicateMember, EncryptedCipher, FolderInfo, MaskedItem, PreloginResponse,
    SyncResponse, TokenResponse,
};

// -------------------------------------------------------------------------- //
// FolderIndex                                                                  //
// -------------------------------------------------------------------------- //

/// In-memory index of decrypted folder name → folder ID, populated during sync.
#[derive(Default, Debug)]
pub struct FolderIndex {
    by_name: HashMap<String, String>, // name → id
}

impl FolderIndex {
    /// Record a folder. Argument order is `(id, name)` — the index is keyed
    /// internally by name, but the public API takes id first ("what the folder
    /// is") then the lookup key ("what to find it by").
    pub fn insert(&mut self, id: String, name: String) {
        self.by_name.insert(name, id);
    }
    pub fn find_id_by_name(&self, name: &str) -> Option<&str> {
        self.by_name.get(name).map(String::as_str)
    }
    pub fn clear(&mut self) {
        self.by_name.clear();
    }
}

/// Populate a FolderIndex from a sequence of (id, decrypted_name) pairs.
/// Idempotent — clears existing entries before insert.
pub fn populate_folder_index(
    index: &mut FolderIndex,
    pairs: impl IntoIterator<Item = (String, String)>,
) {
    index.clear();
    for (id, name) in pairs {
        index.insert(id, name);
    }
}

/// Pure helper — testable without a VaultManager.
pub fn filter_items_by_folder<'a, I>(
    items: I,
    folder_id: &'a str,
) -> impl Iterator<Item = &'a (String, EncryptedCipher)>
where
    I: IntoIterator<Item = &'a (String, EncryptedCipher)>,
{
    items
        .into_iter()
        .filter(move |(_name, c)| c.folder_id.as_deref() == Some(folder_id))
}

/// Pure helper — extract decrypted field names from an already-decrypted cipher view.
/// (Real callers will decrypt the field names themselves; this helper takes plaintext.)
///
/// Gated `#[cfg(test)]` so it is not compiled into production binaries.
/// Kept here for unit tests in this module; the production equivalent is
/// `list_field_names` (async, operates on encrypted data).
#[cfg(test)]
pub fn field_names_from_cipher(cipher: &EncryptedCipher) -> Vec<String> {
    cipher
        .fields
        .as_ref()
        .map(|fs| fs.iter().filter_map(|f| f.name.clone()).collect())
        .unwrap_or_default()
}

// -------------------------------------------------------------------------- //
// VaultManager                                                                //
// -------------------------------------------------------------------------- //

/// Manages an authenticated Vaultwarden session.
///
/// Sensitive key material is held in `SecureBuffer`s (mlocked, zeroized on
/// drop).  Vault items are stored in their _encrypted_ form; plaintext is
/// produced only on demand and never stored.
pub struct VaultManager {
    vaultwarden_url: String,
    access_token: RwLock<String>,
    refresh_token: RwLock<Option<String>>,
    /// Approximate instant at which the current access token expires.
    ///
    /// Set from `TokenResponse.expires_in` at construction time and updated
    /// after every successful token refresh. Used by `maybe_proactive_refresh`
    /// to trigger a proactive refresh when the token is within 5 minutes of
    /// expiry — avoiding the reactive 401 path that adds ~200 ms latency on
    /// the first request after expiry.
    ///
    /// The value is `None` if `expires_in` was 0 / missing in the token
    /// response (older Vaultwarden versions that don't send `expires_in`);
    /// in that case proactive refresh is simply disabled.
    token_expires_at: RwLock<Option<std::time::Instant>>,
    /// Serialises concurrent calls to `reauth()`. Without this mutex, two
    /// concurrent 401 responses race to refresh the *same* (now-revoked)
    /// refresh token. Vaultwarden accepts only the first refresh; the second
    /// returns 400/401 and leaves the `VaultManager` unable to make any further
    /// authenticated requests. The mutex ensures only one goroutine runs the
    /// refresh exchange at a time; the loser re-reads `access_token` after
    /// acquiring the lock and discovers it was already refreshed, so it sends
    /// its retry with the newly-valid token instead of racing again.
    ///
    /// # Why Mutex and not a second RwLock
    ///
    /// The refresh operation is a read-modify-write on `access_token` +
    /// `refresh_token`. Holding two separate write-locks sequentially doesn't
    /// prevent interleaving between them. A single Mutex that the entire reauth
    /// path holds end-to-end is the correct primitive.
    reauth_mutex: Mutex<()>,
    enc_key: SecureBuffer,
    mac_key: SecureBuffer,
    /// Items keyed by cipher id. Value holds `(decrypted_name, cipher)` so
    /// callers don't have to redecrypt the name on every read, and so that
    /// two ciphers with the same decrypted name can coexist — which is the
    /// common case in vaults that have been through broken cloud↔self-hosted
    /// syncs. Keying by name (as we did before) silently collapsed duplicates
    /// and made vault-proxy's view diverge from the upstream by thousands of
    /// items.
    ///
    /// # Cache staleness (iter-10)
    ///
    /// This map is loaded once at startup (in `new()`) and refreshed only
    /// when `sync()` is explicitly called — either via `POST /vault/resync`
    /// or after a write operation (create/update/move/delete cipher). There is
    /// NO automatic TTL or background refresh timer for the common read path.
    ///
    /// Consequence: if an operator updates a credential in Vaultwarden after
    /// vault-proxy has started, the old encrypted blob is served until
    /// `sync()` runs. For most homelab use cases this is acceptable (credentials
    /// change infrequently). If live credential refresh is needed, call
    /// `POST /vault/resync` after each Vaultwarden update, or use the
    /// `--vault-refresh-interval-secs` flag (implemented in iter-37) to enable
    /// an automatic background refresh on a configurable interval.
    items: RwLock<HashMap<String, (String, EncryptedCipher)>>,
    /// Folder name → folder ID index, populated during sync. Deduped by name
    /// (HashMap semantics), so not suitable for surfacing duplicate-name
    /// folders — use `all_folders` for that.
    folders: RwLock<FolderIndex>,
    /// Full list of (id, decrypted_name) pairs, preserving duplicates so the
    /// `/vault/folders` endpoint can expose migration-artefact duplicates.
    all_folders: RwLock<Vec<(String, String)>>,
    http: Client,
}

impl VaultManager {
    /// Authenticate to Vaultwarden and return a ready `VaultManager`.
    ///
    /// Performs:
    ///   1. Prelogin (fetch KDF iterations)
    ///   2. Master-key derivation
    ///   3. Token request
    ///   4. Symmetric-key decryption
    ///   5. Initial cipher sync
    pub async fn new(url: &str, email: &str, master_password: &str) -> Result<Self> {
        let base_url = url.trim_end_matches('/').to_string();

        // Build an HTTP client that tolerates self-signed certificates (common
        // for self-hosted Vaultwarden instances).
        //
        // Issue (iter-14): No timeout was set on this client, so an unreachable
        // or slow Vaultwarden server during `--setup` (or re-auth) would block
        // the caller indefinitely — a 120-second (or longer) hang during the
        // interactive setup wizard is a poor experience. Apply a 30-second
        // connect+read timeout: long enough for legitimate slow auth responses
        // (high-iteration KDF on low-power hardware), short enough to surface
        // connectivity problems quickly.
        let http = Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .context("failed to build HTTP client")?;

        // --- Step 1: prelogin ------------------------------------------------
        #[derive(serde::Serialize)]
        struct PreloginReq<'a> {
            email: &'a str,
        }

        let prelogin: PreloginResponse = http
            .post(format!("{}/identity/accounts/prelogin", base_url))
            .json(&PreloginReq { email })
            .send()
            .await
            .context("prelogin request failed")?
            .error_for_status()
            .context("prelogin returned error status")?
            .json()
            .await
            .context("failed to parse prelogin response")?;

        let iterations = prelogin.kdf_iterations;
        tracing::debug!("prelogin ok — kdfIterations={}", iterations);

        // --- Step 2: derive master key + password hash -----------------------
        let master_key = derive_master_key(master_password, email, iterations);
        let password_hash = hash_master_password(master_key.as_bytes(), master_password);

        // --- Step 3: token request -------------------------------------------
        let params = [
            ("grant_type", "password"),
            ("username", email),
            ("password", password_hash.as_str()),
            ("scope", "api offline_access"),
            ("client_id", "web"),
            ("deviceType", "10"),
            ("deviceIdentifier", "vaultproxy"),
            ("deviceName", "vaultproxy"),
        ];

        let token_resp: TokenResponse = http
            .post(format!("{}/identity/connect/token", base_url))
            .form(&params)
            .send()
            .await
            .context("token request failed")?
            .error_for_status()
            .context("authentication failed")?
            .json()
            .await
            .context("failed to parse token response")?;

        tracing::info!("authenticated to Vaultwarden");

        // --- Step 4: decrypt symmetric key -----------------------------------
        let (enc_key, mac_key) = decrypt_symmetric_key(&token_resp.key, master_key.as_bytes())
            .context("failed to decrypt vault symmetric key")?;

        // Compute the token expiry instant from expires_in (seconds).
        // Vaultwarden typically returns 3600. A value of 0 means the field was
        // absent or zero — proactive refresh is disabled in that case.
        //
        // Issue (iter-25): Use checked_add to avoid a panic on absurdly large
        // expires_in values. Some self-hosted Vaultwarden configs return
        // expires_in = 9999999 or even u64::MAX. Rust's `Instant + Duration`
        // panics on overflow (in both debug and release builds on most platforms).
        // Cap at 7 days (604800 s) — any token with a longer lifetime than that
        // won't benefit from proactive refresh and can simply be refreshed on the
        // first 401 response after the cap window.
        const MAX_EXPIRES_IN_SECS: u64 = 7 * 24 * 3600; // 7 days
        let token_expires_at = if token_resp.expires_in > 0 {
            let clamped = token_resp.expires_in.min(MAX_EXPIRES_IN_SECS);
            if clamped != token_resp.expires_in {
                tracing::warn!(
                    expires_in = token_resp.expires_in,
                    clamped = clamped,
                    "expires_in is unusually large — clamping to {} s for proactive-refresh \
                     tracking to prevent Instant overflow; reactive 401 refresh still active",
                    clamped
                );
            }
            std::time::Instant::now().checked_add(std::time::Duration::from_secs(clamped))
        } else {
            None
        };
        tracing::debug!(
            expires_in = token_resp.expires_in,
            "access token acquired; proactive refresh {}",
            if token_expires_at.is_some() {
                "enabled"
            } else {
                "disabled (no expires_in)"
            }
        );

        let manager = VaultManager {
            vaultwarden_url: base_url,
            access_token: RwLock::new(token_resp.access_token),
            refresh_token: RwLock::new(token_resp.refresh_token),
            token_expires_at: RwLock::new(token_expires_at),
            reauth_mutex: Mutex::new(()),
            enc_key,
            mac_key,
            items: RwLock::new(HashMap::new()),
            folders: RwLock::new(FolderIndex::default()),
            all_folders: RwLock::new(Vec::new()),
            http,
        };

        // --- Step 5: initial sync --------------------------------------------
        manager.sync().await.context("initial vault sync failed")?;

        Ok(manager)
    }

    // ---------------------------------------------------------------------- //
    // Token refresh                                                            //
    // ---------------------------------------------------------------------- //

    /// Re-authenticate using the stored refresh token.
    ///
    /// # Concurrency safety
    ///
    /// This method acquires `reauth_mutex` before touching the token pair so
    /// that concurrent 401 responses don't both try to exchange the same
    /// (now-revoked) refresh token. The second waiter snapshots `access_token`
    /// after winning the mutex; if it has changed since the caller last read it
    /// (i.e. the first task already refreshed), we return `Ok(())` without
    /// hitting Vaultwarden again — the caller will pick up the new token on its
    /// next `access_token.read()`.
    async fn reauth(&self) -> Result<()> {
        // Snapshot the current access token *before* acquiring the lock so we
        // can detect whether another task already refreshed while we waited.
        let token_before_wait = self.access_token.read().await.clone();

        let _guard = self.reauth_mutex.lock().await;

        // Check again under the mutex. If the token changed, the racing task
        // already refreshed successfully — nothing to do.
        let current_token = self.access_token.read().await.clone();
        if current_token != token_before_wait {
            tracing::debug!("reauth: token already refreshed by concurrent task — skipping");
            return Ok(());
        }

        let rt = self.refresh_token.read().await.clone();
        let rt = rt.ok_or_else(|| anyhow!("no refresh token available for re-authentication"))?;

        #[derive(serde::Deserialize)]
        struct RefreshResp {
            access_token: String,
            refresh_token: Option<String>,
            /// Token lifetime in seconds — used to update the expiry tracker.
            #[serde(default)]
            expires_in: u64,
        }

        let resp = self
            .http
            .post(format!("{}/identity/connect/token", self.vaultwarden_url))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", rt.as_str()),
                ("client_id", "web"),
            ])
            .send()
            .await
            .context("refresh token request failed")?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("refresh token auth failed: {}", body);
        }

        let data: RefreshResp = resp
            .json()
            .await
            .context("failed to parse refresh response")?;
        *self.access_token.write().await = data.access_token;
        if let Some(new_rt) = data.refresh_token {
            *self.refresh_token.write().await = Some(new_rt);
        }
        // Update the expiry tracker so proactive refresh uses the new window.
        // Apply the same MAX_EXPIRES_IN_SECS cap as at initial auth to avoid
        // Instant overflow on self-hosted configs with absurdly large expires_in.
        if data.expires_in > 0 {
            const MAX_EXPIRES_IN_SECS: u64 = 7 * 24 * 3600;
            let clamped = data.expires_in.min(MAX_EXPIRES_IN_SECS);
            *self.token_expires_at.write().await =
                std::time::Instant::now().checked_add(std::time::Duration::from_secs(clamped));
        }
        tracing::info!("re-authenticated to Vaultwarden via refresh token");
        Ok(())
    }

    /// Proactively refresh the access token if it is within 5 minutes of
    /// expiry. This eliminates the reactive 401 → refresh → retry path that
    /// adds ~200 ms latency on the first request after the token expires.
    ///
    /// Calling this method is cheap when the token is not near expiry — it
    /// reads `token_expires_at` under a read lock and returns immediately.
    /// When a refresh is needed it calls `reauth()`, which serialises concurrent
    /// callers via `reauth_mutex` so only one refresh happens per expiry window.
    ///
    /// # When to call
    ///
    /// Call this at the start of `authed_request` (before using the token).
    /// It is a no-op when `token_expires_at` is `None` (older Vaultwarden that
    /// does not return `expires_in` in the token response).
    async fn maybe_proactive_refresh(&self) {
        const PROACTIVE_REFRESH_SECS: u64 = 300; // 5 minutes before expiry

        let expires_at = *self.token_expires_at.read().await;
        let Some(exp) = expires_at else { return };

        let now = std::time::Instant::now();
        if exp > now && exp.duration_since(now).as_secs() > PROACTIVE_REFRESH_SECS {
            // Token is not near expiry — nothing to do.
            return;
        }

        tracing::info!(
            "access token expires in <{}s — proactively refreshing before next request",
            PROACTIVE_REFRESH_SECS
        );
        if let Err(e) = self.reauth().await {
            // Non-fatal: the next request will trigger a reactive 401 refresh.
            tracing::warn!(
                "proactive token refresh failed (will retry on 401): {:#}",
                e
            );
        }
    }

    /// Send a request with the current access token. On 401, refresh and retry once.
    ///
    /// Calls `maybe_proactive_refresh` first so tokens near expiry are renewed
    /// before the request is sent — eliminating the reactive 401 → refresh →
    /// retry round-trip that adds ~200 ms latency.
    async fn authed_request(
        &self,
        build: impl Fn(&str) -> reqwest::RequestBuilder,
    ) -> Result<reqwest::Response> {
        // Proactively refresh if the token is within 5 minutes of expiry.
        self.maybe_proactive_refresh().await;

        let token = self.access_token.read().await.clone();
        let raw = build(&token).send().await.context("request failed")?;

        if raw.status() == reqwest::StatusCode::UNAUTHORIZED {
            tracing::warn!("got 401 from Vaultwarden, attempting token refresh");
            self.reauth().await?;
            let token = self.access_token.read().await.clone();
            let raw = build(&token)
                .send()
                .await
                .context("request failed (after reauth)")?;
            Ok(raw)
        } else {
            Ok(raw)
        }
    }

    // ---------------------------------------------------------------------- //
    // Public API                                                               //
    // ---------------------------------------------------------------------- //

    /// Fetch all ciphers and folders from Vaultwarden and store them
    /// (encrypted) indexed by decrypted name.
    ///
    /// # Read/write lock contention (iter-11)
    ///
    /// `sync()` acquires write locks on `items`, `all_folders`, and `folders`
    /// to rebuild the in-memory cache. All concurrent callers of `list_items`,
    /// `list_duplicates`, `decrypt_password`, etc. that use `items.read()` block
    /// for the duration of the write lock.
    ///
    /// For a typical vault with ~1000 ciphers, the HTTP round-trip to VW
    /// (`/api/sync`) dominates: 100–500 ms depending on latency. The decrypt +
    /// insert loop is a few milliseconds. So the read-lock blackout window is
    /// mostly the network round-trip.
    ///
    /// Mitigations considered:
    ///   - **Double-buffering** (build a fresh HashMap off-lock, then swap via
    ///     a single short write-lock): would reduce the blackout to microseconds.
    ///     TODO: implement if sync-vs-read latency becomes a problem in
    ///     production (requires wrapping the HashMap in an Arc so the old and
    ///     new copies can coexist momentarily).
    ///   - **Timeout on write-lock acquisition**: tokio's async RwLock does not
    ///     expose a try_write_timeout; a workaround would be
    ///     `tokio::time::timeout(Duration::from_secs(N), items.write())`.
    ///     Not implemented — a sync that can't acquire the lock would silently
    ///     skip the refresh, which is worse than blocking briefly.
    ///
    /// For the current homelab load (single-digit concurrent requests), blocking
    /// is acceptable. Document and revisit if concurrency increases.
    pub async fn sync(&self) -> Result<()> {
        let url = format!("{}/api/sync", self.vaultwarden_url);
        let sync_response: SyncResponse = self
            .authed_request(|token| self.http.get(&url).bearer_auth(token))
            .await?
            .error_for_status()
            .context("sync returned error status")?
            .json()
            .await
            .context("failed to parse sync response")?;

        let mut map = self.items.write().await;
        map.clear();

        let mut loaded = 0usize;
        for cipher in sync_response.ciphers {
            // Decrypt the name once and cache it alongside the cipher. We key
            // by cipher id so duplicate names don't collapse.
            match crypto::decrypt_cipher_string(
                &cipher.name,
                self.enc_key.as_bytes(),
                self.mac_key.as_bytes(),
            ) {
                Ok(name_buf) => match String::from_utf8(name_buf.to_vec()) {
                    Ok(name) => {
                        map.insert(cipher.id.clone(), (name, cipher));
                        loaded += 1;
                    }
                    Err(e) => {
                        tracing::warn!(id = %cipher.id, "cipher name is not valid UTF-8: {}", e);
                    }
                },
                Err(e) => {
                    tracing::warn!(id = %cipher.id, "failed to decrypt cipher name: {}", e);
                }
            }
        }
        drop(map);

        // Decrypt folder names and rebuild the folder index.
        let decrypted_folders: Vec<(String, String)> = sync_response
            .folders
            .iter()
            .filter_map(|f| {
                match decrypt_to_string(
                    Some(f.name.as_str()),
                    self.enc_key.as_bytes(),
                    self.mac_key.as_bytes(),
                ) {
                    Some(name) => Some((f.id.clone(), name)),
                    None => {
                        tracing::warn!(folder_id = %f.id, "failed to decrypt folder name; skipping");
                        None
                    }
                }
            })
            .collect();

        let folder_count = decrypted_folders.len();
        // Keep a raw copy (allowing duplicate names) for the folders endpoint.
        *self.all_folders.write().await = decrypted_folders.clone();

        // Issue (iter-19): Detect duplicate folder names before indexing.
        // FolderIndex is keyed by name (last-write-wins). When two folders
        // share a name, find_folder_id_by_name_async returns whichever id was
        // inserted last — silently shadowing the other. This is ambiguous and
        // can cause folder-scope guards to pass for items in the wrong folder.
        // Warn loudly so operators know to consolidate or rename.
        {
            let mut seen_names: HashMap<String, String> = HashMap::new();
            for (id, name) in &decrypted_folders {
                if let Some(prev_id) = seen_names.insert(name.clone(), id.clone()) {
                    tracing::warn!(
                        folder_name = %name,
                        id_a = %prev_id,
                        id_b = %id,
                        "sync: two folders share the same decrypted name '{}' (ids {} and {}). \
                         find_folder_id_by_name_async will resolve to one of them non-deterministically. \
                         Consolidate or rename duplicate folders in Vaultwarden to avoid scope-guard ambiguity.",
                        name, prev_id, id
                    );
                }
            }
        }

        let mut idx = self.folders.write().await;
        populate_folder_index(&mut idx, decrypted_folders);
        drop(idx);

        tracing::info!(
            "vault sync complete — {} items loaded, {} folders indexed",
            loaded,
            folder_count
        );
        Ok(())
    }

    /// Return all vault items with passwords replaced by `"********"`.
    pub async fn list_items(&self) -> Vec<MaskedItem> {
        let map = self.items.read().await;
        map.values()
            .map(|(name, cipher)| {
                let username = cipher.login.as_ref().and_then(|l| {
                    decrypt_to_string(
                        l.username.as_deref(),
                        self.enc_key.as_bytes(),
                        self.mac_key.as_bytes(),
                    )
                });

                let uris = cipher
                    .login
                    .as_ref()
                    .and_then(|l| l.uris.as_ref())
                    .map(|uris| {
                        uris.iter()
                            .filter_map(|u| {
                                decrypt_to_string(
                                    u.uri.as_deref(),
                                    self.enc_key.as_bytes(),
                                    self.mac_key.as_bytes(),
                                )
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                let item_type = match cipher.cipher_type {
                    1 => "login",
                    2 => "note",
                    3 => "card",
                    4 => "identity",
                    _ => "unknown",
                }
                .to_string();

                MaskedItem {
                    id: cipher.id.clone(),
                    name: name.clone(),
                    item_type,
                    username,
                    password: "********",
                    uris,
                    organization_id: cipher.organization_id.clone(),
                    folder_id: cipher.folder_id.clone(),
                }
            })
            .collect()
    }

    /// Find credential-level duplicates: items that share the same
    /// `(organization_id, username, password)`. Passwords are decrypted in
    /// place, hashed with SHA-256, and the plaintext is dropped before the
    /// group is assembled — no plaintext or hash leaves the proxy.
    ///
    /// Items without a password (notes, cards, logins with a null password
    /// field such as placeholder MetaMask entries) are excluded from grouping;
    /// callers can find those via `list_items` with a password filter.
    #[allow(dead_code)] // unscoped variant — kept for internal/test use; scoped variant used in production
    pub async fn list_duplicates(&self) -> Vec<DuplicateGroup> {
        // Unscoped variant — kept for internal/test use only.
        self.list_duplicates_in_folder(None).await
    }

    /// Find duplicate items, optionally scoped to a specific folder.
    ///
    /// When `folder_id` is `Some(id)` only items whose `folder_id` matches are
    /// considered — preventing callers from fingerprinting personal items that
    /// live outside the vault-proxy folder. When `folder_id` is `None` (folder
    /// not found / fresh vault) all items are scanned so first-run tooling
    /// continues to work.
    pub async fn list_duplicates_in_folder(&self, folder_id: Option<&str>) -> Vec<DuplicateGroup> {
        use sha2::{Digest, Sha256};

        let map = self.items.read().await;

        // Fingerprint → Vec<DuplicateMember>. The 32-byte SHA-256 digest is
        // used directly as part of the key (Vec<u8>) — avoids pulling in a
        // hex crate for what is purely an internal map lookup.
        type Fingerprint = (String, String, Vec<u8>);
        let mut groups: HashMap<Fingerprint, Vec<DuplicateMember>> = HashMap::new();

        for (name, cipher) in map.values() {
            // Issue (iter-19): When a folder_id scope is active, skip items
            // that don't belong to vault_folder so personal entries are never
            // fingerprinted or exposed in the output.
            if let Some(fid) = folder_id {
                if cipher.folder_id.as_deref() != Some(fid) {
                    continue;
                }
            }

            let login = match cipher.login.as_ref() {
                Some(l) => l,
                None => continue,
            };

            let pw_cs = match login.password.as_deref() {
                Some(cs) => cs,
                None => continue,
            };

            let password = match decrypt_to_string(
                Some(pw_cs),
                self.enc_key.as_bytes(),
                self.mac_key.as_bytes(),
            ) {
                Some(p) if !p.is_empty() => p,
                _ => continue,
            };

            let username = decrypt_to_string(
                login.username.as_deref(),
                self.enc_key.as_bytes(),
                self.mac_key.as_bytes(),
            )
            .unwrap_or_default();

            let mut hasher = Sha256::new();
            hasher.update(password.as_bytes());
            let pw_hash: Vec<u8> = hasher.finalize().to_vec();
            // Drop plaintext ASAP — we only need the hash for grouping.
            drop(password);

            let org = cipher
                .organization_id
                .clone()
                .unwrap_or_else(|| "personal".to_string());

            let key: Fingerprint = (org, username, pw_hash);

            let uris = login
                .uris
                .as_ref()
                .map(|uris| {
                    uris.iter()
                        .filter_map(|u| {
                            decrypt_to_string(
                                u.uri.as_deref(),
                                self.enc_key.as_bytes(),
                                self.mac_key.as_bytes(),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();

            groups.entry(key).or_default().push(DuplicateMember {
                id: cipher.id.clone(),
                name: name.clone(),
                uris,
                revision_date: cipher.revision_date.clone(),
            });
        }

        // Keep only groups with >= 2 members. Discard the password-hash
        // portion of the fingerprint — callers must not receive it.
        let mut out: Vec<DuplicateGroup> = groups
            .into_iter()
            .filter(|(_, v)| v.len() >= 2)
            .map(
                |((organization_id, username, _pw_hash), v)| DuplicateGroup {
                    organization_id,
                    username,
                    count: v.len(),
                    items: v,
                },
            )
            .collect();

        // Deterministic order: largest groups first, then by org/username so
        // two runs produce the same list (useful for the caller batching
        // delete decisions).
        out.sort_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then_with(|| a.organization_id.cmp(&b.organization_id))
                .then_with(|| a.username.cmp(&b.username))
        });

        out
    }

    /// Decrypt and return the password for a vault item, identified by its
    /// decrypted name.
    pub fn decrypt_password(&self, item_name: &str) -> Result<SecureBuffer> {
        let map = self
            .items
            .try_read()
            .map_err(|_| anyhow!("vault items lock is contended"))?;

        let cipher = map
            .values()
            .find(|(n, _)| n == item_name)
            .map(|(_, c)| c)
            .ok_or_else(|| anyhow!("item '{}' not found in vault", item_name))?;

        let password_cs = cipher
            .login
            .as_ref()
            .and_then(|l| l.password.as_deref())
            .ok_or_else(|| anyhow!("item '{}' has no password", item_name))?;

        decrypt_cipher_string(
            password_cs,
            self.enc_key.as_bytes(),
            self.mac_key.as_bytes(),
        )
        .with_context(|| format!("failed to decrypt password for '{}'", item_name))
    }

    /// Decrypt and return the username for a vault item.
    ///
    /// Returns `Ok(None)` if the item has no username field.
    pub fn decrypt_username(&self, item_name: &str) -> Result<Option<SecureBuffer>> {
        let map = self
            .items
            .try_read()
            .map_err(|_| anyhow!("vault items lock is contended"))?;

        let cipher = map
            .values()
            .find(|(n, _)| n == item_name)
            .map(|(_, c)| c)
            .ok_or_else(|| anyhow!("item '{}' not found in vault", item_name))?;

        let username_cs = match cipher.login.as_ref().and_then(|l| l.username.as_deref()) {
            Some(cs) => cs,
            None => return Ok(None),
        };

        let buf = decrypt_cipher_string(
            username_cs,
            self.enc_key.as_bytes(),
            self.mac_key.as_bytes(),
        )
        .with_context(|| format!("failed to decrypt username for '{}'", item_name))?;

        Ok(Some(buf))
    }

    /// Decrypt and return the TOTP seed for a vault item.
    ///
    /// Returns `Ok(None)` if the item has no TOTP field.
    pub fn decrypt_totp(&self, item_name: &str) -> Result<Option<SecureBuffer>> {
        let map = self
            .items
            .try_read()
            .map_err(|_| anyhow!("vault items lock is contended"))?;

        let cipher = map
            .values()
            .find(|(n, _)| n == item_name)
            .map(|(_, c)| c)
            .ok_or_else(|| anyhow!("item '{}' not found in vault", item_name))?;

        let totp_cs = cipher.login.as_ref().and_then(|l| l.totp.as_deref());

        match totp_cs {
            Some(cs) if !cs.is_empty() => {
                let buf =
                    decrypt_cipher_string(cs, self.enc_key.as_bytes(), self.mac_key.as_bytes())?;
                Ok(Some(buf))
            }
            _ => Ok(None),
        }
    }

    /// Decrypt and return the notes content for a vault item (used for secure notes).
    pub fn decrypt_notes(&self, item_name: &str) -> Result<Option<SecureBuffer>> {
        let map = self
            .items
            .try_read()
            .map_err(|_| anyhow!("vault items lock is contended"))?;

        let cipher = map
            .values()
            .find(|(n, _)| n == item_name)
            .map(|(_, c)| c)
            .ok_or_else(|| anyhow!("item '{}' not found in vault", item_name))?;

        let notes_cs = cipher.notes.as_deref();

        match notes_cs {
            Some(cs) if !cs.is_empty() => {
                let buf =
                    decrypt_cipher_string(cs, self.enc_key.as_bytes(), self.mac_key.as_bytes())
                        .with_context(|| format!("failed to decrypt notes for '{}'", item_name))?;
                Ok(Some(buf))
            }
            _ => Ok(None),
        }
    }

    /// Decrypt and return the value of a named custom field on a vault item.
    pub fn decrypt_field(&self, item_name: &str, field_name: &str) -> Result<SecureBuffer> {
        let map = self
            .items
            .try_read()
            .map_err(|_| anyhow!("vault items lock is contended"))?;

        let cipher = map
            .values()
            .find(|(n, _)| n == item_name)
            .map(|(_, c)| c)
            .ok_or_else(|| anyhow!("item '{}' not found in vault", item_name))?;

        let fields = cipher
            .fields
            .as_ref()
            .ok_or_else(|| anyhow!("item '{}' has no custom fields", item_name))?;

        for field in fields {
            // Decrypt the field name to compare.
            if let Some(decrypted_name) = decrypt_to_string(
                field.name.as_deref(),
                self.enc_key.as_bytes(),
                self.mac_key.as_bytes(),
            ) {
                if decrypted_name == field_name {
                    let value_cs = field
                        .value
                        .as_deref()
                        .ok_or_else(|| anyhow!("field '{}' has no value", field_name))?;

                    return decrypt_cipher_string(
                        value_cs,
                        self.enc_key.as_bytes(),
                        self.mac_key.as_bytes(),
                    )
                    .with_context(|| {
                        format!(
                            "failed to decrypt field '{}' on item '{}'",
                            field_name, item_name
                        )
                    });
                }
            }
        }

        bail!("field '{}' not found on item '{}'", field_name, item_name)
    }

    // ---------------------------------------------------------------------- //
    // Write API                                                                //
    // ---------------------------------------------------------------------- //

    /// Return a clone of the encrypted cipher for `id`, or `None` if not found.
    pub async fn get_cipher_by_id(&self, id: &str) -> Option<EncryptedCipher> {
        let items = self.items.read().await;
        items.get(id).map(|(_, cipher)| cipher.clone())
    }

    /// Return the vault item id for the item with the given decrypted name,
    /// or None if no item with that name exists.
    pub async fn find_item_id_by_name(&self, item_name: &str) -> Option<String> {
        let items = self.items.read().await;
        items
            .iter()
            .find(|(_, (name, _))| name == item_name)
            .map(|(id, _)| id.clone())
    }

    /// Create a new cipher in Vaultwarden and return its assigned ID.
    pub async fn create_cipher(&self, cipher: &EncryptedCipher) -> Result<String> {
        tracing::debug!("creating cipher");

        #[derive(serde::Deserialize)]
        struct CreateResponse {
            #[serde(rename = "Id")]
            id: Option<String>,
            #[serde(rename = "id")]
            id_lower: Option<String>,
        }

        let url = format!("{}/api/ciphers", self.vaultwarden_url);
        let cipher_json = serde_json::to_value(cipher).context("failed to serialize cipher")?;
        let resp: CreateResponse = self
            .authed_request(|token| self.http.post(&url).bearer_auth(token).json(&cipher_json))
            .await?
            .error_for_status()
            .context("create cipher returned error status")?
            .json()
            .await
            .context("failed to parse create cipher response")?;

        let id = resp
            .id
            .or(resp.id_lower)
            .ok_or_else(|| anyhow!("create cipher response missing id field"))?;

        tracing::debug!("cipher created with id={}", id);
        Ok(id)
    }

    /// Update an existing cipher by ID.
    pub async fn update_cipher(&self, id: &str, cipher: &EncryptedCipher) -> Result<()> {
        tracing::debug!("updating cipher id={}", id);

        let url = format!("{}/api/ciphers/{}", self.vaultwarden_url, id);
        let cipher_json = serde_json::to_value(cipher).context("failed to serialize cipher")?;
        let resp = self
            .authed_request(|token| self.http.put(&url).bearer_auth(token).json(&cipher_json))
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_else(|_| "<no body>".into());
            anyhow::bail!("update cipher {} returned {}: {}", id, status, body);
        }

        tracing::debug!("cipher updated id={}", id);
        Ok(())
    }

    /// Find a cipher by item name, re-encrypt a new password, and push the
    /// update to Vaultwarden. Used by the browser rotation workflow after
    /// the password has been changed on the target site — without this, the
    /// site has the new credential while the vault still holds the old one.
    ///
    /// Errors on: item not found, encryption failure, update API failure.
    // iter-81: used by browser/workflow.rs (feature = "browser"). Dead in default builds.
    #[allow(dead_code)]
    pub async fn update_password_for_item(
        &self,
        item_name: &str,
        new_password: &str,
    ) -> Result<()> {
        let cipher = {
            let items = self.items.read().await;
            // Name-based lookup now scans values since the map is keyed by id.
            // If multiple items share `item_name`, the first match wins; that
            // mirrors the old HashMap-by-name behaviour for this code path.
            items
                .values()
                .find(|(n, _)| n == item_name)
                .map(|(_, c)| c.clone())
                .ok_or_else(|| anyhow!("vault item '{}' not found", item_name))?
        };

        let enc_pw = crate::vault::crypto::encrypt_to_cipher_string(
            new_password,
            self.enc_key.as_bytes(),
            self.mac_key.as_bytes(),
        )
        .context("re-encrypting new password")?;

        let mut updated = cipher.clone();
        let login = updated
            .login
            .get_or_insert(crate::vault::types::EncryptedLogin {
                username: None,
                password: None,
                uris: None,
                totp: None,
            });
        login.password = Some(enc_pw);

        self.update_cipher(&cipher.id, &updated).await?;
        Ok(())
    }

    /// Create a new login item in Vaultwarden.
    /// Encrypts all fields before sending. Never receives plaintext after return.
    /// Returns the new item's VW id.
    pub async fn create_login_item(
        &self,
        name: &str,
        username: Option<&str>,
        password: &str,
        uris: Vec<String>,
        folder_id: Option<&str>,
    ) -> Result<String> {
        let enc_name = crate::vault::crypto::encrypt_to_cipher_string(
            name,
            self.enc_key.as_bytes(),
            self.mac_key.as_bytes(),
        )
        .context("encrypting name")?;

        let enc_password = crate::vault::crypto::encrypt_to_cipher_string(
            password,
            self.enc_key.as_bytes(),
            self.mac_key.as_bytes(),
        )
        .context("encrypting password")?;

        let enc_username = username
            .map(|u| {
                crate::vault::crypto::encrypt_to_cipher_string(
                    u,
                    self.enc_key.as_bytes(),
                    self.mac_key.as_bytes(),
                )
                .context("encrypting username")
            })
            .transpose()?;

        let enc_uris = uris
            .iter()
            .map(|u| {
                crate::vault::crypto::encrypt_to_cipher_string(
                    u,
                    self.enc_key.as_bytes(),
                    self.mac_key.as_bytes(),
                )
                .map(|enc| crate::vault::types::EncryptedUri { uri: Some(enc) })
                .context("encrypting URI")
            })
            .collect::<Result<Vec<_>>>()?;

        let cipher = crate::vault::types::EncryptedCipher {
            id: String::new(),
            name: enc_name,
            cipher_type: 1,
            login: Some(crate::vault::types::EncryptedLogin {
                username: enc_username,
                password: Some(enc_password),
                uris: if enc_uris.is_empty() {
                    None
                } else {
                    Some(enc_uris)
                },
                totp: None,
            }),
            card: None,
            identity: None,
            secure_note: None,
            fields: None,
            notes: None,
            organization_id: None,
            collection_ids: None,
            folder_id: folder_id.map(|s| s.to_string()),
            revision_date: None,
            key: None,
            extra: None,
        };

        self.create_cipher(&cipher).await
    }

    /// Update name, username, and/or password of a login item by its VW id.
    /// Only fields with Some(...) are changed; None fields are left as-is.
    /// Never returns plaintext.
    pub async fn update_login_item_fields(
        &self,
        id: &str,
        new_name: Option<&str>,
        new_username: Option<&str>,
        new_password: Option<&str>,
    ) -> Result<()> {
        let cipher = {
            let items = self.items.read().await;
            items
                .get(id)
                .map(|(_, c)| c.clone())
                .ok_or_else(|| anyhow!("vault item id '{}' not found", id))?
        };

        let mut updated = cipher.clone();

        if let Some(name) = new_name {
            updated.name = crate::vault::crypto::encrypt_to_cipher_string(
                name,
                self.enc_key.as_bytes(),
                self.mac_key.as_bytes(),
            )
            .context("encrypting name")?;
        }

        let login = updated
            .login
            .get_or_insert(crate::vault::types::EncryptedLogin {
                username: None,
                password: None,
                uris: None,
                totp: None,
            });

        if let Some(username) = new_username {
            login.username = Some(
                crate::vault::crypto::encrypt_to_cipher_string(
                    username,
                    self.enc_key.as_bytes(),
                    self.mac_key.as_bytes(),
                )
                .context("encrypting username")?,
            );
        }

        if let Some(password) = new_password {
            login.password = Some(
                crate::vault::crypto::encrypt_to_cipher_string(
                    password,
                    self.enc_key.as_bytes(),
                    self.mac_key.as_bytes(),
                )
                .context("encrypting password")?,
            );
        }

        self.update_cipher(id, &updated).await
    }

    /// Decrypt notes for a cipher identified by its VW id (NOT name). Returns
    /// `Ok(None)` if the cipher exists but has no notes, or the decrypted
    /// notes as a `SecureBuffer`. Errors if the cipher id is not in the
    /// vault map or decryption fails.
    // iter-81: used by credential_audit/marker.rs (feature = "engine"). Dead in default builds.
    #[allow(dead_code)]
    pub fn decrypt_notes_by_id(&self, item_id: &str) -> Result<Option<SecureBuffer>> {
        let map = self
            .items
            .try_read()
            .map_err(|_| anyhow!("vault items lock is contended"))?;
        let cipher = map
            .get(item_id)
            .map(|(_, c)| c)
            .ok_or_else(|| anyhow!("vault cipher id '{}' not found", item_id))?;
        match cipher.notes.as_deref() {
            Some(cs) if !cs.is_empty() => {
                let buf = crate::vault::crypto::decrypt_cipher_string(
                    cs,
                    self.enc_key.as_bytes(),
                    self.mac_key.as_bytes(),
                )
                .with_context(|| format!("failed to decrypt notes for id '{}'", item_id))?;
                Ok(Some(buf))
            }
            _ => Ok(None),
        }
    }

    /// Re-encrypt and update only the notes field of a cipher (by VW id).
    /// Pulls the current cipher from the cached map, sets `notes`, and
    /// pushes via `update_cipher`. The rest of the cipher stays unchanged.
    // iter-81: used by credential_audit/marker.rs (feature = "engine"). Dead in default builds.
    #[allow(dead_code)]
    pub async fn update_notes_by_id(&self, item_id: &str, new_notes: &str) -> Result<()> {
        let cipher = {
            let map = self.items.read().await;
            map.get(item_id)
                .map(|(_, c)| c.clone())
                .ok_or_else(|| anyhow!("vault cipher id '{}' not found", item_id))?
        };
        let enc = crate::vault::crypto::encrypt_to_cipher_string(
            new_notes,
            self.enc_key.as_bytes(),
            self.mac_key.as_bytes(),
        )
        .context("re-encrypting notes")?;
        let mut updated = cipher.clone();
        updated.notes = Some(enc);
        self.update_cipher(&cipher.id, &updated).await
    }

    /// List every folder with its decrypted name, current item count, and
    /// whether it's tracked in the provided set of synced folder ids. The
    /// caller passes in the tracked set (from the sync map) so the vault
    /// Return `true` if `folder_id` is a folder that currently exists in this
    /// VW instance. Used by the cloud→VW reconciler to avoid pushing a cipher
    /// with a cloud-side folder id that VW doesn't know about (VW rejects such
    /// a PUT/POST with 400 "Invalid folder").
    pub async fn folder_id_exists(&self, folder_id: &str) -> bool {
        self.all_folders
            .read()
            .await
            .iter()
            .any(|(id, _)| id == folder_id)
    }

    /// module doesn't have to know about sync internals.
    pub async fn list_folders_with_counts(
        &self,
        tracked_folder_ids: &std::collections::HashSet<String>,
    ) -> Vec<FolderInfo> {
        // Snapshot folders + items under read locks, then compute without
        // holding the locks (item_count is O(n_items * n_folders) in the
        // naive join; for 884 items × 15 folders this is trivial, but we
        // still release locks as soon as possible).
        let folders_snapshot: Vec<(String, String)> = self.all_folders.read().await.clone();
        let items_snapshot: Vec<Option<String>> = self
            .items
            .read()
            .await
            .values()
            .map(|(_, c)| c.folder_id.clone())
            .collect();

        // Build folder_id → count.
        let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for fid in items_snapshot.iter().flatten() {
            *counts.entry(fid.as_str()).or_insert(0) += 1;
        }

        folders_snapshot
            .into_iter()
            .map(|(id, name)| {
                let item_count = counts.get(id.as_str()).copied().unwrap_or(0);
                let tracked = tracked_folder_ids.contains(&id);
                FolderInfo {
                    id,
                    name,
                    item_count,
                    tracked,
                }
            })
            .collect()
    }

    /// Return the ids of cipher items in the vault that are NOT in the given
    /// set of tracked vw ids (i.e. have no sync-map entry). These are the
    /// candidates for review when the user suspects broken-sync duplicates.
    pub async fn list_untracked_item_ids(
        &self,
        tracked_vw_ids: &std::collections::HashSet<String>,
    ) -> Vec<(String, String)> {
        self.items
            .read()
            .await
            .values()
            .filter(|(_, c)| !tracked_vw_ids.contains(&c.id))
            .map(|(name, c)| (c.id.clone(), name.clone()))
            .collect()
    }

    /// Clone a cipher by id into a new login item with modified name/username/uri,
    /// **preserving the source's already-encrypted password blob**. This is the
    /// recovery path for "I deleted the only copy of a credential I still know
    /// exists in another vault item": we never decrypt or handle the password
    /// in plaintext — we just copy the encrypted string to a new cipher.
    ///
    /// Returns the new cipher id.
    pub async fn clone_cipher_with_overrides(
        &self,
        source_id: &str,
        new_name: &str,
        new_username: Option<&str>,
        new_uri: Option<&str>,
        folder_id: Option<&str>,
    ) -> Result<String> {
        use crypto::encrypt_to_cipher_string;
        use types::{EncryptedCipher, EncryptedLogin, EncryptedUri};

        let source = {
            let items = self.items.read().await;
            items
                .get(source_id)
                .map(|(_, c)| c.clone())
                .ok_or_else(|| anyhow!("source item '{}' not found", source_id))?
        };

        let source_login = source
            .login
            .as_ref()
            .ok_or_else(|| anyhow!("source item '{}' has no login", source_id))?;

        let src_password = source_login
            .password
            .clone()
            .ok_or_else(|| anyhow!("source item '{}' has no password to clone", source_id))?;

        let enc_key = self.enc_key.as_bytes();
        let mac_key = self.mac_key.as_bytes();

        // Encrypt the overridden plaintext fields with the vault's own keys.
        let enc_name =
            encrypt_to_cipher_string(new_name, enc_key, mac_key).context("encrypt new name")?;
        let enc_username = match new_username {
            Some(u) if !u.is_empty() => Some(
                encrypt_to_cipher_string(u, enc_key, mac_key).context("encrypt new username")?,
            ),
            _ => source_login.username.clone(),
        };
        let enc_uris = match new_uri {
            Some(u) if !u.is_empty() => {
                let enc_uri =
                    encrypt_to_cipher_string(u, enc_key, mac_key).context("encrypt new uri")?;
                Some(vec![EncryptedUri { uri: Some(enc_uri) }])
            }
            _ => source_login.uris.clone(),
        };

        let cipher = EncryptedCipher {
            id: String::new(),
            name: enc_name,
            cipher_type: 1,
            login: Some(EncryptedLogin {
                username: enc_username,
                password: Some(src_password),
                uris: enc_uris,
                totp: source_login.totp.clone(),
            }),
            card: None,
            identity: None,
            secure_note: None,
            fields: source.fields.clone(),
            notes: source.notes.clone(),
            organization_id: None,
            collection_ids: None,
            folder_id: folder_id.map(String::from),
            revision_date: None,
            key: None,
            extra: None,
        };

        let new_id = self.create_cipher(&cipher).await?;
        if let Err(e) = self.sync().await {
            tracing::warn!("post-clone sync failed: {}", e);
        }
        Ok(new_id)
    }

    /// Fetch (username, password) for a cipher by id, decrypting in place.
    /// Caller must drop the returned buffers as soon as the plaintext is no
    /// longer needed — the SecureBuffers zeroise on drop. Returns `None` for
    /// username if the cipher has no username field; password is required.
    pub async fn decrypt_credentials_by_id(
        &self,
        id: &str,
    ) -> Result<(Option<SecureBuffer>, SecureBuffer)> {
        let cipher = {
            let items = self.items.read().await;
            items
                .get(id)
                .map(|(_, c)| c.clone())
                .ok_or_else(|| anyhow!("vault item with id '{}' not found", id))?
        };

        let login = cipher
            .login
            .as_ref()
            .ok_or_else(|| anyhow!("item '{}' has no login (not a credential)", id))?;

        let password_cs = login
            .password
            .as_deref()
            .ok_or_else(|| anyhow!("item '{}' has no password", id))?;

        let password = crypto::decrypt_cipher_string(
            password_cs,
            self.enc_key.as_bytes(),
            self.mac_key.as_bytes(),
        )
        .with_context(|| format!("decrypt password for '{}'", id))?;

        let username = match login.username.as_deref() {
            Some(cs) => Some(
                crypto::decrypt_cipher_string(cs, self.enc_key.as_bytes(), self.mac_key.as_bytes())
                    .with_context(|| format!("decrypt username for '{}'", id))?,
            ),
            None => None,
        };

        Ok((username, password))
    }

    /// Find an existing folder by decrypted name, or create one if missing.
    /// Returns the folder id. Used by the move-to-folder flow so callers can
    /// say "bucket this in 'Duplicates Review'" without first checking whether
    /// the folder already exists.
    pub async fn ensure_folder_by_name(&self, name: &str) -> Result<String> {
        if let Some(id) = self.find_folder_id_by_name_async(name).await {
            return Ok(id);
        }
        let enc_name = crypto::encrypt_to_cipher_string(
            name,
            self.enc_key.as_bytes(),
            self.mac_key.as_bytes(),
        )
        .context("encrypt folder name")?;
        let id = self.create_folder(&enc_name).await?;
        // Sync so the folder index picks up the new folder.
        if let Err(e) = self.sync().await {
            tracing::warn!("post-create-folder sync failed: {}", e);
        }
        Ok(id)
    }

    /// Move a cipher into the folder with the given id. Preserves all
    /// encrypted fields byte-for-byte; only `folder_id` changes. Does NOT
    /// validate that the folder exists — caller must have resolved the id
    /// via `list_folders_with_counts` or similar.
    pub async fn move_cipher_to_folder_id(&self, id: &str, folder_id: &str) -> Result<()> {
        let cipher = {
            let items = self.items.read().await;
            items
                .get(id)
                .map(|(_, c)| c.clone())
                .ok_or_else(|| anyhow!("vault item with id '{}' not found", id))?
        };

        if cipher.folder_id.as_deref() == Some(folder_id) {
            return Ok(());
        }

        let mut updated = cipher.clone();
        updated.folder_id = Some(folder_id.to_string());
        self.update_cipher(&cipher.id, &updated).await?;
        if let Err(e) = self.sync().await {
            tracing::warn!("post-move sync failed: {}", e);
        }
        Ok(())
    }

    /// Move a cipher into the named folder (creating the folder on-demand).
    /// Preserves all encrypted fields byte-for-byte; only `folder_id` changes.
    pub async fn move_cipher_to_folder(&self, id: &str, folder_name: &str) -> Result<()> {
        let folder_id = self.ensure_folder_by_name(folder_name).await?;

        let cipher = {
            let items = self.items.read().await;
            items
                .get(id)
                .map(|(_, c)| c.clone())
                .ok_or_else(|| anyhow!("vault item with id '{}' not found", id))?
        };

        // Already in the target folder — nothing to do, avoid an unnecessary
        // write + server roundtrip.
        if cipher.folder_id.as_deref() == Some(folder_id.as_str()) {
            return Ok(());
        }

        let mut updated = cipher.clone();
        updated.folder_id = Some(folder_id);
        self.update_cipher(&cipher.id, &updated).await?;
        if let Err(e) = self.sync().await {
            tracing::warn!("post-move sync failed: {}", e);
        }
        Ok(())
    }

    /// Soft-delete a cipher by ID — moves it to Vaultwarden's trash where it
    /// stays for 30 days before auto-purge. User can restore via VW UI.
    ///
    /// Vaultwarden's routing:
    ///   `DELETE /api/ciphers/<id>`         → HARD delete (irreversible)
    ///   `PUT    /api/ciphers/<id>/delete`  → soft delete (what we want)
    ///
    /// We originally used the DELETE form here — which on 2026-04-18 caused
    /// an irrecoverable hard-delete of a live service credential. Now we go
    /// through the soft-delete path. Callers needing a permanent purge should
    /// use `hard_delete_cipher` instead.
    pub async fn delete_cipher(&self, id: &str) -> Result<()> {
        tracing::debug!("soft-deleting cipher id={}", id);

        let url = format!("{}/api/ciphers/{}/delete", self.vaultwarden_url, id);
        self.authed_request(|token| self.http.put(&url).bearer_auth(token))
            .await?
            .error_for_status()
            .context("soft-delete cipher returned error status")?;

        tracing::debug!("cipher soft-deleted id={}", id);
        Ok(())
    }

    /// Hard-delete a cipher by ID — permanently removes it from Vaultwarden.
    /// Not reachable via the default MCP delete tool: use this only for a
    /// second-confirmation "purge trash" flow.
    #[allow(dead_code)]
    pub async fn hard_delete_cipher(&self, id: &str) -> Result<()> {
        tracing::debug!("hard-deleting cipher id={}", id);

        let url = format!("{}/api/ciphers/{}", self.vaultwarden_url, id);
        self.authed_request(|token| self.http.delete(&url).bearer_auth(token))
            .await?
            .error_for_status()
            .context("hard-delete cipher returned error status")?;

        tracing::debug!("cipher hard-deleted id={}", id);
        Ok(())
    }

    /// Delete a folder by id. Vaultwarden rejects the delete if the folder
    /// still contains ciphers, so callers must move items out first (the
    /// move-to-folder flow handles that). Returns `Ok(())` on success.
    pub async fn delete_folder(&self, id: &str) -> Result<()> {
        tracing::debug!("deleting folder id={}", id);

        let url = format!("{}/api/folders/{}", self.vaultwarden_url, id);
        self.authed_request(|token| self.http.delete(&url).bearer_auth(token))
            .await?
            .error_for_status()
            .context("delete folder returned error status")?;

        if let Err(e) = self.sync().await {
            tracing::warn!("post-delete-folder sync failed: {}", e);
        }

        tracing::debug!("folder deleted id={}", id);
        Ok(())
    }

    /// Create a new folder with the given encrypted name and return its ID.
    pub async fn create_folder(&self, name_encrypted: &str) -> Result<String> {
        tracing::debug!("creating folder");

        #[derive(serde::Serialize)]
        struct FolderReq<'a> {
            name: &'a str,
        }

        #[derive(serde::Deserialize)]
        struct FolderResponse {
            #[serde(rename = "Id")]
            id: Option<String>,
            #[serde(rename = "id")]
            id_lower: Option<String>,
        }

        let url = format!("{}/api/folders", self.vaultwarden_url);
        let folder_body = serde_json::to_value(&FolderReq {
            name: name_encrypted,
        })
        .context("failed to serialize folder request")?;
        let resp: FolderResponse = self
            .authed_request(|token| self.http.post(&url).bearer_auth(token).json(&folder_body))
            .await?
            .error_for_status()
            .context("create folder returned error status")?
            .json()
            .await
            .context("failed to parse create folder response")?;

        let id = resp
            .id
            .or(resp.id_lower)
            .ok_or_else(|| anyhow!("create folder response missing id field"))?;

        tracing::debug!("folder created with id={}", id);
        Ok(id)
    }

    /// Resolve a named field from a vault item by item name.
    ///
    /// `field` must be `"password"`, `"username"`, or `"uri"`. Used by the
    /// launcher to inject credentials into child-process env vars.
    pub async fn get_field_by_item_name(&self, item_name: &str, field: &str) -> Result<String> {
        match field {
            "password" => {
                let buf = self
                    .decrypt_password(item_name)
                    .with_context(|| format!("decrypt password for '{}'", item_name))?;
                let s = std::str::from_utf8(&buf)
                    .map_err(|e| anyhow!("password for '{}' is not valid UTF-8: {}", item_name, e))?
                    .to_string();
                Ok(s)
            }
            "username" => {
                let buf = self
                    .decrypt_username(item_name)
                    .with_context(|| format!("decrypt username for '{}'", item_name))?
                    .ok_or_else(|| anyhow!("item '{}' has no username field", item_name))?;
                let s = std::str::from_utf8(&buf)
                    .map_err(|e| anyhow!("username for '{}' is not valid UTF-8: {}", item_name, e))?
                    .to_string();
                Ok(s)
            }
            "uri" => {
                let map = self
                    .items
                    .try_read()
                    .map_err(|_| anyhow!("vault items lock is contended"))?;
                let cipher = map
                    .values()
                    .find(|(n, _)| n == item_name)
                    .map(|(_, c)| c)
                    .ok_or_else(|| anyhow!("item '{}' not found in vault", item_name))?;
                let uri_cs = cipher
                    .login
                    .as_ref()
                    .and_then(|l| l.uris.as_ref())
                    .and_then(|uris| uris.first())
                    .and_then(|u| u.uri.as_deref())
                    .ok_or_else(|| anyhow!("item '{}' has no URI", item_name))?;
                let buf =
                    decrypt_cipher_string(uri_cs, self.enc_key.as_bytes(), self.mac_key.as_bytes())
                        .with_context(|| format!("failed to decrypt URI for '{}'", item_name))?;
                let s = std::str::from_utf8(&buf)
                    .map_err(|e| anyhow!("URI for '{}' is not valid UTF-8: {}", item_name, e))?
                    .to_string();
                Ok(s)
            }
            other => {
                anyhow::bail!(
                    "unsupported field '{}' — must be 'password', 'username', or 'uri'",
                    other
                )
            }
        }
    }

    /// Resolve a named field by cipher **id** first, falling back to a by-name
    /// match. This lets socket callers disambiguate items that share a
    /// decrypted name (e.g. several "whatbox.ca" logins) by passing the exact
    /// cipher id — the by-name path returns only the first HashMap match.
    ///
    /// `field` must be `"password"`, `"username"`, or `"uri"`.
    pub async fn get_field_resolved(&self, item: &str, field: &str) -> Result<String> {
        let map = self
            .items
            .try_read()
            .map_err(|_| anyhow!("vault items lock is contended"))?;

        let cipher = match map.get(item) {
            Some((_, c)) => c,
            None => map
                .values()
                .find(|(n, _)| n == item)
                .map(|(_, c)| c)
                .ok_or_else(|| anyhow!("item '{}' not found in vault", item))?,
        };

        let cs = match field {
            "password" => cipher
                .login
                .as_ref()
                .and_then(|l| l.password.as_deref())
                .ok_or_else(|| anyhow!("item '{}' has no password", item))?,
            "username" => cipher
                .login
                .as_ref()
                .and_then(|l| l.username.as_deref())
                .ok_or_else(|| anyhow!("item '{}' has no username field", item))?,
            "uri" => cipher
                .login
                .as_ref()
                .and_then(|l| l.uris.as_ref())
                .and_then(|uris| uris.first())
                .and_then(|u| u.uri.as_deref())
                .ok_or_else(|| anyhow!("item '{}' has no URI", item))?,
            other => {
                anyhow::bail!(
                    "unsupported field '{}' — must be 'password', 'username', or 'uri'",
                    other
                )
            }
        };

        let buf = decrypt_cipher_string(cs, self.enc_key.as_bytes(), self.mac_key.as_bytes())
            .with_context(|| format!("decrypt {} for '{}'", field, item))?;
        let s = std::str::from_utf8(&buf)
            .map_err(|e| anyhow!("{} for '{}' is not valid UTF-8: {}", field, item, e))?
            .to_string();
        Ok(s)
    }

    // ---------------------------------------------------------------------- //
    // Key accessors                                                            //
    // ---------------------------------------------------------------------- //

    /// Return the encryption key bytes.
    pub fn enc_key(&self) -> &[u8] {
        self.enc_key.as_bytes()
    }

    /// Return the MAC key bytes.
    pub fn mac_key(&self) -> &[u8] {
        self.mac_key.as_bytes()
    }

    /// Return the Vaultwarden base URL.
    ///
    /// Kept for introspection and test helpers; not currently used by any
    /// runtime code path (all callers have the URL from their own state).
    #[allow(dead_code)]
    pub fn base_url(&self) -> &str {
        &self.vaultwarden_url
    }
}

impl VaultManager {
    /// Resolve a decrypted folder name to its folder ID.
    /// Returns None if no folder with that name exists in the vault.
    pub async fn find_folder_id_by_name_async(&self, name: &str) -> Option<String> {
        self.folders
            .read()
            .await
            .find_id_by_name(name)
            .map(String::from)
    }

    /// Check whether the item with the given decrypted name belongs to the
    /// folder with the given folder UUID. Used by `item_in_vault_folder` in
    /// handlers.rs (iter-96 cache-aware wrapper) so the caller can supply a
    /// pre-resolved folder ID from `cached_folder_id` without re-scanning the
    /// folder index.
    pub async fn item_name_is_in_folder_id(&self, item_name: &str, folder_id: &str) -> bool {
        let items = self.items.read().await;
        items
            .values()
            .any(|(n, c)| n.as_str() == item_name && c.folder_id.as_deref() == Some(folder_id))
    }

    /// Return items in the folder with the given (decrypted) name.
    /// Empty Vec if the folder is unknown or has no items.
    pub async fn list_items_in_folder(&self, folder_name: &str) -> Vec<(String, EncryptedCipher)> {
        let folder_id = match self.folders.read().await.find_id_by_name(folder_name) {
            Some(id) => id.to_string(),
            None => return Vec::new(),
        };
        let items = self.items.read().await;
        let pairs: Vec<(String, EncryptedCipher)> = items
            .values()
            .map(|(n, c)| (n.clone(), c.clone()))
            .collect();
        filter_items_by_folder(pairs.iter(), &folder_id)
            .cloned()
            .collect()
    }

    /// Create or merge a named item in the given folder.
    ///
    /// - Returns `Ok(true)` when a new cipher was created.
    /// - Returns `Ok(false)` when an existing cipher was updated (fields merged).
    ///
    /// On merge, only the fields whose names appear in `fields` are touched;
    /// all other encrypted fields (including credential values) are left byte-for-byte
    /// unchanged.  The function never decrypts credential values — field *names*
    /// are decrypted only to find the matching slot, consistent with the policy in
    /// `connecterr_secrets.rs`.
    pub async fn upsert_folder_item(
        &self,
        folder: &str,
        name: &str,
        fields: std::collections::BTreeMap<String, String>,
    ) -> anyhow::Result<bool> {
        use crypto::encrypt_to_cipher_string;
        use types::{EncryptedCipher, EncryptedField, EncryptedLogin};

        let enc_key = self.enc_key.as_bytes();
        let mac_key = self.mac_key.as_bytes();

        // Resolve folder name → folder ID.
        let folder_id = self
            .find_folder_id_by_name_async(folder)
            .await
            .ok_or_else(|| anyhow!("folder '{}' not found in vault", folder))?;

        // Look for an existing item with this name inside the folder.
        let existing = self.find_item_by_name_in_folder_id(name, &folder_id).await;

        if let Some(mut cipher) = existing {
            // --- MERGE path ---------------------------------------------------
            // Build a set of field names the caller wants to update.
            // We'll walk existing fields, re-encrypt values for names that match,
            // and collect the names we've handled.
            let mut handled: std::collections::HashSet<String> = std::collections::HashSet::new();

            // Update or keep each existing field.
            if let Some(ref mut existing_fields) = cipher.fields {
                for ef in existing_fields.iter_mut() {
                    // Decrypt the field name (non-sensitive metadata).
                    if let Some(dec_name) =
                        crypto::decrypt_to_string(ef.name.as_deref(), enc_key, mac_key)
                    {
                        if let Some(new_val) = fields.get(&dec_name) {
                            // Re-encrypt the new value; leave the encrypted name in place.
                            let enc_val = encrypt_to_cipher_string(new_val, enc_key, mac_key)
                                .with_context(|| {
                                    format!("encrypt value for field '{}'", dec_name)
                                })?;
                            ef.value = Some(enc_val);
                            handled.insert(dec_name);
                        }
                        // else: field not in request → leave entirely untouched
                    }
                }
            }

            // Append any brand-new fields not already present.
            let new_fields: Vec<EncryptedField> = fields
                .iter()
                .filter(|(k, _)| !handled.contains(*k))
                .map(|(k, v)| -> anyhow::Result<EncryptedField> {
                    let enc_name = encrypt_to_cipher_string(k, enc_key, mac_key)
                        .with_context(|| format!("encrypt field name '{}'", k))?;
                    let enc_val = encrypt_to_cipher_string(v, enc_key, mac_key)
                        .with_context(|| format!("encrypt field value for '{}'", k))?;
                    Ok(EncryptedField {
                        name: Some(enc_name),
                        value: Some(enc_val),
                        field_type: 1, // hidden
                    })
                })
                .collect::<anyhow::Result<Vec<_>>>()?;

            if !new_fields.is_empty() {
                cipher
                    .fields
                    .get_or_insert_with(Vec::new)
                    .extend(new_fields);
            }

            let cipher_id = cipher.id.clone();
            self.update_cipher(&cipher_id, &cipher).await?;
            if let Err(e) = self.sync().await {
                tracing::warn!("post-upsert(merge) sync failed: {}", e);
            }
            Ok(false)
        } else {
            // --- CREATE path --------------------------------------------------
            let enc_name =
                encrypt_to_cipher_string(name, enc_key, mac_key).context("encrypt item name")?;

            let enc_fields: Option<Vec<EncryptedField>> = if fields.is_empty() {
                None
            } else {
                let mut out = Vec::with_capacity(fields.len());
                for (k, v) in &fields {
                    let enc_fname = encrypt_to_cipher_string(k, enc_key, mac_key)
                        .with_context(|| format!("encrypt field name '{}'", k))?;
                    let enc_fval = encrypt_to_cipher_string(v, enc_key, mac_key)
                        .with_context(|| format!("encrypt field value for '{}'", k))?;
                    out.push(EncryptedField {
                        name: Some(enc_fname),
                        value: Some(enc_fval),
                        field_type: 1, // hidden
                    });
                }
                Some(out)
            };

            let cipher = EncryptedCipher {
                id: String::new(),
                name: enc_name,
                cipher_type: 1,
                login: Some(EncryptedLogin {
                    username: None,
                    password: None,
                    uris: None,
                    totp: None,
                }),
                card: None,
                identity: None,
                secure_note: None,
                fields: enc_fields,
                notes: None,
                organization_id: None,
                collection_ids: None,
                folder_id: Some(folder_id),
                revision_date: None,
                key: None,
                extra: None,
            };

            self.create_cipher(&cipher).await?;
            if let Err(e) = self.sync().await {
                tracing::warn!("post-upsert(create) sync failed: {}", e);
            }
            Ok(true)
        }
    }

    /// Private helper: find an item by decrypted name that belongs to `folder_id`.
    /// Returns a clone of the `EncryptedCipher` if found, `None` otherwise.
    async fn find_item_by_name_in_folder_id(
        &self,
        name: &str,
        folder_id: &str,
    ) -> Option<EncryptedCipher> {
        let items = self.items.read().await;
        items
            .values()
            .find(|(item_name, cipher)| {
                item_name.as_str() == name && cipher.folder_id.as_deref() == Some(folder_id)
            })
            .map(|(_, cipher)| cipher.clone())
    }

    /// Return decrypted custom field names for a given item.
    /// Returns an empty Vec if the item has no custom fields.
    ///
    /// Unlike `sync()`'s best-effort folder-name decrypt path (warn-and-skip),
    /// a decrypt failure here is fatal: the aggregator (connecterr_secrets)
    /// requires a complete field set to produce a valid secrets JSON, so
    /// returning partial data would silently corrupt connecterr's config.
    ///
    /// Async + `read().await` (vs `try_read`) avoids spurious "vault busy"
    /// errors when the aggregator races a concurrent `sync()` write lock.
    // iter-81: used by credential_audit/vw_adapter.rs (feature = "engine"). Dead in default builds.
    #[allow(dead_code)]
    pub async fn list_field_names(&self, item_name: &str) -> Result<Vec<String>> {
        let items = self.items.read().await;
        // Scan values (items are id-keyed now); first name match wins.
        let cipher = items
            .values()
            .find(|(n, _)| n.as_str() == item_name)
            .map(|(_, c)| c)
            .ok_or_else(|| anyhow!("item not found: {}", item_name))?;
        let Some(fields) = cipher.fields.as_ref() else {
            return Ok(Vec::new());
        };

        let mut names = Vec::with_capacity(fields.len());
        for f in fields {
            if let Some(enc_name) = &f.name {
                match decrypt_to_string(
                    Some(enc_name.as_str()),
                    self.enc_key.as_bytes(),
                    self.mac_key.as_bytes(),
                ) {
                    Some(dec) => names.push(dec),
                    None => {
                        return Err(anyhow!(
                            "failed to decrypt field name on item '{}'",
                            item_name
                        ));
                    }
                }
            }
        }
        Ok(names)
    }

    /// Decrypt all custom fields on `item_name` in a single pass over the
    /// cipher's field list, returning `(field_name, value_buffer)` pairs.
    ///
    /// This is the O(n) replacement for calling `list_field_names` followed by
    /// `decrypt_field` per name: the old pattern locked the items map twice and
    /// iterated the field list twice (once to collect names, once to find and
    /// decrypt each named field), giving O(n²) in field count per item.
    ///
    /// This method locks the items map once, iterates the field list once, and
    /// decrypts both name and value in the same loop — O(n) in fields.
    ///
    /// # Errors
    /// - Item not found in vault.
    /// - Any field's name or value fails to decrypt (hard error, matching
    ///   `list_field_names`'s fatal-on-failure contract).
    pub async fn list_field_pairs(&self, item_name: &str) -> Result<Vec<(String, SecureBuffer)>> {
        let items = self.items.read().await;
        let cipher = items
            .values()
            .find(|(n, _)| n.as_str() == item_name)
            .map(|(_, c)| c)
            .ok_or_else(|| anyhow!("item not found: {}", item_name))?;

        let Some(fields) = cipher.fields.as_ref() else {
            return Ok(Vec::new());
        };

        let mut pairs = Vec::with_capacity(fields.len());
        for f in fields {
            let enc_name = match &f.name {
                Some(n) => n.as_str(),
                None => continue, // unnamed field — skip
            };

            // Decrypt the field name.
            let field_name = decrypt_to_string(
                Some(enc_name),
                self.enc_key.as_bytes(),
                self.mac_key.as_bytes(),
            )
            .ok_or_else(|| anyhow!("failed to decrypt field name on item '{}'", item_name))?;

            // Decrypt the field value in the same pass.
            let value_cs = f
                .value
                .as_deref()
                .ok_or_else(|| anyhow!("field '{}' on '{}' has no value", field_name, item_name))?;

            let value_buf =
                decrypt_cipher_string(value_cs, self.enc_key.as_bytes(), self.mac_key.as_bytes())
                    .with_context(|| {
                    format!(
                        "failed to decrypt field '{}' on item '{}'",
                        field_name, item_name
                    )
                })?;

            pairs.push((field_name, value_buf));
        }
        Ok(pairs)
    }
}

// =========================================================================== //
// Test-only helpers                                                            //
// =========================================================================== //

#[cfg(any(test, feature = "test-utils"))]
impl VaultManager {
    /// Build a minimal stub `VaultManager` for use in unit and integration tests.
    ///
    /// The returned manager has:
    /// - No vault items (empty cipher/folder maps).
    /// - Dummy encryption keys (all-zero bytes — useless for real decryption,
    ///   but sufficient for handlers that don't call `decrypt_*`).
    /// - A fake URL so connectivity assertions pass without a live server.
    ///
    /// Issue (iter-29): integration tests need an `AppState` without a live
    /// Vaultwarden. Using this stub lets tests verify routing, 404 handling,
    /// and proxied request forwarding without a real vault dependency.
    pub fn new_stub() -> Self {
        VaultManager {
            vaultwarden_url: "http://localhost:0".to_string(),
            access_token: RwLock::new("test-access-token".to_string()),
            refresh_token: RwLock::new(None),
            token_expires_at: RwLock::new(None),
            reauth_mutex: Mutex::new(()),
            // Dummy keys — dec/enc operations will fail gracefully (no panic).
            enc_key: crate::secure::SecureBuffer::new(vec![0u8; 32]),
            mac_key: crate::secure::SecureBuffer::new(vec![0u8; 32]),
            items: RwLock::new(std::collections::HashMap::new()),
            folders: RwLock::new(FolderIndex::default()),
            all_folders: RwLock::new(Vec::new()),
            http: Client::new(),
        }
    }

    /// Build a stub `VaultManager` with caller-supplied encryption keys.
    ///
    /// Like `new_stub()` but with real (non-zero) keys, so tests that exercise
    /// the decryption path (e.g. `list_field_pairs`) can pre-encrypt test data
    /// with `crate::vault::crypto::encrypt_to_cipher_string` and then verify
    /// the round-trip through the vault.
    pub fn new_stub_with_keys(enc_key: Vec<u8>, mac_key: Vec<u8>) -> Self {
        VaultManager {
            vaultwarden_url: "http://localhost:0".to_string(),
            access_token: RwLock::new("test-access-token".to_string()),
            refresh_token: RwLock::new(None),
            token_expires_at: RwLock::new(None),
            reauth_mutex: Mutex::new(()),
            enc_key: crate::secure::SecureBuffer::new(enc_key),
            mac_key: crate::secure::SecureBuffer::new(mac_key),
            items: RwLock::new(std::collections::HashMap::new()),
            folders: RwLock::new(FolderIndex::default()),
            all_folders: RwLock::new(Vec::new()),
            http: Client::new(),
        }
    }

    /// Seed the stub vault with a cipher and a named folder.
    ///
    /// Only available in test builds. Allows integration tests to populate
    /// the in-memory vault without a live Vaultwarden connection, so that
    /// handlers that call `get_cipher_by_id` and `find_folder_id_by_name_async`
    /// return deterministic values rather than None/empty.
    ///
    /// `folder_id` and `folder_name` are inserted into the folder index.
    /// `cipher` is stored under its `cipher.id` key.
    #[cfg(test)]
    pub async fn seed_for_test(
        &self,
        folder_id: String,
        folder_name: String,
        cipher: crate::vault::types::EncryptedCipher,
    ) {
        // Insert folder into both the name→id index and all_folders list.
        let mut folders = self.folders.write().await;
        folders.insert(folder_id.clone(), folder_name.clone());
        drop(folders);

        let mut all_folders = self.all_folders.write().await;
        all_folders.push((folder_id, folder_name));
        drop(all_folders);

        // Insert cipher into the items map keyed by its id.
        let mut items = self.items.write().await;
        items.insert(cipher.id.clone(), (cipher.id.clone(), cipher));
    }

    /// Seed the stub vault with a named item (pre-decrypted name, raw cipher).
    ///
    /// Unlike `seed_for_test`, which stores `cipher.id` as the item name, this
    /// method stores an explicit `item_name` in the (name, cipher) tuple so
    /// that methods which look up items by name (e.g. `list_field_pairs`) find
    /// the correct entry. Use this variant when testing name-keyed lookups.
    pub async fn seed_item_by_name(
        &self,
        item_name: String,
        cipher: crate::vault::types::EncryptedCipher,
    ) {
        let mut items = self.items.write().await;
        items.insert(cipher.id.clone(), (item_name, cipher));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_find_item_id_by_name_returns_none_for_missing() {
        let vault = VaultManager::new_stub();
        let result = vault.find_item_id_by_name("nonexistent").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_find_item_id_by_name_returns_id_when_found() {
        let vault = VaultManager::new_stub();
        let cipher = crate::vault::types::EncryptedCipher {
            id: "abc-123".into(),
            name: "unifi/home-key".into(),
            cipher_type: 1,
            login: None,
            card: None,
            identity: None,
            secure_note: None,
            fields: None,
            notes: None,
            organization_id: None,
            collection_ids: None,
            folder_id: None,
            revision_date: None,
            key: None,
            extra: None,
        };
        vault
            .seed_item_by_name("unifi/home-key".into(), cipher)
            .await;

        let result = vault.find_item_id_by_name("unifi/home-key").await;
        assert_eq!(result.as_deref(), Some("abc-123"));
    }

    #[test]
    fn folder_index_resolves_name_to_id() {
        let mut idx = FolderIndex::default();
        idx.insert("folder-uuid-1".into(), "Connecterr".into());
        idx.insert("folder-uuid-2".into(), "Personal".into());

        assert_eq!(idx.find_id_by_name("Connecterr"), Some("folder-uuid-1"));
        assert_eq!(idx.find_id_by_name("Personal"), Some("folder-uuid-2"));
        assert_eq!(idx.find_id_by_name("Missing"), None);
    }

    #[test]
    fn folder_index_populated_from_sync_folders() {
        use crate::vault::types::SyncFolder;

        // Simulate the post-sync population step in isolation.
        let folders = [SyncFolder {
            id: "id-c".into(),
            name: "ENCRYPTED_NAME_PLACEHOLDER".into(),
            revision_date: None,
        }];

        // The real impl decrypts `name`. For this unit test we test the helper that
        // takes already-decrypted (id, name) pairs.
        let mut idx = FolderIndex::default();
        populate_folder_index(&mut idx, [("id-c".to_string(), "Connecterr".to_string())]);

        assert_eq!(idx.find_id_by_name("Connecterr"), Some("id-c"));
        assert_eq!(folders.len(), 1); // suppress unused-warning
    }

    #[test]
    fn list_items_in_folder_filters_by_folder_id() {
        use crate::vault::types::EncryptedCipher;

        let make_cipher = |name: &str, folder: Option<&str>| EncryptedCipher {
            id: format!("id-{}", name),
            name: name.to_string(),
            cipher_type: 1,
            login: None,
            card: None,
            identity: None,
            secure_note: None,
            fields: None,
            notes: None,
            organization_id: None,
            collection_ids: None,
            folder_id: folder.map(String::from),
            revision_date: None,
            key: None,
            extra: None,
        };

        let items = [
            ("apiKey".to_string(), make_cipher("apiKey", Some("id-c"))),
            (
                "unifi/home".to_string(),
                make_cipher("unifi/home", Some("id-c")),
            ),
            (
                "personal-thing".to_string(),
                make_cipher("personal-thing", Some("id-other")),
            ),
            ("orphan".to_string(), make_cipher("orphan", None)),
        ];

        let filtered: Vec<&str> = filter_items_by_folder(items.iter(), "id-c")
            .map(|(name, _)| name.as_str())
            .collect();

        assert_eq!(filtered, vec!["apiKey", "unifi/home"]);
    }

    #[test]
    fn list_field_names_returns_decrypted_names() {
        use crate::vault::types::{EncryptedCipher, EncryptedField};

        let cipher = EncryptedCipher {
            id: "id-1".into(),
            name: "any".into(),
            cipher_type: 1,
            login: None,
            card: None,
            identity: None,
            secure_note: None,
            // Plaintext names used here for the pure helper; real impl decrypts.
            fields: Some(vec![
                EncryptedField {
                    name: Some("apiKey".into()),
                    value: Some("v".into()),
                    field_type: 1,
                },
                EncryptedField {
                    name: Some("password".into()),
                    value: Some("v".into()),
                    field_type: 1,
                },
                EncryptedField {
                    name: None,
                    value: Some("v".into()),
                    field_type: 1,
                },
            ]),
            notes: None,
            organization_id: None,
            collection_ids: None,
            folder_id: None,
            revision_date: None,
            key: None,
            extra: None,
        };

        let names = field_names_from_cipher(&cipher);
        assert_eq!(names, vec!["apiKey", "password"]);
    }

    // ---------------------------------------------------------------------- //
    // list_field_pairs tests (iter-49)                                        //
    // ---------------------------------------------------------------------- //

    /// `list_field_pairs` returns `Err` when the named item is not in the vault.
    /// Verifies the "item not found" error path without needing real cipher data.
    #[tokio::test]
    async fn list_field_pairs_returns_err_for_missing_item() {
        let vault = VaultManager::new_stub();
        let err = vault
            .list_field_pairs("nonexistent-item")
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("item not found"),
            "expected 'item not found' error, got: {err}"
        );
    }

    /// `list_field_pairs` returns `Ok(Vec::new())` when the item exists but
    /// has no custom fields (`cipher.fields == None`).
    #[tokio::test]
    async fn list_field_pairs_returns_empty_for_item_with_no_fields() {
        use crate::vault::types::EncryptedCipher;

        let vault = VaultManager::new_stub();
        let cipher = EncryptedCipher {
            id: "id-nf".into(),
            name: "item-no-fields".into(),
            cipher_type: 1,
            login: None,
            card: None,
            identity: None,
            secure_note: None,
            fields: None, // explicitly absent
            notes: None,
            organization_id: None,
            collection_ids: None,
            folder_id: None,
            revision_date: None,
            key: None,
            extra: None,
        };
        vault
            .seed_item_by_name("item-no-fields".into(), cipher)
            .await;

        let pairs = vault.list_field_pairs("item-no-fields").await.unwrap();
        assert!(
            pairs.is_empty(),
            "item with fields:None should return empty pairs"
        );
    }

    /// `list_field_pairs` decrypts field names and values and returns them as
    /// `(String, SecureBuffer)` pairs, skipping unnamed fields.
    ///
    /// The test uses `VaultManager::new_stub_with_keys` so the vault holds
    /// known enc/mac keys, and `encrypt_to_cipher_string` to pre-encrypt the
    /// test data — validating the full round-trip through the AES-256-CBC +
    /// HMAC-SHA256 crypto layer.
    #[tokio::test]
    async fn list_field_pairs_decrypts_field_name_and_value() {
        use crate::vault::crypto::encrypt_to_cipher_string;
        use crate::vault::types::{EncryptedCipher, EncryptedField};

        // Use distinct, non-zero test keys.
        let enc_key: Vec<u8> = (1u8..=32).collect();
        let mac_key: Vec<u8> = (33u8..=64).collect();

        let vault = VaultManager::new_stub_with_keys(enc_key.clone(), mac_key.clone());

        // Encrypt the field name and value with the same keys the vault holds.
        let enc_name = encrypt_to_cipher_string("apiKey", &enc_key, &mac_key).unwrap();
        let enc_value = encrypt_to_cipher_string("super-secret-123", &enc_key, &mac_key).unwrap();

        let cipher = EncryptedCipher {
            id: "id-fp".into(),
            name: "item-with-fields".into(), // raw; not decrypted by seed helper
            cipher_type: 1,
            login: None,
            card: None,
            identity: None,
            secure_note: None,
            fields: Some(vec![
                EncryptedField {
                    name: Some(enc_name),
                    value: Some(enc_value),
                    field_type: 1,
                },
                // Unnamed field — must be skipped.
                EncryptedField {
                    name: None,
                    value: Some("v".into()),
                    field_type: 1,
                },
            ]),
            notes: None,
            organization_id: None,
            collection_ids: None,
            folder_id: None,
            revision_date: None,
            key: None,
            extra: None,
        };
        vault
            .seed_item_by_name("item-with-fields".into(), cipher)
            .await;

        let pairs = vault.list_field_pairs("item-with-fields").await.unwrap();

        assert_eq!(pairs.len(), 1, "only the named field should be returned");
        let (name, value_buf) = &pairs[0];
        assert_eq!(name, "apiKey");
        assert_eq!(
            std::str::from_utf8(value_buf.as_bytes()).unwrap(),
            "super-secret-123"
        );
    }

    #[tokio::test]
    async fn create_login_item_returns_id() {
        let vault = VaultManager::new_stub();
        let id = vault
            .create_login_item(
                "Test Service",
                Some("user@example.com"),
                "s3cret!",
                vec!["https://example.com".to_string()],
                None,
            )
            .await;
        // stub has no HTTP; expect an error (the method exists and compiles)
        assert!(id.is_err());
    }

    #[tokio::test]
    async fn update_login_item_fields_id_not_found() {
        let vault = VaultManager::new_stub();
        let result = vault
            .update_login_item_fields("nonexistent-id", None, None, Some("newpass"))
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_uri_field_returns_not_found_not_unsupported() {
        let vault = VaultManager::new_stub();
        let result = vault.get_field_by_item_name("nonexistent", "uri").await;
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("not found"),
            "expected 'not found' error, got: {}",
            err
        );
        assert!(
            !err.contains("unsupported field"),
            "should not hit unsupported arm, got: {}",
            err
        );
    }
}
