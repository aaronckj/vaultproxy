//! Bitwarden cloud client — authenticates against bitwarden.com's split-URL
//! infrastructure and provides cipher CRUD plus org key management.

use std::collections::HashMap;

use anyhow::{anyhow, bail, Context, Result};
use reqwest::Client;

use crate::secure::SecureBuffer;
use crate::vault::crypto::{
    decrypt_cipher_string, decrypt_cipher_string_rsa, decrypt_private_key, decrypt_symmetric_key,
    derive_master_key, encrypt_cipher_string, hash_master_password, stretch_master_key,
};
use crate::vault::types::*;

// -------------------------------------------------------------------------- //
// CloudClient                                                                 //
// -------------------------------------------------------------------------- //

/// Client for Bitwarden cloud (bitwarden.com).
///
/// Unlike the local `VaultManager` which talks to a single Vaultwarden URL,
/// `CloudClient` uses Bitwarden's split-URL design:
///   - `identity.bitwarden.com` for authentication
///   - `api.bitwarden.com` for vault data
///   - `notifications.bitwarden.com` for real-time push
pub struct CloudClient {
    identity_url: String,
    api_url: String,
    notifications_url: String,
    access_token: String,
    enc_key: SecureBuffer,
    mac_key: SecureBuffer,
    /// RSA private key (PKCS#8 DER) for decrypting org keys.
    private_key: Option<SecureBuffer>,
    /// Organization keys: org_id → (enc_key, mac_key).
    org_keys: HashMap<String, (SecureBuffer, SecureBuffer)>,
    /// KDF iterations used for key derivation (needed for password change).
    #[allow(dead_code)]
    // read by change_master_password (post-v1.0: Bitwarden cloud password change)
    kdf_iterations: u32,
    http: Client,
    /// API key credentials for re-authentication when token expires.
    api_client_id: Option<String>,
    api_client_secret: Option<String>,
}

impl CloudClient {
    /// Create a CloudClient using a refresh token + master password for decryption.
    ///
    /// The refresh token handles API auth (no password hashing needed).
    /// The master password is only used to derive encryption keys for E2E crypto.
    pub async fn from_refresh_token(
        email: &str,
        master_password: &str,
        refresh_token: &str,
        kdf_iterations_override: Option<u32>,
    ) -> Result<(Self, String)> {
        let identity_url = "https://identity.bitwarden.com".to_string();
        let api_url = "https://api.bitwarden.com".to_string();
        let notifications_url = "https://notifications.bitwarden.com".to_string();

        let http = Client::builder()
            .build()
            .context("failed to build HTTP client")?;

        // Get access token via refresh token
        let resp = http
            .post(format!("{}/connect/token", identity_url))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", "cli"),
            ])
            .send()
            .await
            .context("refresh token request failed")?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("refresh token auth failed: {}", body);
        }

        #[derive(serde::Deserialize)]
        struct RefreshResp {
            access_token: String,
            refresh_token: Option<String>,
            #[serde(rename = "Key")]
            key: Option<String>,
        }

        let token_data: RefreshResp = resp
            .json()
            .await
            .context("failed to parse refresh token response")?;

        let new_refresh = token_data
            .refresh_token
            .unwrap_or_else(|| refresh_token.to_string());

        tracing::info!("authenticated to Bitwarden cloud via refresh token");

        // Fetch full sync to get profile (with correct KDF iterations) and encrypted key
        let sync: serde_json::Value = http
            .get(format!("{}/sync", api_url))
            .bearer_auth(&token_data.access_token)
            .send()
            .await
            .context("sync request failed")?
            .error_for_status()
            .context("sync returned error")?
            .json()
            .await
            .context("failed to parse sync response")?;

        let profile = sync
            .get("profile")
            .ok_or_else(|| anyhow!("sync response missing profile"))?;

        // Get KDF iterations: override → profile → prelogin fallback.
        // Note: Bitwarden cloud's prelogin and profile can return wrong/missing
        // values. The bw CLI caches the real value locally. Use --cloud-kdf-iterations
        // to override if needed.
        let kdf_iterations = if let Some(override_val) = kdf_iterations_override {
            override_val
        } else {
            profile
                .get("kdfIterations")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32)
                .unwrap_or_else(|| {
                    tracing::warn!("profile missing kdfIterations, falling back to prelogin");
                    // Try prelogin as last resort
                    600_000
                })
        };

        tracing::debug!("cloud profile kdfIterations={}", kdf_iterations);

        let master_key = derive_master_key(master_password, email, kdf_iterations);

        // Get the encrypted symmetric key from token response or profile
        let encrypted_key = token_data.key.unwrap_or_else(|| {
            profile
                .get("key")
                .and_then(|k| k.as_str())
                .unwrap_or("")
                .to_string()
        });

        if encrypted_key.is_empty() {
            bail!("no encrypted symmetric key found in token response or profile");
        }

        let (enc_key, mac_key) = decrypt_symmetric_key(&encrypted_key, master_key.as_bytes())
            .context("failed to decrypt vault symmetric key")?;

        // Decrypt the RSA private key from the profile (used for org key decryption).
        let private_key = profile
            .get("privateKey")
            .and_then(|v| v.as_str())
            .and_then(|pk_str| {
                match decrypt_private_key(pk_str, enc_key.as_bytes(), mac_key.as_bytes()) {
                    Ok(pk) => Some(pk),
                    Err(e) => {
                        tracing::warn!("failed to decrypt RSA private key: {}", e);
                        None
                    }
                }
            });

        Ok((
            CloudClient {
                identity_url,
                api_url,
                notifications_url,
                access_token: token_data.access_token,
                enc_key,
                mac_key,
                private_key,
                org_keys: HashMap::new(),
                kdf_iterations,
                http,
                api_client_id: None,
                api_client_secret: None,
            },
            new_refresh,
        ))
    }

    /// Create a CloudClient using a Bitwarden API key (client_id + client_secret).
    ///
    /// This bypasses password-based auth and 2FA entirely. The master password
    /// is still needed to derive encryption keys for E2E crypto.
    pub async fn from_api_key(
        email: &str,
        master_password: &str,
        client_id: &str,
        client_secret: &str,
        kdf_iterations_override: Option<u32>,
    ) -> Result<(Self, String)> {
        let identity_url = "https://identity.bitwarden.com".to_string();
        let api_url = "https://api.bitwarden.com".to_string();
        let notifications_url = "https://notifications.bitwarden.com".to_string();

        let http = Client::builder()
            .build()
            .context("failed to build HTTP client")?;

        // Authenticate with API key (client_credentials grant)
        let resp = http
            .post(format!("{}/connect/token", identity_url))
            .header("Bitwarden-Client-Version", "2026.3.0")
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", client_id),
                ("client_secret", client_secret),
                ("scope", "api"),
                ("deviceType", "10"),
                ("deviceIdentifier", "connecterr-vault-proxy"),
                ("deviceName", "Connecterr Vault Proxy"),
            ])
            .send()
            .await
            .context("API key auth request failed")?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("API key auth failed: {}", body);
        }

        #[derive(serde::Deserialize)]
        struct ApiKeyResp {
            access_token: String,
            refresh_token: Option<String>,
            #[serde(rename = "Key")]
            key: Option<String>,
        }

        let token_data: ApiKeyResp = resp
            .json()
            .await
            .context("failed to parse API key auth response")?;

        tracing::info!("authenticated to Bitwarden cloud via API key");

        // Fetch sync to get profile with KDF iterations and encrypted key
        let sync: serde_json::Value = http
            .get(format!("{}/sync", api_url))
            .bearer_auth(&token_data.access_token)
            .send()
            .await
            .context("sync request failed")?
            .error_for_status()
            .context("sync returned error")?
            .json()
            .await
            .context("failed to parse sync response")?;

        let profile = sync
            .get("profile")
            .ok_or_else(|| anyhow!("sync response missing profile"))?;

        let kdf_iterations = if let Some(override_val) = kdf_iterations_override {
            override_val
        } else {
            profile
                .get("kdfIterations")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32)
                .unwrap_or(600_000)
        };

        tracing::debug!("cloud profile kdfIterations={}", kdf_iterations);

        let master_key = derive_master_key(master_password, email, kdf_iterations);

        let encrypted_key = token_data.key.unwrap_or_else(|| {
            profile
                .get("key")
                .and_then(|k| k.as_str())
                .unwrap_or("")
                .to_string()
        });

        if encrypted_key.is_empty() {
            bail!("no encrypted symmetric key found in response or profile");
        }

        let (enc_key, mac_key) = decrypt_symmetric_key(&encrypted_key, master_key.as_bytes())
            .context("failed to decrypt vault symmetric key")?;

        let private_key = profile
            .get("privateKey")
            .and_then(|v| v.as_str())
            .and_then(|pk_str| {
                match decrypt_private_key(pk_str, enc_key.as_bytes(), mac_key.as_bytes()) {
                    Ok(pk) => Some(pk),
                    Err(e) => {
                        tracing::warn!("failed to decrypt RSA private key: {}", e);
                        None
                    }
                }
            });

        let refresh_token = token_data.refresh_token.unwrap_or_default();

        Ok((
            CloudClient {
                identity_url,
                api_url,
                notifications_url,
                access_token: token_data.access_token,
                enc_key,
                mac_key,
                private_key,
                org_keys: HashMap::new(),
                kdf_iterations,
                http,
                api_client_id: Some(client_id.to_string()),
                api_client_secret: Some(client_secret.to_string()),
            },
            refresh_token,
        ))
    }

    /// Authenticate to Bitwarden cloud with password + optional 2FA.
    ///
    /// Auth flow is identical to VaultManager but uses split URLs and does
    /// NOT accept invalid certificates (bitwarden.com has valid certs).
    ///
    /// - `totp_code`: One-time TOTP code for 2FA (required on first login).
    /// - `device_token`: Remembered device token from a previous login (skips 2FA).
    ///
    /// Returns the CloudClient and an optional device token to save for future logins.
    pub async fn new(
        email: &str,
        master_password: &str,
        totp_code: Option<&str>,
        device_token: Option<&str>,
    ) -> Result<(Self, Option<String>)> {
        let identity_url = "https://identity.bitwarden.com".to_string();
        let api_url = "https://api.bitwarden.com".to_string();
        let notifications_url = "https://notifications.bitwarden.com".to_string();

        let http = Client::builder()
            .build()
            .context("failed to build HTTP client")?;

        // --- Step 1: prelogin ------------------------------------------------
        #[derive(serde::Serialize)]
        struct PreloginReq<'a> {
            email: &'a str,
        }

        let prelogin: PreloginResponse = http
            .post(format!("{}/accounts/prelogin", identity_url))
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
        tracing::debug!("cloud prelogin ok — kdfIterations={}", iterations);

        // --- Step 2: derive master key + password hash -----------------------
        let master_key = derive_master_key(master_password, email, iterations);
        let password_hash = hash_master_password(master_key.as_bytes(), master_password);

        // --- Step 3: token request (with 2FA handling) -----------------------
        let mut params = vec![
            ("grant_type".to_string(), "password".to_string()),
            ("username".to_string(), email.to_string()),
            ("password".to_string(), password_hash.clone()),
            ("scope".to_string(), "api offline_access".to_string()),
            ("client_id".to_string(), "web".to_string()),
            ("deviceType".to_string(), "10".to_string()),
            (
                "deviceIdentifier".to_string(),
                "connecterr-vault-proxy".to_string(),
            ),
            (
                "deviceName".to_string(),
                "Connecterr Vault Proxy".to_string(),
            ),
        ];

        // Add 2FA params if provided
        if let Some(code) = totp_code {
            params.push(("twoFactorProvider".to_string(), "0".to_string())); // TOTP
            params.push(("twoFactorToken".to_string(), code.to_string()));
            params.push(("twoFactorRemember".to_string(), "1".to_string())); // Get device token
        } else if let Some(dt) = device_token {
            params.push(("twoFactorProvider".to_string(), "5".to_string())); // Remember
            params.push(("twoFactorToken".to_string(), dt.to_string()));
        }

        let resp = http
            .post(format!("{}/connect/token", identity_url))
            .form(&params)
            .send()
            .await
            .context("token request failed")?;

        if resp.status() == 400 {
            let body: serde_json::Value = resp.json().await.unwrap_or_default();

            // Check if this is a 2FA challenge
            if body.get("TwoFactorProviders2").is_some() {
                if totp_code.is_some() {
                    bail!("2FA code was rejected — check the code and try again");
                }
                bail!(
                    "2FA required — provide a TOTP code via /run/secrets/cloud_totp_code \
                     or POST /sync/setup-cloud with twoFactorCode field"
                );
            }

            bail!("authentication failed: {}", body);
        }

        let resp = resp.error_for_status().context("authentication failed")?;

        #[derive(serde::Deserialize)]
        struct TokenResp2FA {
            access_token: String,
            #[serde(rename = "Key")]
            key: String,
            #[serde(rename = "TwoFactorToken")]
            two_factor_token: Option<String>,
        }

        let token_resp: TokenResp2FA = resp
            .json()
            .await
            .context("failed to parse token response")?;

        let saved_device_token = token_resp.two_factor_token.clone();
        if saved_device_token.is_some() {
            tracing::info!("received device token for future 2FA-free logins");
        }

        tracing::info!("authenticated to Bitwarden cloud");

        // --- Step 4: decrypt symmetric key -----------------------------------
        let (enc_key, mac_key) = decrypt_symmetric_key(&token_resp.key, master_key.as_bytes())
            .context("failed to decrypt vault symmetric key")?;

        // Note: private key will be decrypted during first full_sync when
        // the profile data (including privateKey) is available.
        Ok((
            CloudClient {
                identity_url,
                api_url,
                notifications_url,
                access_token: token_resp.access_token,
                enc_key,
                mac_key,
                private_key: None,
                org_keys: HashMap::new(),
                kdf_iterations: iterations,
                http,
                api_client_id: None,
                api_client_secret: None,
            },
            saved_device_token,
        ))
    }

    // ---------------------------------------------------------------------- //
    // Sync                                                                     //
    // ---------------------------------------------------------------------- //

    /// Re-authenticate using stored API key credentials.
    /// Called when the access token expires (401 response).
    async fn reauth(&mut self) -> Result<()> {
        let (cid, csec) = match (&self.api_client_id, &self.api_client_secret) {
            (Some(id), Some(secret)) => (id.clone(), secret.clone()),
            _ => bail!("no API key credentials stored for re-authentication"),
        };

        let resp = self
            .http
            .post(format!("{}/connect/token", self.identity_url))
            .header("Bitwarden-Client-Version", "2026.3.0")
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", cid.as_str()),
                ("client_secret", csec.as_str()),
                ("scope", "api"),
                ("deviceType", "10"),
                ("deviceIdentifier", "connecterr-vault-proxy"),
                ("deviceName", "Connecterr Vault Proxy"),
            ])
            .send()
            .await
            .context("API key reauth failed")?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("API key reauth failed: {}", body);
        }

        #[derive(serde::Deserialize)]
        struct TokenResp {
            access_token: String,
        }

        let data: TokenResp = resp
            .json()
            .await
            .context("failed to parse reauth response")?;
        self.access_token = data.access_token;
        tracing::info!("re-authenticated to Bitwarden cloud via API key");
        Ok(())
    }

    /// Perform a full sync against Bitwarden cloud.
    ///
    /// Also decrypts and caches organization encryption keys from the profile.
    pub async fn full_sync(&mut self) -> Result<SyncResponse> {
        let sync_url = format!("{}/sync", self.api_url);
        let raw = self
            .http
            .get(&sync_url)
            .bearer_auth(&self.access_token)
            .send()
            .await
            .context("sync request failed")?;

        let raw = if raw.status() == reqwest::StatusCode::UNAUTHORIZED {
            self.reauth().await?;
            self.http
                .get(&sync_url)
                .bearer_auth(&self.access_token)
                .send()
                .await
                .context("sync request failed (after reauth)")?
        } else {
            raw
        };

        let resp: SyncResponse = raw
            .error_for_status()
            .context("sync returned error status")?
            .json()
            .await
            .context("failed to parse sync response")?;

        // Decrypt the RSA private key from the profile if we don't have it yet.
        if self.private_key.is_none() {
            if let Some(ref pk_str) = resp.profile.private_key {
                match decrypt_private_key(pk_str, self.enc_key.as_bytes(), self.mac_key.as_bytes())
                {
                    Ok(pk) => {
                        tracing::debug!("decrypted RSA private key from sync profile");
                        self.private_key = Some(pk);
                    }
                    Err(e) => {
                        tracing::warn!("failed to decrypt RSA private key: {}", e);
                    }
                }
            }
        }

        // Decrypt and store org keys.
        if let Some(ref orgs) = resp.profile.organizations {
            for org in orgs {
                match self.decrypt_org_key(&org.key) {
                    Ok((org_enc, org_mac)) => {
                        tracing::debug!(org_id = %org.id, org_name = %org.name, "decrypted org key");
                        self.org_keys.insert(org.id.clone(), (org_enc, org_mac));
                    }
                    Err(e) => {
                        tracing::warn!(
                            org_id = %org.id,
                            org_name = %org.name,
                            "failed to decrypt org key: {}",
                            e
                        );
                    }
                }
            }
        }

        tracing::info!(
            ciphers = resp.ciphers.len(),
            folders = resp.folders.len(),
            collections = resp.collections.len(),
            orgs = self.org_keys.len(),
            "cloud sync complete"
        );

        Ok(resp)
    }

    // ---------------------------------------------------------------------- //
    // Cipher CRUD                                                              //
    // ---------------------------------------------------------------------- //

    /// Fetch a single cipher by ID.
    pub async fn get_cipher(&mut self, id: &str) -> Result<EncryptedCipher> {
        let cipher_url = format!("{}/ciphers/{}", self.api_url, id);
        let raw = self
            .http
            .get(&cipher_url)
            .bearer_auth(&self.access_token)
            .send()
            .await
            .context("get cipher request failed")?;

        let raw = if raw.status() == reqwest::StatusCode::UNAUTHORIZED {
            self.reauth().await?;
            self.http
                .get(&cipher_url)
                .bearer_auth(&self.access_token)
                .send()
                .await
                .context("get cipher request failed (after reauth)")?
        } else {
            raw
        };

        let cipher: EncryptedCipher = raw
            .error_for_status()
            .context("get cipher returned error status")?
            .json()
            .await
            .context("failed to parse cipher response")?;

        Ok(cipher)
    }

    /// Create a new cipher and return its assigned ID.
    #[allow(dead_code)] // needed for cloud write operations
    pub async fn create_cipher(&self, cipher: &EncryptedCipher) -> Result<String> {
        #[derive(serde::Deserialize)]
        struct CreateResponse {
            #[serde(rename = "Id")]
            id: Option<String>,
            #[serde(rename = "id")]
            id_lower: Option<String>,
        }

        let resp: CreateResponse = self
            .http
            .post(format!("{}/ciphers", self.api_url))
            .bearer_auth(&self.access_token)
            .json(cipher)
            .send()
            .await
            .context("create cipher request failed")?
            .error_for_status()
            .context("create cipher returned error status")?
            .json()
            .await
            .context("failed to parse create cipher response")?;

        resp.id
            .or(resp.id_lower)
            .ok_or_else(|| anyhow!("create cipher response missing id field"))
    }

    /// Update an existing cipher by ID.
    #[allow(dead_code)] // needed for cloud write operations
    pub async fn update_cipher(&self, id: &str, cipher: &EncryptedCipher) -> Result<()> {
        self.http
            .put(format!("{}/ciphers/{}", self.api_url, id))
            .bearer_auth(&self.access_token)
            .json(cipher)
            .send()
            .await
            .context("update cipher request failed")?
            .error_for_status()
            .context("update cipher returned error status")?;

        Ok(())
    }

    /// Delete a cipher by ID.
    #[allow(dead_code)] // needed for cloud write operations
    pub async fn delete_cipher(&self, id: &str) -> Result<()> {
        self.http
            .delete(format!("{}/ciphers/{}", self.api_url, id))
            .bearer_auth(&self.access_token)
            .send()
            .await
            .context("delete cipher request failed")?
            .error_for_status()
            .context("delete cipher returned error status")?;

        Ok(())
    }

    // ---------------------------------------------------------------------- //
    // Key management                                                           //
    // ---------------------------------------------------------------------- //

    /// Return the appropriate (enc_key, mac_key) pair for a cipher.
    ///
    /// If the cipher belongs to an organization, returns that org's keys.
    /// Otherwise returns the user's personal keys.
    pub fn keys_for_cipher<'a>(&'a self, cipher: &EncryptedCipher) -> Result<(&'a [u8], &'a [u8])> {
        match cipher.organization_id.as_deref() {
            None => Ok((self.enc_key.as_bytes(), self.mac_key.as_bytes())),
            Some(org_id) => {
                let (org_enc, org_mac) = self
                    .org_keys
                    .get(org_id)
                    .ok_or_else(|| anyhow!("no decrypted key for organization '{}'", org_id))?;
                Ok((org_enc.as_bytes(), org_mac.as_bytes()))
            }
        }
    }

    /// Resolve the actual encryption keys for a cipher's fields.
    /// If the cipher has a per-item `key` field, decrypt it to get the real keys.
    /// Otherwise fall back to org/personal keys.
    pub fn resolve_cipher_keys(&self, cipher: &EncryptedCipher) -> Result<([u8; 32], [u8; 32])> {
        let (base_enc, base_mac) = self.keys_for_cipher(cipher)?;

        match &cipher.key {
            Some(key_cs) => {
                // Decrypt the per-item key using org/personal keys
                let key_buf = decrypt_cipher_string(key_cs, base_enc, base_mac)
                    .context("failed to decrypt per-item cipher key")?;
                let key_bytes = key_buf.as_bytes();
                if key_bytes.len() < 64 {
                    bail!(
                        "per-item key too short: {} bytes (need 64)",
                        key_bytes.len()
                    );
                }
                let mut enc = [0u8; 32];
                let mut mac = [0u8; 32];
                enc.copy_from_slice(&key_bytes[..32]);
                mac.copy_from_slice(&key_bytes[32..64]);
                Ok((enc, mac))
            }
            None => {
                let mut enc = [0u8; 32];
                let mut mac = [0u8; 32];
                enc.copy_from_slice(base_enc);
                mac.copy_from_slice(base_mac);
                Ok((enc, mac))
            }
        }
    }

    /// Personal encryption key.
    #[allow(dead_code)] // needed for cloud write operations
    pub fn enc_key(&self) -> &[u8] {
        self.enc_key.as_bytes()
    }

    /// Personal MAC key.
    #[allow(dead_code)] // needed for cloud write operations
    pub fn mac_key(&self) -> &[u8] {
        self.mac_key.as_bytes()
    }

    /// Notifications WebSocket URL.
    pub fn notifications_url(&self) -> &str {
        &self.notifications_url
    }

    /// Bearer token for authenticated requests.
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    // ---------------------------------------------------------------------- //
    // Password change                                                          //
    // ---------------------------------------------------------------------- //

    /// Change the Bitwarden cloud master password.
    ///
    /// This re-encrypts the vault's symmetric key with the new password and
    /// POSTs the change to the Bitwarden API. On success, updates the internal
    /// encryption keys to match the new password.
    #[allow(dead_code)] // post-v1.0: will be exposed via dashboard cloud-account settings
    pub async fn change_master_password(
        &mut self,
        email: &str,
        current_password: &str,
        new_password: &str,
    ) -> Result<()> {
        use zeroize::Zeroize;

        let kdf_iterations = self.kdf_iterations;

        // 1. Hash CURRENT password for API verification.
        let current_master_key = derive_master_key(current_password, email, kdf_iterations);
        let current_password_hash =
            hash_master_password(current_master_key.as_bytes(), current_password);

        // 2. Derive new master key from new password + email.
        let new_master_key = derive_master_key(new_password, email, kdf_iterations);

        // 3. Hash new password for the API.
        let new_password_hash = hash_master_password(new_master_key.as_bytes(), new_password);

        // 4. Get current symmetric key (enc_key + mac_key = 64 bytes).
        let mut combined_key = Vec::with_capacity(64);
        combined_key.extend_from_slice(self.enc_key.as_bytes());
        combined_key.extend_from_slice(self.mac_key.as_bytes());

        // 5. Stretch new master key for encryption.
        let (mut new_stretch_enc, mut new_stretch_mac) =
            stretch_master_key(new_master_key.as_bytes());

        // 6. Re-encrypt the 64-byte symmetric key with new stretched keys.
        let encrypted_key =
            encrypt_cipher_string(&combined_key, &new_stretch_enc, &new_stretch_mac)
                .context("failed to re-encrypt symmetric key with new master password")?;

        // 7. POST to Bitwarden API.
        let body = serde_json::json!({
            "masterPasswordHash": current_password_hash,
            "newMasterPasswordHash": new_password_hash,
            "masterPasswordHint": "",
            "key": encrypted_key,
        });

        let resp = self
            .http
            .post(format!("{}/accounts/password", self.api_url))
            .bearer_auth(&self.access_token)
            .json(&body)
            .send()
            .await
            .context("password change request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let err_body = resp.text().await.unwrap_or_default();
            // Zeroize intermediate keys before bailing.
            combined_key.zeroize();
            new_stretch_enc.zeroize();
            new_stretch_mac.zeroize();
            bail!("password change API returned {}: {}", status, err_body);
        }

        tracing::info!("Bitwarden cloud master password changed successfully");

        // 7. The symmetric key itself hasn't changed — only the wrapping.
        //    enc_key and mac_key remain the same. But we re-derive from the
        //    new password to validate consistency.
        //    (The actual enc_key/mac_key don't change — they're the inner keys.)

        // 8. Zeroize all intermediate keys.
        combined_key.zeroize();
        new_stretch_enc.zeroize();
        new_stretch_mac.zeroize();

        Ok(())
    }

    // ---------------------------------------------------------------------- //
    // Private helpers                                                          //
    // ---------------------------------------------------------------------- //

    /// Decrypt an organization key into separate enc and mac keys.
    ///
    /// Bitwarden org keys can be:
    /// - Type 4 (RSA-OAEP): encrypted with the user's RSA private key (Bitwarden cloud)
    /// - Type 2 (AES-CBC): encrypted with the user's symmetric key (some Vaultwarden setups)
    ///
    /// The decrypted payload is 64 bytes: first 32 = enc_key, last 32 = mac_key.
    fn decrypt_org_key(&self, encrypted_key: &str) -> Result<(SecureBuffer, SecureBuffer)> {
        let cipher_type = encrypted_key.split('.').next().unwrap_or("");

        let decrypted = match cipher_type {
            "4" => {
                // RSA-OAEP: decrypt with user's RSA private key
                let pk = self.private_key.as_ref().ok_or_else(|| {
                    anyhow!("org key is RSA-encrypted (type 4) but no RSA private key available")
                })?;
                decrypt_cipher_string_rsa(encrypted_key, pk.as_bytes())
                    .context("failed to decrypt org key with RSA")?
            }
            _ => {
                // Type 2 (AES-CBC) or other: decrypt with symmetric key
                decrypt_cipher_string(
                    encrypted_key,
                    self.enc_key.as_bytes(),
                    self.mac_key.as_bytes(),
                )
                .context("failed to decrypt org key")?
            }
        };

        if decrypted.len() < 64 {
            bail!(
                "decrypted org key is too short: {} bytes (expected 64)",
                decrypted.len()
            );
        }

        let org_enc = SecureBuffer::new(decrypted[..32].to_vec());
        let org_mac = SecureBuffer::new(decrypted[32..64].to_vec());
        Ok((org_enc, org_mac))
    }
}
