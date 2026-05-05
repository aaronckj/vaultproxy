use crate::credential_audit::engine_client::EngineInputItem;
use crate::credential_audit::vault_adapter::{VaultAdapter, VaultItemSecrets};
use crate::vault::VaultManager;
use anyhow::Result;
use async_trait::async_trait;
use secrecy::SecretString;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use url::Url;

pub struct VwAdapter {
    vault: Arc<VaultManager>,
}

impl VwAdapter {
    pub fn new(vault: Arc<VaultManager>) -> Self {
        Self { vault }
    }

    fn host_of(uri: &str) -> Option<String> {
        Url::parse(uri).ok().and_then(|p| p.host_str().map(String::from))
    }
}

#[async_trait]
impl VaultAdapter for VwAdapter {
    async fn list_items_metadata(&self) -> Result<Vec<EngineInputItem>> {
        let masked = self.vault.list_items().await;
        let mut out = Vec::with_capacity(masked.len());
        for item in masked {
            // Try to fetch decrypted notes excerpt + custom field names by NAME.
            let notes_excerpt = self
                .vault
                .decrypt_notes(&item.name)
                .ok()
                .flatten()
                .and_then(|sb| sb.as_str().ok().map(|s| s.chars().take(200).collect::<String>()));
            let custom_field_names = self
                .vault
                .list_field_names(&item.name)
                .await
                .unwrap_or_default();
            // has_password: try decrypt_credentials_by_id and check if it succeeds.
            let has_password = self.vault.decrypt_credentials_by_id(&item.id).await.is_ok();
            let has_totp = self
                .vault
                .decrypt_totp(&item.name)
                .ok()
                .flatten()
                .is_some();
            out.push(EngineInputItem {
                id: item.id,
                name: item.name,
                url: item.uris.first().cloned(),
                folder: item.folder_id,
                item_type: item.item_type,
                custom_field_names,
                has_password,
                has_totp,
                has_ssh_key: false,  // VaultManager doesn't distinguish ssh items
                has_attachments: false,  // not exposed by MaskedItem
                notes_excerpt,
            });
        }
        Ok(out)
    }

    async fn item_secrets(&self, item_id: &str) -> Result<VaultItemSecrets> {
        // Need item name to fetch totp (decrypt_totp is by name).
        let masked = self.vault.list_items().await;
        let item_name = masked
            .iter()
            .find(|i| i.id == item_id)
            .map(|i| i.name.clone());

        // Decrypt password — keep raw string so we can build two SecretStrings from it
        // (password + api_key_value). SecretString wraps a Box<str> and doesn't impl Clone.
        let pw_plaintext: Option<String> = self
            .vault
            .decrypt_credentials_by_id(item_id)
            .await
            .ok()
            .and_then(|(_, pw)| pw.as_str().ok().map(|s| s.to_string()));

        let password = pw_plaintext.as_deref().map(SecretString::from);
        // For api_key items, the password field IS the api key.
        // The engine decides whether to use it based on the LLM-classified category.
        let api_key_value = pw_plaintext.as_deref().map(SecretString::from);

        let totp_seed = if let Some(name) = item_name.as_deref() {
            self.vault
                .decrypt_totp(name)
                .ok()
                .flatten()
                .and_then(|sb| sb.as_str().ok().map(|s| SecretString::from(s.to_string())))
        } else {
            None
        };

        Ok(VaultItemSecrets {
            password,
            totp_seed,
            api_key_value,
        })
    }

    async fn item_password_hash(&self, item_id: &str) -> Result<Option<String>> {
        match self.vault.decrypt_credentials_by_id(item_id).await {
            Ok((_, pw)) => {
                let pw_str = pw.as_str().unwrap_or("");
                let mut h = Sha256::new();
                h.update(pw_str.as_bytes());
                Ok(Some(format!("{:x}", h.finalize())))
            }
            Err(_) => Ok(None),
        }
    }

    async fn item_username(&self, item_id: &str) -> Result<Option<String>> {
        match self.vault.decrypt_credentials_by_id(item_id).await {
            Ok((Some(user), _)) => Ok(Some(user.as_str().unwrap_or("").to_string())),
            _ => Ok(None),
        }
    }

    async fn item_url_host(&self, item_id: &str) -> Result<Option<String>> {
        let masked = self.vault.list_items().await;
        Ok(masked
            .iter()
            .find(|i| i.id == item_id)
            .and_then(|i| i.uris.first().cloned())
            .and_then(|uri| Self::host_of(&uri)))
    }

    async fn item_url(&self, item_id: &str) -> Result<Option<String>> {
        let masked = self.vault.list_items().await;
        Ok(masked
            .iter()
            .find(|i| i.id == item_id)
            .and_then(|i| i.uris.first().cloned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_of_extracts_host() {
        assert_eq!(VwAdapter::host_of("https://example.com/path"), Some("example.com".to_string()));
        assert_eq!(VwAdapter::host_of("not a url"), None);
        assert_eq!(VwAdapter::host_of("https://Example.COM"), Some("example.com".to_string()));
    }
}
