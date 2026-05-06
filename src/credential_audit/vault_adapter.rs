use crate::credential_audit::engine_client::EngineInputItem;
use anyhow::Result;
use secrecy::SecretString;

#[allow(dead_code)] // iter-82: password read by judge_one (scaffold); totp_seed/api_key_value for future pass2 paths
pub struct VaultItemSecrets {
    pub password: Option<SecretString>,
    pub totp_seed: Option<SecretString>,
    pub api_key_value: Option<SecretString>,
}

#[async_trait::async_trait]
pub trait VaultAdapter: Send + Sync {
    async fn list_items_metadata(&self) -> Result<Vec<EngineInputItem>>;
    async fn item_secrets(&self, item_id: &str) -> Result<VaultItemSecrets>;
    async fn item_password_hash(&self, item_id: &str) -> Result<Option<String>>;
    async fn item_username(&self, item_id: &str) -> Result<Option<String>>;
    async fn item_url_host(&self, item_id: &str) -> Result<Option<String>>;
    /// Full URL of the item's first URI — needed by Pass-2 to navigate.
    /// `item_url_host` only returns the host; this returns the full URL.
    #[allow(dead_code)] // iter-82: called by pass2_run_worker (scaffold)
    async fn item_url(&self, item_id: &str) -> Result<Option<String>>;
}
