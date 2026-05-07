use std::sync::Arc;
use crate::vault::VaultManager;

pub async fn run(vault: Arc<VaultManager>, _vault_folder: String) -> anyhow::Result<()> {
    let _ = vault;
    Ok(())
}
