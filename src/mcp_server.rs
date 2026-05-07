use std::sync::Arc;
use rmcp::{ServiceExt, tool, tool_router, transport};
use rmcp::handler::server::wrapper::Parameters;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use crate::vault::VaultManager;

// -------------------------------------------------------------------------- //
// Parameter structs                                                           //
// -------------------------------------------------------------------------- //

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GeneratePasswordParams {
    /// Password length (default: 20, max: 128)
    pub length: Option<u32>,
    /// Include symbols like !@#$%^&* (default: true)
    pub symbols: Option<bool>,
}

#[allow(dead_code)] // used by Task 4 write tools
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CreateItemParams {
    /// Display name for the vault item
    pub name: String,
    /// Username / login identity
    pub username: Option<String>,
    /// Plaintext password (will be encrypted before storage)
    pub password: String,
    /// List of URIs associated with this login
    pub uris: Option<Vec<String>>,
    /// Vaultwarden folder id to place this item in
    pub folder_id: Option<String>,
}

#[allow(dead_code)] // used by Task 4 write tools
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct UpdateItemParams {
    /// Vaultwarden item id to update
    pub id: String,
    /// New display name (optional — omit to keep current)
    pub name: Option<String>,
    /// New username (optional — omit to keep current)
    pub username: Option<String>,
    /// New plaintext password (optional — omit to keep current; will be encrypted)
    pub password: Option<String>,
}

#[allow(dead_code)] // used by Task 4 write tools
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DeleteItemParams {
    /// Vaultwarden item id to delete (soft-delete / move to trash)
    pub id: String,
}

#[allow(dead_code)] // used by Task 4 write tools
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MoveItemParams {
    /// Vaultwarden item id to move
    pub id: String,
    /// Target folder name (the folder will be looked up by name)
    pub folder_name: String,
}

#[allow(dead_code)] // used by Task 4 write tools
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct CloneItemParams {
    /// Vaultwarden item id to clone
    pub id: String,
    /// Name for the new cloned item
    pub new_name: String,
    /// Optional new username for the clone
    pub new_username: Option<String>,
    /// Optional new URI for the clone
    pub new_uri: Option<String>,
    /// Optional folder id for the clone
    pub folder_id: Option<String>,
}

// -------------------------------------------------------------------------- //
// Server struct                                                               //
// -------------------------------------------------------------------------- //

#[derive(Clone)]
pub struct VaultMcpServer {
    vault: Arc<VaultManager>,
    vault_folder: String,
}

impl VaultMcpServer {
    pub fn new(vault: Arc<VaultManager>, vault_folder: String) -> Self {
        Self { vault, vault_folder }
    }
}

// -------------------------------------------------------------------------- //
// Tool implementations                                                        //
// -------------------------------------------------------------------------- //

#[tool_router(server_handler)]
impl VaultMcpServer {
    /// List all vault items. Passwords are always masked as "***".
    #[tool(description = "List all Vaultwarden items. Passwords are always masked.")]
    pub async fn list_items(&self) -> String {
        let items = self.vault.list_items().await;
        match serde_json::to_string(&items) {
            Ok(json) => json,
            Err(e) => format!("{{\"error\": \"{e}\"}}"),
        }
    }

    /// List all vault folders with item counts.
    #[tool(description = "List all Vaultwarden folders with item counts.")]
    pub async fn list_folders(&self) -> String {
        let empty_set = std::collections::HashSet::new();
        let folders = self.vault.list_folders_with_counts(&empty_set).await;
        match serde_json::to_string(&folders) {
            Ok(json) => json,
            Err(e) => format!("{{\"error\": \"{e}\"}}"),
        }
    }

    /// Find duplicate credentials (same username+password stored multiple times).
    #[tool(description = "Find duplicate credentials in Vaultwarden. Never returns plaintext passwords.")]
    pub async fn list_duplicates(&self) -> String {
        let dupes = self.vault.list_duplicates().await;
        match serde_json::to_string(&dupes) {
            Ok(json) => json,
            Err(e) => format!("{{\"error\": \"{e}\"}}"),
        }
    }

    /// Check vault-proxy health: reports cached item count.
    #[tool(description = "Check vault-proxy health: cached item count.")]
    pub async fn health(&self) -> String {
        let items = self.vault.list_items().await;
        serde_json::json!({
            "status": "ok",
            "cached_items": items.len(),
            "vault_folder": self.vault_folder,
        })
        .to_string()
    }

    /// Generate a cryptographically random password.
    #[tool(description = "Generate a cryptographically random password.")]
    pub async fn generate_password(
        &self,
        Parameters(p): Parameters<GeneratePasswordParams>,
    ) -> String {
        use rand::Rng;
        let len = p.length.unwrap_or(20).clamp(8, 128) as usize;
        let use_symbols = p.symbols.unwrap_or(true);

        let lowercase = b"abcdefghijklmnopqrstuvwxyz";
        let uppercase = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        let digits = b"0123456789";
        let syms = b"!@#$%^&*-_=+?";

        let mut pool: Vec<u8> = Vec::new();
        pool.extend_from_slice(lowercase);
        pool.extend_from_slice(uppercase);
        pool.extend_from_slice(digits);
        if use_symbols {
            pool.extend_from_slice(syms);
        }

        let mut rng = rand::thread_rng();
        let password: String = (0..len)
            .map(|_| pool[rng.gen_range(0..pool.len())] as char)
            .collect();

        serde_json::json!({ "password": password, "length": len }).to_string()
    }
}

// -------------------------------------------------------------------------- //
// Entry point                                                                 //
// -------------------------------------------------------------------------- //

pub async fn run(vault: Arc<VaultManager>, vault_folder: String) -> anyhow::Result<()> {
    tracing::info!("starting vault-proxy MCP server on stdio");
    let server = VaultMcpServer::new(vault, vault_folder);
    let service = server.serve(transport::stdio()).await?;
    service.waiting().await?;
    Ok(())
}
