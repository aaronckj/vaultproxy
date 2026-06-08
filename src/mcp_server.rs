use crate::access_log::AccessLog;
use crate::proxy::SmbConfig;
use crate::vault::smb::{self, SmbMountRequest, SmbUnmountRequest};
use crate::vault::VaultManager;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use rmcp::{tool, tool_router, transport, ServiceExt};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

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

#[derive(Deserialize, Serialize, JsonSchema)]
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

#[derive(Deserialize, Serialize, JsonSchema)]
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

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct DeleteItemParams {
    /// Vaultwarden item id to delete (soft-delete / move to trash)
    pub id: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct MoveItemParams {
    /// Vaultwarden item id to move
    pub id: String,
    /// Target folder name (the folder will be looked up by name)
    pub folder_name: String,
}

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

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct RotateParams {
    /// Registered rotation service name (must match a service configured for
    /// rotation on the daemon).
    pub service: String,
    /// Rotation strategy. Currently only "api" is accepted; defaults to "api".
    pub strategy: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct SmbMountParams {
    /// Vaultwarden cipher id (uuid) whose login holds the SMB username + password.
    /// You never pass the credentials yourself — vault-proxy resolves them.
    pub vault_item_id: String,
    /// SMB UNC path, e.g. `//10.0.0.30/screenshots`.
    pub share: String,
    /// Local mount point under --smb-mount-root (e.g. `/mnt/screenshots`).
    pub mount_point: String,
    /// Stable slug used in the creds filename + fstab markers (`[a-z0-9-]{1,32}`).
    pub slug: String,
    /// Optional extra cifs mount options. `credentials=`, `username=`, `password=` reserved.
    pub fs_options: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct SmbUnmountParams {
    /// Same slug used in the original smb_mount call.
    pub slug: String,
    /// Mount point to unmount and remove from fstab.
    pub mount_point: String,
}

// -------------------------------------------------------------------------- //
// Server struct                                                               //
// -------------------------------------------------------------------------- //

#[derive(Clone)]
pub struct VaultMcpServer {
    vault: Arc<VaultManager>,
    vault_folder: String,
    smb: SmbConfig,
}

impl VaultMcpServer {
    /// Construct a server without SMB support enabled (default).
    #[allow(dead_code)]
    pub fn new(vault: Arc<VaultManager>, vault_folder: String) -> Self {
        Self {
            vault,
            vault_folder,
            smb: SmbConfig::default(),
        }
    }

    /// Construct a server with SMB mount tools wired to the given config.
    pub fn with_smb(vault: Arc<VaultManager>, vault_folder: String, smb: SmbConfig) -> Self {
        Self {
            vault,
            vault_folder,
            smb,
        }
    }
}

// -------------------------------------------------------------------------- //
// Tool implementations                                                        //
// -------------------------------------------------------------------------- //

#[tool_router(server_handler)]
impl VaultMcpServer {
    /// List vault items scoped to vault_folder. Passwords are always masked as "***".
    #[tool(
        description = "List Vaultwarden items in the configured vault folder. Passwords are always masked."
    )]
    pub async fn list_items(&self) -> String {
        let folder_id = self
            .vault
            .find_folder_id_by_name_async(&self.vault_folder)
            .await;
        let items: Vec<_> = self
            .vault
            .list_items()
            .await
            .into_iter()
            .filter(|item| item.folder_id.as_deref() == folder_id.as_deref())
            .collect();
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

    /// Find duplicate credentials scoped to vault_folder. Never returns plaintext passwords.
    #[tool(
        description = "Find duplicate credentials in the configured vault folder. Never returns plaintext passwords."
    )]
    pub async fn list_duplicates(&self) -> String {
        let folder_id = self
            .vault
            .find_folder_id_by_name_async(&self.vault_folder)
            .await;
        let dupes = match folder_id.as_deref() {
            Some(fid) => self.vault.list_duplicates_in_folder(Some(fid)).await,
            None => vec![],
        };
        match serde_json::to_string(&dupes) {
            Ok(json) => json,
            Err(e) => format!("{{\"error\": \"{e}\"}}"),
        }
    }

    /// Check vault-proxy health: reports folder-scoped cached item count.
    #[tool(description = "Check vault-proxy health: folder-scoped cached item count.")]
    pub async fn health(&self) -> String {
        let folder_id = self
            .vault
            .find_folder_id_by_name_async(&self.vault_folder)
            .await;
        let count = self
            .vault
            .list_items()
            .await
            .into_iter()
            .filter(|item| item.folder_id.as_deref() == folder_id.as_deref())
            .count();
        serde_json::json!({
            "status": "ok",
            "cached_items": count,
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

    /// Resync the vault cache from Vaultwarden. Call after making changes externally.
    #[tool(description = "Resync the vault cache from Vaultwarden.")]
    pub async fn resync(&self) -> String {
        match self.vault.sync().await {
            Ok(()) => r#"{"status":"ok","message":"vault resynced"}"#.to_string(),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    /// Create a new login item in Vaultwarden. Password is encrypted; never returned.
    #[tool(
        description = "Create a new login item. Password is encrypted; the new item id is returned."
    )]
    pub async fn create_item(&self, Parameters(p): Parameters<CreateItemParams>) -> String {
        let uris = p.uris.unwrap_or_default();
        match self
            .vault
            .create_login_item(
                &p.name,
                p.username.as_deref(),
                &p.password,
                uris,
                p.folder_id.as_deref(),
            )
            .await
        {
            Ok(id) => serde_json::json!({"status":"ok","id":id}).to_string(),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    /// Update name, username, and/or password of an existing vault item.
    #[tool(
        description = "Update name, username, and/or password of a vault item by id. Omit fields to keep current values."
    )]
    pub async fn update_item(&self, Parameters(p): Parameters<UpdateItemParams>) -> String {
        match self
            .vault
            .update_login_item_fields(
                &p.id,
                p.name.as_deref(),
                p.username.as_deref(),
                p.password.as_deref(),
            )
            .await
        {
            Ok(()) => r#"{"status":"ok"}"#.to_string(),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    /// Soft-delete a vault item (moves it to Vaultwarden trash).
    #[tool(description = "Soft-delete a vault item by id (moves to trash).")]
    pub async fn delete_item(&self, Parameters(p): Parameters<DeleteItemParams>) -> String {
        match self.vault.delete_cipher(&p.id).await {
            Ok(()) => r#"{"status":"ok"}"#.to_string(),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    /// Move a vault item to a different folder (looked up by name).
    #[tool(description = "Move a vault item to a folder, looked up by name.")]
    pub async fn move_item(&self, Parameters(p): Parameters<MoveItemParams>) -> String {
        match self
            .vault
            .move_cipher_to_folder(&p.id, &p.folder_name)
            .await
        {
            Ok(()) => r#"{"status":"ok"}"#.to_string(),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    /// Clone an existing vault item with a new name (and optionally new username/URI/folder).
    #[tool(
        description = "Clone a vault item with a new name. Optionally override username, URI, or folder."
    )]
    pub async fn clone_item(&self, Parameters(p): Parameters<CloneItemParams>) -> String {
        match self
            .vault
            .clone_cipher_with_overrides(
                &p.id,
                &p.new_name,
                p.new_username.as_deref(),
                p.new_uri.as_deref(),
                p.folder_id.as_deref(),
            )
            .await
        {
            Ok(new_id) => serde_json::json!({"status":"ok","id":new_id}).to_string(),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    /// Set up an SMB/CIFS mount using credentials from a vault item. Vault-proxy
    /// resolves the credential internally and pipes it to a setuid helper which
    /// writes /etc/samba/vaultproxy-<slug>.credentials, edits /etc/fstab, and
    /// runs mount. The plaintext password never leaves vault-proxy's address
    /// space and is never returned to the caller. Disabled unless
    /// --smb-helper-path is configured at vault-proxy startup.
    #[tool(
        description = "Set up an SMB mount using a vault item. Vault-proxy never reveals the password to you — it writes the credentials file, edits /etc/fstab, and runs mount internally via a setuid helper. Returns only ok/error."
    )]
    pub async fn smb_mount(&self, Parameters(p): Parameters<SmbMountParams>) -> String {
        let req = SmbMountRequest {
            vault_item_id: p.vault_item_id,
            share: p.share,
            mount_point: p.mount_point,
            slug: p.slug,
            fs_options: p.fs_options.unwrap_or_default(),
        };
        let (_, body) = smb::perform_mount(&self.vault, &self.smb, req).await;
        body.to_string()
    }

    /// Tear down a previously-installed SMB mount: unmount, remove its
    /// /etc/fstab block, and delete the credentials file.
    #[tool(
        description = "Tear down an SMB mount previously created by smb_mount. Unmounts, removes the fstab block, deletes the credentials file. Returns only ok/error."
    )]
    pub async fn smb_unmount(&self, Parameters(p): Parameters<SmbUnmountParams>) -> String {
        let req = SmbUnmountRequest {
            slug: p.slug,
            mount_point: p.mount_point,
        };
        let (_, body) = smb::perform_unmount(&self.smb, req).await;
        body.to_string()
    }

    /// Trigger credential rotation for a registered service via the running
    /// vault-proxy daemon. The MCP process posts to the daemon's `/rotate`
    /// HTTP endpoint with the internal bearer token from disk.
    ///
    /// Audit logging is handled by the daemon: when this tool proxies a
    /// rotation request to `POST /rotate`, the daemon writes the
    /// HMAC-chained access-log entry inside its own process. The MCP server
    /// deliberately does not write to the access log itself, because two
    /// separate processes appending to the same file would interleave
    /// lines once a payload exceeds PIPE_BUF.
    #[tool(
        description = "Rotate credentials for a registered service via the running vault-proxy daemon. The MCP process posts to the daemon's POST /rotate; the daemon resolves the rotation strategy configured for the named service. An unknown service name returns a typed error result, and some registered-but-stubbed services return 'unsupported' — generic API-key/password rotation is not broadly implemented. Requires the daemon to be live (default http://127.0.0.1:3201; override with VP_URL env). Returns the daemon's JSON response verbatim."
    )]
    pub async fn rotate(&self, Parameters(p): Parameters<RotateParams>) -> String {
        let config_dir = std::env::var("CONFIG_DIR").unwrap_or_default();
        if config_dir.is_empty() {
            return r#"{"ok":false,"error":"CONFIG_DIR env not set; cannot locate internal-token"}"#.to_string();
        }
        let token_path = format!("{}/internal-token", config_dir);
        let internal_token = match std::fs::read_to_string(&token_path) {
            Ok(s) => s.trim().to_string(),
            Err(e) => {
                return format!(
                    r#"{{"ok":false,"error":"read internal-token from {}: {}"}}"#,
                    token_path, e
                );
            }
        };
        let vp_url =
            std::env::var("VP_URL").unwrap_or_else(|_| "http://127.0.0.1:3201".to_string());
        let strategy = p.strategy.unwrap_or_else(|| "api".to_string());
        let body = serde_json::json!({"service": p.service, "strategy": strategy});
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .unwrap();
        let resp = match client
            .post(format!("{}/rotate", vp_url))
            .header("Authorization", format!("Bearer {}", internal_token))
            .json(&body)
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                return format!(
                    r#"{{"ok":false,"error":"POST /rotate to {}: {}"}}"#,
                    vp_url, e
                );
            }
        };
        match resp.text().await {
            Ok(t) => t,
            Err(e) => format!(r#"{{"ok":false,"error":"read response body: {}"}}"#, e),
        }
    }
}

// -------------------------------------------------------------------------- //
// Entry point                                                                 //
// -------------------------------------------------------------------------- //

pub async fn run(
    vault: Arc<VaultManager>,
    vault_folder: String,
    smb: SmbConfig,
    // Kept in the signature so callers in `main.rs` don't have to special-case
    // MCP startup. The MCP server itself no longer writes to the access log
    // (rotate logging is now consolidated daemon-side); callers should pass
    // `None`. A non-None value is silently ignored.
    _access_log: Option<Arc<AccessLog>>,
) -> anyhow::Result<()> {
    tracing::info!("starting vault-proxy MCP server on stdio");
    let server = VaultMcpServer::with_smb(vault, vault_folder, smb);
    let service = server.serve(transport::stdio()).await?;
    service.waiting().await?;
    Ok(())
}

pub async fn run_http(
    vault: Arc<VaultManager>,
    vault_folder: String,
    smb: SmbConfig,
    listen_addr: std::net::SocketAddr,
    // See `run` above — kept for signature symmetry only.
    _access_log: Option<Arc<AccessLog>>,
) -> anyhow::Result<()> {
    tracing::info!("starting vault-proxy MCP HTTP server on {listen_addr}");
    let ct = CancellationToken::new();
    let service: StreamableHttpService<VaultMcpServer, LocalSessionManager> =
        StreamableHttpService::new(
            {
                let vault = vault.clone();
                let vault_folder = vault_folder.clone();
                let smb = smb.clone();
                move || {
                    Ok(VaultMcpServer::with_smb(
                        vault.clone(),
                        vault_folder.clone(),
                        smb.clone(),
                    ))
                }
            },
            Default::default(),
            StreamableHttpServerConfig::default()
                .with_allowed_hosts(vec![
                    listen_addr.ip().to_string(),
                    "localhost".to_string(),
                    "127.0.0.1".to_string(),
                ])
                .with_cancellation_token(ct.child_token()),
        );
    let router = axum::Router::new().nest_service("/mcp", service);
    let tcp_listener = tokio::net::TcpListener::bind(listen_addr).await?;
    let handle = tokio::spawn({
        let ct = ct.clone();
        async move {
            axum::serve(tcp_listener, router)
                .with_graceful_shutdown(async move { ct.cancelled_owned().await })
                .await
                .expect("mcp http server error");
        }
    });
    handle.await?;
    Ok(())
}
