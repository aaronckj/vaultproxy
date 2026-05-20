# vault-proxy --mcp Server Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `--mcp` stdio flag to the `vaultproxy` binary that starts an in-process MCP server exposing Vaultwarden management tools — but never returning plaintext credentials.

**Architecture:** Single new file `src/mcp_server.rs` containing a `VaultMcpServer` struct that holds `Arc<VaultManager>`, wired via rmcp 1.6.0 `#[tool_router(server_handler)]` macro. The `--mcp` flag added to `Args` causes `start_server()` to call `mcp_server::run()` instead of binding the HTTP proxy port. Two new convenience methods are added to `VaultManager` to support create/update without exposing the encryption API to the MCP layer.

**Tech Stack:** Rust 2021, rmcp 1.6.0 (`server`, `macros`, `transport-io` features), schemars 1.0, existing rand 0.8

---

## File Structure

- **Create:** `src/mcp_server.rs` — `VaultMcpServer` struct + all 13 tools
- **Modify:** `src/vault/mod.rs` — add `create_login_item()` and `update_login_item_fields()` convenience methods
- **Modify:** `Cargo.toml` — add rmcp + schemars dependencies
- **Modify:** `src/main.rs` — add `--mcp` flag to `Args` and `--mcp` branch in `start_server()`

---

## Task 1: Add dependency, CLI flag, and module stub

**Files:**
- Modify: `Cargo.toml`
- Modify: `src/main.rs` (Args struct and `mod mcp_server;`)
- Create: `src/mcp_server.rs` (stub)

- [ ] **Step 1: Add rmcp and schemars to Cargo.toml**

In `/home/aaron/projects/mcp-vault-proxy/Cargo.toml`, add after the `rand = "0.8"` line:

```toml
rmcp = { version = "1.6", features = ["server", "macros", "transport-io"] }
schemars = "1.0"
```

- [ ] **Step 2: Add `--mcp` flag to Args struct in main.rs**

In `src/main.rs`, after the `--check` arg block (around line 208), add:

```rust
    /// Run as a stdio MCP server exposing Vaultwarden management tools.
    /// Never returns plaintext credentials — passwords are always masked.
    /// Credentials must already be configured (keystore unlocked) before
    /// this flag is used. Reads JSON-RPC from stdin, writes to stdout.
    #[arg(long)]
    mcp: bool,
```

- [ ] **Step 3: Add `mod mcp_server;` to main.rs**

In `src/main.rs`, after the `mod launcher;` line (line 27), add:

```rust
mod mcp_server;
```

- [ ] **Step 4: Create stub mcp_server.rs**

Create `/home/aaron/projects/mcp-vault-proxy/src/mcp_server.rs`:

```rust
use std::sync::Arc;
use crate::vault::VaultManager;

pub async fn run(vault: Arc<VaultManager>, _vault_folder: String) -> anyhow::Result<()> {
    // TODO: implement
    let _ = vault;
    Ok(())
}
```

- [ ] **Step 5: Verify the project still compiles**

```bash
cd /home/aaron/projects/mcp-vault-proxy && cargo check 2>&1 | tail -5
```

Expected: `Finished` with no errors (rmcp resolves from cache)

- [ ] **Step 6: Commit**

```bash
cd /home/aaron/projects/mcp-vault-proxy
git add Cargo.toml Cargo.lock src/main.rs src/mcp_server.rs
git commit -m "feat: add rmcp dependency, --mcp CLI flag, and mcp_server stub"
```

---

## Task 2: VaultManager convenience methods

Two methods are needed so the MCP layer never calls `encrypt_to_cipher_string` directly and never handles plaintext after encryption.

**Files:**
- Modify: `src/vault/mod.rs`

- [ ] **Step 1: Write the failing test for create_login_item**

Add to the test block at the bottom of `src/vault/mod.rs` (inside `#[cfg(test)] mod tests`):

```rust
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
```

- [ ] **Step 2: Run tests to verify they fail (method not found)**

```bash
cd /home/aaron/projects/mcp-vault-proxy && cargo test create_login_item_returns_id update_login_item_fields_id_not_found 2>&1 | tail -10
```

Expected: compilation error "no method named `create_login_item`"

- [ ] **Step 3: Implement create_login_item in vault/mod.rs**

Add after the `update_password_for_item` method (around line 1030):

```rust
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
            uris: if enc_uris.is_empty() { None } else { Some(enc_uris) },
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
```

- [ ] **Step 4: Implement update_login_item_fields in vault/mod.rs**

Add after `create_login_item`:

```rust
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

    let login = updated.login.get_or_insert(crate::vault::types::EncryptedLogin {
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
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd /home/aaron/projects/mcp-vault-proxy && cargo test create_login_item_returns_id update_login_item_fields_id_not_found 2>&1 | tail -10
```

Expected: both tests pass (the stub has no HTTP so create returns err, and update returns err for unknown id)

- [ ] **Step 6: Commit**

```bash
cd /home/aaron/projects/mcp-vault-proxy
git add src/vault/mod.rs
git commit -m "feat: add create_login_item and update_login_item_fields to VaultManager"
```

---

## Task 3: Read-only MCP tools

Implements the five read-only tools: `list_items`, `list_folders`, `list_duplicates`, `health`, `generate_password`.

**Files:**
- Modify: `src/mcp_server.rs`

- [ ] **Step 1: Write the failing test**

Create `/home/aaron/projects/mcp-vault-proxy/tests/mcp_server_read_tools.rs`:

```rust
//! Integration tests for mcp_server read-only tools.
//! Uses VaultManager::new_stub() — no live Vaultwarden required.

use std::sync::Arc;
use vaultproxy::vault::VaultManager;

// We can't call the MCP tools directly without spinning up a transport,
// so we test by running the tool methods on VaultMcpServer directly.
// The #[tool_router] macro keeps the underlying async fns callable.

#[tokio::test]
async fn list_items_returns_json() {
    let vault = Arc::new(VaultManager::new_stub());
    let server = vaultproxy::mcp_server::VaultMcpServer::new(vault, "vault-proxy".into());
    let result = server.list_items().await;
    // stub vault is empty — should return JSON array
    assert!(result.contains("[]") || result.contains("\"items\""), "got: {result}");
}

#[tokio::test]
async fn list_folders_returns_json() {
    let vault = Arc::new(VaultManager::new_stub());
    let server = vaultproxy::mcp_server::VaultMcpServer::new(vault, "vault-proxy".into());
    let result = server.list_folders().await;
    assert!(result.contains("[]") || result.contains("\"folders\""), "got: {result}");
}

#[tokio::test]
async fn health_returns_ok() {
    let vault = Arc::new(VaultManager::new_stub());
    let server = vaultproxy::mcp_server::VaultMcpServer::new(vault, "vault-proxy".into());
    let result = server.health().await;
    assert!(result.contains("ok") || result.contains("connected"), "got: {result}");
}

#[tokio::test]
async fn generate_password_default_length() {
    use rmcp::handler::server::wrapper::Parameters;
    let vault = Arc::new(VaultManager::new_stub());
    let server = vaultproxy::mcp_server::VaultMcpServer::new(vault, "vault-proxy".into());
    let result = server.generate_password(Parameters(vaultproxy::mcp_server::GeneratePasswordParams {
        length: None,
        symbols: None,
    })).await;
    // result should be a JSON string; password should be 20 chars by default
    assert!(!result.is_empty(), "got: {result}");
    // extract password from JSON: {"password":"..."} 
    let v: serde_json::Value = serde_json::from_str(&result).expect("valid JSON");
    let pw = v["password"].as_str().expect("password field");
    assert_eq!(pw.len(), 20, "default length should be 20");
}

#[tokio::test]
async fn generate_password_custom_length() {
    use rmcp::handler::server::wrapper::Parameters;
    let vault = Arc::new(VaultManager::new_stub());
    let server = vaultproxy::mcp_server::VaultMcpServer::new(vault, "vault-proxy".into());
    let result = server.generate_password(Parameters(vaultproxy::mcp_server::GeneratePasswordParams {
        length: Some(32),
        symbols: None,
    })).await;
    let v: serde_json::Value = serde_json::from_str(&result).expect("valid JSON");
    let pw = v["password"].as_str().expect("password field");
    assert_eq!(pw.len(), 32);
}
```

- [ ] **Step 2: Add `pub` visibility and lib target to make tests compile**

In `Cargo.toml`, add a `[lib]` section (if not present) and add `crate-type`:

```toml
[lib]
name = "vaultproxy"
path = "src/lib.rs"
crate-type = ["rlib"]
```

Create `src/lib.rs` with re-exports needed for tests:

```rust
// Re-exports for integration tests
pub mod vault;
pub mod mcp_server;
```

- [ ] **Step 3: Run tests to verify they fail (VaultMcpServer not defined)**

```bash
cd /home/aaron/projects/mcp-vault-proxy && cargo test --test mcp_server_read_tools 2>&1 | head -20
```

Expected: compilation error "module `mcp_server` is private" or "no struct VaultMcpServer"

- [ ] **Step 4: Implement read-only tools in mcp_server.rs**

Replace the stub content of `src/mcp_server.rs` with:

```rust
use std::sync::Arc;
use rmcp::{ServerHandler, ServiceExt, tool_router, transport};
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

    /// Check vault-proxy health: reports base URL and cached item count.
    #[tool(description = "Check vault-proxy health: base URL and cached item count.")]
    pub async fn health(&self) -> String {
        let items = self.vault.list_items().await;
        serde_json::json!({
            "status": "ok",
            "base_url": self.vault.base_url(),
            "cached_items": items.len(),
            "vault_folder": self.vault_folder,
        })
        .to_string()
    }

    /// Generate a random password.
    #[tool(description = "Generate a cryptographically random password.")]
    pub async fn generate_password(
        &self,
        rmcp::handler::server::wrapper::Parameters(p): rmcp::handler::server::wrapper::Parameters<GeneratePasswordParams>,
    ) -> String {
        let length = p.length;
        let symbols = p.symbols;
        use rand::Rng;
        let len = length.unwrap_or(20).clamp(8, 128) as usize;
        let use_symbols = symbols.unwrap_or(true);

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
```

- [ ] **Step 5: Run read-only tests to verify they pass**

```bash
cd /home/aaron/projects/mcp-vault-proxy && cargo test --test mcp_server_read_tools 2>&1 | tail -15
```

Expected: all 5 tests pass

- [ ] **Step 6: Commit**

```bash
cd /home/aaron/projects/mcp-vault-proxy
git add src/mcp_server.rs src/lib.rs Cargo.toml tests/mcp_server_read_tools.rs
git commit -m "feat: implement read-only MCP tools (list_items, list_folders, list_duplicates, health, generate_password)"
```

---

## Task 4: Write MCP tools

Implements the six write tools: `resync`, `create_item`, `update_item`, `delete_item`, `move_item`, `clone_item`.

**Files:**
- Modify: `src/mcp_server.rs` — add 6 more tools to `#[tool_router(server_handler)]` impl block

- [ ] **Step 1: Write the failing tests**

Add to `/home/aaron/projects/mcp-vault-proxy/tests/mcp_server_read_tools.rs`:

```rust
#[tokio::test]
async fn delete_item_unknown_id_returns_error_json() {
    let vault = Arc::new(VaultManager::new_stub());
    let server = vaultproxy::mcp_server::VaultMcpServer::new(vault, "vault-proxy".into());
    let result = server
        .delete_item(vaultproxy::mcp_server::DeleteItemParams {
            id: "nonexistent-id".into(),
        })
        .await;
    // stub has no HTTP; expect error JSON
    assert!(result.contains("error"), "got: {result}");
}

#[tokio::test]
async fn move_item_unknown_id_returns_error_json() {
    let vault = Arc::new(VaultManager::new_stub());
    let server = vaultproxy::mcp_server::VaultMcpServer::new(vault, "vault-proxy".into());
    let result = server
        .move_item(vaultproxy::mcp_server::MoveItemParams {
            id: "nonexistent-id".into(),
            folder_name: "TestFolder".into(),
        })
        .await;
    assert!(result.contains("error"), "got: {result}");
}

#[tokio::test]
async fn create_item_stub_returns_error_json() {
    let vault = Arc::new(VaultManager::new_stub());
    let server = vaultproxy::mcp_server::VaultMcpServer::new(vault, "vault-proxy".into());
    let result = server
        .create_item(vaultproxy::mcp_server::CreateItemParams {
            name: "Test".into(),
            username: Some("user".into()),
            password: "pass".into(),
            uris: None,
            folder_id: None,
        })
        .await;
    // stub has no HTTP so create fails — result should be error JSON
    assert!(result.contains("error"), "got: {result}");
}

#[tokio::test]
async fn update_item_unknown_id_returns_error_json() {
    let vault = Arc::new(VaultManager::new_stub());
    let server = vaultproxy::mcp_server::VaultMcpServer::new(vault, "vault-proxy".into());
    let result = server
        .update_item(vaultproxy::mcp_server::UpdateItemParams {
            id: "nonexistent-id".into(),
            name: None,
            username: None,
            password: Some("newpass".into()),
        })
        .await;
    assert!(result.contains("error"), "got: {result}");
}
```

- [ ] **Step 2: Run tests to verify they fail (methods not found)**

```bash
cd /home/aaron/projects/mcp-vault-proxy && cargo test --test mcp_server_read_tools delete_item_unknown move_item_unknown create_item_stub update_item_unknown 2>&1 | head -20
```

Expected: compilation errors "no method named `delete_item`" etc.

- [ ] **Step 3: Add write tools to the tool_router impl block in mcp_server.rs**

Inside the `#[tool_router(server_handler)] impl VaultMcpServer` block, add these 6 methods after `generate_password`:

```rust
    /// Resync the vault cache from Vaultwarden. Call after making changes externally.
    #[tool(description = "Resync the vault cache from Vaultwarden.")]
    pub async fn resync(&self) -> String {
        match self.vault.sync().await {
            Ok(()) => r#"{"status":"ok","message":"vault resynced"}"#.to_string(),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    /// Create a new login item in Vaultwarden. Password is encrypted; never returned.
    #[tool(description = "Create a new login item. Password is encrypted; the new item id is returned.")]
    pub async fn create_item(
        &self,
        rmcp::handler::server::wrapper::Parameters(p): rmcp::handler::server::wrapper::Parameters<CreateItemParams>,
    ) -> String {
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
    #[tool(description = "Update name, username, and/or password of a vault item by id. Omit fields to keep current values.")]
    pub async fn update_item(
        &self,
        rmcp::handler::server::wrapper::Parameters(p): rmcp::handler::server::wrapper::Parameters<UpdateItemParams>,
    ) -> String {
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
    pub async fn delete_item(
        &self,
        rmcp::handler::server::wrapper::Parameters(p): rmcp::handler::server::wrapper::Parameters<DeleteItemParams>,
    ) -> String {
        match self.vault.delete_cipher(&p.id).await {
            Ok(()) => r#"{"status":"ok"}"#.to_string(),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    /// Move a vault item to a different folder (looked up by name).
    #[tool(description = "Move a vault item to a folder, looked up by name.")]
    pub async fn move_item(
        &self,
        rmcp::handler::server::wrapper::Parameters(p): rmcp::handler::server::wrapper::Parameters<MoveItemParams>,
    ) -> String {
        match self.vault.move_cipher_to_folder(&p.id, &p.folder_name).await {
            Ok(()) => r#"{"status":"ok"}"#.to_string(),
            Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
        }
    }

    /// Clone an existing vault item with a new name (and optionally new username/URI/folder).
    #[tool(description = "Clone a vault item with a new name. Optionally override username, URI, or folder.")]
    pub async fn clone_item(
        &self,
        rmcp::handler::server::wrapper::Parameters(p): rmcp::handler::server::wrapper::Parameters<CloneItemParams>,
    ) -> String {
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
```

- [ ] **Step 4: Run all mcp_server tests to verify they pass**

```bash
cd /home/aaron/projects/mcp-vault-proxy && cargo test --test mcp_server_read_tools 2>&1 | tail -15
```

Expected: all 9 tests pass

- [ ] **Step 5: Run the full test suite to confirm no regressions**

```bash
cd /home/aaron/projects/mcp-vault-proxy && cargo test 2>&1 | tail -10
```

Expected: all tests pass

- [ ] **Step 6: Commit**

```bash
cd /home/aaron/projects/mcp-vault-proxy
git add src/mcp_server.rs tests/mcp_server_read_tools.rs
git commit -m "feat: implement write MCP tools (resync, create_item, update_item, delete_item, move_item, clone_item)"
```

---

## Task 5: Wire --mcp branch into main() and install

**Files:**
- Modify: `src/main.rs` — add --mcp branch in `start_server()`

- [ ] **Step 1: Add --mcp branch to start_server() in main.rs**

In `src/main.rs`, in the `start_server()` function, immediately after the `if let Some(ref server_name) = args.launch` block (around line 861), add:

```rust
    // MCP server mode: expose Vaultwarden management tools over stdio.
    // Runs instead of the HTTP proxy — the binary becomes a stdio MCP server.
    if args.mcp {
        return crate::mcp_server::run(vault_arc, args.vault_folder.clone()).await;
    }
```

- [ ] **Step 2: Verify cargo check passes**

```bash
cd /home/aaron/projects/mcp-vault-proxy && cargo check 2>&1 | tail -5
```

Expected: `Finished` with no errors

- [ ] **Step 3: Run full test suite**

```bash
cd /home/aaron/projects/mcp-vault-proxy && cargo test 2>&1 | tail -10
```

Expected: all tests pass

- [ ] **Step 4: Commit**

```bash
cd /home/aaron/projects/mcp-vault-proxy
git add src/main.rs
git commit -m "feat: wire --mcp flag into start_server() to run MCP stdio server"
```

- [ ] **Step 5: Build release binary to verify it links**

```bash
cd /home/aaron/projects/mcp-vault-proxy && cargo build --release 2>&1 | tail -5
```

Expected: `Finished release` with no errors

- [ ] **Step 6: Install to Claude Code at user scope**

```bash
claude mcp add vaultproxy -s user \
  -e VAULT_FOLDER=vault-proxy \
  -e CONFIG_DIR=/config \
  -- /home/aaron/projects/mcp-vault-proxy/target/release/vaultproxy --mcp
```

Verify it appears:

```bash
claude mcp list
```

Expected: `vaultproxy` listed with the correct command

- [ ] **Step 7: Final commit**

```bash
cd /home/aaron/projects/mcp-vault-proxy
git add -p  # review any remaining uncommitted changes
git commit -m "feat: complete --mcp stdio server mode with 13 Vaultwarden management tools"
```

---

## Self-Review

### Spec Coverage

| Requirement | Task |
|-------------|------|
| `list_items` tool | Task 3 |
| `list_folders` tool | Task 3 |
| `list_duplicates` tool | Task 3 |
| `health` tool | Task 3 |
| `generate_password` tool | Task 3 |
| `resync` tool | Task 4 |
| `create_item` tool | Task 4 |
| `update_item` tool | Task 4 |
| `delete_item` tool | Task 4 |
| `move_item` tool | Task 4 |
| `clone_item` tool | Task 4 |
| Never returns plaintext passwords | All tools use MaskedItem / avoid decrypt_password |
| rmcp 1.6.0 with transport-io | Task 1 |
| Wire into main() | Task 5 |
| Install to Claude Code | Task 5 |

### Notes on Clone_item signature

`VaultManager::clone_cipher_with_overrides` takes `(source_id, new_name, new_username?, new_uri?, folder_id?)` where the last three are `Option<&str>`. The CloneItemParams maps directly.

### Password safety

`generate_password` uses rand 0.8's `thread_rng()` which is a cryptographically secure PRNG on all supported platforms. The password is returned in tool output (it was just generated, not retrieved from vault — this is intentional and correct).

Write tools (`create_item`, `update_item`) accept plaintext passwords as input (the tool caller provides them) and immediately encrypt via `create_login_item`/`update_login_item_fields`. The plaintext parameter is never stored, cached, or logged — it lives only in the stack frame of the tool call.
