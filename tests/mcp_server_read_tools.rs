//! Integration tests for mcp_server read-only tools.
//! Uses VaultManager::new_stub() — no live Vaultwarden required.
//!
//! Run with: cargo test --test mcp_server_read_tools --features test-utils

#![cfg(feature = "test-utils")]

use std::sync::Arc;
use vaultproxy::vault::VaultManager;

#[tokio::test]
async fn list_items_returns_json() {
    let vault = Arc::new(VaultManager::new_stub());
    let server = vaultproxy::mcp_server::VaultMcpServer::new(vault, "vault-proxy".into());
    let result = server.list_items().await;
    assert!(
        result.contains("[]") || result.contains("\"items\""),
        "got: {result}"
    );
}

#[tokio::test]
async fn list_folders_returns_json() {
    let vault = Arc::new(VaultManager::new_stub());
    let server = vaultproxy::mcp_server::VaultMcpServer::new(vault, "vault-proxy".into());
    let result = server.list_folders().await;
    assert!(
        result.contains("[]") || result.contains("\"folders\""),
        "got: {result}"
    );
}

#[tokio::test]
async fn health_returns_ok() {
    let vault = Arc::new(VaultManager::new_stub());
    let server = vaultproxy::mcp_server::VaultMcpServer::new(vault, "vault-proxy".into());
    let result = server.health().await;
    assert!(
        result.contains("ok") || result.contains("connected"),
        "got: {result}"
    );
}

#[tokio::test]
async fn generate_password_default_length() {
    use rmcp::handler::server::wrapper::Parameters;
    let vault = Arc::new(VaultManager::new_stub());
    let server = vaultproxy::mcp_server::VaultMcpServer::new(vault, "vault-proxy".into());
    let result = server
        .generate_password(Parameters(vaultproxy::mcp_server::GeneratePasswordParams {
            length: None,
            symbols: None,
        }))
        .await;
    assert!(!result.is_empty(), "got: {result}");
    let v: serde_json::Value = serde_json::from_str(&result).expect("valid JSON");
    let pw = v["password"].as_str().expect("password field");
    assert_eq!(pw.len(), 20, "default length should be 20");
}

#[tokio::test]
async fn generate_password_custom_length() {
    use rmcp::handler::server::wrapper::Parameters;
    let vault = Arc::new(VaultManager::new_stub());
    let server = vaultproxy::mcp_server::VaultMcpServer::new(vault, "vault-proxy".into());
    let result = server
        .generate_password(Parameters(vaultproxy::mcp_server::GeneratePasswordParams {
            length: Some(32),
            symbols: None,
        }))
        .await;
    let v: serde_json::Value = serde_json::from_str(&result).expect("valid JSON");
    let pw = v["password"].as_str().expect("password field");
    assert_eq!(pw.len(), 32);
}

#[tokio::test]
async fn delete_item_unknown_id_returns_error_json() {
    use rmcp::handler::server::wrapper::Parameters;
    let vault = Arc::new(VaultManager::new_stub());
    let server = vaultproxy::mcp_server::VaultMcpServer::new(vault, "vault-proxy".into());
    let result = server
        .delete_item(Parameters(vaultproxy::mcp_server::DeleteItemParams {
            id: "nonexistent-id".into(),
        }))
        .await;
    assert!(result.contains("error"), "got: {result}");
}

#[tokio::test]
async fn move_item_unknown_id_returns_error_json() {
    use rmcp::handler::server::wrapper::Parameters;
    let vault = Arc::new(VaultManager::new_stub());
    let server = vaultproxy::mcp_server::VaultMcpServer::new(vault, "vault-proxy".into());
    let result = server
        .move_item(Parameters(vaultproxy::mcp_server::MoveItemParams {
            id: "nonexistent-id".into(),
            folder_name: "TestFolder".into(),
        }))
        .await;
    assert!(result.contains("error"), "got: {result}");
}

#[tokio::test]
async fn create_item_stub_returns_error_json() {
    use rmcp::handler::server::wrapper::Parameters;
    let vault = Arc::new(VaultManager::new_stub());
    let server = vaultproxy::mcp_server::VaultMcpServer::new(vault, "vault-proxy".into());
    let result = server
        .create_item(Parameters(vaultproxy::mcp_server::CreateItemParams {
            name: "Test".into(),
            username: Some("user".into()),
            password: "pass".into(),
            uris: None,
            folder_id: None,
        }))
        .await;
    assert!(result.contains("error"), "got: {result}");
}

#[tokio::test]
async fn update_item_unknown_id_returns_error_json() {
    use rmcp::handler::server::wrapper::Parameters;
    let vault = Arc::new(VaultManager::new_stub());
    let server = vaultproxy::mcp_server::VaultMcpServer::new(vault, "vault-proxy".into());
    let result = server
        .update_item(Parameters(vaultproxy::mcp_server::UpdateItemParams {
            id: "nonexistent-id".into(),
            name: None,
            username: None,
            password: Some("newpass".into()),
        }))
        .await;
    assert!(result.contains("error"), "got: {result}");
}

#[tokio::test]
async fn resync_stub_returns_error_json() {
    let vault = Arc::new(VaultManager::new_stub());
    let server = vaultproxy::mcp_server::VaultMcpServer::new(vault, "vault-proxy".into());
    let result = server.resync().await;
    // stub has no HTTP; sync() fails
    assert!(result.contains("error"), "got: {result}");
}

#[tokio::test]
async fn clone_item_unknown_id_returns_error_json() {
    use rmcp::handler::server::wrapper::Parameters;
    let vault = Arc::new(VaultManager::new_stub());
    let server = vaultproxy::mcp_server::VaultMcpServer::new(vault, "vault-proxy".into());
    let result = server
        .clone_item(Parameters(vaultproxy::mcp_server::CloneItemParams {
            id: "nonexistent-id".into(),
            new_name: "Clone".into(),
            new_username: None,
            new_uri: None,
            folder_id: None,
        }))
        .await;
    assert!(result.contains("error"), "got: {result}");
}
