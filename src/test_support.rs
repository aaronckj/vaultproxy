//! Helpers for integration tests that need to construct vault-proxy
//! internal types without booting the full daemon. Gated behind the
//! `test-utils` Cargo feature; never compiled into the production binary.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Arc;

use crate::notify::Notifier;
use crate::proxy::registry::ServiceRegistry;
use crate::proxy::unifi_session::UnifiSessionCache;
use crate::proxy::{AppState, SmbConfig};
use crate::security::audit_log::AuditLog;
use crate::security::permissions::ToolPermissions;
use crate::vault::VaultManager;

/// Build a minimal `AppState` suitable for transparent-mode integration
/// tests. Uses a stub VaultManager (no Vaultwarden connection required).
/// The returned state has an empty `ServiceRegistry`; tests that need
/// services should grab `state.registry.write().await` and replace it.
pub async fn stub_app_state() -> AppState {
    AppState {
        vault: Arc::new(VaultManager::new_stub()),
        registry: Arc::new(tokio::sync::RwLock::new(ServiceRegistry::new())),
        http: reqwest::Client::new(),
        http_permissive: reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap(),
        ca_cert_clients: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        unifi_sessions: Arc::new(UnifiSessionCache::new()),
        session_tokens: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        client_certs: None,
        cloud_sync: None,
        approval_queue: Arc::new(tokio::sync::RwLock::new(VecDeque::new())),
        browser: None,
        permissions: Arc::new(tokio::sync::RwLock::new(ToolPermissions::load(
            "/nonexistent/tool-permissions.json",
        ))),
        audit_log: Arc::new(AuditLog::new("/tmp/vp-test-transparent.json")),
        access_log: None,
        rotation_hook: None,
        mint_wi_mcp: Arc::new(crate::rotate::strategies::SshDockerMintExecutor::from_env()),
        change_wi_mcp_admin: Arc::new(
            crate::rotate::strategies::SshDockerAdminPasswordChanger::from_env(),
        ),
        notifier: Arc::new(Notifier::disabled()),
        handshake_completed: Arc::new(AtomicBool::new(false)),
        vault_folder: "vault-proxy".to_string(),
        last_resync_unix: Arc::new(AtomicU64::new(0)),
        internal_token: Arc::new("test-token".to_string()),
        cached_folder_id: Arc::new(tokio::sync::RwLock::new(None)),
        env_write_root: String::new(),
        config_dir: "/config".to_string(),
        proxy_timeout: 120,
        reload_mutex: Arc::new(tokio::sync::Mutex::new(())),
        audit_mutex: Arc::new(tokio::sync::Mutex::new(())),
        smb: SmbConfig::default(),
    }
}
