//! Native HTTP MCP proxy that bridges a local stdio MCP client to a
//! remote streamable-HTTP / SSE MCP endpoint. Bearer token comes from
//! the vault-proxy local socket; never via argv or env.

pub mod header_injector;
pub mod http_client;
pub mod stdio_server;

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// Capability to forward a JSON-RPC request to the upstream MCP and
/// return the response. Implemented by `http_client::HttpClient` for
/// production use, and by test fakes for the stdio_server tests.
#[async_trait::async_trait]
pub trait Forwarder: Send + Sync + 'static {
    async fn forward(&self, request: serde_json::Value) -> Result<serde_json::Value>;
}

#[derive(serde::Deserialize, Debug)]
struct BridgeConfig {
    upstream: String,
    vault_item: String,
    field: String,
    #[serde(default = "default_refresh_secs")]
    refresh_secs: u64,
    #[serde(default)]
    socket: Option<PathBuf>,
}

fn default_refresh_secs() -> u64 {
    300
}

#[derive(clap::Parser, Debug)]
#[command(
    name = "mcp-rpc-bridge",
    about = "Native HTTP MCP proxy with vault-proxy bearer injection."
)]
struct Args {
    /// Named bridge config to load. Resolves to
    /// <config-dir>/bridges/<name>.toml.
    #[arg(long)]
    bridge: String,

    /// Override the default config dir (~/.config/vaultproxy).
    #[arg(long, env = "VAULTPROXY_CONFIG_DIR")]
    config_dir: Option<PathBuf>,
}

fn default_config_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        return PathBuf::from(xdg).join("vaultproxy");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".config").join("vaultproxy");
    }
    PathBuf::from("/etc/vaultproxy")
}

fn resolve_bridge_path(args: &Args) -> PathBuf {
    let base = args.config_dir.clone().unwrap_or_else(default_config_dir);
    base.join("bridges").join(format!("{}.toml", args.bridge))
}

pub async fn run() -> Result<()> {
    let args = Args::parse();
    let path = resolve_bridge_path(&args);
    let body = std::fs::read_to_string(&path)
        .with_context(|| format!("read bridge config {}", path.display()))?;
    let cfg: BridgeConfig = toml::from_str(&body)
        .with_context(|| format!("parse bridge config {}", path.display()))?;

    let socket = cfg
        .socket
        .clone()
        .unwrap_or_else(crate::local_socket::default_socket_path);

    tracing::info!(
        bridge = %args.bridge,
        upstream = %cfg.upstream,
        socket = %socket.display(),
        refresh_secs = cfg.refresh_secs,
        "mcp-rpc-bridge starting",
    );

    let injector = Arc::new(
        header_injector::HeaderInjector::new(
            socket,
            cfg.vault_item.clone(),
            cfg.field.clone(),
            Duration::from_secs(cfg.refresh_secs),
        )
        .await
        .with_context(|| format!("init header injector for bridge {}", args.bridge))?,
    );
    let client = Arc::new(
        http_client::HttpClient::new(cfg.upstream.clone(), injector)
            .with_context(|| format!("init http client for bridge {}", args.bridge))?,
    );

    stdio_server::serve(client)
        .await
        .with_context(|| format!("stdio server for bridge {}", args.bridge))
}

/// Test hook so integration tests can exercise the path resolver
/// without invoking `Args::parse()` (which would consume the test
/// runner's argv). Marked `#[doc(hidden)]` so it doesn't surface in
/// rustdoc output. Public because integration tests live in a
/// separate crate and `pub(crate)` would not be visible.
#[doc(hidden)]
pub fn test_resolve_bridge_path(args_bridge: &str, args_config_dir: Option<PathBuf>) -> PathBuf {
    resolve_bridge_path(&Args {
        bridge: args_bridge.to_string(),
        config_dir: args_config_dir,
    })
}
