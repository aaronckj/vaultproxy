//! Thin entrypoint for the `mcp-rpc-bridge` binary. All logic lives in
//! the library module `vaultproxy::mcp_rpc_bridge` so it can be exercised
//! from integration tests without spawning the binary.

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Tracing initialization for the bridge — stderr only, since stdout
    // carries the JSON-RPC payload stream.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")))
        .init();
    vaultproxy::mcp_rpc_bridge::run().await
}
