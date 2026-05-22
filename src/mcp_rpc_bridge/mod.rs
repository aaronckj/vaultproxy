//! Native HTTP MCP proxy that bridges a local stdio MCP client to a
//! remote streamable-HTTP / SSE MCP endpoint. Bearer token comes from
//! the vault-proxy local socket; never via argv or env.
//!
//! Wave 3 Task 8: empty scaffolding.
//! Wave 3 Task 9: header_injector implemented.
//! Wave 3 Task 10: stdio_server + Forwarder trait.
//! Wave 3 Task 11: http_client (impls Forwarder).
//! Wave 3 Task 12: run() wires them.

pub mod header_injector;
pub mod http_client;
pub mod stdio_server;

use anyhow::Result;

/// Capability to forward a JSON-RPC request to the upstream MCP and
/// return the response. Implemented by `http_client::HttpClient` for
/// production use, and by test fakes for the stdio_server tests.
#[async_trait::async_trait]
pub trait Forwarder: Send + Sync + 'static {
    async fn forward(&self, request: serde_json::Value) -> Result<serde_json::Value>;
}

/// Entry point invoked by `src/bin/mcp_rpc_bridge.rs`. Wave 3 Task 12
/// fills this in.
pub async fn run() -> Result<()> {
    anyhow::bail!("mcp-rpc-bridge not yet implemented — Wave 3 Task 12 wires the components together")
}
