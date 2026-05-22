//! Native HTTP MCP proxy that bridges a local stdio MCP client (e.g.
//! Claude Code launching a server entry) to a remote streamable-HTTP /
//! SSE MCP endpoint. The bearer token for the remote is fetched from the
//! vault-proxy local socket at startup and re-fetched on a configurable
//! interval (default 5 min) or on demand when the upstream returns 401.
//!
//! The token never enters argv, env, or any child process tree — closing
//! the leak that exists in `src/bearer_bridge.rs` where the legacy
//! invocation execs `npx mcp-remote --header "Authorization: Bearer ..."`
//! and exposes the token via /proc/<pid>/cmdline.
//!
//! Wave 3 Task 8: empty scaffolding. The functional implementation
//! arrives in Tasks 9 (header_injector), 10 (stdio_server),
//! 11 (http_client), 12 (run() wires them together), 13 (consumer
//! migration in mcp-servers.toml).

pub mod header_injector;
pub mod http_client;
pub mod stdio_server;

use anyhow::Result;

/// Entry point invoked by `src/bin/mcp_rpc_bridge.rs`. Empty stub for
/// Task 8 — will load the bridge config, instantiate the header
/// injector + http client + stdio server, and run the dispatch loop.
pub async fn run() -> Result<()> {
    anyhow::bail!("mcp-rpc-bridge not yet implemented — Wave 3 Task 12 wires the components together")
}
