//! Minimal stdio-to-HTTP MCP bridge with Bearer token injection.
//!
//! Designed to be launched by `vaultproxy --launch` so the Bearer token is
//! injected from Vaultwarden and never appears in any config file.
//!
//! Required env vars (injected by vaultproxy launcher):
//!   MCP_URL       - full URL of the remote HTTP MCP server
//!   BEARER_TOKEN  - Bearer token to inject as Authorization header
//!
//! Execs `npx -y mcp-remote <url> --header "Authorization: Bearer <token>"`.
//! npx is not on vaultproxy's shell-interpreter denylist, so this works from
//! --launch without modification to the launcher.
//!
//! Security: uses CommandExt::exec() which calls execve(2) directly.
//! All arguments are passed as separate Vec elements — no shell expansion,
//! no injection risk even if BEARER_TOKEN contains spaces or special chars.

use std::env;
use std::os::unix::process::CommandExt;
use std::process::Command;

fn main() {
    let url = env::var("MCP_URL").unwrap_or_else(|_| {
        eprintln!("mcp-bearer-bridge: MCP_URL env var is required");
        std::process::exit(1);
    });
    let token = env::var("BEARER_TOKEN").unwrap_or_else(|_| {
        eprintln!("mcp-bearer-bridge: BEARER_TOKEN env var is required");
        std::process::exit(1);
    });

    // "Authorization: Bearer <token>" passed as a single --header argument.
    // mcp-remote parses it as key: value — no shell involved at any step.
    let auth_header = format!("Authorization: Bearer {}", token);

    let err = Command::new("npx")
        .args(["-y", "mcp-remote", &url, "--header", &auth_header, "--allow-http"])
        .exec();

    eprintln!("mcp-bearer-bridge: exec failed: {}", err);
    std::process::exit(1);
}
