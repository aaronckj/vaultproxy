//! Minimal stdio-to-HTTP MCP bridge with Bearer token injection.
//!
//! Designed to be launched by `vaultproxy --launch` so the Bearer token is
//! pulled from Vaultwarden via the local credential socket — never embedded
//! in this process's environment.
//!
//! Required env (one of):
//!   VAULT_ITEM    — name of the Vaultwarden item that holds the token
//!                   (preferred; queried via the vault-proxy credential socket)
//!   BEARER_TOKEN  — token verbatim (legacy / fallback)
//!
//! Required env (always):
//!   MCP_URL       — full URL of the remote HTTP MCP server
//!
//! Optional env:
//!   VAULT_FIELD          — field name on the vault item (default: "password")
//!   VAULT_PROXY_SOCKET   — override the credential socket path
//!
//! Execs `npx -y mcp-remote <url> --header "Authorization: Bearer <token>"`
//! via execve(2). All arguments are separate Vec elements so no shell
//! expansion happens — even if the token contains spaces or special chars.

use std::env;
use std::os::unix::process::CommandExt;
use std::process::Command;

use vaultproxy::bearer_bridge::{resolve_token, TokenError};
use vaultproxy::local_socket::default_socket_path;

fn main() {
    let url = env::var("MCP_URL").unwrap_or_else(|_| {
        eprintln!("mcp-bearer-bridge: MCP_URL env var is required");
        std::process::exit(1);
    });

    let rt = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("mcp-bearer-bridge: failed to start tokio runtime: {}", e);
            std::process::exit(1);
        }
    };
    let token_result = rt.block_on(resolve_token(|k| env::var(k).ok(), default_socket_path));
    let token = match token_result {
        Ok(t) => t,
        Err(TokenError::Missing) => {
            eprintln!("mcp-bearer-bridge: neither VAULT_ITEM nor BEARER_TOKEN env var is set");
            std::process::exit(1);
        }
        Err(TokenError::SocketFailed(e)) => {
            eprintln!("mcp-bearer-bridge: VAULT_ITEM resolution failed: {}", e);
            std::process::exit(1);
        }
    };

    let auth_header = format!("Authorization: Bearer {}", &*token);

    let err = Command::new("npx")
        .args([
            "-y",
            "mcp-remote",
            &url,
            "--header",
            &auth_header,
            "--allow-http",
        ])
        .exec();

    eprintln!("mcp-bearer-bridge: exec failed: {}", err);
    std::process::exit(1);
}
