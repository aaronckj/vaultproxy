//! Launcher mode — spawns "dumb" MCP servers with credentials injected via fork/exec.
//!
//! Dumb servers have no vault-proxy knowledge and read credentials from env vars.
//! This module resolves credentials from Vaultwarden at launch time and passes them
//! to the child process via the standard `Command::envs` mechanism (fork/exec).
//!
//! # Security note
//! Credentials injected via fork/exec exist in the child process's memory space.
//! On Linux, `/proc/<pid>/environ` allows any process running as the same OS user
//! to read these values. This is weaker than the `/proxy` model (where credentials
//! never leave vault-proxy) but stronger than storing credentials in `.env` files
//! (which persist on disk). See `SECURITY.md` for the full two-tier model.

use std::path::Path;
use std::process::Command;
use anyhow::{Context, Result};
use zeroize::Zeroizing;

#[derive(serde::Deserialize)]
struct McpServersFile {
    #[serde(default)]
    mcp_server: Vec<McpServerConfig>,
}

#[derive(serde::Deserialize)]
struct McpServerConfig {
    name: String,
    command: String,
    #[serde(default)]
    env: Vec<EnvMapping>,
}

#[derive(serde::Deserialize)]
struct EnvMapping {
    var: String,
    /// Static value — not secret, written directly into the env.
    value: Option<String>,
    /// Vault item name — resolved from Vaultwarden at launch time.
    vault_item: Option<String>,
    /// Which field to resolve: `"password"` (default) or `"username"`.
    field: Option<String>,
}

/// Resolve credentials and exec the named MCP server.
///
/// This function **does not return** on success — it calls `std::process::exit`
/// with the child's exit code, mirroring the child's lifecycle. On failure it
/// returns an `Err` so the caller can report the error and exit.
pub async fn launch(
    server_name: &str,
    config_dir: &str,
    vault: &crate::vault::VaultManager,
) -> Result<()> {
    let path = Path::new(config_dir).join("mcp-servers.toml");
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!(
            "could not read {:?} — create mcp-servers.toml in your config dir",
            path
        ))?;

    let parsed: McpServersFile = toml::from_str(&content)
        .context("failed to parse mcp-servers.toml")?;

    let server = parsed
        .mcp_server
        .into_iter()
        .find(|s| s.name == server_name)
        .with_context(|| format!(
            "no mcp_server named '{}' found in mcp-servers.toml",
            server_name
        ))?;

    // Resolve env vars — static values pass through, vault refs are decrypted.
    let mut resolved: Vec<(String, Zeroizing<String>)> = Vec::new();
    for mapping in server.env {
        if let Some(static_val) = mapping.value {
            resolved.push((mapping.var, Zeroizing::new(static_val)));
        } else if let Some(item_name) = mapping.vault_item {
            let field = mapping.field.as_deref().unwrap_or("password");
            let credential = vault
                .get_field_by_item_name(&item_name, field)
                .await
                .with_context(|| format!(
                    "failed to resolve vault item '{}' field '{}'",
                    item_name, field
                ))?;
            resolved.push((mapping.var, Zeroizing::new(credential)));
        } else {
            anyhow::bail!(
                "env mapping for '{}' must have either 'value' or 'vault_item'",
                mapping.var
            );
        }
    }

    // Parse the command string into program + args using shell word splitting
    // so quoted arguments and paths with spaces are handled correctly.
    let mut parts = shell_words::split(&server.command)
        .with_context(|| format!("failed to parse command: {}", server.command))?;
    if parts.is_empty() {
        anyhow::bail!("command is empty for mcp_server '{}'", server_name);
    }
    let program = parts.remove(0);

    tracing::info!(
        "launching '{}': {} (injecting {} env vars)",
        server_name,
        server.command,
        resolved.len()
    );

    // Safe env vars to inherit from parent (non-sensitive, needed for child to function)
    let safe_parent_vars = ["PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "TEMP", "TMP",
                             "LANG", "LC_ALL", "LC_CTYPE", "TERM", "XDG_RUNTIME_DIR"];

    let status = Command::new(&program)
        .args(&parts)
        .env_clear()
        .envs(safe_parent_vars.iter().filter_map(|k| {
            std::env::var(k).ok().map(|v| (k.to_string(), v))
        }))
        .envs(resolved.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .status()
        .with_context(|| format!("failed to spawn '{}'", program))?;

    std::process::exit(status.code().unwrap_or(1));
}

#[cfg(test)]
mod tests {
    /// Verify that McpServersFile deserializes a complete config correctly.
    #[test]
    fn test_mcp_servers_file_parses() {
        let toml = r#"
[[mcp_server]]
name = "test-server"
command = "echo hello"

  [[mcp_server.env]]
  var = "STATIC_VAR"
  value = "static-value"

  [[mcp_server.env]]
  var = "SECRET_VAR"
  vault_item = "my-vault-item"
  field = "password"
"#;
        let parsed: super::McpServersFile = toml::from_str(toml).unwrap();
        assert_eq!(parsed.mcp_server.len(), 1);
        let server = &parsed.mcp_server[0];
        assert_eq!(server.name, "test-server");
        assert_eq!(server.command, "echo hello");
        assert_eq!(server.env.len(), 2);
        assert_eq!(server.env[0].var, "STATIC_VAR");
        assert_eq!(server.env[0].value.as_deref(), Some("static-value"));
        assert!(server.env[0].vault_item.is_none());
        assert_eq!(server.env[1].var, "SECRET_VAR");
        assert_eq!(server.env[1].vault_item.as_deref(), Some("my-vault-item"));
        assert_eq!(server.env[1].field.as_deref(), Some("password"));
    }

    /// Verify that the `field` key is optional — absence means the runtime
    /// defaults to `"password"`.
    #[test]
    fn test_field_defaults_to_password() {
        let toml = r#"
[[mcp_server]]
name = "s"
command = "echo"
  [[mcp_server.env]]
  var = "X"
  vault_item = "some-item"
"#;
        let parsed: super::McpServersFile = toml::from_str(toml).unwrap();
        // `field` not set in the TOML — should deserialize to None.
        // The `"password"` default is applied at runtime by `unwrap_or`.
        assert!(parsed.mcp_server[0].env[0].field.is_none());
    }

    /// An env mapping with neither `value` nor `vault_item` is still valid
    /// TOML but the `launch()` function bails at runtime. Here we just verify
    /// that the struct deserializes without a panic.
    #[test]
    fn test_env_mapping_neither_field_deserializes() {
        let toml = r#"
[[mcp_server]]
name = "s"
command = "echo"
  [[mcp_server.env]]
  var = "EMPTY"
"#;
        let parsed: super::McpServersFile = toml::from_str(toml).unwrap();
        let mapping = &parsed.mcp_server[0].env[0];
        assert_eq!(mapping.var, "EMPTY");
        assert!(mapping.value.is_none());
        assert!(mapping.vault_item.is_none());
    }

    /// Multiple servers in one file.
    #[test]
    fn test_multiple_servers() {
        let toml = r#"
[[mcp_server]]
name = "server-a"
command = "cmd-a"

[[mcp_server]]
name = "server-b"
command = "cmd-b"
"#;
        let parsed: super::McpServersFile = toml::from_str(toml).unwrap();
        assert_eq!(parsed.mcp_server.len(), 2);
        assert_eq!(parsed.mcp_server[0].name, "server-a");
        assert_eq!(parsed.mcp_server[1].name, "server-b");
    }

    /// An empty file (no `[[mcp_server]]` sections) should parse to an empty Vec.
    #[test]
    fn test_empty_file_parses() {
        let toml = "";
        let parsed: super::McpServersFile = toml::from_str(toml).unwrap();
        assert!(parsed.mcp_server.is_empty());
    }
}
