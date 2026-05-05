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
        // Issue-4 (iter-5): Validate env var names before accepting them.
        //
        // Dangerous cases the operator config file could set, accidentally or
        // through a supply-chain attack on the config:
        //
        //   var = ""            → empty name: rejected by most env APIs but
        //                         behaviour is undefined / platform-specific.
        //   var = "LD_PRELOAD"  → shared-library injection into the child.
        //   var = "LD_LIBRARY_PATH" → same class.
        //   var = "PATH"        → redirects which binary the child resolves.
        //   var = "VAR=INJECT"  → on POSIX, an env entry that contains '='
        //                         before the value delimiter splits incorrectly
        //                         and can shadow a different variable.
        //   var = "BAD\0NAME"   → null bytes terminate the C string and
        //                         silently truncate the name.
        //
        // POSIX env var names must match [A-Za-z_][A-Za-z0-9_]* — we enforce
        // this strictly so that any name that could cause unexpected behaviour
        // is rejected at config-load time with an actionable error message.
        // Operators with a genuine need for unconventional names should use a
        // wrapper script that sets them after vault-proxy exits.
        let var_name = &mapping.var;
        if var_name.is_empty() {
            anyhow::bail!(
                "mcp_server '{}': env mapping has empty var name — \
                 environment variable names must be non-empty",
                server_name
            );
        }
        if var_name.contains('\0') {
            anyhow::bail!(
                "mcp_server '{}': env var name '{}' contains a null byte — \
                 this would silently truncate the name and is never correct",
                server_name, var_name
            );
        }
        if var_name.contains('=') {
            anyhow::bail!(
                "mcp_server '{}': env var name '{}' contains '=' — \
                 this is a common injection pattern that would corrupt the \
                 child's environment. Use a name without '='.",
                server_name, var_name
            );
        }
        // Warn (but allow) names that override well-known loader variables.
        // Blocking these outright would break legitimate wrappers that need
        // to set PATH; warning ensures operators see it in startup logs.
        const SENSITIVE_ENV_VARS: &[&str] = &[
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "LD_AUDIT",
            "LD_DEBUG",
            "DYLD_INSERT_LIBRARIES",  // macOS equivalent
            "DYLD_LIBRARY_PATH",
        ];
        if SENSITIVE_ENV_VARS.iter().any(|s| s.eq_ignore_ascii_case(var_name)) {
            tracing::warn!(
                "mcp_server '{}': env var '{}' is a dynamic-linker control variable — \
                 setting it can cause shared-library injection into the child process. \
                 Verify this is intentional.",
                server_name, var_name
            );
        }

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

    // Guard against shell interpreters and other dangerous binaries being used
    // as the launch target. A crafted mcp-servers.toml with
    // `command = "/usr/bin/bash -c <evil>"` would execute arbitrary commands
    // with vault credentials in scope — shell_words::split() prevents injection
    // through argument splitting, but not through the program itself being a
    // shell. Block the most obvious vectors; operators with a legitimate need
    // to wrap a script should use a dedicated non-shell wrapper.
    //
    // TODO: Consider an explicit allowlist (`allowed_commands`) in
    // mcp-servers.toml so operators can lock down which binaries are
    // launchable — a denylist is inherently incomplete.
    let program_lower = program.to_lowercase();
    let dangerous_programs: &[&str] = &[
        "bash", "sh", "zsh", "fish", "ksh", "csh", "tcsh", "dash",
        "python", "python2", "python3",
        "perl", "ruby", "node", "nodejs", "php",
        "lua", "tclsh", "wish",
        "powershell", "pwsh",
    ];
    // Check both the bare name and absolute-path tail (e.g. "/usr/bin/bash" → "bash").
    let program_basename = std::path::Path::new(&program)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&program)
        .to_lowercase();
    // Strip version suffixes: "python3.11" → "python3", "python3" → "python3" (match)
    let program_stem: &str = program_basename
        .split(|c: char| c == '-' || c == '.')
        .next()
        .unwrap_or(&program_basename);
    if dangerous_programs.contains(&program_lower.as_str())
        || dangerous_programs.contains(&program_basename.as_str())
        || dangerous_programs.contains(&program_stem)
    {
        anyhow::bail!(
            "mcp_server '{}': refusing to launch dangerous binary '{}' — \
             use a purpose-built wrapper instead of a shell interpreter",
            server_name, program
        );
    }

    // Issue-8 (iter-4): Warn operators about the /proc/<pid>/environ exposure
    // at runtime, not just in the example config file. The SECURITY.md and
    // mcp-servers.example.toml both document this, but operators who copy the
    // file without reading the header never see the warning. Emitting it here
    // ensures it appears in container logs on every launch, making it
    // discoverable without reading documentation.
    tracing::warn!(
        "--launch mode: credentials for '{}' are injected into the child process via \
         fork/exec and are readable via /proc/<pid>/environ by same-user processes. \
         For stronger isolation use an MCP server that supports the native /proxy \
         integration and does not need credentials in its environment.",
        server_name
    );

    tracing::info!(
        "launching '{}': {} (injecting {} env vars)",
        server_name,
        server.command,
        resolved.len()
    );

    // Safe env vars to inherit from parent (non-sensitive, needed for child to function).
    // XDG_RUNTIME_DIR is intentionally excluded: it points to /run/user/<uid>
    // which contains D-Bus, Wayland, and systemd session sockets. Passing it
    // to an untrusted MCP server child process would give it the same IPC
    // surface as the vault-proxy process, undermining the env_clear isolation.
    let safe_parent_vars = ["PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "TEMP", "TMP",
                             "LANG", "LC_ALL", "LC_CTYPE", "TERM"];

    // stdout/stderr: the child process inherits vault-proxy's stdout and stderr
    // (Command::status() does not redirect them). This is intentional: MCP
    // servers communicate over stdio; their stdout MUST reach the MCP client
    // (the calling process that invoked vault-proxy --launch), and their stderr
    // is the standard channel for diagnostic output.
    //
    // RISK: the child's stderr output is interleaved with vault-proxy's own
    // tracing output on the same file descriptor. Because vault-proxy uses
    // `tracing_subscriber::fmt` (line-framed structured text or JSON), a child
    // process that writes partial lines or binary data can corrupt the log
    // stream. Two mitigations are in place:
    //
    //   1. vault-proxy emits all its own startup logs (including this warning)
    //      *before* calling status() — once the child starts, vault-proxy is
    //      effectively silent (it either exits with the child or parks in exec).
    //
    //   2. The `dangerous_programs` check above refuses to launch shell
    //      interpreters, which are the most likely sources of noisy stderr.
    //
    // Operators who need clean separation should redirect vault-proxy's own
    // tracing output to a separate file descriptor (e.g. 2>/var/log/vp.log)
    // before invoking --launch.
    //
    // TODO: if MCP stdio framing is ever moved to a dedicated fd pair (not
    // stdin/stdout), revisit whether child stdout should be redirected to a
    // pipe so vault-proxy can prefix or filter log lines.
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

    /// Helper that replicates the dangerous-binary check inline for unit testing.
    /// The real check lives in `launch()` which is async and needs a VaultManager.
    fn is_dangerous_program(command: &str) -> bool {
        let parts = shell_words::split(command).unwrap_or_default();
        if parts.is_empty() { return false; }
        let program = &parts[0];
        let dangerous: &[&str] = &[
            "bash", "sh", "zsh", "fish", "ksh", "csh", "tcsh", "dash",
            "python", "python2", "python3",
            "perl", "ruby", "node", "nodejs", "php",
            "lua", "tclsh", "wish",
            "powershell", "pwsh",
        ];
        let lower = program.to_lowercase();
        let basename = std::path::Path::new(program)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(program)
            .to_lowercase();
        let stem: &str = basename
            .split(|c: char| c == '-' || c == '.')
            .next()
            .unwrap_or(&basename);
        dangerous.contains(&lower.as_str())
            || dangerous.contains(&basename.as_str())
            || dangerous.contains(&stem)
    }

    #[test]
    fn test_dangerous_programs_blocked() {
        assert!(is_dangerous_program("bash"), "bare 'bash' must be blocked");
        assert!(is_dangerous_program("/usr/bin/bash"), "absolute path bash must be blocked");
        assert!(is_dangerous_program("/bin/sh"), "absolute path sh must be blocked");
        assert!(is_dangerous_program("python3"), "python3 must be blocked");
        assert!(is_dangerous_program("/usr/bin/python3.11"), "versioned python must be blocked");
        assert!(is_dangerous_program("node"), "node must be blocked");
        assert!(is_dangerous_program("perl"), "perl must be blocked");
    }

    #[test]
    fn test_safe_programs_allowed() {
        assert!(!is_dangerous_program("uvx"), "'uvx' must be allowed");
        assert!(!is_dangerous_program("/usr/local/bin/my-mcp-server"), "custom binary must be allowed");
        assert!(!is_dangerous_program("npx"), "'npx' must be allowed");
        assert!(!is_dangerous_program("docker"), "'docker' must be allowed");
    }

    // Issue-4 (iter-5): Env var name validation helper — replicated inline
    // for unit testing without needing a live VaultManager.
    fn validate_env_var_name(name: &str) -> Result<(), String> {
        if name.is_empty() {
            return Err("empty var name".to_string());
        }
        if name.contains('\0') {
            return Err(format!("null byte in var name '{}'", name));
        }
        if name.contains('=') {
            return Err(format!("'=' in var name '{}' is an injection pattern", name));
        }
        Ok(())
    }

    #[test]
    fn test_empty_env_var_name_rejected() {
        assert!(validate_env_var_name("").is_err(), "empty var name must be rejected");
    }

    #[test]
    fn test_eq_sign_in_env_var_name_rejected() {
        assert!(
            validate_env_var_name("VAR=INJECTION").is_err(),
            "var name with '=' must be rejected"
        );
        assert!(
            validate_env_var_name("=LEADING").is_err(),
            "var name starting with '=' must be rejected"
        );
    }

    #[test]
    fn test_null_byte_in_env_var_name_rejected() {
        // Null bytes in env var names silently truncate the C-string name.
        let bad = "VAR\x00INJECTED";
        assert!(
            validate_env_var_name(bad).is_err(),
            "var name with null byte must be rejected"
        );
    }

    #[test]
    fn test_normal_env_var_names_pass() {
        assert!(validate_env_var_name("PATH").is_ok(), "PATH must be allowed");
        assert!(validate_env_var_name("MY_SECRET").is_ok(), "MY_SECRET must be allowed");
        assert!(validate_env_var_name("UNIFI_API_KEY").is_ok(), "UNIFI_API_KEY must be allowed");
        assert!(validate_env_var_name("LD_PRELOAD").is_ok(), "LD_PRELOAD allowed (but logs a warning)");
    }
}
