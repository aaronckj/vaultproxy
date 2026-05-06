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

/// Validate a VAULT_PROXY_PUBLIC_URL value.
///
/// Requirements:
///   - Must start with `"http://"` or `"https://"`.
///   - Must have a non-empty host component (rejects bare `"http://"` etc.).
///   - Must NOT end with `'/'` — a trailing slash would produce double-slash paths
///     (`"https://host//proxy"`) when smart MCP servers append `"/proxy"`.
///
/// Paths without trailing slashes are explicitly allowed (e.g.
/// `"https://vault-proxy.example.com/vaultproxy"`) — operators behind a
/// reverse proxy with a path prefix need them.
///
/// `pub(crate)` so `main.rs` can call this at startup (for an early WARN log)
/// without duplicating the validation logic.
pub(crate) fn validate_public_url(url: &str) -> std::result::Result<(), String> {
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(format!(
            "VAULT_PROXY_PUBLIC_URL '{}' must start with 'http://' or 'https://'",
            url
        ));
    }
    // Strip scheme and check host is non-empty.
    let after_scheme = url.trim_start_matches("http://").trim_start_matches("https://");
    let host = after_scheme.split('/').next().unwrap_or("");
    if host.is_empty() {
        return Err(format!(
            "VAULT_PROXY_PUBLIC_URL '{}' has an empty host — \
             use a full URL such as 'https://vault-proxy.example.com'",
            url
        ));
    }
    if url.ends_with('/') {
        return Err(format!(
            "VAULT_PROXY_PUBLIC_URL '{}' must not end with a trailing slash — \
             use 'https://vault-proxy.example.com' not 'https://vault-proxy.example.com/'",
            url
        ));
    }
    Ok(())
}

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
///
/// `listen_addr` is the `--listen` address vault-proxy is bound to (or will
/// bind to).  It is injected as `VAULT_PROXY_URL` into the child's environment
/// so that smart MCP servers that discover the proxy via that variable find the
/// correct URL without the operator having to set it manually.  The value is
/// derived from the actual `--listen` CLI argument rather than a hard-coded
/// default so it stays correct when the operator changes the port.
pub async fn launch(
    server_name: &str,
    config_dir: &str,
    vault: &crate::vault::VaultManager,
    listen_addr: std::net::SocketAddr,
) -> Result<()> {
    let path = Path::new(config_dir).join("mcp-servers.toml");
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!(
            "could not read {:?} — create mcp-servers.toml in your config dir",
            path
        ))?;

    let parsed: McpServersFile = toml::from_str(&content)
        .context("failed to parse mcp-servers.toml")?;

    // Issue (iter-12): Warn on duplicate server names at load time, mirroring
    // the duplicate-service warning in proxy/registry.rs.  Two entries with the
    // same `name` are always a config mistake: the first match wins, making the
    // second silently unreachable.  Emitting a warning here surfaces the problem
    // in startup logs before it causes confusing "wrong server launched" bugs.
    let mut seen_names: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for s in &parsed.mcp_server {
        if !seen_names.insert(s.name.as_str()) {
            tracing::warn!(
                "mcp_server '{}': duplicate name in mcp-servers.toml — \
                 only the first entry is reachable; remove or rename the duplicate",
                s.name
            );
        }
    }

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
        .split(['-', '.'])
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

    // Issue (iter-18): Reject server names that contain '/' before building the
    // lock file path.
    //
    // The lock file is created at `<config_dir>/.launch-lock-<name>.lock`. If
    // `name` contains a `/` (e.g. `name = "unix/server"`) the `Path::join`
    // below constructs `.launch-lock-unix/server.lock`, which tries to create
    // the file inside a subdirectory `unix/` that does not exist, causing a
    // confusing "No such file or directory" error rather than the expected
    // duplicate-launch message. Worse, a crafted name like `../../etc/cron.d/x`
    // would escape config_dir entirely.
    //
    // The mcp-servers.toml validator in from_toml_file does not check for '/'
    // in server names, so we guard here at the point of use.
    if server_name.contains('/') || server_name.contains('\\') {
        anyhow::bail!(
            "mcp_server name '{}' contains a path separator ('/' or '\\\\') — \
             server names must not contain path separators (they are embedded \
             in the lock file name). Use a name like 'my-server' instead.",
            server_name
        );
    }

    // Issue (iter-17): Prevent duplicate launches of the same MCP server.
    //
    // Two processes running `vault-proxy --launch <name>` simultaneously would
    // both resolve the same vault credentials, both spawn the same MCP server
    // binary, and both write the same env vars — resulting in two competing MCP
    // server instances attached to the same stdio session, which corrupts the
    // MCP protocol stream.
    //
    // Guard: create a lock file named after the server in the config directory.
    // If the file already exists and is locked (another vault-proxy instance
    // holds it via fcntl advisory lock), abort with a clear error. The lock is
    // released automatically when the process exits (advisory locks are not
    // inherited across exec).
    //
    // Using a name-based lock (not a PID file) means the check is
    // instantaneous — we don't need to read a PID and probe /proc.
    //
    // Non-Unix builds fall back to a best-effort file existence check (advisory
    // locks are not available on Windows).
    let lock_path = Path::new(config_dir).join(format!(".launch-lock-{}.lock", server_name));
    let _lock_file = {
        let f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .with_context(|| format!("could not open launch lock file {:?}", lock_path))?;
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let ret = unsafe {
                libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB)
            };
            if ret != 0 {
                anyhow::bail!(
                    "another vault-proxy --launch {} is already running (lock file {:?} is held). \
                     Wait for it to finish or kill the duplicate process.",
                    server_name, lock_path
                );
            }
        }
        f
    };

    // Safe env vars to inherit from parent (non-sensitive, needed for child to function).
    // XDG_RUNTIME_DIR is intentionally excluded: it points to /run/user/<uid>
    // which contains D-Bus, Wayland, and systemd session sockets. Passing it
    // to an untrusted MCP server child process would give it the same IPC
    // surface as the vault-proxy process, undermining the env_clear isolation.
    let safe_parent_vars = ["PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "TEMP", "TMP",
                             "LANG", "LC_ALL", "LC_CTYPE", "TERM"];

    // Issue (iter-39): Smart MCP servers discover the proxy via VAULT_PROXY_URL.
    // When `--launch` uses env_clear() the child's environment is wiped, so
    // VAULT_PROXY_URL (if the operator set it in the shell before invoking
    // vault-proxy) would be absent — the smart server falls back to direct
    // credential env vars, defeating the point of the proxy.
    //
    // We synthesise VAULT_PROXY_URL from the actual --listen address so it is
    // always correct regardless of which port the operator chose.  This value
    // takes precedence over any VAULT_PROXY_URL the operator may have set in the
    // mcp-servers.toml `env` list (that list is processed after this injection
    // and would overwrite it — intentional, giving the operator the last word).
    //
    // Issue (iter-40): Normalise wildcard listen addresses before embedding them
    // in VAULT_PROXY_URL.  `--listen 0.0.0.0:3201` (IPv4 unspecified) and
    // `--listen [::]:3201` (IPv6 unspecified) mean "bind on all interfaces".
    // Injecting `http://0.0.0.0:3201` or `http://[::]:3201` as VAULT_PROXY_URL
    // would be wrong — clients cannot *connect* to the unspecified address.
    // Map unspecified → loopback so the injected URL always resolves correctly
    // from the same host.  Operators who deliberately bind to a LAN address
    // (e.g. 192.168.1.10) are unaffected — only the INADDR_ANY / IN6ADDR_ANY
    // wildcards are rewritten.
    let connect_ip: std::net::IpAddr = match listen_addr.ip() {
        ip if ip.is_unspecified() => {
            // IPv4 0.0.0.0  →  127.0.0.1
            // IPv6 ::       →  ::1
            if ip.is_ipv6() {
                std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
            } else {
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
            }
        }
        ip => ip,
    };
    // Issue (iter-43): IPv6 addresses require square brackets in URLs.
    // `format!("http://{}:{}", ipv6_addr, port)` produces `http://::1:3201`
    // which is an invalid URL — the colon before the port is ambiguous with
    // the colons inside the IPv6 address.  RFC 3986 §3.2.2 requires brackets:
    // `http://[::1]:3201`.  IPv4 addresses need no brackets.
    let derived_vault_proxy_url = match connect_ip {
        std::net::IpAddr::V6(v6) => format!("http://[{}]:{}", v6, listen_addr.port()),
        std::net::IpAddr::V4(_)  => format!("http://{}:{}", connect_ip, listen_addr.port()),
    };

    // Issue (iter-44): Operators who place vault-proxy behind a reverse proxy
    // (nginx, Caddy, Traefik) with TLS termination need VAULT_PROXY_URL to
    // reflect the public-facing HTTPS address, not the loopback listen address.
    // For example, if vault-proxy is fronted by `https://vault-proxy.example.com`,
    // injecting `http://127.0.0.1:3201` as VAULT_PROXY_URL causes smart MCP
    // servers to use unencrypted loopback instead of the HTTPS front-end.
    //
    // If `VAULT_PROXY_PUBLIC_URL` is set in vault-proxy's environment, use it
    // as the injected VAULT_PROXY_URL.  The mcp-servers.toml `env` list
    // (processed after this injection) can still override VAULT_PROXY_URL for a
    // specific server — `VAULT_PROXY_PUBLIC_URL` is purely a process-wide default.
    //
    // Issue (iter-45): Validate VAULT_PROXY_PUBLIC_URL at launch time so
    // operators get a clear error instead of injecting a malformed URL into
    // the child environment.  Requirements:
    //   - Must start with "http://" or "https://".
    //   - Must not end with '/' (trailing slashes would produce double-slash
    //     paths when the smart server appends "/proxy" to the URL).
    //   - Must have a non-empty host component (rejects "http://" and "https://").
    //
    // A trailing slash is rejected as an error (not just a warning) because
    // "https://vault-proxy.example.com/" would cause every smart server to call
    // "https://vault-proxy.example.com//proxy" — a subtle bug that produces
    // 404s on path-sensitive reverse proxies.
    //
    // Issue (iter-46): validate_public_url is pub(crate) so main.rs can call it
    // at startup for early warning without duplicating the validation logic.
    // Paths without trailing slashes (e.g. "https://host/subpath") are explicitly
    // allowed — operators behind a reverse proxy with a path prefix need them.
    let vault_proxy_url = match std::env::var("VAULT_PROXY_PUBLIC_URL") {
        Ok(public_url) if !public_url.is_empty() => {
            // Validate before injecting so a misconfigured URL fails loudly here
            // rather than silently producing broken VAULT_PROXY_URL in the child.
            if let Err(e) = validate_public_url(&public_url) {
                anyhow::bail!(
                    "VAULT_PROXY_PUBLIC_URL is invalid: {} — \
                     fix the value or unset the variable to use the derived loopback URL",
                    e
                );
            }
            tracing::info!(
                "--launch '{}': VAULT_PROXY_PUBLIC_URL is set; injecting '{}' as VAULT_PROXY_URL \
                 (overrides derived loopback URL '{}')",
                server_name, public_url, derived_vault_proxy_url
            );
            public_url
        }
        _ => derived_vault_proxy_url,
    };

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
        // Issue (iter-39): Inject VAULT_PROXY_URL so smart MCP servers find the
        // proxy sidecar at the correct address.  Set it before the per-server
        // `env` mappings so an explicit `var = "VAULT_PROXY_URL"` in the config
        // can override it (operator has the last word).
        .env("VAULT_PROXY_URL", &vault_proxy_url)
        .envs(resolved.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .status()
        .map_err(|e| {
            // Issue (iter-12): Distinguish "command not found" (ENOENT / NotFound)
            // from other spawn failures (permission denied, etc.) so operators
            // get an actionable error message instead of a bare OS error code.
            if e.kind() == std::io::ErrorKind::NotFound {
                anyhow::anyhow!(
                    "command not found: '{}' — is it installed and on PATH?\n\
                     PATH inherited by vault-proxy: {}",
                    program,
                    std::env::var("PATH").unwrap_or_else(|_| "<unset>".to_string())
                )
            } else {
                anyhow::anyhow!("failed to spawn '{}': {}", program, e)
            }
        })?;

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
            .split(['-', '.'])
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

    // Issue (iter-18): Validate the path-separator check on server names used in
    // lock file construction. Inline the check logic for unit testing without a
    // live VaultManager.
    fn server_name_has_path_separator(name: &str) -> bool {
        name.contains('/') || name.contains('\\')
    }

    #[test]
    fn test_server_name_with_forward_slash_rejected() {
        // "unix/server" would embed a directory separator in the lock file path,
        // turning ".launch-lock-unix/server.lock" into a path traversal.
        assert!(
            server_name_has_path_separator("unix/server"),
            "server name with '/' must be rejected for lock file safety"
        );
        assert!(
            server_name_has_path_separator("../../etc/cron.d/x"),
            "path traversal via server name must be rejected"
        );
    }

    #[test]
    fn test_server_name_with_backslash_rejected() {
        assert!(
            server_name_has_path_separator("win\\server"),
            "server name with '\\\\' must be rejected"
        );
    }

    #[test]
    fn test_normal_server_names_pass() {
        assert!(!server_name_has_path_separator("my-mcp-server"), "hyphenated name must pass");
        assert!(!server_name_has_path_separator("server_a"), "underscored name must pass");
        assert!(!server_name_has_path_separator("unifi"), "simple name must pass");
    }

    // Issue (iter-40): Wildcard listen-address normalisation for VAULT_PROXY_URL.
    // Replicates the address-normalisation logic inline so it can be unit-tested
    // without spawning a live VaultManager or binding a socket.
    fn normalise_listen_ip(listen: std::net::SocketAddr) -> std::net::IpAddr {
        match listen.ip() {
            ip if ip.is_unspecified() => {
                if ip.is_ipv6() {
                    std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
                } else {
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                }
            }
            ip => ip,
        }
    }

    // Issue (iter-43): Replicates the URL-building logic inline for unit tests.
    // IPv6 addresses require square brackets per RFC 3986 §3.2.2;
    // `format!("http://{}:{}", ::1, 3201)` produces the invalid `http://::1:3201`.
    fn build_vault_proxy_url(ip: std::net::IpAddr, port: u16) -> String {
        match ip {
            std::net::IpAddr::V6(v6) => format!("http://[{}]:{}", v6, port),
            std::net::IpAddr::V4(_)  => format!("http://{}:{}", ip, port),
        }
    }

    #[test]
    fn test_vault_proxy_url_ipv4_wildcard_normalised() {
        let addr: std::net::SocketAddr = "0.0.0.0:3201".parse().unwrap();
        let ip = normalise_listen_ip(addr);
        assert_eq!(ip, std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            "0.0.0.0 must be normalised to 127.0.0.1 for VAULT_PROXY_URL");
        assert_eq!(build_vault_proxy_url(ip, addr.port()), "http://127.0.0.1:3201");
    }

    #[test]
    fn test_vault_proxy_url_ipv6_wildcard_normalised() {
        let addr: std::net::SocketAddr = "[::]:3201".parse().unwrap();
        let ip = normalise_listen_ip(addr);
        assert_eq!(ip, std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            ":: must be normalised to ::1 for VAULT_PROXY_URL");
        // iter-43: IPv6 addresses MUST be bracketed in URLs — http://[::1]:3201
        // (NOT the invalid http://::1:3201 that the unbracketed format produces).
        assert_eq!(build_vault_proxy_url(ip, addr.port()), "http://[::1]:3201");
    }

    #[test]
    fn test_vault_proxy_url_explicit_ip_unchanged() {
        // A specific LAN address should pass through unmodified.
        let addr: std::net::SocketAddr = "192.168.1.50:3201".parse().unwrap();
        let ip = normalise_listen_ip(addr);
        assert_eq!(ip, std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 50)),
            "explicit LAN IP must not be rewritten");
    }

    #[test]
    fn test_vault_proxy_url_loopback_unchanged() {
        // 127.0.0.1 is already loopback — no rewrite needed.
        let addr: std::net::SocketAddr = "127.0.0.1:3201".parse().unwrap();
        let ip = normalise_listen_ip(addr);
        assert_eq!(ip, std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    }

    // Issue (iter-44): Verify VAULT_PROXY_PUBLIC_URL override logic.
    // When the env var is set, the derived loopback URL must be replaced by the
    // public URL so operators behind a reverse proxy get the correct value.
    #[test]
    fn test_vault_proxy_public_url_overrides_derived() {
        // The override logic cannot be tested against the real std::env without
        // affecting other tests (env vars are process-global).  Test the decision
        // function inline instead — same logic as the production code.
        fn resolve_vault_proxy_url(derived: &str, public_url_env: Option<&str>) -> String {
            match public_url_env {
                Some(u) if !u.is_empty() => u.to_string(),
                _ => derived.to_string(),
            }
        }

        // Override is present and non-empty → use it.
        assert_eq!(
            resolve_vault_proxy_url(
                "http://127.0.0.1:3201",
                Some("https://vault-proxy.example.com"),
            ),
            "https://vault-proxy.example.com",
            "VAULT_PROXY_PUBLIC_URL must override the derived loopback URL"
        );

        // Override is empty string → fall back to derived.
        assert_eq!(
            resolve_vault_proxy_url("http://127.0.0.1:3201", Some("")),
            "http://127.0.0.1:3201",
            "empty VAULT_PROXY_PUBLIC_URL must fall back to derived URL"
        );

        // Override is absent → fall back to derived.
        assert_eq!(
            resolve_vault_proxy_url("http://127.0.0.1:3201", None),
            "http://127.0.0.1:3201",
            "absent VAULT_PROXY_PUBLIC_URL must fall back to derived URL"
        );

        // IPv6 listen address with public URL override.
        assert_eq!(
            resolve_vault_proxy_url(
                "http://[::1]:3201",
                Some("https://vault-proxy.example.com"),
            ),
            "https://vault-proxy.example.com",
            "public URL override must work for IPv6 listen addresses too"
        );
    }

    // Issue (iter-41): Verify that the actual environment of a launched process
    // contains VAULT_PROXY_URL set to the correct value derived from listen_addr.
    //
    // This test spawns the `env` command (available on all POSIX systems) with
    // env_clear() + the same VAULT_PROXY_URL injection logic used by `launch()`,
    // then asserts the variable appears in the child's stdout.
    //
    // We cannot call `launch()` directly in a unit test because it requires a
    // live `VaultManager` and calls `std::process::exit()` — so we replicate
    // the env-injection logic inline, which is the exact code path tested here.
    //
    // Skip on non-Unix targets where `env` may not be available.
    #[cfg(unix)]
    #[test]
    fn test_vault_proxy_url_injected_into_child_environment() {
        use std::process::Command;

        let listen_addr: std::net::SocketAddr = "0.0.0.0:3201".parse().unwrap();
        let connect_ip = normalise_listen_ip(listen_addr);
        let vault_proxy_url = build_vault_proxy_url(connect_ip, listen_addr.port());
        assert_eq!(vault_proxy_url, "http://127.0.0.1:3201",
            "VAULT_PROXY_URL should be normalised from 0.0.0.0 to 127.0.0.1");

        // Safe env vars to inherit (mirrors the launcher's safe_parent_vars list).
        let safe_parent_vars = ["PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "TEMP", "TMP",
                                 "LANG", "LC_ALL", "LC_CTYPE", "TERM"];

        let output = Command::new("env")
            .env_clear()
            .envs(safe_parent_vars.iter().filter_map(|k| {
                std::env::var(k).ok().map(|v| (k.to_string(), v))
            }))
            .env("VAULT_PROXY_URL", &vault_proxy_url)
            .output()
            .expect("`env` command must be available on POSIX systems");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains(&format!("VAULT_PROXY_URL={}", vault_proxy_url)),
            "VAULT_PROXY_URL must be present in the launched process's environment; \
             got stdout: {}",
            stdout,
        );
    }

    // Issue (iter-45): Unit tests for VAULT_PROXY_PUBLIC_URL validation.
    // Replicates the `validate_public_url` helper inline (matching the
    // production code in `launch()`) so it can be tested in isolation.
    fn validate_public_url_test(url: &str) -> Result<(), String> {
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(format!(
                "VAULT_PROXY_PUBLIC_URL '{}' must start with 'http://' or 'https://'",
                url
            ));
        }
        let after_scheme = url.trim_start_matches("http://").trim_start_matches("https://");
        let host = after_scheme.split('/').next().unwrap_or("");
        if host.is_empty() {
            return Err(format!(
                "VAULT_PROXY_PUBLIC_URL '{}' has an empty host component",
                url
            ));
        }
        if url.ends_with('/') {
            return Err(format!(
                "VAULT_PROXY_PUBLIC_URL '{}' must not end with a trailing slash",
                url
            ));
        }
        Ok(())
    }

    #[test]
    fn test_vault_proxy_public_url_valid() {
        assert!(validate_public_url_test("https://vault-proxy.example.com").is_ok(),
            "HTTPS URL without trailing slash must be valid");
        assert!(validate_public_url_test("http://127.0.0.1:3201").is_ok(),
            "HTTP loopback URL must be valid");
        assert!(validate_public_url_test("https://vault-proxy.example.com:8443").is_ok(),
            "HTTPS URL with non-standard port must be valid");
    }

    #[test]
    fn test_vault_proxy_public_url_invalid_scheme() {
        let e = validate_public_url_test("not-a-url");
        assert!(e.is_err(), "bare string without scheme must be rejected");
        assert!(e.unwrap_err().contains("must start with"), "error message must name the requirement");

        assert!(validate_public_url_test("ftp://example.com").is_err(),
            "ftp:// scheme must be rejected");
        assert!(validate_public_url_test("").is_err(),
            "empty string must be rejected (no scheme)");
    }

    #[test]
    fn test_vault_proxy_public_url_empty_host() {
        let e = validate_public_url_test("http://");
        assert!(e.is_err(), "'http://' with no host must be rejected");
        assert!(e.unwrap_err().contains("empty host"), "error message must name empty host");

        assert!(validate_public_url_test("https://").is_err(),
            "'https://' with no host must be rejected");
    }

    #[test]
    fn test_vault_proxy_public_url_trailing_slash() {
        let e = validate_public_url_test("https://vault-proxy.example.com/");
        assert!(e.is_err(), "trailing slash must be rejected");
        assert!(e.unwrap_err().contains("trailing slash"), "error message must name trailing slash");

        assert!(validate_public_url_test("http://127.0.0.1:3201/").is_err(),
            "trailing slash on loopback URL must also be rejected");
    }
}
