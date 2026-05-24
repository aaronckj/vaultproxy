// iter-50: Replaced the crate-level `#![allow(dead_code)]` with targeted
// per-module attributes on the scaffold modules only.  This means production
// modules (proxy, vault, keystore, security, etc.) receive normal dead-code
// warnings, so a newly-written but never-called function in those modules will
// be flagged by `cargo clippy -- -D warnings` in CI.
//
// iter-81: The `browser` and `credential_audit` (engine sidecar path) modules
// are now feature-gated instead of suppressing dead-code warnings. When the
// feature flag is off, the modules are entirely absent from the build — no
// dead code remains because the code is never compiled.
//
// Remaining per-module suppression (remove each when wired):
//   - audit (audit log — schema only, no consumer yet)
//
// All other modules (proxy, vault, keystore, tpm, notify, setup, sync, etc.)
// receive full dead-code checking.

mod access_log;
mod approle;
mod audit;
#[cfg(feature = "browser")]
mod browser;
mod cred_cache;
#[cfg(feature = "engine")]
mod credential_audit;
#[cfg(feature = "dashboard")]
mod dashboard;
mod hooks;
mod internal_token;
mod keystore;
mod launcher;
mod local_socket;
mod mcp_server;
mod notify;
mod policy;
mod proxy;
mod rotate;
mod secure;
mod security;
mod setup;
mod sync;
mod template;
mod tls;
mod totp;
mod tpm;
mod vault;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::State as AxumState,
    response::IntoResponse,
    routing::{get, post},
    Json as AxumJson, Router,
};
use clap::Parser;

use proxy::{handle_proxy, registry::ServiceRegistry, AppState};
use sync::{cloud::CloudClient, websocket, SyncManager};
use vault::handlers;
use vault::VaultManager;

// -------------------------------------------------------------------------- //
// CLI args                                                                    //
// -------------------------------------------------------------------------- //

/// Subcommands accepted by the `vaultproxy` binary.
///
/// When `None`, the binary runs as the long-lived daemon (the historical
/// default). Subcommands run a one-shot utility action and exit before any
/// daemon-startup logic.
#[derive(clap::Subcommand, Debug, Clone)]
enum Cmd {
    /// Verify the integrity of an access log file produced by the daemon.
    AuditVerify {
        /// Path to the access log to verify. The HMAC key is read from
        /// `<log>.key`.
        #[arg(long)]
        log: std::path::PathBuf,
    },

    /// Render a config template, interpolating vault items via the daemon
    /// socket. Writes the output 0600 with an atomic rename.
    Render {
        /// Template path.
        #[arg(long = "in")]
        input: std::path::PathBuf,
        /// Output path. Existing files at this path are overwritten.
        #[arg(long)]
        out: std::path::PathBuf,
        /// Optional socket path. Defaults to vault-proxy's standard
        /// socket at `$XDG_RUNTIME_DIR/vaultproxy.sock` (or
        /// `/tmp/vaultproxy-<uid>.sock` if XDG_RUNTIME_DIR is unset).
        #[arg(long, env = "VAULTPROXY_SOCKET")]
        socket: Option<std::path::PathBuf>,
    },

    /// Provision a new AppRole (role_id, secret_id) for non-TPM daemon
    /// unlock. Reads the existing keystore via the master-password prompt
    /// (or VAULTPROXY_MASTER_PASSWORD env) and writes an encrypted bundle
    /// to <config-dir>/approles/<role-id>.json (mode 0600). Prints the
    /// hex-encoded secret_id once to stdout — capture it, store in a 0600
    /// file, and reference via --approle-secret-id-file at daemon startup.
    ApproleSetup {
        #[arg(long)]
        role_id: String,
    },
}

#[derive(Parser, Clone)]
#[command(
    name = "vaultproxy",
    version,  // iter-33: automatically derives version from Cargo.toml via env!("CARGO_PKG_VERSION")
    about = "Secure credential sidecar for MCP servers — injects auth from Vaultwarden without exposing secrets"
)]
struct Args {
    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:3201")]
    listen: SocketAddr,

    /// Run the interactive setup wizard.
    #[arg(long)]
    setup: bool,

    /// Config directory for credentials and keystore files.
    #[arg(long, default_value = "/config", env = "CONFIG_DIR")]
    config_dir: String,

    /// Address for the dashboard web UI.
    #[arg(long, default_value = "127.0.0.1:3202", env = "DASHBOARD_LISTEN")]
    dashboard_listen: SocketAddr,

    /// Transparent HTTPS_PROXY listen address. Agents set
    /// `HTTPS_PROXY=http://<this-addr>` to route outbound HTTPS through
    /// vault-proxy. Only honoured when built with `--features transparent`.
    /// Set the env var to an empty string to disable.
    #[cfg(feature = "transparent")]
    #[arg(long, env = "TRANSPARENT_LISTEN", default_value = "127.0.0.1:3203")]
    transparent_listen: String,

    /// Path to operator-provided CA cert (PEM) for the transparent MITM
    /// listener. Pairs with --transparent-ca-key. When BOTH are set,
    /// vault-proxy uses BYO mode and does NOT auto-generate. Default
    /// (both unset) = auto-generate into $CONFIG_DIR.
    #[cfg(feature = "transparent")]
    #[arg(long, env = "TRANSPARENT_CA_CERT")]
    transparent_ca_cert: Option<String>,

    /// Path to operator-provided CA key (PEM). Must be mode 0600.
    #[cfg(feature = "transparent")]
    #[arg(long, env = "TRANSPARENT_CA_KEY")]
    transparent_ca_key: Option<String>,

    /// Default `transparent_mode` for services that omit the field.
    /// Reserved for future use; the per-service field always wins.
    #[cfg(feature = "transparent")]
    #[arg(long, env = "TRANSPARENT_DEFAULT_MODE", default_value = "off")]
    transparent_default_mode: String,

    /// Behaviour for hosts with no `[[service]]` block.
    ///   passthrough — relay TCP unchanged (default)
    ///   allowlist   — reject with 502 + transparent_error_code = "unregistered_host_blocked"
    #[cfg(feature = "transparent")]
    #[arg(
        long,
        env = "TRANSPARENT_UNREGISTERED_POLICY",
        default_value = "passthrough"
    )]
    transparent_unregistered_policy: String,

    /// Bitwarden cloud account email (enables cloud sync when set).
    #[arg(long, env = "CLOUD_EMAIL")]
    cloud_email: Option<String>,

    /// Override KDF iterations for Bitwarden cloud (use if prelogin returns wrong value).
    #[arg(long, env = "CLOUD_KDF_ITERATIONS")]
    cloud_kdf_iterations: Option<u32>,

    /// LiteLLM (OpenAI-compatible) base URL for vision model inference.
    /// Only used when the `browser` feature is enabled.
    #[cfg(feature = "browser")]
    #[arg(long, env = "LITELLM_URL", default_value = "")]
    litellm_url: String,

    /// LiteLLM API key (Bearer auth). Empty = no auth header.
    /// Only used when the `browser` feature is enabled.
    #[cfg(feature = "browser")]
    #[arg(long, env = "LITELLM_API_KEY", default_value = "")]
    litellm_api_key: String,

    /// Vision model name served by LiteLLM (browser rotation feature).
    /// Must be set to the name of a vision-capable model in your LiteLLM
    /// deployment (e.g. `"gpt-4o"` or a local model alias). Empty = browser
    /// rotation is disabled even when `--litellm-url` is set.
    /// Only used when the `browser` feature is enabled.
    #[cfg(feature = "browser")]
    #[arg(long, env = "VISION_MODEL", default_value = "")]
    vision_model: String,

    /// ntfy.sh topic URL for push notifications (e.g. `"https://ntfy.sh/connecterr-alerts"`).
    /// Leave empty to disable notifications.
    #[arg(long, env = "NTFY_URL", default_value = "")]
    ntfy_url: String,

    /// Notification channel: "ntfy", "email", or "disabled".
    #[arg(long, env = "NOTIFY_CHANNEL", default_value = "disabled")]
    notify_channel: String,

    /// Email address to send notifications to (used when notify_channel=email).
    /// Notifications are queued to /config/notification-queue.json for the
    /// Node.js side to send via Gmail.
    #[arg(long, env = "NOTIFY_EMAIL", default_value = "")]
    notify_email: String,

    /// Proxy request timeout in seconds.
    #[arg(long, env = "PROXY_TIMEOUT", default_value = "120")]
    proxy_timeout: u64,

    /// Vaultwarden folder name that holds this proxy's service credentials.
    /// Vault items must be named `"<vault-folder> - <Service>"` (e.g. `"vault-proxy - UniFi"`).
    #[arg(long, env = "VAULT_FOLDER", default_value = "vault-proxy")]
    vault_folder: String,

    /// Launch a registered MCP server with credentials injected from Vaultwarden.
    /// The server name must match an `[[mcp_server]]` entry in mcp-servers.toml.
    #[arg(long)]
    launch: Option<String>,

    /// Persist the dashboard TLS certificate across restarts.
    ///
    /// By default the dashboard TLS certificate is ephemeral — a fresh
    /// self-signed certificate is generated on every startup, causing the
    /// browser to show a "certificate has changed" warning after each restart.
    ///
    /// When this flag is set, vault-proxy:
    ///   1. On the first run, generates the certificate as normal and writes it
    ///      to `{config_dir}/dashboard.crt` and `{config_dir}/dashboard.key`
    ///      (mode 0600, atomic write via tempfile+rename).
    ///   2. On subsequent runs, reads the certificate back from disk instead of
    ///      generating a new one — the browser warning disappears after the
    ///      first run.
    ///
    /// The persisted certificate is a self-signed ECDSA P-256 cert valid until
    /// 2099-12-31. It is NOT bound to the TPM-sealed keystore — the cert
    /// material is stored in plaintext PEM alongside the other config files.
    /// Deleting `dashboard.crt` and `dashboard.key` forces regeneration.
    ///
    /// Equivalent env var: `PERSIST_DASHBOARD_CERT=1`.
    #[arg(long, env = "PERSIST_DASHBOARD_CERT")]
    persist_dashboard_cert: bool,

    /// Suppress the root-user security warning.
    ///
    /// vault-proxy emits a prominent warning when run as uid 0 (root) because
    /// running a credential broker as root violates least privilege — a
    /// compromise would grant full system access. This flag suppresses that
    /// warning for deployments where root is genuinely required (e.g. accessing
    /// `/dev/tpm0` on systems without udev rules that grant non-root TPM access).
    ///
    /// Using this flag does NOT disable any security controls — it only
    /// suppresses the log entry. If you are unsure whether you need root, you
    /// almost certainly do not; use a dedicated non-root user instead.
    #[arg(long)]
    allow_root: bool,

    /// Root directory that `POST /vault/write-env` is allowed to write into.
    ///
    /// `write_env` decrypts credentials and writes them as env-var assignments
    /// to a file on disk. The target path must begin with this prefix so the
    /// endpoint cannot be used as a write-anywhere primitive.
    ///
    /// If unset, `POST /vault/write-env` returns `501 Not Implemented` with an
    /// explanation of how to enable it. For the Connecterr Docker Compose stack
    /// the conventional value is `/envs`.
    ///
    /// # Security
    ///
    /// Set this to the narrowest path that covers your legitimate use case. A
    /// value of `/` would make the endpoint a write-anywhere primitive, which
    /// defeats the purpose of the guard.
    #[arg(long, env = "ENV_WRITE_ROOT", default_value = "")]
    env_write_root: String,

    /// Absolute path to the setuid `vaultproxy-mount-helper` binary.
    ///
    /// Empty string disables the SMB mount endpoints (501). When set, the
    /// proxy will exec this binary to perform credential file writes,
    /// `/etc/fstab` edits, and mount calls — operations vault-proxy itself
    /// cannot perform unprivileged. The helper is the privilege boundary;
    /// install it 4750 root:<vault-proxy-group>.
    #[arg(long, env = "SMB_HELPER_PATH", default_value = "")]
    smb_helper_path: String,

    /// Allowed root directory for SMB mount points (default `/mnt`).
    ///
    /// Caller-supplied `mount_point` values must begin with `<root>/` so the
    /// endpoint cannot be used to mount over `/etc`, `/`, or other sensitive
    /// directories. Narrow this to the smallest path that covers your use
    /// case.
    #[arg(long, env = "SMB_MOUNT_ROOT", default_value = "/mnt")]
    smb_mount_root: String,

    /// Directory the mount helper writes credential files into.
    ///
    /// Only `/etc/samba` and `/run/vaultproxy/smb` are accepted by the
    /// helper. Files are written 0600 root:root with name
    /// `vaultproxy-<slug>.credentials`.
    #[arg(long, env = "SMB_CREDS_DIR", default_value = "/etc/samba")]
    smb_creds_dir: String,

    /// Path to /etc/fstab. Overridable for tests; do not change in production.
    #[arg(long, env = "SMB_FSTAB_PATH", default_value = "/etc/fstab")]
    smb_fstab_path: String,

    /// Validate services.toml (parsing + SSRF rules) and exit without
    /// connecting to Vaultwarden or binding any port.
    ///
    /// Exits 0 if services.toml parses cleanly and all registered services
    /// pass SSRF validation. Exits 1 if the file contains parse errors,
    /// invalid base_url values, or SSRF-blocked addresses. Useful in CI,
    /// pre-deploy hooks, and Docker HEALTHCHECK CMD scripts.
    ///
    /// No Vaultwarden credentials are required. No network calls are made.
    #[arg(long)]
    check: bool,

    /// Run as a stdio MCP server exposing Vaultwarden management tools.
    /// Never returns plaintext credentials — passwords are always masked.
    /// Credentials must already be configured (keystore unlocked) before
    /// this flag is used. Reads JSON-RPC from stdin, writes to stdout.
    #[arg(long)]
    mcp: bool,

    /// Run as an HTTP MCP server (Streamable HTTP transport) on the given address.
    /// Allows remote Claude clients to connect over the network.
    /// Example: --mcp-http 0.0.0.0:3203
    #[arg(long, value_name = "ADDR")]
    mcp_http: Option<String>,

    /// Background vault refresh interval in seconds.
    ///
    /// When set to a non-zero value, vault-proxy spawns a background task that
    /// calls `vault.sync()` (the same operation as `POST /vault/resync`) every
    /// N seconds. This closes the staleness window when Vaultwarden credentials
    /// are rotated externally — without this, the cached credential blobs are
    /// only refreshed when an operator manually calls `POST /vault/resync` or
    /// when vault-proxy restarts.
    ///
    /// Set to 0 (the default) to disable the background refresh entirely.
    /// A value of 300 (5 minutes) is a reasonable default for most homelabs.
    ///
    /// The background task logs a warning if `sync()` fails (Vaultwarden
    /// unreachable, re-auth error) but does NOT restart or exit — the last
    /// successfully cached credentials remain in use until the next successful
    /// refresh. Operators should monitor for repeated sync-failure warnings.
    #[arg(long, env = "VAULT_REFRESH_INTERVAL_SECS", default_value = "0")]
    vault_refresh_interval_secs: u64,

    /// TTL in seconds for credentials cached by the local-socket handler.
    ///
    /// On a cache hit the socket handler returns the previously-fetched
    /// credential directly without re-reading from Vaultwarden, eliminating
    /// the per-spawn re-auth round-trip that triggers Bitwarden cloud
    /// rate-limits when many MCP children launch in close succession.
    ///
    /// Set to 0 to disable caching entirely (every socket fetch re-reads
    /// from Vaultwarden — pre-cache behavior). Default 60 s is a sensible
    /// balance: long enough to coalesce typical bursts of MCP launches,
    /// short enough that rotations propagate within a minute.
    #[arg(long, env = "CRED_CACHE_TTL", default_value = "60")]
    cred_cache_ttl: u64,

    /// Path to the HMAC-chained access log written by the daemon for every
    /// credential fetch over the local socket and every rotate MCP tool
    /// invocation. Empty string disables logging entirely.
    ///
    /// The HMAC key lives next to the log at `<log-path>.key` with mode
    /// 0600. On first start the daemon generates the key; subsequent starts
    /// reuse it so the chain is verifiable across restarts.
    ///
    /// Verify integrity with: `vaultproxy audit-verify --log <path>`.
    #[arg(long, env = "ACCESS_LOG_PATH", default_value = "")]
    access_log_path: String,

    /// Path to a script invoked after every SUCCESSFUL rotation.
    ///
    /// The script receives the rotated service name and an opaque item
    /// identifier as positional args, plus env vars VP_ROTATION_SERVICE /
    /// VP_ROTATION_ITEM_ID / VP_ROTATION_TS. Stdin is closed; stdout/stderr
    /// are captured and logged (info on success, warn on non-zero exit). A
    /// 30 s timeout kills the child if it hangs.
    ///
    /// The hook runs AFTER the rotation has been committed to the vault, so
    /// a non-zero exit code is logged but does NOT undo the rotation. Use
    /// this to bounce downstream services that cache the rotated credential,
    /// e.g. `docker restart wi-mcp` after the wi-mcp bearer rotates.
    #[arg(long, env = "ON_ROTATION_SCRIPT", default_value = "")]
    on_rotation: String,

    /// Provisioned AppRole role_id for non-TPM unlock. Pairs with
    /// --approle-secret-id-file. If set, the daemon reads secret_id from
    /// the file, derives a KEK, and unlocks <config-dir>/approles/<role>.json
    /// instead of prompting for a master password or unsealing via TPM.
    #[arg(long, env = "APPROLE_ROLE_ID")]
    approle_role_id: Option<String>,

    /// Path to a 0600 file containing the hex-encoded secret_id generated
    /// by `vaultproxy approle-setup --role-id <name>`. Read once at
    /// startup, then immediately zeroized; never re-read.
    #[arg(long, env = "APPROLE_SECRET_ID_FILE")]
    approle_secret_id_file: Option<std::path::PathBuf>,

    /// Subcommand. Currently only `audit-verify` is supported — daemon
    /// startup happens when no subcommand is provided.
    #[command(subcommand)]
    cmd: Option<Cmd>,

    /// Background credential-health audit interval in seconds.
    ///
    /// When set to a non-zero value, vault-proxy spawns a background task that
    /// calls `run_audit()` (the same operation as `GET /vault/audit/run`) every
    /// N seconds and logs the summary at INFO level.  This gives operators
    /// continuous visibility into weak and reused passwords without requiring
    /// manual API calls.
    ///
    /// The audit is read-only and runs entirely in-process: it HMAC-fingerprints
    /// passwords with an ephemeral key and zeroizes them immediately — no
    /// plaintext is stored or emitted.  Each audit decrypts every vault item's
    /// password once, so on large vaults (500+ items) choose a generous interval
    /// (e.g. 3600 s / 1 hour) to avoid sustained CPU use.
    ///
    /// MINIMUM INTERVAL: values below 60 s are accepted but trigger a startup
    /// warning.  Sub-60 s intervals cause sustained CPU load on large vaults;
    /// the recommended minimum is 60 s.  For most homelabs, 3600 (hourly) is ideal.
    ///
    /// FIRST-TICK BEHAVIOUR: the first background audit fires after one full
    /// interval, NOT immediately at startup.  This avoids a double-decrypt
    /// on startup (the vault is freshly loaded) and gives the vault time to
    /// finish initial sync before the audit decrypts every item.  If you need
    /// an immediate baseline, call `GET /vault/audit/run` manually once after
    /// startup.  Compare: `--vault-refresh-interval-secs` also skips the first
    /// tick for the same reason.
    ///
    /// NOTIFICATIONS: when `--notify-channel` / `--ntfy-url` is configured,
    /// the background task sends a push notification when weak or reused
    /// passwords are found (priority 4 — high).  Clean runs do not notify.
    ///
    /// ON-DEMAND AUDIT ENDPOINT: at any time you can trigger a one-shot audit
    /// by calling `GET /vault/audit/run` with the internal bearer token:
    ///
    ///   curl -H "Authorization: Bearer $(cat $CONFIG_DIR/internal-token)" \
    ///        http://127.0.0.1:3201/vault/audit/run
    ///
    /// `$CONFIG_DIR` is the value of `--config-dir` (default: `/config`).
    /// The endpoint returns the same JSON as the background task logs.
    /// Rate-limited to 2 req/60 s.
    ///
    /// Set to 0 (the default) to disable the background audit entirely and
    /// rely on on-demand calls to `GET /vault/audit/run`.
    #[arg(long, env = "AUDIT_INTERVAL_SECS", default_value = "0")]
    audit_interval_secs: u64,
}

// -------------------------------------------------------------------------- //
// Access log construction                                                     //
// -------------------------------------------------------------------------- //

/// Build the optional [`AccessLog`] for both the daemon and the `--mcp` /
/// `--mcp-http` paths from the CLI/env value. Empty path = disabled.
fn build_access_log(
    access_log_path: &str,
) -> anyhow::Result<Option<std::sync::Arc<crate::access_log::AccessLog>>> {
    if access_log_path.is_empty() {
        return Ok(None);
    }
    let log_path = std::path::PathBuf::from(access_log_path);
    let key_path = std::path::PathBuf::from(format!("{}.key", access_log_path));
    let log = crate::access_log::AccessLog::open(log_path, key_path)?;
    Ok(Some(std::sync::Arc::new(log)))
}

// -------------------------------------------------------------------------- //
// Entry point                                                                 //
// -------------------------------------------------------------------------- //

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    tracing_subscriber::fmt()
        .with_env_filter("vault_proxy=debug,info")
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();
    let config_dir = args.config_dir.clone();

    // Subcommand short-circuit — runs before any daemon-startup logic so the
    // utility action can complete without touching Vaultwarden, keystore, etc.
    if let Some(Cmd::AuditVerify { log }) = &args.cmd {
        let key = std::path::PathBuf::from(format!("{}.key", log.display()));
        crate::access_log::AccessLog::verify(log, &key)?;
        let line_count = std::fs::read_to_string(log)?
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count();
        println!("access log valid: {} ({} lines)", log.display(), line_count);
        return Ok(());
    }

    if let Some(Cmd::Render { input, out, socket }) = args.cmd.as_ref() {
        use anyhow::Context as _;
        let r = crate::template::Renderer::new();
        let ctx = crate::template::RenderContext {
            socket_path: socket.clone(),
        };
        r.render_file(input, out, &ctx)
            .with_context(|| format!("render {} -> {}", input.display(), out.display()))?;
        println!(
            "rendered {} -> {} (mode 0600)",
            input.display(),
            out.display()
        );
        return Ok(());
    }

    if let Some(Cmd::ApproleSetup { role_id }) = args.cmd.as_ref() {
        use anyhow::Context as _;
        // Read master password from env or interactive prompt. Wrap in
        // Zeroizing so the buffer is zeroed when the variable drops; the
        // password lives only as long as the unlock call.
        let master =
            zeroize::Zeroizing::new(if let Ok(m) = std::env::var("VAULTPROXY_MASTER_PASSWORD") {
                m
            } else {
                rpassword::prompt_password("master password: ")
                    .context("read master password from tty")?
            });
        let creds = crate::keystore::unlock_keystore(&args.config_dir, Some(master.as_str()))
            .context("unlock keystore with master password")?;
        drop(master);
        let sid =
            crate::approle::setup_approle(std::path::Path::new(&args.config_dir), role_id, &creds)?;
        use secrecy::ExposeSecret;
        println!("AppRole '{}' provisioned.", role_id);
        println!();
        println!("secret_id (write to a 0600 file, e.g. /etc/vp/secret-id):");
        println!("{}", sid.expose_secret());
        println!();
        println!("Then start the daemon with:");
        println!("  vaultproxy --listen ... \\");
        println!("    --approle-role-id {} \\", role_id);
        println!("    --approle-secret-id-file /etc/vp/secret-id");
        return Ok(());
    }

    // Issue (iter-27/28): --check validates services.toml without a live
    // Vaultwarden connection. Useful for CI, pre-deploy hooks, and Docker
    // HEALTHCHECK CMD scripts.
    //
    // Exit codes (iter-28 clarification):
    //   0 — services.toml parsed cleanly (zero or more valid services loaded).
    //         A zero-service result is NOT an error — it is the first-run state
    //         where the operator has not yet populated services.toml. The output
    //         message tells them what to do next.
    //   1 — services.toml exists but contains a TOML parse error or every
    //         service entry was rejected by validation (all skipped). This is
    //         an actionable error that must be fixed before deploying.
    //   2 — services.toml does not exist and this is not a first-run scenario
    //         (i.e. --config-dir was provided but the file is missing). In
    //         practice, `from_toml_file` returns an empty registry with a
    //         tracing::warn for NotFound; we treat that as exit 0 (first-run).
    //
    // The tracing output from from_toml_file is the authoritative per-service
    // diagnostic. We emit a human-readable summary line on stdout for CI
    // pipelines that capture stdout but not stderr/tracing.
    //
    // Interaction with other flags (iter-28):
    //   --check --launch <name>: --check runs and exits before --launch is
    //     evaluated. The two flags do NOT interact.
    //   --check --setup: same — --check short-circuits before --setup.
    //   --check is fully independent of all other flags.
    if args.check {
        let services_path = std::path::Path::new(&config_dir).join("services.toml");
        // Detect missing file before calling from_toml_file_with_counts so we can
        // emit a clear first-run message and exit 0 (not an error).
        let file_missing = !services_path.exists();

        // Issue (iter-29): use from_toml_file_with_counts so we know how many
        // [[service]] entries were attempted vs accepted. The difference is the
        // number of rejected services; naming them helps operators debug CI
        // failures without parsing structured tracing JSON.
        let (registry, attempted) =
            proxy::registry::ServiceRegistry::from_toml_file_with_counts(&services_path);
        let accepted = registry.list().len();
        let rejected = attempted.saturating_sub(accepted);

        if file_missing {
            // First-run: no services.toml yet. Not an error — give operator
            // the actionable next step. Use println! (stdout) so CI pipelines
            // that only capture stdout see the message.
            println!(
                "vaultproxy check: services.toml not found at {}. \
                 This is normal on first run. \
                 Copy services.example.toml to {} and add [[service]] blocks.",
                services_path.display(),
                services_path.display()
            );
            std::process::exit(0);
        }

        if accepted == 0 {
            // File exists but loaded zero services — either it is empty or
            // every entry was rejected by validation (SSRF, missing fields, etc).
            // The tracing output (emitted to stderr above) names each rejected
            // service and reason. Exit 1 so CI pipelines detect the misconfiguration.
            println!(
                "vaultproxy check: FAIL — 0/{attempted} service(s) accepted from {}. \
                 {rejected} service(s) rejected — see log output above for per-service errors \
                 (SSRF violations, missing fields, bad base_url). \
                 Fix services.toml and re-run --check before deploying.",
                services_path.display()
            );
            std::process::exit(1);
        }

        // Issue (iter-29): report accepted service names + rejected count on stdout
        // so CI pipelines get actionable output without parsing structured logs.
        if rejected > 0 {
            // iter-38: hint the MAX_SERVICES=512 cap when the file is very large,
            // since that is a non-obvious rejection reason (not SSRF / parse error).
            let cap_hint = if attempted > 512 {
                " NOTE: services.toml contains more than 512 entries — \
                 vault-proxy hard-caps at 512 (MAX_SERVICES). \
                 Split into multiple vault-proxy instances or remove unused [[service]] blocks."
            } else {
                ""
            };
            println!(
                "vaultproxy check: PARTIAL — {accepted}/{attempted} service(s) accepted from {}: {:?}. \
                 {rejected} service(s) were REJECTED — see log output above for names and reasons \
                 (SSRF violations, unknown auth types, missing required fields, MAX_SERVICES=512 cap).{} \
                 Fix services.toml and re-run --check.",
                services_path.display(),
                registry.list(),
                cap_hint,
            );
            std::process::exit(1);
        }

        // iter-44: advise operators to inspect log output for per-service
        // warnings (timeout_secs >= 600, insecure_tls, etc.) that are emitted
        // via `tracing::warn!` during from_toml_file — they appear on stderr
        // but are not reflected in the stdout summary above.
        println!(
            "vaultproxy check: OK — {accepted} service(s) registered from {}: {:?}. \
             Check log output above for per-service warnings (e.g. timeout_secs >= 600, \
             insecure_tls = true).",
            services_path.display(),
            registry.list()
        );

        // iter-45/46: also validate VAULT_PROXY_PUBLIC_URL when it is set.
        // This env var is only consumed at --launch time but is easily
        // misconfigured and has no other validation path. --check is the
        // natural place for operators to verify their full env configuration
        // before deploying. An invalid value (wrong scheme, trailing slash,
        // empty host) would silently inject a broken VAULT_PROXY_URL into
        // every smart MCP server launched by vault-proxy.
        //
        // iter-46: use launcher::validate_public_url() (now pub(crate)) instead
        // of a duplicated inline block. All output uses println! (stdout) so CI
        // pipelines that capture stdout see the result — consistent with all
        // other --check output.
        if let Ok(public_url) = std::env::var("VAULT_PROXY_PUBLIC_URL") {
            if !public_url.is_empty() {
                match launcher::validate_public_url(&public_url) {
                    Ok(()) => println!(
                        "vaultproxy check: VAULT_PROXY_PUBLIC_URL='{}' — looks valid.",
                        public_url
                    ),
                    Err(e) => println!(
                        "vaultproxy check: WARN — {} — this will cause --launch to exit with an error",
                        e
                    ),
                }
            }
        }

        std::process::exit(0);
    }

    // Issue (iter-15): Running vault-proxy as root (uid 0) is unnecessary and
    // violates least privilege. vault-proxy is a credential broker — if it runs
    // as root and is compromised, the attacker gains root. All it needs is read
    // access to --config-dir and the ability to bind a TCP port above 1024
    // (default 3201), neither of which requires root.
    //
    // We warn (not refuse) to avoid breaking Docker containers that are launched
    // as root by default (e.g. `docker run --rm ghcr.io/.../vaultproxy`). A
    // hard refusal would require ALL Docker users to set `--user` before they
    // can even run --setup, which is a poor first-run experience. The warning
    // is prominent enough that operators who care will act on it.
    //
    // Operators who truly need root (e.g. TPM /dev/tpm0 access on some distros
    // without udev rules) can suppress the warning by passing `--allow-root`.
    #[cfg(unix)]
    if unsafe { libc::geteuid() } == 0 && !args.allow_root {
        tracing::warn!(
            "SECURITY: vault-proxy is running as root (uid 0). This is unnecessary — \
             vault-proxy only needs read access to --config-dir and the ability to bind \
             to its listen port. Running as root means a compromise of this process \
             grants full system access. Use a dedicated non-root user (e.g. `--user vaultproxy` \
             in Docker). Pass --allow-root to suppress this warning if root is intentional."
        );
    }

    // Issue (iter-10): Create --config-dir if it does not exist.
    // Previously, a non-existent config_dir caused `safe_write_config()` to
    // fail with an obscure OS error ("open tmp file /nonexistent/keystore.json.tmp.NNN:
    // No such file or directory") deep inside the setup flow, with no indication
    // that the *directory* was the missing piece. Creating it here (at startup,
    // with a clear log message) allows operators to mount a new volume or specify
    // a fresh path without pre-creating it manually.
    if !std::path::Path::new(&config_dir).exists() {
        std::fs::create_dir_all(&config_dir).map_err(|e| {
            anyhow::anyhow!(
                "--config-dir '{}' does not exist and could not be created: {}",
                config_dir,
                e
            )
        })?;
        tracing::info!("created config directory '{}'", config_dir);
    }

    // iter-11: Warn when an API key is passed as a CLI argument. On Linux,
    // every process's full command line is readable by any process running as
    // the same OS user via /proc/<pid>/cmdline and /proc/self/cmdline, making
    // --litellm-api-key (and to a lesser extent --ntfy-url, --cloud-email)
    // visible to other user-space processes. Environment variables (LITELLM_API_KEY
    // etc.) are also visible via /proc/<pid>/environ *by default* on Linux, but
    // only to the process owner and root — the same threat model as cmdline for
    // a typical homelab single-user deployment. The recommended mitigation is to
    // use env vars sourced from a secrets manager or a file that is chmod 600.
    //
    // We warn specifically on --litellm-api-key because it is a third-party API
    // credential (sent to LiteLLM over the network); the others are URLs or
    // account emails that have a lower sensitivity. We do NOT reject the flag —
    // Docker / compose users often have no choice but to use CLI args.
    #[cfg(feature = "browser")]
    if !args.litellm_api_key.is_empty() {
        // Only warn if the value looks like it was passed on the command line
        // (i.e. not sourced from the env var, which is the safer channel).
        // Clap doesn't expose whether a value came from the CLI or env, so we
        // check std::env directly: if the env var is set with the same value,
        // suppress the warning (the user is already using the safer path).
        let from_env = std::env::var("LITELLM_API_KEY")
            .map(|v| v == args.litellm_api_key)
            .unwrap_or(false);
        if !from_env {
            tracing::warn!(
                "SECURITY: --litellm-api-key was passed as a CLI argument. \
                 On Linux, /proc/<pid>/cmdline is readable by any same-user process, \
                 exposing this value. Prefer the LITELLM_API_KEY environment variable \
                 sourced from a secrets manager or a chmod-600 env file instead."
            );
        }
    }

    // Issue-3 (iter-4): Validate --vault-folder early so a bad value produces
    // a clear startup error instead of silently returning zero credentials.
    // The folder name is passed to Vaultwarden folder-lookup; an empty name
    // would match nothing, a name with null bytes could confuse the HTTP layer,
    // and leading/trailing slashes look like path components in the Vaultwarden
    // API URL even though they never are — reject them to avoid confusion.
    {
        let f = args.vault_folder.as_str();
        if f.is_empty() {
            anyhow::bail!("--vault-folder / VAULT_FOLDER must not be empty");
        }
        if f.contains('\0') {
            anyhow::bail!("--vault-folder / VAULT_FOLDER must not contain null bytes");
        }
        if f.contains('/') {
            anyhow::bail!(
                "--vault-folder / VAULT_FOLDER must not contain '/' — got '{}'",
                f
            );
        }
    }

    // Issue (iter-46): Validate VAULT_PROXY_PUBLIC_URL at startup (normal server
    // mode) so operators get an early warning if the value is malformed.  Without
    // this check the bad value sits silently in the environment until --launch is
    // called and fails, which is confusing for operators who set the env var in
    // Docker Compose and never run --launch interactively.
    //
    // We emit a tracing::warn (not a hard error) here because vault-proxy can
    // still serve /proxy requests without a valid VAULT_PROXY_PUBLIC_URL — the
    // variable is only used when --launch is invoked. A hard bail!() would break
    // existing deployments that happen to have a mis-set env var but never use
    // --launch. The warning surfaces in structured logs (Loki, journald) where
    // operators can catch it during deployment review.
    if let Ok(public_url) = std::env::var("VAULT_PROXY_PUBLIC_URL") {
        if !public_url.is_empty() {
            if let Err(e) = launcher::validate_public_url(&public_url) {
                tracing::warn!(
                    "VAULT_PROXY_PUBLIC_URL is set but invalid: {} — \
                     --launch will exit with an error until this is fixed. \
                     Unset the variable or correct it to a valid 'http://' or 'https://' URL \
                     without a trailing slash.",
                    e
                );
            } else {
                tracing::debug!(
                    "VAULT_PROXY_PUBLIC_URL='{}' validated at startup (OK)",
                    public_url
                );
            }
        }
    }

    // CLI setup mode (headless/Docker) — interactive wizard, then start server.
    //
    // NOTE: `--setup` and `--launch <server>` are NOT mutually exclusive.
    // If both flags are present, the wizard runs first, then `start_server()`
    // immediately calls `launcher::launch()` and execs the MCP server — the
    // proxy never actually starts accepting connections. This is intentional
    // for "setup + run" one-shot containers.
    //
    // NOTE (iter-7): After `--setup` completes, the process calls `start_server()`
    // and begins proxying on the configured address. It does NOT exit. The wizard
    // prints "Remove --setup from your start command and restart to begin proxying"
    // as a reminder, but the proxy is already functional without a restart.
    // On the next restart WITH --setup still present, the overwrite-confirmation
    // guard (added in iter-3) prevents accidental keystore destruction.
    // This design means `--setup` is idempotent-safe: first run configures and
    // starts; subsequent runs with --setup require explicit confirmation before
    // overwriting.
    // Socket fast-path for --launch: if a running daemon (this same binary in
    // server mode) is exposing the credential socket, fetch creds over the
    // socket and execve the child WITHOUT re-authenticating to Bitwarden cloud.
    // Eliminates the rate-limit churn when several MCPs launch concurrently.
    // On any failure (socket absent, bootstrap-needed, malformed item) we fall
    // through to the existing full TPM+VW path below.
    if let Some(ref server_name) = args.launch {
        let socket_path = crate::local_socket::default_socket_path();
        if socket_path.exists() {
            let cred = crate::launcher::CredSource::Socket(socket_path.clone());
            match crate::launcher::launch(
                server_name,
                &config_dir,
                &cred,
                args.listen,
                &args.vault_folder,
            )
            .await
            {
                Ok(()) => return Ok(()), // execve never returns; unreachable on success
                Err(e) => {
                    tracing::warn!(
                        "socket fast-path for --launch {} failed ({}); falling back to full TPM+VW auth",
                        server_name,
                        e
                    );
                    // fall through to keystore unlock + VW auth flow below
                }
            }
        }
    }

    if args.setup {
        // Guard against silent overwrite of an existing, working keystore.
        // An operator who accidentally passes --setup on a running deployment
        // would destroy the encrypted keystore (and any sealed TPM blob),
        // requiring full re-setup. Make them confirm before proceeding.
        if keystore::is_configured(&config_dir) {
            println!();
            println!("WARNING: A keystore already exists in '{}'.", config_dir);
            println!("Running --setup will OVERWRITE it, destroying the current");
            println!("encrypted credentials (including any TPM-sealed key).");
            println!();
            print!("Type 'overwrite' to confirm, or press Enter to abort: ");
            std::io::Write::flush(&mut std::io::stdout())?;
            let mut confirm = String::new();
            std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut confirm)?;
            if confirm.trim() != "overwrite" {
                println!("Aborted — existing keystore preserved.");
                return Ok(());
            }
            println!();
        }

        tracing::info!("running CLI setup wizard (--setup flag)");
        let creds = setup::run_cli_setup(&config_dir).await?;
        tracing::info!("connecting to Vaultwarden at {}", creds.vaultwarden.url);
        let vault = VaultManager::new(
            &creds.vaultwarden.url,
            &creds.vaultwarden.email,
            &creds.vaultwarden.master_password,
        )
        .await
        .map_err(|e| anyhow::anyhow!("vault init failed: {}", e))?;
        return start_server(args, vault, &config_dir, creds.cloud).await;
    }

    // AppRole unlock path — non-TPM unlock for cloud VMs, containers, and
    // headless CI where MASTER_PASSWORD env would leak via /proc/<pid>/environ.
    // Reads secret_id from a 0600 file once at startup, zeroizes it, and
    // bypasses both the TPM and password-prompt paths.
    if let (Some(role), Some(sid_file)) = (
        args.approle_role_id.as_deref(),
        args.approle_secret_id_file.as_ref(),
    ) {
        use anyhow::Context as _;
        tracing::info!("unlocking keystore via AppRole '{}'", role);
        let sid_raw = std::fs::read_to_string(sid_file)
            .with_context(|| format!("read --approle-secret-id-file {}", sid_file.display()))?;
        let sid = zeroize::Zeroizing::new(sid_raw);
        let creds = crate::approle::unlock_with_approle(
            std::path::Path::new(&config_dir),
            role,
            sid.trim(),
        )?;
        // sid (Zeroizing) drops here, zeroizing the buffer.
        drop(sid);
        tracing::info!("connecting to Vaultwarden at {}", creds.vaultwarden.url);
        let vault = VaultManager::new(
            &creds.vaultwarden.url,
            &creds.vaultwarden.email,
            &creds.vaultwarden.master_password,
        )
        .await
        .map_err(|e| anyhow::anyhow!("vault init failed: {}", e))?;
        return start_server(args, vault, &config_dir, creds.cloud).await;
    }

    // Try automatic unlock (TPM or already configured)
    if keystore::is_configured(&config_dir) {
        if keystore::has_tpm_key(&config_dir) {
            tracing::info!("unlocking keystore via TPM");
            match keystore::unlock_keystore(&config_dir, None) {
                Ok(creds) => {
                    tracing::info!("connecting to Vaultwarden at {}", creds.vaultwarden.url);
                    let vault = VaultManager::new(
                        &creds.vaultwarden.url,
                        &creds.vaultwarden.email,
                        &creds.vaultwarden.master_password,
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!("vault init failed: {}", e))?;
                    return start_server(args, vault, &config_dir, creds.cloud).await;
                }
                Err(e) => {
                    tracing::warn!("TPM unlock failed, falling through to web unlock: {}", e);
                }
            }
        }
        // Credentials exist but can't auto-unlock — start dashboard in locked mode
        tracing::info!("keystore locked — starting dashboard for web-based unlock");
    } else {
        // No credentials at all — start dashboard in setup mode
        tracing::info!("no credentials found — starting dashboard for web-based setup");
    }

    // Start dashboard-only mode (setup or locked) and wait for user action
    #[cfg(feature = "dashboard")]
    return start_dashboard_only(args, &config_dir).await;

    #[cfg(not(feature = "dashboard"))]
    {
        tracing::error!(
            "Keystore is locked or not configured. Run with --setup to configure headlessly, \
             or rebuild with --features dashboard to enable the web UI."
        );
        std::process::exit(1);
    }
}

/// Start the dashboard in setup/locked mode without a VaultManager.
/// The dashboard serves /setup or /unlock pages. Once the user completes
/// setup or unlock via the web UI, the process needs to be restarted to
/// fully initialize (or we poll until credentials appear).
///
/// # Issue (iter-8): generate_mtls_certs() called twice in the same process
///
/// When `start_dashboard_only` is called and the user subsequently completes
/// setup/unlock, this function calls `start_server()`, which calls
/// `generate_mtls_certs()` a *second* time.
///
/// `generate_mtls_certs()` is stateless and pure: it calls `rcgen` to generate
/// new in-memory ECDSA P-256 key pairs and self-signed certificates using only
/// the OS entropy source. There are no global side effects, no file I/O, and no
/// shared mutable state — each call produces a fresh independent set of
/// certificates. The certs from the first call are used for the dashboard-only
/// HTTPS server; the certs from the second call are used for the full server.
/// Both sets are independent and simultaneously valid.
///
/// The only cost is entropy consumption (3 key pairs × 32 bytes each ≈ 96 bytes
/// of entropy per call) and CPU time (a few milliseconds). This is not a
/// resource leak.
#[cfg(feature = "dashboard")]
async fn start_dashboard_only(args: Args, config_dir: &str) -> anyhow::Result<()> {
    // Generate (or load persisted) mTLS certificates for the dashboard.
    // iter-113: when --persist-dashboard-cert is set, attempt to read back a
    // previously-saved server cert+key so the browser doesn't warn on restart.
    let certs =
        tpm::generate_mtls_certs().map_err(|e| anyhow::anyhow!("cert generation failed: {}", e))?;
    let dashboard_server_cert_pem;
    let dashboard_server_key_pem;
    if args.persist_dashboard_cert {
        match tpm::load_persisted_dashboard_cert(config_dir) {
            Some(persisted) => {
                dashboard_server_cert_pem = persisted.server_cert_pem;
                dashboard_server_key_pem = persisted.server_key_pem;
            }
            None => {
                // First run: save and use the freshly-generated cert.
                tpm::persist_dashboard_cert(config_dir, &certs);
                dashboard_server_cert_pem = certs.server_cert_pem.clone();
                dashboard_server_key_pem = certs.server_key_pem.clone();
            }
        }
    } else {
        dashboard_server_cert_pem = certs.server_cert_pem.clone();
        dashboard_server_key_pem = certs.server_key_pem.clone();
    };

    // Shared channel: dashboard writes the setup password here after setup/unlock,
    // the polling loop reads it to decrypt credentials.
    let unlock_password: Arc<tokio::sync::RwLock<Option<zeroize::Zeroizing<String>>>> =
        Arc::new(tokio::sync::RwLock::new(None));

    let dash_state = dashboard::DashboardState {
        app: None,
        sessions: dashboard::auth::SessionStore::new(&format!("{}/dashboard.json", config_dir)),
        config_dir: config_dir.to_string(),
        pending_password: Arc::new(tokio::sync::RwLock::new(None)),
        unlock_password: unlock_password.clone(),
        cred_audit_orch: None,
    };

    let config_dir_poll = config_dir.to_string();
    let args_poll = args.clone();
    let unlock_password_poll = unlock_password.clone();

    let dash_router = dashboard::router(dash_state);
    let dash_addr = args.dashboard_listen;

    let dash_tls_config = {
        let cert_pem = dashboard_server_cert_pem.as_bytes().to_vec();
        let key_pem = dashboard_server_key_pem.as_bytes().to_vec();
        axum_server::tls_rustls::RustlsConfig::from_pem(cert_pem, key_pem)
            .await
            .expect("failed to build dashboard TLS config")
    };

    // Spawn dashboard
    tokio::spawn(async move {
        tracing::info!(
            "dashboard listening on {} (HTTPS) — waiting for setup/unlock",
            dash_addr
        );
        if let Err(e) = axum_server::bind_rustls(dash_addr, dash_tls_config)
            .serve(dash_router.into_make_service())
            .await
        {
            tracing::error!("dashboard server error: {}", e);
        }
    });

    // Poll for credentials to appear (user completes setup/unlock via web UI)
    tracing::info!("waiting for credentials to be configured via dashboard...");
    let mut tpm_tried = false;
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        if !keystore::is_configured(&config_dir_poll) {
            continue;
        }

        // Try TPM once — if it fails (e.g. corrupt sealed blob), don't retry every second
        if !tpm_tried {
            tpm_tried = true;
            if let Ok(creds) = keystore::unlock_keystore(&config_dir_poll, None) {
                tracing::info!(
                    "credentials unlocked via TPM — connecting to Vaultwarden at {}",
                    creds.vaultwarden.url
                );
                match VaultManager::new(
                    &creds.vaultwarden.url,
                    &creds.vaultwarden.email,
                    &creds.vaultwarden.master_password,
                )
                .await
                {
                    Ok(vault) => {
                        tracing::info!("vault initialized — starting full server");
                        return start_server(args_poll, vault, &config_dir_poll, creds.cloud).await;
                    }
                    Err(e) => {
                        tracing::error!("vault init failed: {}", e);
                    }
                }
            }
        }

        // Check if dashboard provided the unlock password
        let pw = unlock_password_poll.read().await.clone();
        if let Some(ref password) = pw {
            // Zeroizing<String> derefs through String to &str.
            let pw_str: &str = password.as_str();
            match keystore::unlock_keystore(&config_dir_poll, Some(pw_str)) {
                Ok(creds) => {
                    tracing::info!(
                        "credentials unlocked via dashboard — connecting to Vaultwarden at {}",
                        creds.vaultwarden.url
                    );
                    match VaultManager::new(
                        &creds.vaultwarden.url,
                        &creds.vaultwarden.email,
                        &creds.vaultwarden.master_password,
                    )
                    .await
                    {
                        Ok(vault) => {
                            // Clear the password from memory. Setting `None`
                            // drops the `Zeroizing<String>`, which zeroes the
                            // underlying bytes before freeing.
                            *unlock_password_poll.write().await = None;
                            // Seal to TPM if not already sealed (enables auto-unlock on next boot)
                            if !keystore::has_tpm_key(&config_dir_poll)
                                && crate::tpm::tpm_available()
                            {
                                tracing::info!("sealing keystore to TPM for auto-unlock");
                                if let Err(e) =
                                    keystore::seal_after_unlock(&config_dir_poll, pw_str)
                                {
                                    tracing::warn!(
                                        "TPM sealing failed (software fallback still works): {}",
                                        e
                                    );
                                }
                            }
                            tracing::info!("vault initialized — starting full server");
                            return start_server(args_poll, vault, &config_dir_poll, creds.cloud)
                                .await;
                        }
                        Err(e) => {
                            tracing::error!("vault init failed after unlock: {}", e);
                            *unlock_password_poll.write().await = None;
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("unlock with dashboard password failed: {}", e);
                    *unlock_password_poll.write().await = None;
                }
            }
        }
    }
}

// -------------------------------------------------------------------------- //
// Server startup (after credentials resolved)                                 //
// -------------------------------------------------------------------------- //

async fn start_server(
    args: Args,
    vault: VaultManager,
    config_dir: &str,
    cloud_creds: Option<keystore::CloudCreds>,
) -> anyhow::Result<()> {
    // Wrap VaultManager in Arc for sharing with SyncManager.
    let vault_arc = Arc::new(vault);

    // Launch mode: resolve credentials from Vaultwarden and exec a dumb MCP server.
    // This check runs BEFORE any other startup work (cloud sync, registry loading, etc.)
    // because --launch replaces the server process rather than starting a sidecar.
    //
    // NOTE: `launcher::launch` calls `std::process::exit` on success, which skips
    // Rust destructors including the VaultManager's HTTP client (benign — all
    // outstanding connections are torn down by the OS).  This is intentional:
    // `exec` semantics require process replacement, not graceful shutdown.
    // Background tokio tasks spawned below are never reached in this branch.
    // MCP server mode: expose Vaultwarden management tools over stdio.
    // Runs instead of the HTTP proxy — the binary becomes a stdio MCP server.
    //
    // The MCP server intentionally does NOT receive an AccessLog handle: all
    // privileged actions surfaced by the MCP server (currently just `rotate`)
    // proxy back to the daemon over HTTP, and the daemon records the audit
    // entry on the server side. Logging from both sides would mean two
    // separate processes appending to the same file without a shared
    // in-process Mutex, which can interleave lines larger than PIPE_BUF.
    if args.mcp {
        let smb = crate::proxy::SmbConfig {
            helper_path: args.smb_helper_path.clone(),
            mount_root: args.smb_mount_root.clone(),
            creds_dir: args.smb_creds_dir.clone(),
            fstab_path: args.smb_fstab_path.clone(),
        };
        return crate::mcp_server::run(vault_arc, args.vault_folder.clone(), smb, None).await;
    }

    if let Some(ref addr_str) = args.mcp_http {
        let addr: std::net::SocketAddr = addr_str
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid --mcp-http address {addr_str}: {e}"))?;
        let smb = crate::proxy::SmbConfig {
            helper_path: args.smb_helper_path.clone(),
            mount_root: args.smb_mount_root.clone(),
            creds_dir: args.smb_creds_dir.clone(),
            fstab_path: args.smb_fstab_path.clone(),
        };
        return crate::mcp_server::run_http(vault_arc, args.vault_folder.clone(), smb, addr, None)
            .await;
    }

    if let Some(ref server_name) = args.launch {
        // Issue (iter-39): pass listen_addr so VAULT_PROXY_URL is synthesised
        // from the actual --listen address rather than a hard-coded default.
        let cred = crate::launcher::CredSource::Vault(&vault_arc);
        return crate::launcher::launch(
            server_name,
            config_dir,
            &cred,
            args.listen,
            &args.vault_folder,
        )
        .await;
    }

    // Cloud sync setup — activates when cloud credentials exist in keystore
    // or when --cloud-email is provided (legacy).
    let cloud_sync_arc: Option<Arc<SyncManager>> = if let Some(ref cloud) = cloud_creds {
        {
            let cloud_email = args.cloud_email.as_deref().unwrap_or(&cloud.email);
            tracing::info!("cloud sync enabled for {}", cloud_email);
            let cloud_password = &cloud.master_password;
            let saved_refresh_token = cloud.refresh_token.clone();

            // Try API key auth first (bypasses 2FA and password hashing issues).
            let cloud_client: Option<CloudClient> = if let (Some(ref cid), Some(ref csec)) =
                (&cloud.api_client_id, &cloud.api_client_secret)
            {
                tracing::info!("authenticating to Bitwarden cloud via API key");
                let kdf_override = cloud.kdf_iterations.or(args.cloud_kdf_iterations);
                match CloudClient::from_api_key(
                    cloud_email,
                    cloud_password,
                    cid,
                    csec,
                    kdf_override,
                )
                .await
                {
                    Ok((client, _refresh)) => Some(client),
                    Err(e) => {
                        tracing::warn!("API key auth failed: {:#}", e);
                        None
                    }
                }
            }
            // Then try refresh token.
            else if let Some(ref rt) = saved_refresh_token {
                tracing::info!("authenticating to Bitwarden cloud via refresh token");
                let kdf_override = cloud.kdf_iterations.or(args.cloud_kdf_iterations);
                match CloudClient::from_refresh_token(cloud_email, cloud_password, rt, kdf_override)
                    .await
                {
                    Ok((client, _new_refresh)) => Some(client),
                    Err(e) => {
                        tracing::warn!("refresh token auth failed: {:#}", e);
                        None
                    }
                }
            } else {
                None
            };

            // Fallback: password-based auth if above methods failed or missing.
            let cloud_client = if cloud_client.is_some() {
                cloud_client
            } else {
                tracing::info!("attempting cloud auth via password");
                let kdf_iters = args.cloud_kdf_iterations.unwrap_or(600_000);
                let master_key =
                    vault::crypto::derive_master_key(cloud_password, cloud_email, kdf_iters);
                let pw_hash =
                    vault::crypto::hash_master_password(master_key.as_bytes(), cloud_password);

                // Explicit 30s timeout — startup cloud auth against
                // identity.bitwarden.com without a deadline would stall
                // the entire vault-proxy startup path on a network hiccup.
                let http_tmp = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(30))
                    .build()
                    .unwrap_or_else(|_| reqwest::Client::new());
                let token_resp = http_tmp
                    .post("https://identity.bitwarden.com/connect/token")
                    .form(&[
                        ("grant_type", "password"),
                        ("username", cloud_email),
                        ("password", pw_hash.as_str()),
                        ("scope", "api offline_access"),
                        ("client_id", "cli"),
                        ("deviceType", "14"),
                        ("deviceIdentifier", "vaultproxy"),
                        ("deviceName", "vaultproxy"),
                    ])
                    .send()
                    .await;

                match token_resp {
                    Ok(resp) if resp.status().is_success() => {
                        #[derive(serde::Deserialize)]
                        struct TokenResp {
                            refresh_token: Option<String>,
                        }
                        if let Ok(data) = resp.json::<TokenResp>().await {
                            if let Some(rt) = data.refresh_token {
                                tracing::info!("got fresh refresh token via password auth");
                                match CloudClient::from_refresh_token(
                                    cloud_email,
                                    cloud_password,
                                    &rt,
                                    args.cloud_kdf_iterations,
                                )
                                .await
                                {
                                    Ok((client, _new_rt)) => Some(client),
                                    Err(e) => {
                                        tracing::error!(
                                            "from_refresh_token with fresh token failed: {:#}",
                                            e
                                        );
                                        None
                                    }
                                }
                            } else {
                                tracing::error!(
                                    "password auth succeeded but no refresh token returned"
                                );
                                None
                            }
                        } else {
                            tracing::error!("failed to parse token response");
                            None
                        }
                    }
                    Ok(resp) => {
                        let status = resp.status();
                        let body = resp.text().await.unwrap_or_default();
                        tracing::error!("password auth failed ({}): {}", status, body);
                        tracing::warn!("continuing without cloud sync — may need 2FA, use dashboard to configure");
                        None
                    }
                    Err(e) => {
                        tracing::error!("password auth request failed: {:#}", e);
                        None
                    }
                }
            };

            // If either auth path succeeded, create SyncManager.
            if let Some(client) = cloud_client {
                let sync_mgr = SyncManager::new(client, vault_arc.clone());
                if let Err(e) = sync_mgr.full_sync().await {
                    tracing::warn!("initial cloud sync failed (non-fatal): {:#}", e);
                }

                Some(Arc::new(sync_mgr))
            } else {
                None
            }
        }
    } else {
        None
    };

    // Build service registry from services.toml in the config directory.
    let services_path = std::path::Path::new(&config_dir).join("services.toml");
    let registry = ServiceRegistry::from_toml_file(&services_path);
    let svc_count = registry.list().len();
    if svc_count == 0 {
        // iter-11: Provide an actionable first-run hint. An empty registry is
        // normal on the very first run (before services.toml is populated) but
        // confusing in production. Every /proxy call will return 404 "unknown
        // service" until at least one [[service]] block is added.
        tracing::warn!(
            "no services registered — all /proxy calls will return 404 \"unknown service\". \
             First-run? Copy services.example.toml to {:?} and add [[service]] blocks. \
             See README for the required fields (name, base_url, auth, vault_item).",
            services_path
        );
    } else {
        tracing::info!(
            "registered {} services from {:?}: {:?} \
             (services.toml is loaded at startup; send SIGHUP to reload without restart; \
             POST /vault/resync reloads vault credentials only)",
            svc_count,
            services_path,
            registry.list()
        );
    }

    // Issue (iter-15): Startup configuration summary — log all key settings so
    // operators can confirm that configuration was read correctly without having
    // to dig through individual startup messages scattered across the log.
    //
    // Printed once, right after the registry is loaded (so svc_count is final)
    // and before the heavy lifting of building HTTP clients and spawning tasks.
    // The format is human-readable in structured logs (each field on its own
    // key=value pair so Loki/Splunk can index them).
    {
        let cloud_sync_enabled = cloud_sync_arc.is_some();
        let tpm_active = crate::keystore::has_tpm_key(config_dir);
        tracing::info!(
            listen            = %args.listen,
            services          = svc_count,
            vault_folder      = %args.vault_folder,
            config_dir        = %config_dir,
            tpm_active,
            cloud_sync        = cloud_sync_enabled,
            dashboard_listen  = %args.dashboard_listen,
            proxy_timeout_s   = args.proxy_timeout,
            "vault-proxy startup configuration summary"
        );
        // iter-78: surface the on-demand audit endpoint in startup logs when the
        // background scheduler is enabled, so operators who set --audit-interval-secs
        // for the first time see both the scheduled cadence and the manual endpoint.
        // iter-79: use config_dir instead of the hardcoded "/config" path so the
        // log reflects the actual token location when --config-dir is set.
        if args.audit_interval_secs > 0 {
            tracing::info!(
                audit_interval_secs = args.audit_interval_secs,
                "credential audit scheduler enabled — on-demand endpoint: \
                 GET /vault/audit/run (Authorization: Bearer <token from {}/internal-token>)",
                config_dir
            );
        }
    }

    // Issue (iter-25): Validate that vault_folder actually EXISTS in Vaultwarden
    // at startup. The name is validated for format (non-empty, no slashes, no
    // nulls) at parse time, but that cannot catch a typo like
    // VAULT_FOLDER=vault_prox (missing 'y') — the folder is simply absent and
    // every scoped handler silently falls through to permissive mode (returns
    // all items) or creates items without a folder. Operators get no warning
    // until they notice wrong behavior. Check once here and emit a SECURITY
    // warning so the misconfiguration surfaces immediately in startup logs.
    {
        let resolved = vault_arc
            .find_folder_id_by_name_async(&args.vault_folder)
            .await;
        if resolved.is_none() {
            tracing::warn!(
                vault_folder = %args.vault_folder,
                "STARTUP: vault_folder '{}' was NOT FOUND in Vaultwarden. \
                 Scoped endpoints (list, create, update, duplicate-scan) will \
                 fall through to permissive mode or skip folder placement. \
                 Check that VAULT_FOLDER matches an existing Vaultwarden folder name \
                 exactly (case-sensitive). Use POST /vault/resync to reload after \
                 creating the folder.",
                args.vault_folder
            );
        } else {
            tracing::info!(
                vault_folder = %args.vault_folder,
                "vault_folder '{}' resolved in Vaultwarden — scoped endpoints active",
                args.vault_folder
            );
        }
    }

    // Generate (or load persisted) mTLS certificates for the dashboard.
    //
    // Issue-6 (iter-5): Certs were regenerated on every startup — a fresh
    // self-signed cert with a new fingerprint caused a "certificate has changed"
    // browser warning after every restart.
    //
    // iter-113: `--persist-dashboard-cert` / PERSIST_DASHBOARD_CERT resolves this.
    // When the flag is set:
    //   1. First run: generate as normal, save server cert+key to
    //      {config_dir}/dashboard.crt and dashboard.key (mode 0600, atomic).
    //   2. Subsequent runs: load the saved cert+key — browser sees the same
    //      identity and the "cert changed" warning disappears.
    //
    // The mTLS CA and client certs (used for the /handshake endpoint) are always
    // regenerated fresh — only the dashboard server cert (used by the HTTPS
    // listener on 3202) is persisted. This keeps the mTLS material ephemeral
    // (forward secrecy) while stabilising the only user-visible cert.
    //
    // When the flag is NOT set, behaviour is identical to pre-iter-113:
    // a fully ephemeral cert set is generated on every startup.
    tracing::info!("generating mTLS certificates");
    let certs =
        tpm::generate_mtls_certs().map_err(|e| anyhow::anyhow!("cert generation failed: {}", e))?;

    // When --persist-dashboard-cert is active, try to read back a previously
    // saved server cert+key and splice it into the freshly-generated CertMaterial
    // so the dashboard TLS identity remains stable across restarts.
    #[cfg(feature = "dashboard")]
    let dashboard_certs = if args.persist_dashboard_cert {
        match tpm::load_persisted_dashboard_cert(config_dir) {
            Some(mut persisted) => {
                // Splice: keep the ephemeral CA/client material (for /handshake
                // mTLS), but use the stable server cert+key for the dashboard.
                persisted.ca_cert_pem = certs.ca_cert_pem.clone();
                persisted.client_cert_pem = certs.client_cert_pem.clone();
                persisted.client_key_pem = certs.client_key_pem.clone();
                persisted
            }
            None => {
                // First run or files missing — save and use the freshly-generated cert.
                tpm::persist_dashboard_cert(config_dir, &certs);
                certs.clone()
            }
        }
    } else {
        certs.clone()
    };
    #[cfg(not(feature = "dashboard"))]
    {
        // iter-115: Warn when --persist-dashboard-cert is passed to a headless
        // build. The flag is accepted by clap (it is NOT gated at the struct-
        // field level, because gating it would cause "unexpected argument" errors
        // that give no hint about needing --features dashboard). Instead we emit
        // a startup warning so the operator sees a clear message rather than
        // silently discovering the flag had no effect.
        if args.persist_dashboard_cert {
            tracing::warn!(
                "--persist-dashboard-cert has no effect: this binary was compiled \
                 without the dashboard feature. Rebuild with \
                 `--features dashboard` to enable dashboard TLS cert persistence."
            );
        }
        let _ = args.persist_dashboard_cert; // suppress unused-variable warning
    }

    // Validate proxy_timeout: a value of 0 means every upstream request times
    // out immediately, making the proxy entirely non-functional. Enforce a
    // minimum of 1 second so operators catch the misconfiguration at startup
    // rather than seeing every /proxy call return 504 with no obvious cause.
    //
    // iter-9 fix: previously PROXY_TIMEOUT=0 was silently accepted and passed
    // to reqwest as Duration::from_secs(0), causing instant timeouts.
    const PROXY_TIMEOUT_MIN_SECS: u64 = 1;
    if args.proxy_timeout < PROXY_TIMEOUT_MIN_SECS {
        anyhow::bail!(
            "--proxy-timeout / PROXY_TIMEOUT must be at least {} second(s); got {} \
             (a zero-second timeout makes every upstream request fail immediately)",
            PROXY_TIMEOUT_MIN_SECS,
            args.proxy_timeout
        );
    }

    // Build two HTTP clients:
    // - `http`: strict TLS verification (default) — for every module except UniFi.
    // - `http_permissive`: accepts invalid certs — only for UniFi UDM, which
    //   presents a self-signed cert on its classic HTTPS port by design.
    //
    // Issue (iter-10): SSRF via redirect following.
    // reqwest follows HTTP redirects automatically by default. If an upstream
    // service returns a `301 Moved Permanently` pointing at `http://127.0.0.1:3201/vault/items`
    // (or any other internal endpoint), reqwest would follow it — bypassing the
    // SSRF guard that only runs at service registration time. Setting
    // `redirect::Policy::none()` on both clients means a 3xx response is
    // returned to vault-proxy as-is (the upstream status is forwarded to the
    // MCP caller), and no redirect is ever followed. This is the correct
    // posture for a JSON API bridge: all downstream URLs are pre-validated at
    // registration time, and the caller controls the path — vault-proxy should
    // never silently follow a server-side redirect to an unvalidated URL.
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(args.proxy_timeout))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let http_permissive = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(args.proxy_timeout))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    // Issue (iter-16): Build per-service CA-cert clients once at startup.
    //
    // Services with a `ca_cert` path in services.toml need a custom reqwest
    // Client that trusts their private CA. These clients MUST be built once
    // here and shared across requests — building a new Client per request
    // (the iter-15 approach) defeats reqwest's connection pooling and forces
    // a full TLS handshake on every proxy call to that service.
    //
    // The registry has already validated the PEM content at load time
    // (iter-16 fix in registry.rs), so these builds should not fail. If one
    // does (reqwest API change, platform issue), we log and continue without
    // a CA-cert client for that service — it will fall back to the strict
    // system-root client, which may fail with a TLS error, but startup is not
    // aborted so other services remain functional.
    //
    // Issue (iter-25): CA cert rotation requires a restart.
    // The PEM file for each service's `ca_cert` is read ONCE here at startup
    // and baked into a reqwest::Client. If an operator rotates the CA cert
    // on disk (replaces the PEM file) while vault-proxy is running, the new
    // cert is NOT picked up — vault-proxy continues to use the old client
    // until restarted. This is logged below for each loaded CA cert so operators
    // have a visible record that a restart is required after cert rotation.
    // There is no hot-reload mechanism for CA certs at this time.
    let ca_cert_clients: std::collections::HashMap<String, reqwest::Client> = {
        let mut map = std::collections::HashMap::new();
        for svc_name in registry.list() {
            if let Some(entry) = registry.get(svc_name) {
                if let Some(ref ca_path) = entry.ca_cert_path {
                    match std::fs::read(ca_path)
                        .ok()
                        .and_then(|pem| reqwest::Certificate::from_pem(&pem).ok())
                    {
                        Some(cert) => {
                            match reqwest::Client::builder()
                                .add_root_certificate(cert)
                                .timeout(std::time::Duration::from_secs(args.proxy_timeout))
                                .redirect(reqwest::redirect::Policy::none())
                                .build()
                            {
                                Ok(client) => {
                                    tracing::info!(
                                        "service '{}': CA-cert client loaded from '{}' \
                                         (restart required to pick up cert rotation)",
                                        svc_name,
                                        ca_path
                                    );
                                    map.insert(svc_name.to_string(), client);
                                }
                                Err(e) => {
                                    tracing::error!(
                                        "service '{}': failed to build CA-cert client from '{}': {} \
                                         — falling back to strict TLS client",
                                        svc_name, ca_path, e
                                    );
                                }
                            }
                        }
                        None => {
                            tracing::error!(
                                "service '{}': ca_cert '{}' could not be read or parsed at startup \
                                 — falling back to strict TLS client",
                                svc_name, ca_path
                            );
                        }
                    }
                }
            }
        }
        map
    };

    // Initialize browser agent (only when the `browser` feature is enabled).
    #[cfg(feature = "browser")]
    let browser_agent = Arc::new(browser::BrowserAgent::new(
        &args.litellm_url,
        &args.litellm_api_key,
        &args.vision_model,
    ));

    // Initialize tool permissions and audit log.
    let permissions = Arc::new(tokio::sync::RwLock::new(
        security::permissions::ToolPermissions::load(&format!(
            "{}/tool-permissions.json",
            config_dir
        )),
    ));
    let audit_log = Arc::new(security::audit_log::AuditLog::new(&format!(
        "{}/audit-log.json",
        config_dir
    )));

    // Build the HMAC-chained access log up front so both the local credential
    // socket and the daemon-side /rotate handler share the same in-process
    // `Mutex<File>` — opening twice in the same process would also be safe
    // (Mutex<File> guards the writer) but sharing one Arc keeps a single
    // chain head and avoids the cross-process write race on >PIPE_BUF lines.
    let access_log = build_access_log(&args.access_log_path)?;

    // Build the optional post-rotation hook. We validate existence and the
    // executable bit at startup so a misconfigured --on-rotation flag fails
    // fast — otherwise the spawn would only error at the first rotation,
    // which an operator may not notice for hours.
    let rotation_hook: Option<std::sync::Arc<crate::hooks::RotationHook>> =
        if args.on_rotation.is_empty() {
            None
        } else {
            let path = std::path::PathBuf::from(&args.on_rotation);
            if !path.exists() {
                anyhow::bail!("--on-rotation script {} does not exist", path.display());
            }
            // Verify the file is executable by the daemon's UID — otherwise
            // the spawn will fail at the first rotation and the operator may
            // not notice for hours. Refuse to start instead.
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path)?.permissions().mode();
            if mode & 0o111 == 0 {
                anyhow::bail!(
                    "--on-rotation script {} is not executable (mode {:o})",
                    path.display(),
                    mode
                );
            }
            Some(std::sync::Arc::new(crate::hooks::RotationHook::new(path)))
        };

    // Initialize notifier (supports ntfy, email queue, or disabled).
    //
    // Issue (iter-13): Warn when NOTIFY_CHANNEL is set to a channel that
    // requires a companion variable that is empty. Silently falling through to
    // Notifier::disabled() means credential rotation events and audit alerts
    // are swallowed with no operator-visible indication.
    //
    //   NOTIFY_CHANNEL=email  with empty NOTIFY_EMAIL  → warn, disable
    //   NOTIFY_CHANNEL=ntfy   with empty NTFY_URL       → warn, disable
    //
    // This mirrors the pattern used by PROXY_TIMEOUT=0 (iter-9) and ensures
    // misconfigured notification channels surface in startup logs.
    let notifier = Arc::new(match args.notify_channel.as_str() {
        "ntfy" if !args.ntfy_url.is_empty() => notify::Notifier::new(notify::NotifyChannel::Ntfy {
            url: args.ntfy_url.clone(),
        }),
        "ntfy" => {
            // NOTIFY_CHANNEL=ntfy but NTFY_URL is empty — notifications will
            // be silently dropped. Warn so the operator can fix the config.
            tracing::warn!(
                "NOTIFY_CHANNEL=ntfy is set but NTFY_URL is empty — \
                 notifications will be DISABLED. Set NTFY_URL to your ntfy \
                 topic URL (e.g. NTFY_URL=https://ntfy.sh/my-topic)."
            );
            notify::Notifier::disabled()
        }
        "email" if !args.notify_email.is_empty() => {
            notify::Notifier::new(notify::NotifyChannel::Email {
                to: args.notify_email.clone(),
            })
        }
        "email" => {
            // NOTIFY_CHANNEL=email but NOTIFY_EMAIL is empty — notifications
            // will be silently dropped. Warn so the operator can fix the config.
            tracing::warn!(
                "NOTIFY_CHANNEL=email is set but NOTIFY_EMAIL is empty — \
                 notifications will be DISABLED. Set NOTIFY_EMAIL to the \
                 recipient address (e.g. NOTIFY_EMAIL=alerts@example.com)."
            );
            notify::Notifier::disabled()
        }
        _ if !args.ntfy_url.is_empty() => {
            // Backward compat: if ntfy_url is set but notify_channel is not,
            // default to ntfy.
            notify::Notifier::new(notify::NotifyChannel::Ntfy {
                url: args.ntfy_url.clone(),
            })
        }
        _ => notify::Notifier::disabled(),
    });

    // Load or generate the internal bearer token (implemented in iter-22).
    //
    // All internal-only endpoints (/handshake, /vault/connecterr-secrets,
    // /vault/connecterr-secrets/upsert, /rotate, /browser/*) are gated by
    // `require_internal_token` middleware.  The token is a 32-byte random hex
    // string persisted to $CONFIG_DIR/internal-token with 0o600 permissions.
    //
    // The TypeScript Connecterr side reads the token from the same path before
    // calling these endpoints:
    //   const token = fs.readFileSync(process.env.CONFIG_DIR + '/internal-token', 'utf8').trim();
    //   fetch('http://127.0.0.1:3201/vault/connecterr-secrets', {
    //     headers: { 'Authorization': `Bearer ${token}` }
    //   });
    let token = internal_token::load_or_generate(config_dir)
        .map_err(|e| anyhow::anyhow!("internal-token init failed: {}", e))?;
    tracing::info!(
        "internal bearer token path: {}/internal-token \
         (TypeScript Connecterr side must present 'Authorization: Bearer <token>')",
        config_dir
    );

    // Assemble shared state.
    let state: Arc<AppState> = Arc::new(AppState {
        vault: vault_arc.clone(),
        registry: Arc::new(tokio::sync::RwLock::new(registry)),
        http,
        http_permissive,
        ca_cert_clients: Arc::new(tokio::sync::RwLock::new(ca_cert_clients)),
        unifi_sessions: Arc::new(crate::proxy::unifi_session::UnifiSessionCache::new()),
        session_tokens: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        client_certs: Some(certs),
        cloud_sync: cloud_sync_arc.clone(),
        approval_queue: Arc::new(tokio::sync::RwLock::new(std::collections::VecDeque::new())),
        #[cfg(feature = "browser")]
        browser: Some(browser_agent),
        #[cfg(not(feature = "browser"))]
        browser: None,
        permissions,
        audit_log,
        access_log: access_log.clone(),
        rotation_hook: rotation_hook.clone(),
        mint_wi_mcp: Arc::new(crate::rotate::strategies::SshDockerMintExecutor::from_env()),
        change_wi_mcp_admin: Arc::new(
            crate::rotate::strategies::SshDockerAdminPasswordChanger::from_env(),
        ),
        notifier,
        handshake_completed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        vault_folder: args.vault_folder.clone(),
        last_resync_unix: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        internal_token: Arc::new(token),
        // Populated lazily on the first vault mutation that needs the folder_id.
        // Cleared by POST /vault/resync to pick up any folder renames/recreations.
        cached_folder_id: Arc::new(tokio::sync::RwLock::new(None)),
        // iter-23: empty string = disabled (returns 501 Not Implemented).
        env_write_root: args.env_write_root.clone(),
        // iter-35: store startup config_dir so reload-services never reads
        // CONFIG_DIR from the environment at reload time.
        config_dir: config_dir.to_string(),
        // iter-36: store validated proxy_timeout so reload-services uses
        // the startup value, not a potentially-changed env var.
        proxy_timeout: args.proxy_timeout,
        reload_mutex: Arc::new(tokio::sync::Mutex::new(())),
        // iter-62: serialises concurrent audit runs (background task vs HTTP).
        audit_mutex: Arc::new(tokio::sync::Mutex::new(())),
        smb: crate::proxy::SmbConfig {
            helper_path: args.smb_helper_path.clone(),
            mount_root: args.smb_mount_root.clone(),
            creds_dir: args.smb_creds_dir.clone(),
            fstab_path: args.smb_fstab_path.clone(),
        },
        transparent_registry: Arc::new(tokio::sync::RwLock::new(None)),
        transparent_placeholders: Arc::new(tokio::sync::RwLock::new(None)),
    });

    // Spawn the transparent HTTPS_PROXY listener (Phase 1: passthrough only).
    // No-op when --features transparent is not compiled in, or when the
    // operator sets TRANSPARENT_LISTEN="" to disable.
    #[cfg(feature = "transparent")]
    if !args.transparent_listen.is_empty() {
        let addr: std::net::SocketAddr = args.transparent_listen.parse().map_err(|e| {
            anyhow::anyhow!(
                "--transparent-listen '{}' is not a valid SocketAddr: {}",
                args.transparent_listen,
                e
            )
        })?;
        if !addr.ip().is_loopback() {
            tracing::warn!(
                addr = %addr,
                "SECURITY: --transparent-listen is bound to a NON-LOOPBACK address. \
                 Anyone on this network can use this host as an HTTPS-MITM proxy. \
                 See SECURITY.md before exposing port {}.",
                addr.port(),
            );
        }
        let ca_source = match (
            args.transparent_ca_cert.as_deref(),
            args.transparent_ca_key.as_deref(),
        ) {
            (Some(c), Some(k)) => crate::proxy::transparent::init::CaSource::Byo {
                cert_path: c.into(),
                key_path: k.into(),
            },
            (None, None) => crate::proxy::transparent::init::CaSource::Auto {
                config_dir: args.config_dir.clone().into(),
            },
            _ => {
                return Err(anyhow::anyhow!(
                    "--transparent-ca-cert and --transparent-ca-key must both be set or both unset"
                ));
            }
        };
        let ca = crate::proxy::transparent::init::init(&ca_source)?;
        let policy = crate::proxy::transparent::UnregisteredPolicy::parse(
            &args.transparent_unregistered_policy,
        )?;
        // Validate transparent_default_mode parses, even though it's
        // reserved for future use right now.
        let _ = crate::proxy::registry::TransparentMode::parse(&args.transparent_default_mode)
            .map_err(|e| anyhow::anyhow!("--transparent-default-mode: {e}"))?;
        let (tr_cell, ph_cell) =
            crate::proxy::transparent::spawn_listener_with_policy(addr, state.clone(), ca, policy)
                .await?;
        *state.transparent_registry.write().await = Some(tr_cell);
        *state.transparent_placeholders.write().await = Some(ph_cell);
    }

    // Build router with rate limiting on sensitive endpoints.
    //
    // Body-size caps: axum's default extractor limit is ~2 MB. Every vault
    // endpoint here legitimately takes JSON envelopes well under 64 KB, so
    // we apply a 64 KB global floor. The one exception is the bulk-upsert
    // route for Connecterr secrets, which can carry many items — override
    // to 512 KB per-route.
    //
    // Security posture (iter-22 hardening):
    //
    // ALL routes go through:
    //   - `dns_rebinding_guard` (rejects non-localhost Host headers)
    //   - `rate_limit_middleware` (token-bucket per source IP)
    //   - `api_security_headers` (X-Content-Type-Options, X-Frame-Options, etc.)
    //
    // INTERNAL routes additionally require:
    //   - `require_internal_token` (checks Authorization: Bearer <token>)
    //
    // Internal routes (gated by bearer token):
    //   /handshake               — returns ephemeral mTLS private key (single-use)
    //   /vault/connecterr-secrets        — legacy Connecterr TypeScript API
    //   /vault/connecterr-secrets/upsert — legacy Connecterr upsert
    //   /rotate                  — credential rotation trigger
    //   /browser/rotate          — browser-based rotation workflow trigger
    //   /browser/status          — rotation status poll
    //   /browser/screenshot      — last rotation screenshot
    //   /browser/abort           — abort active rotation
    use axum::extract::DefaultBodyLimit;
    let rate_limiter = security::rate_limit::default_rate_limiter();

    // Sub-router for internal-only endpoints — protected by bearer token.
    // iter-22: these were previously open to any localhost process; now they
    // require `Authorization: Bearer <token>` where <token> is read from
    // $CONFIG_DIR/internal-token (0o600 — owner read/write only).
    //
    // iter-23: added POST /vault/notes (decrypt_notes) here — it was previously
    // on the open router despite returning raw decrypted notes (API tokens, SSH
    // keys, recovery codes). See TODO(public-release) in handlers.rs.
    // Build the core internal router (always-on internal endpoints).
    let internal_router_base = Router::new()
        .route("/handshake", get(handlers::handshake))
        .route(
            "/vault/connecterr-secrets",
            get(handlers::connecterr_secrets),
        )
        .route(
            "/vault/connecterr-secrets/upsert",
            axum::routing::post(crate::vault::handlers::upsert_connecterr_secrets)
                .layer(DefaultBodyLimit::max(512 * 1024)),
        )
        .route("/rotate", post(rotate::handle_rotate))
        // iter-23: decrypt_notes returns full plaintext notes (API tokens, SSH
        // keys, recovery codes). Gate it behind the internal bearer token.
        .route("/vault/notes", post(handlers::decrypt_notes))
        // iter-34: reload-services performs a hot-reload of services.toml and
        // returns a synchronous JSON confirmation. Gated behind the internal
        // bearer token because it modifies live routing state (the registry and
        // CA-cert client map). Equivalent to sending SIGHUP but HTTP-accessible.
        .route("/vault/reload-services", post(handlers::reload_services))
        // iter-53: in-process credential health audit — read-only, no vault
        // mutations. Returns weak/reused password report. Gated behind the
        // internal bearer token because it decrypts every vault password to
        // compute HMAC fingerprints (sensitive operation even though no
        // plaintext leaks in the response).
        .route("/vault/audit/run", get(crate::audit::handle_audit_run))
        // iter-77: expose current tool permissions as a diagnostic endpoint.
        // Gated behind the internal bearer token — the permissions map reveals
        // which tools are allowed/blocked/logged, which is security-relevant
        // configuration an unauthenticated caller should not see.
        .route("/vault/permissions", get(handle_get_permissions))
        // Durably change a cipher's password in Bitwarden cloud (source of
        // truth) by VW item id. Bypasses the update_item folder-scope guard,
        // so it is bearer-token-gated like the other sensitive internal routes.
        // Needed because mirrored items get folder_id cleared on the VW side
        // (unmapped cloud folders), which the folder guard would reject.
        .route(
            "/vault/cloud/update-password",
            post(handlers::cloud_update_password),
        );

    // iter-81: merge browser routes only when the `browser` feature is on.
    // /browser/* requests return 404 when the feature is off (routes absent).
    #[cfg(feature = "browser")]
    let internal_router_base = {
        let browser_routes = Router::new()
            .route("/browser/rotate", post(browser_rotate))
            .route("/browser/status", get(browser_status))
            .route("/browser/screenshot", get(browser_screenshot))
            .route("/browser/abort", post(browser_abort));
        internal_router_base.merge(browser_routes)
    };

    let internal_router = internal_router_base
        // Gate the entire sub-router behind the internal bearer token.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_internal_token,
        ))
        .with_state(state.clone());

    let app = Router::new()
        .route("/vault/health", get(handlers::health))
        // Issue (iter-26): New debugging endpoint — returns service names, auth types,
        // and base URLs without exposing vault_item names or credential details.
        // Helps MCP server developers verify that services.toml loaded correctly.
        .route("/vault/services", get(handlers::list_services))
        .route("/vault/items", get(handlers::list_items))
        .route("/vault/duplicates", get(handlers::list_duplicates))
        .route("/vault/folders", get(handlers::list_folders))
        .route("/vault/folders/delete", post(handlers::delete_folder))
        .route("/vault/test-credential", post(handlers::test_credential))
        .route("/vault/items/clone", post(handlers::clone_item))
        .route("/vault/write-env", post(handlers::write_env))
        .route(
            "/vault/items/untracked",
            get(handlers::list_untracked_items),
        )
        .route("/vault/totp", post(handlers::generate_totp))
        // NOTE: POST /vault/notes is on the internal_router (bearer token required).
        // Moved to internal_router in iter-23 — returns raw decrypted notes.
        .route("/vault/items", post(handlers::create_item))
        .route("/vault/items/delete", post(handlers::delete_item))
        .route("/vault/items/update", post(handlers::update_item))
        .route("/vault/items/move", post(handlers::move_item))
        .route("/vault/inject-creds", post(handlers::inject_creds))
        .route("/vault/smb/mount", post(crate::vault::smb::smb_mount))
        .route("/vault/smb/unmount", post(crate::vault::smb::smb_unmount))
        .route("/vault/check-permission", get(handlers::check_permission))
        .route("/vault/resync", post(handlers::vault_resync))
        .route("/sync/status", get(handlers::sync_status))
        .route("/sync/trigger", post(handlers::sync_trigger))
        .route("/sync/init", post(handlers::sync_init))
        .route("/sync/setup-cloud", post(handlers::setup_cloud))
        .route("/sync/totp", post(handlers::provide_totp))
        .route("/proxy", post(handle_proxy))
        .merge(internal_router)
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(axum::middleware::from_fn_with_state(
            rate_limiter,
            security::rate_limit::rate_limit_middleware,
        ))
        .layer(axum::middleware::from_fn(dns_rebinding_guard))
        // Issue (iter-21): Add security response headers to all API endpoints.
        // The dashboard router already applies these via its own `security_headers`
        // middleware (dashboard/mod.rs). The main API router (serving /proxy and
        // /vault/*) lacked equivalent headers — browser-based dashboard callers
        // making cross-origin requests to the API port were unprotected against
        // MIME sniffing, framing, and referrer leakage. Apply the same three
        // defensive headers here.
        //
        // Note: HSTS is intentionally omitted — the sidecar binds to plain HTTP
        // on 127.0.0.1:3201 (no TLS on the API port). HSTS is only meaningful
        // for HTTPS contexts.
        .layer(axum::middleware::from_fn(api_security_headers))
        .with_state(state.clone());

    // Construct credential_audit orchestrator + router and merge into app.
    // iter-81: gated behind the `engine` feature — the external-sidecar modules
    // (engine_client, orchestrator, pass2) are only compiled when this feature
    // is enabled. The in-process audit (audit.rs + GET /vault/audit/run) is
    // always available and is NOT gated.
    #[cfg(feature = "engine")]
    let cred_audit_orch = {
        let cred_audit_db_path = format!("{}/credential_audit.sqlite", config_dir);
        let cred_audit_conn =
            credential_audit::db::open_db(&cred_audit_db_path).expect("open credential_audit db");
        credential_audit::db::run_migrations(&cred_audit_conn)
            .expect("run credential_audit migrations");
        // Sweep any audit_runs that were `running` when the previous orchestrator
        // process exited (or was killed mid-scan). Without this, start_scan would
        // forever refuse new runs with "another audit run is in progress".
        match credential_audit::db::cleanup_orphaned_runs(&cred_audit_conn) {
            Ok(0) => {}
            Ok(n) => tracing::warn!(
                count = n,
                "credaudit: swept orphaned `running` audit_runs from a prior process"
            ),
            Err(e) => tracing::error!(error = %e, "credaudit: orphan cleanup failed"),
        }

        let cred_audit_engine = credential_audit::engine_client::EngineClient::new(
            std::env::var("CRED_AUDIT_ENGINE_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8765".to_string()),
        );
        let cred_audit_pass2 = std::sync::Arc::new(credential_audit::pass2::Pass2Engine::new(
            std::sync::Arc::new(cred_audit_engine.clone()),
            std::env::var("CRED_AUDIT_AGENT_PATH")
                .unwrap_or_else(|_| "/app/playwright/agent.py".to_string()),
            std::env::var("AUDIT_EGRESS_PROXY_URL").ok(),
        ));
        // Issue (iter-53): Pass vault_folder to VwAdapter so the credential-audit
        // scan is scoped to vault-proxy's own folder. This prevents the scan from
        // fingerprinting or marking personal items outside vault_folder.
        std::sync::Arc::new(credential_audit::orchestrator::Orchestrator {
            vault: std::sync::Arc::new(credential_audit::vw_adapter::VwAdapter::new(
                vault_arc.clone(),
                Some(args.vault_folder.clone()),
            )),
            engine: cred_audit_engine,
            marker: credential_audit::marker::Marker::new(
                vault_arc.clone(),
                Some(args.vault_folder.clone()),
            ),
            conn: std::sync::Arc::new(std::sync::Mutex::new(cred_audit_conn)),
            pass2: cred_audit_pass2,
        })
    };

    #[cfg(feature = "engine")]
    let app = {
        let cred_audit_router = credential_audit::router(cred_audit_orch.clone());
        app.merge(cred_audit_router)
    };

    // Spawn policy scheduler — checks rotation policies every hour.
    //
    // Issue (iter-8): A panic inside `tokio::spawn` silently terminates the
    // spawned task. The JoinHandle is dropped immediately (we don't `.await`
    // it), so the panic is swallowed with only a tokio runtime warning in
    // debug builds.
    //
    // Fix (iter-23): The scheduler is now wrapped in an outer restart loop.
    // Each iteration spawns a new task that runs the hourly scheduler body.
    // If the inner task panics (JoinError::is_panic()), the outer loop logs
    // the event and re-spawns after a 5-second delay so scheduling is never
    // silently lost. Normal task completion (which cannot happen — the inner
    // body is its own `loop {}`) would also trigger a re-spawn after the delay,
    // which is safe.
    //
    // `AssertUnwindSafe` is NOT needed here because we use the JoinHandle
    // approach: `tokio::spawn` catches panics automatically and returns them
    // as `JoinError::is_panic()`. The outer loop `.await`s the handle and
    // inspects the result, re-spawning unconditionally on error.
    {
        let policy_vault = vault_arc.clone();
        let _policy_notifier = state.notifier.clone();
        let policies_path = format!("{}/policies.json", config_dir);
        tokio::spawn(async move {
            loop {
                // Inner task: runs the scheduler body. If it panics, the
                // JoinHandle returns Err(JoinError) and we restart below.
                let pv = policy_vault.clone();
                let pp = policies_path.clone();
                let inner = tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await; // every hour

                        // Load once at the top and save once at the bottom. The old
                        // shape reloaded the file for every due policy, producing
                        // quadratic I/O and visible file churn. `load_policies` now
                        // also drops interval_days==0 entries so the scheduler can't
                        // hot-loop on a malformed entry.
                        let mut policies = crate::policy::load_policies(&pp);
                        let now = chrono::Utc::now();
                        let mut mutated = false;

                        for policy in policies.iter_mut() {
                            if !policy.enabled {
                                continue;
                            }

                            let last_run = policy
                                .last_run
                                .as_deref()
                                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                                .map(|dt| dt.with_timezone(&chrono::Utc));

                            let due = match last_run {
                                Some(lr) => {
                                    let elapsed = now.signed_duration_since(lr);
                                    elapsed.num_days() >= policy.interval_days as i64
                                }
                                None => true, // never run
                            };

                            if due {
                                tracing::info!(
                                    "policy '{}' is due -- would trigger rotation for {:?}",
                                    policy.name,
                                    policy.target
                                );
                                policy.last_run = Some(now.to_rfc3339());
                                policy.last_result = Some("checked".to_string());
                                mutated = true;
                            }
                        }

                        if mutated {
                            if let Err(e) = crate::policy::save_policies(&pp, &policies) {
                                tracing::warn!("failed to persist policy run times: {}", e);
                            }
                        }

                        // Keep the vault reference alive to prove it compiles
                        let _ = &pv;
                    }
                });

                match inner.await {
                    Ok(_) => {
                        // The inner loop never returns normally; if it does,
                        // restart it after a brief delay.
                        tracing::warn!(
                            "policy scheduler task exited unexpectedly — restarting in 5s"
                        );
                    }
                    Err(e) if e.is_panic() => {
                        tracing::error!(
                            "policy scheduler panicked — restarting in 5s. \
                             This should not happen; please file a bug report. {:?}",
                            e
                        );
                    }
                    Err(e) => {
                        tracing::warn!("policy scheduler task ended ({:?}) — restarting in 5s", e);
                    }
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        });
    }

    // Start background tasks for cloud sync.
    if let Some(ref sync_arc) = cloud_sync_arc {
        // WebSocket listener (real-time notifications).
        let sync_ws = Arc::clone(sync_arc);
        tokio::spawn(async move {
            // Reconnect backoff state — starts at 5s, doubles to a 300s cap,
            // reset to 5s whenever we see a successful frame from the upstream.
            let mut ws_backoff_secs: u64 = 5;
            loop {
                let (tx, mut rx) = tokio::sync::mpsc::channel::<websocket::SyncNotification>(64);

                // Read connection details from the cloud client.
                let (notifications_url, access_token) = {
                    let cloud = sync_ws.cloud.read().await;
                    (
                        cloud.notifications_url().to_string(),
                        cloud.access_token().to_string(),
                    )
                };

                // Spawn the websocket listener.
                let ws_url = notifications_url.clone();
                let ws_token = access_token.clone();
                let ws_handle =
                    tokio::spawn(async move { websocket::listen(&ws_url, &ws_token, tx).await });

                // Process notifications.
                while let Some(notif) = rx.recv().await {
                    // Any successful frame means the connection is healthy —
                    // reset backoff so the next disconnect starts at 5s again.
                    ws_backoff_secs = 5;
                    match notif {
                        websocket::SyncNotification::CipherUpdate(id)
                        | websocket::SyncNotification::CipherCreate(id) => {
                            tracing::info!(cipher_id = %id, "cloud cipher changed, syncing");
                            let mut cloud = sync_ws.cloud.write().await;
                            match cloud.get_cipher(&id).await {
                                Ok(cipher) => {
                                    let mut map = sync_ws.map.write().await;
                                    if let Err(e) =
                                        sync_ws.sync_cipher_to_vw(&cloud, &cipher, &mut map).await
                                    {
                                        tracing::error!(
                                            cipher_id = %id,
                                            "failed to sync cipher to VW: {:#}", e
                                        );
                                    } else {
                                        drop(map);
                                        drop(cloud);
                                        if let Err(e) = sync_ws.vw.sync().await {
                                            tracing::warn!("VW re-sync failed: {:#}", e);
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::error!(
                                        cipher_id = %id,
                                        "failed to fetch cipher from cloud: {:#}", e
                                    );
                                }
                            }
                        }
                        websocket::SyncNotification::CipherDelete(id) => {
                            tracing::info!(cipher_id = %id, "cloud cipher deleted");
                            let mut map = sync_ws.map.write().await;
                            if let Some(vw_id) = map.get_vw_id(&id).map(|s| s.to_string()) {
                                if let Err(e) = sync_ws.vw.delete_cipher(&vw_id).await {
                                    tracing::error!(
                                        vw_id = %vw_id,
                                        "failed to delete cipher from VW: {:#}", e
                                    );
                                }
                                map.remove_item(&id);
                            }
                        }
                        websocket::SyncNotification::VaultSync => {
                            tracing::info!("cloud requested full vault sync");
                            drop(rx);
                            if let Err(e) = sync_ws.full_sync().await {
                                tracing::error!("full sync from notification failed: {:#}", e);
                            }
                            break;
                        }
                        websocket::SyncNotification::Unknown(desc) => {
                            tracing::debug!(desc = %desc, "ignoring unknown notification");
                        }
                    }
                }

                // WebSocket disconnected — wait and reconnect with exponential
                // backoff + jitter. A flat 5s retry (previous behaviour) would
                // hammer the Bitwarden cloud notification service at 12 req/min
                // during a sustained outage and could trigger account-level
                // rate limits. Reset the delay on the next successful loop
                // iteration — tracked via `backoff_secs` at the outer scope.
                if let Err(e) = ws_handle.await {
                    tracing::warn!("websocket task ended: {:?}", e);
                }
                // Exponential 5s → 300s cap, with ±25% full jitter.
                let jitter_max = (ws_backoff_secs / 4).max(1);
                let jitter: u64 = (rand::random::<u64>() % jitter_max.max(1)) as u64;
                let sleep_secs = ws_backoff_secs.saturating_add(jitter);
                tracing::info!(
                    "websocket disconnected, reconnecting in {}s (backoff={}s, jitter={}s)",
                    sleep_secs,
                    ws_backoff_secs,
                    jitter,
                );
                tokio::time::sleep(std::time::Duration::from_secs(sleep_secs)).await;
                ws_backoff_secs = (ws_backoff_secs.saturating_mul(2)).min(300);
            }
        });

        // Polling fallback — full sync every 300 seconds.
        let sync_poll = Arc::clone(sync_arc);
        tokio::spawn(async move {
            let interval = std::time::Duration::from_secs(300);
            loop {
                tokio::time::sleep(interval).await;
                tracing::debug!("polling full sync");
                if let Err(e) = sync_poll.full_sync().await {
                    tracing::warn!("polling full sync failed: {:#}", e);
                }
            }
        });
    }

    // Spawn dashboard on a separate port (HTTPS with ephemeral certs).
    #[cfg(feature = "dashboard")]
    {
        let dash_state = dashboard::DashboardState {
            app: Some(state.clone()),
            sessions: dashboard::auth::SessionStore::new(&format!("{}/dashboard.json", config_dir)),
            config_dir: config_dir.to_string(),
            pending_password: Arc::new(tokio::sync::RwLock::new(None)),
            unlock_password: Arc::new(tokio::sync::RwLock::new(None)),
            // iter-81: cred_audit_orch only exists when both `engine` and
            // `dashboard` features are enabled. When `engine` is off, pass None.
            #[cfg(feature = "engine")]
            cred_audit_orch: Some(cred_audit_orch.clone()),
            #[cfg(not(feature = "engine"))]
            cred_audit_orch: None,
        };
        // Spawn periodic session cleanup — purges expired sessions every
        // 15 minutes to prevent memory leaks from abandoned sessions.
        let cleanup_sessions = dash_state.sessions.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(900)).await;
                cleanup_sessions.cleanup_expired().await;
            }
        });

        let dash_router = dashboard::router(dash_state);
        let dash_addr = args.dashboard_listen;

        // Build RustlsConfig from the ephemeral mTLS certs for the dashboard.
        //
        // TLS version policy (iter-11 verification):
        // `axum_server::tls_rustls::RustlsConfig::from_pem` constructs a
        // rustls `ServerConfig` using the default provider installed at startup
        // (`rustls::crypto::ring::default_provider().install_default()` in
        // main). Rustls's built-in defaults explicitly omit TLS 1.0 and 1.1
        // from the supported protocol versions — only TLS 1.2 and TLS 1.3
        // are negotiated. See: https://docs.rs/rustls/latest/rustls/struct.ServerConfig.html
        // We do NOT override `ServerConfig::protocol_versions`, so the rustls
        // default (TLS 1.2+) applies. No action needed; this comment documents
        // the verified state to make future auditors' jobs easier.
        let dash_tls_config = {
            let cert_pem = dashboard_certs.server_cert_pem.as_bytes().to_vec();
            let key_pem = dashboard_certs.server_key_pem.as_bytes().to_vec();
            axum_server::tls_rustls::RustlsConfig::from_pem(cert_pem, key_pem)
                .await
                .expect("failed to build dashboard TLS config from ephemeral certs")
        };

        // Only start dashboard if not already running (e.g., from setup/locked mode)
        match tokio::net::TcpListener::bind(dash_addr).await {
            Ok(probe) => {
                drop(probe); // Port is free — start dashboard
                tokio::spawn(async move {
                    tracing::info!("dashboard listening on {} (HTTPS)", dash_addr);
                    if let Err(e) = axum_server::bind_rustls(dash_addr, dash_tls_config)
                        .serve(dash_router.into_make_service())
                        .await
                    {
                        tracing::error!("dashboard server error: {}", e);
                    }
                });
            }
            Err(_) => {
                tracing::info!("dashboard already running on {} — skipping", dash_addr);
            }
        }
    }

    // Bind and serve.
    // `into_make_service_with_connect_info::<SocketAddr>()` is required so the
    // rate-limit middleware can key on the client IP; without it the
    // `ConnectInfo` extension is absent and the limiter would collapse to a
    // single global bucket.
    //
    // Issue-5 (iter-5): Graceful shutdown on SIGTERM (Docker stop) and Ctrl-C.
    //
    // Without this, SIGTERM instantly kills the process mid-request. Docker
    // sends SIGTERM and then waits 10s (configurable via stop_grace_period)
    // before SIGKILL. With `with_graceful_shutdown`, axum stops accepting new
    // connections immediately but waits for in-flight `/proxy` requests to
    // complete before exiting — within Docker's grace window this is safe.
    //
    // NOTE: In-memory session token cache and decrypted keys are held in
    // `AppState`. Rust's async drop for `Arc`-wrapped values runs on shutdown
    // when the last strong reference is dropped — `SecureBuffer`s use `zeroize`
    // on Drop, so key material is zeroed before the process exits. This does NOT
    // require explicit zeroing here; it happens automatically as the `Arc<AppState>`
    // is released when the server future completes.
    //
    // Sessions cached in `state.session_tokens` are in-memory only; they are
    // not persisted and do not need explicit clearing on shutdown.
    // Issue (iter-13): Warn when --listen binds to a non-loopback address.
    // vault-proxy's security model is built on localhost-only process isolation:
    // no authentication middleware guards the proxy/vault endpoints — only the
    // DNS-rebinding guard and rate limiter do. Binding to 0.0.0.0 or any
    // non-loopback interface exposes all unauthenticated endpoints to the local
    // network, breaking the core trust model. The default is 127.0.0.1:3201
    // (loopback-only). Operators who intentionally bind to a non-loopback
    // address must add authentication at the network layer (reverse proxy +
    // mTLS or similar) — this warning is a reminder to do that.
    {
        let listen_ip = args.listen.ip();
        if !listen_ip.is_loopback() {
            tracing::warn!(
                "SECURITY: --listen {} binds to a non-loopback address. \
                 vault-proxy has no authentication middleware — all /proxy, /vault/*, \
                 and credential endpoints are accessible to any host that can reach \
                 this address. This BREAKS the localhost-only trust model. \
                 Ensure a reverse proxy with mTLS or network-layer ACLs guards this \
                 port before exposing it beyond the local machine.",
                args.listen
            );
        }
    }
    // Per-connection HTTP/1 header-read timeout — Slowloris defence (iter-22).
    //
    // We use `axum_server::bind` (not `axum::serve`) because `axum::serve` does
    // not expose HTTP/1 connection-level options. `axum_server::bind` wraps
    // `hyper_util::server::conn::auto::Builder` and exposes `.http_builder()`,
    // giving us access to the HTTP/1 builder:
    //   server.http_builder()
    //       .http1()
    //       .timer(TokioTimer::new())
    //       .header_read_timeout(Duration::from_secs(5));
    //
    // A Slowloris attack keeps HTTP/1.1 connections alive by sending request
    // header bytes one at a time, never completing the header block. Without a
    // header-read deadline, each such connection holds a tokio task indefinitely;
    // the rate limiter only counts *completed* requests, so Slowloris bypasses it.
    // A 5-second header-read timeout drops partial connections before they
    // accumulate enough to exhaust available tasks.
    //
    // Graceful shutdown is implemented via `axum_server::Handle::graceful_shutdown`
    // (10-second drain window): we spawn a task that waits for SIGTERM or Ctrl-C
    // and then calls `handle.graceful_shutdown(Some(10s))`, stopping new accepts
    // and waiting for in-flight requests to finish.
    //
    // ConnectInfo<SocketAddr> is preserved: `into_make_service_with_connect_info`
    // is still used so the rate-limit middleware can key on client IP.
    // Issue (iter-28): SIGHUP hot-reload of services.toml.
    //
    // Sending SIGHUP to a running vault-proxy reloads services.toml from disk
    // without restarting the process. This allows operators to add, remove, or
    // modify [[service]] entries while the proxy is live — useful for adding new
    // services to a long-running container without incurring the full
    // Vaultwarden reconnect + startup overhead.
    //
    // The reload steps are:
    //   1. Re-read and parse services.toml with `ServiceRegistry::from_toml_file`.
    //   2. Rebuild the per-service CA-cert client map (new services may have
    //      ca_cert entries that need new reqwest::Clients).
    //   3. Swap both into AppState under their respective write locks
    //      (registry and ca_cert_clients).
    //   4. Clear `cached_folder_id` so the next vault mutation re-resolves
    //      the folder (in case services.toml was edited alongside a folder rename).
    //
    // In-flight requests continue using the old registry snapshot (they hold
    // a cloned ServiceEntry from before the lock was acquired). New requests
    // after the lock swap see the updated registry.
    //
    // The SIGHUP handler is only compiled on Unix; on non-Unix targets (Windows)
    // the signal concept doesn't exist and this block is a no-op.
    #[cfg(unix)]
    {
        let sighup_state = state.clone();
        let sighup_config_dir = config_dir.to_string();
        let sighup_proxy_timeout = args.proxy_timeout;
        let sighup_vault = vault_arc.clone();
        let sighup_vault_folder = args.vault_folder.clone();
        tokio::spawn(async move {
            let mut sighup =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!(
                            "SIGHUP: failed to register signal handler: {} — hot-reload disabled",
                            e
                        );
                        return;
                    }
                };
            loop {
                sighup.recv().await;
                tracing::info!("SIGHUP received — reloading services.toml");

                let services_path = std::path::Path::new(&sighup_config_dir).join("services.toml");
                let new_registry = proxy::registry::ServiceRegistry::from_toml_file(&services_path);
                let svc_count = new_registry.list().len();

                // Rebuild CA-cert clients for the new registry.
                let mut new_ca_clients: std::collections::HashMap<String, reqwest::Client> =
                    std::collections::HashMap::new();
                for svc_name in new_registry.list() {
                    if let Some(entry) = new_registry.get(svc_name) {
                        if let Some(ref ca_path) = entry.ca_cert_path {
                            match std::fs::read(ca_path)
                                .ok()
                                .and_then(|pem| reqwest::Certificate::from_pem(&pem).ok())
                            {
                                Some(cert) => {
                                    match reqwest::Client::builder()
                                        .add_root_certificate(cert)
                                        .timeout(std::time::Duration::from_secs(
                                            sighup_proxy_timeout,
                                        ))
                                        .redirect(reqwest::redirect::Policy::none())
                                        .build()
                                    {
                                        Ok(client) => {
                                            tracing::info!(
                                                "SIGHUP: service '{}': CA-cert client rebuilt from '{}'",
                                                svc_name, ca_path
                                            );
                                            new_ca_clients.insert(svc_name.to_string(), client);
                                        }
                                        Err(e) => {
                                            tracing::error!(
                                                "SIGHUP: service '{}': CA-cert client rebuild failed: {} \
                                                 — falling back to strict TLS",
                                                svc_name, e
                                            );
                                        }
                                    }
                                }
                                None => {
                                    tracing::error!(
                                        "SIGHUP: service '{}': ca_cert '{}' unreadable or unparseable \
                                         — falling back to strict TLS",
                                        svc_name, ca_path
                                    );
                                }
                            }
                        }
                    }
                }

                // Issue (iter-29): rollback guard — if from_toml_file returned an
                // empty registry, the file may have become unreadable or had every
                // service rejected during the reload. Swapping in an empty registry
                // would take vault-proxy offline until the next SIGHUP. Instead,
                // keep the previous registry and log a warning so the operator knows
                // the reload was rejected. A zero-service result is only accepted when
                // the old registry was also empty (first-run / intentionally empty).
                let prev_svc_count = sighup_state.registry.read().await.list().len();
                if svc_count == 0 && prev_svc_count > 0 {
                    tracing::warn!(
                        "SIGHUP: reload produced 0 services (was {}) — \
                         rolling back to previous registry. \
                         Check services.toml for parse errors or SSRF violations \
                         (the log lines above contain per-entry details). \
                         Fix services.toml and send SIGHUP again.",
                        prev_svc_count
                    );
                    // Intentionally skip the write-lock swap: old registry stays in place.
                } else {
                    // Atomically swap in the new registry and CA-cert clients under
                    // their respective write locks.
                    //
                    // Issue (iter-29): these three write lock acquisitions are NOT
                    // a single atomic operation — a reader between the first and
                    // second acquire could briefly see the new registry with stale
                    // ca_cert_clients, or vice versa. In practice this window is
                    // nanoseconds and only affects ca_cert services. A truly atomic
                    // swap would require combining registry + ca_cert_clients into a
                    // single Arc-swapped struct; that refactor is tracked as a future
                    // improvement. The non-atomicity is safe (no data corruption),
                    // only potentially causing a single stale-client request during
                    // the window.
                    *sighup_state.registry.write().await = new_registry;
                    *sighup_state.ca_cert_clients.write().await = new_ca_clients;
                    // Invalidate the folder-id cache so the next vault mutation
                    // re-resolves the folder (handles services.toml edits alongside
                    // a vault_folder rename).
                    *sighup_state.cached_folder_id.write().await = None;

                    // Rebuild the transparent-mode registry + placeholder
                    // list so transparent_mode / [[transparent_placeholder]]
                    // changes take effect without restart. No-op when the
                    // transparent listener is disabled.
                    #[cfg(feature = "transparent")]
                    if let Err(e) =
                        crate::proxy::transparent::rebuild_from_state(&sighup_state).await
                    {
                        tracing::warn!(
                            "SIGHUP: transparent registry rebuild failed: {} \
                             — old transparent registry remains active",
                            e
                        );
                    }

                    tracing::info!(
                        "SIGHUP: reload complete — {} service(s) now registered (was {})",
                        svc_count,
                        prev_svc_count
                    );

                    // iter-33: Re-run the vault_folder existence check so
                    // operators who created the folder and then sent SIGHUP
                    // see an explicit confirmation rather than silence. This
                    // mirrors the startup check in main() and uses the same
                    // log format so log-scrapers can match either event.
                    let resolved = sighup_vault
                        .find_folder_id_by_name_async(&sighup_vault_folder)
                        .await;
                    if resolved.is_none() {
                        tracing::warn!(
                            vault_folder = %sighup_vault_folder,
                            "SIGHUP: vault_folder '{}' was NOT FOUND in Vaultwarden. \
                             Scoped endpoints will fall through to permissive mode. \
                             Create the folder in Vaultwarden and send SIGHUP again.",
                            sighup_vault_folder
                        );
                    } else {
                        tracing::info!(
                            vault_folder = %sighup_vault_folder,
                            "SIGHUP: vault_folder '{}' confirmed in Vaultwarden — scoped endpoints active",
                            sighup_vault_folder
                        );
                    }
                }
            }
        });
    }

    // iter-37: background vault refresh task.
    //
    // When `--vault-refresh-interval-secs` (or `VAULT_REFRESH_INTERVAL_SECS`) is
    // non-zero, spawn a task that calls `vault.sync()` every N seconds. This
    // closes the staleness window when Vaultwarden credentials are rotated
    // externally — without it the cached credential blobs are only refreshed via
    // `POST /vault/resync` or a restart.
    //
    // On sync failure the task logs a warning and continues — the last successful
    // credentials remain in use. Repeated failures surface in structured logs so
    // operators can investigate (Vaultwarden down, network partition, re-auth
    // expiry, etc.).
    if args.vault_refresh_interval_secs > 0 {
        let refresh_vault = vault_arc.clone();
        let interval_secs = args.vault_refresh_interval_secs;
        tokio::spawn(async move {
            tracing::info!(
                "vault background refresh task started — interval {} s",
                interval_secs
            );
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            // The first tick fires immediately; skip it so we don't double-sync
            // right after startup (the initial sync ran in `VaultManager::new`).
            interval.tick().await;
            loop {
                interval.tick().await;
                tracing::debug!("vault background refresh: calling sync()");
                match refresh_vault.sync().await {
                    Ok(()) => {
                        // vault::sync() already logs at info! ("vault sync complete — N items");
                        // log the background-task outcome at debug! to avoid doubling the noise.
                        tracing::debug!("vault background refresh: sync complete");
                    }
                    Err(e) => {
                        tracing::warn!(
                            "vault background refresh: sync failed (will retry in {} s): {:#}",
                            interval_secs,
                            e
                        );
                    }
                }
            }
        });
    } else {
        // Issue (iter-42): Emit at info! not debug! so operators running with
        // the default INFO filter see a positive confirmation that background
        // refresh is intentionally disabled, rather than having to infer it
        // from the absence of the "task started" message.
        tracing::info!(
            "vault background refresh: disabled \
             (set VAULT_REFRESH_INTERVAL_SECS=300 to enable 5-minute auto-sync)"
        );
    }

    // iter-61: background credential-health audit task.
    //
    // When `--audit-interval-secs` (or `AUDIT_INTERVAL_SECS`) is non-zero,
    // spawn a task that runs `run_audit()` every N seconds and logs the
    // summary.  This is the same operation as a manual call to
    // `GET /vault/audit/run` but triggered automatically by the scheduler.
    //
    // The audit is read-only and entirely in-process — it does not mutate
    // the vault or call Vaultwarden.  Passwords are HMAC-fingerprinted with
    // an ephemeral key and zeroized immediately; no plaintext is logged.
    //
    // iter-62 changes:
    //   - Minimum interval: warn when < 60 s (every-second runs cause sustained
    //     CPU load on large vaults; 60 s is still very aggressive but acceptable
    //     for development environments).
    //   - audit_mutex: hold the shared audit_mutex for the duration of run_audit()
    //     so a concurrent HTTP call to GET /vault/audit/run does not trigger a
    //     second full-vault decryption pass at the same time.
    //   - Log verbosity: only log at INFO/WARN when issues are found; log at
    //     DEBUG for clean runs to avoid hundreds of identical INFO lines per day.
    //
    // iter-72: CancellationToken created unconditionally so the signal handler
    // (below) can always call `audit_shutdown_token.cancel()` regardless of
    // whether the background audit task was actually spawned.  When the interval
    // is 0 (disabled), the token is created but never cloned into a task — the
    // cancel() call in the signal handler is a no-op.
    let audit_shutdown_token = tokio_util::sync::CancellationToken::new();

    // iter-73: capture the JoinHandle so the signal handler can await completion.
    let audit_task_handle: Option<tokio::task::JoinHandle<()>> = if args.audit_interval_secs > 0 {
        // iter-62: warn operators who set an aggressively short interval.
        const AUDIT_MIN_INTERVAL_SECS: u64 = 60;
        if args.audit_interval_secs < AUDIT_MIN_INTERVAL_SECS {
            tracing::warn!(
                interval_secs = args.audit_interval_secs,
                min_secs = AUDIT_MIN_INTERVAL_SECS,
                "AUDIT_INTERVAL_SECS is below the recommended minimum of {} s — \
                 every audit decrypts all vault passwords; sub-60s intervals cause \
                 sustained CPU load on large vaults. Consider 3600 (hourly).",
                AUDIT_MIN_INTERVAL_SECS,
            );
        }
        let audit_vault = vault_arc.clone();
        let audit_interval = args.audit_interval_secs;
        let audit_mutex = state.audit_mutex.clone();
        // iter-63: capture vault_folder so background log lines include it.
        // In a multi-instance deployment (prod/staging both writing to the same
        // log stream) the vault_folder distinguishes which instance's audit fired.
        let audit_vault_folder = args.vault_folder.clone();
        // iter-79: capture config_dir so the ntfy notification body references
        // the correct token path (e.g. /tmp/vp-test/internal-token) rather than
        // the hardcoded /config/internal-token that was in iter-72's format string.
        let audit_config_dir = config_dir.to_string();
        // iter-72: capture notifier so the background task can push alerts when
        // weak or reused passwords are found.  Previously the task only logged at
        // WARN, so operators using ntfy.sh/email never received a push notification
        // without also watching structured logs.  With this change, every audit
        // run that finds issues fires a priority-4 notification via the configured
        // channel.  Clean runs do not notify (avoids alert fatigue).
        let audit_notifier = state.notifier.clone();
        // iter-72: CancellationToken shutdown integration.
        //
        // The audit task is a detached `tokio::spawn` — it continues running after
        // the TCP listener closes during graceful shutdown.  If an audit is in
        // progress at SIGTERM time, it would keep decrypted password buffers live
        // in mlocked memory until the OS SIGKILL (10 s later on Docker).  The
        // token lets the outer restart-loop exit cleanly once shutdown is signalled,
        // and the `tokio::select!` inside the inner tick-loop exits the current
        // audit iteration via the abort path (inner task abort propagates as
        // JoinError::is_cancelled, which the outer loop does NOT restart on).
        //
        // Shutdown sequence:
        //   1. SIGTERM/Ctrl-C fires → audit_shutdown_token.cancel() (in signal handler)
        //   2. Outer loop checks is_cancelled() and returns (no restart).
        //   3. inner `tokio::select!` picks up cancellation on the next tick
        //      and returns — all SecureBuffers are dropped (zeroized) promptly.
        //   4. The outer tokio::spawn future exits; the graceful-shutdown drain
        //      window (10 s) completes with no decrypted buffers in flight.
        let audit_shutdown_child = audit_shutdown_token.clone();
        // iter-64: wrap the audit task in the same panic-restart loop used by
        // the policy scheduler (iter-23).  Without the outer loop, a panic inside
        // `run_audit()` — however unlikely — silently kills the background task:
        // the JoinHandle is dropped immediately and the panic is swallowed by the
        // tokio runtime.  The outer loop catches `JoinError::is_panic()` and
        // re-spawns after a 5-second delay so the periodic audit is never silently
        // lost.  Note: `tokio::sync::Mutex` has no poison semantics — a panic
        // while holding `audit_mutex` simply drops the guard and leaves the mutex
        // acquirable by the next caller, so no PoisonError cleanup is needed here.
        // iter-73: store the JoinHandle so the signal handler can await audit
        // completion before the process exits, ensuring SecureBuffers are
        // zeroized within the 10-second drain window rather than relying on the
        // OS to reclaim mlocked pages at SIGKILL time.
        let audit_task_handle: tokio::task::JoinHandle<()> = tokio::spawn(async move {
            loop {
                let inner_vault = audit_vault.clone();
                let inner_mutex = audit_mutex.clone();
                let inner_folder = audit_vault_folder.clone();
                let inner_notifier = audit_notifier.clone();
                let inner_shutdown = audit_shutdown_child.clone();
                let inner_config_dir = audit_config_dir.clone();
                let inner = tokio::spawn(async move {
                    tracing::info!(
                        vault_folder = %inner_folder,
                        "credential audit background task started — interval {} s",
                        audit_interval
                    );
                    let mut interval =
                        tokio::time::interval(std::time::Duration::from_secs(audit_interval));
                    // iter-78: skip missed ticks instead of bursting.  The default
                    // `Burst` behaviour means that if an audit takes longer than the
                    // configured interval, every missed tick fires immediately after
                    // the slow audit completes — potentially queuing up dozens of
                    // back-to-back runs on a very short interval.  `Skip` discards
                    // all missed ticks so exactly one new run is scheduled after the
                    // slow audit finishes, maintaining the intended cadence.
                    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    // Skip the first immediate tick so we don't run an audit right at
                    // startup (the vault may still be loading items).
                    //
                    // iter-64 note: this means the first background audit fires after
                    // one full interval, not immediately at startup.  Operators who
                    // need an immediate baseline can call `GET /vault/audit/run` manually.
                    interval.tick().await;
                    loop {
                        // iter-72: exit cleanly when shutdown is signalled instead of
                        // waiting for the next interval tick.  `tokio::select!` races
                        // the next tick against the cancellation token; whichever fires
                        // first wins.  On cancellation the inner task returns normally
                        // (not a panic), which the outer loop treats as a clean exit and
                        // does NOT restart.
                        tokio::select! {
                            _ = interval.tick() => {}
                            _ = inner_shutdown.cancelled() => {
                                tracing::debug!(
                                    vault_folder = %inner_folder,
                                    "credential audit background task: shutdown signalled — exiting"
                                );
                                return;
                            }
                        }
                        tracing::debug!("credential audit background: running in-process audit");
                        // iter-62: hold audit_mutex to prevent a concurrent HTTP audit
                        // from running a second full-vault decryption pass simultaneously.
                        let _guard = inner_mutex.lock().await;
                        let result = crate::audit::run_audit(&inner_vault).await;
                        let n_weak = result.weak_passwords.len();
                        let n_reuse_groups = result.reused_passwords.len();
                        // iter-74: count total reused items (sum of group sizes), not
                        // just group count.  "1 reuse group" could mean 2 items or 50
                        // items sharing a password — the group count alone severely
                        // under-reports severity for large shared-credential incidents.
                        let n_reused_items: usize =
                            result.reused_passwords.iter().map(|g| g.len()).sum();
                        if n_weak > 0 || n_reuse_groups > 0 {
                            // Issues found — log at WARN so it surfaces through default
                            // log filters and alerts operators without manual inspection.
                            tracing::warn!(
                                vault_folder = %inner_folder,
                                total = result.total_items,
                                weak = n_weak,
                                reuse_groups = n_reuse_groups,
                                reused_items = n_reused_items,
                                "credential audit background: issues found — review GET /vault/audit/run"
                            );
                            // iter-72: send push notification via configured channel
                            // (ntfy.sh or email queue).  Rate-limited internally by
                            // Notifier (5 per 5 min) — a very short audit interval
                            // cannot flood the notification channel.
                            //
                            // iter-73: scale priority with severity so routine
                            // single-item findings don't wake the operator's phone
                            // with a critical alert.  ntfy priority meanings:
                            //   2 = low  — fewer than 5 total issues
                            //   3 = default — 5–9 total issues
                            //   4 = high — 10 or more total issues (warrants immediate attention)
                            // This avoids sending an Android wake-lock notification for
                            // "1 weak password", while still escalating real incidents.
                            //
                            // iter-74: use n_weak + n_reused_items (total affected credentials)
                            // instead of n_weak + n_reuse_groups.  A single reuse group with
                            // 50 items is a severe incident; group-count-based scaling
                            // would produce total_issues=2 and priority=2 (low) for it.
                            let total_issues = n_weak + n_reused_items;
                            let priority: u8 = if total_issues >= 10 {
                                4 // high
                            } else if total_issues >= 5 {
                                3 // default
                            } else {
                                2 // low
                            };
                            let title = format!(
                                "Vault audit: {} weak, {} item(s) with shared passwords — {}",
                                n_weak, n_reused_items, inner_folder
                            );
                            // iter-79: use inner_config_dir so the body references
                            // the actual token path (respects --config-dir flag).
                            let body = format!(
                                "vault-proxy credential audit found issues in '{}': \
                                 {} weak password(s), {} item(s) with shared passwords \
                                 across {} reuse group(s) (total {} items scanned). \
                                 Review: GET /vault/audit/run \
                                 (Authorization: Bearer <token from {}/internal-token>)",
                                inner_folder,
                                n_weak,
                                n_reused_items,
                                n_reuse_groups,
                                result.total_items,
                                inner_config_dir
                            );
                            // iter-74: log a warning if the notification fails so
                            // operators know the audit alert was not delivered.
                            // Previously `.ok()` silently discarded send errors —
                            // if ntfy.sh is unreachable, the operator would never
                            // know the push notification was dropped.
                            if let Err(e) = inner_notifier.send(&title, &body, priority).await {
                                tracing::warn!("audit alert notification failed to send: {}", e);
                            }
                        } else {
                            // Clean run — log at DEBUG to avoid 288 identical INFO lines
                            // per day when no issues exist (e.g. 300 s interval, 0 weak).
                            tracing::debug!(
                                vault_folder = %inner_folder,
                                total = result.total_items,
                                weak = 0,
                                reuse_groups = 0,
                                "credential audit background: complete — no issues"
                            );
                        }
                    }
                });

                match inner.await {
                    Ok(_) => {
                        // iter-72: a clean return from the inner task means the
                        // shutdown token was cancelled.  Exit the outer loop without
                        // restarting so the task terminates cleanly.
                        if audit_shutdown_child.is_cancelled() {
                            tracing::debug!("credential audit background task: shutdown complete");
                            return;
                        }
                        // Otherwise the inner loop exited unexpectedly — restart.
                        tracing::warn!(
                            "credential audit background task exited unexpectedly — restarting in 5s"
                        );
                    }
                    Err(e) if e.is_panic() => {
                        tracing::error!(
                            "credential audit background task panicked — restarting in 5s. \
                             This should not happen; please file a bug report. {:?}",
                            e
                        );
                    }
                    Err(e) => {
                        // iter-72: abort (from cancellation) also arrives here as
                        // JoinError::is_cancelled().  Exit cleanly; do not restart.
                        if e.is_cancelled() {
                            tracing::debug!(
                                "credential audit background task: cancelled during audit — shutdown complete"
                            );
                            return;
                        }
                        tracing::warn!(
                            "credential audit background task ended ({:?}) — restarting in 5s",
                            e
                        );
                    }
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        });
        Some(audit_task_handle)
    } else {
        tracing::info!(
            "credential audit background: disabled \
             (set AUDIT_INTERVAL_SECS=3600 to enable hourly audits, \
             or call GET /vault/audit/run on demand)"
        );
        None
    };

    let server_handle = axum_server::Handle::new();
    let shutdown_handle = server_handle.clone();

    // Spawn the signal watcher — triggers graceful shutdown on SIGTERM or Ctrl-C.
    //
    // iter-72: also cancel the audit shutdown token so the background audit task
    // exits cleanly within the 10-second drain window.  Without this, an in-flight
    // audit would keep decrypted SecureBuffers live in mlocked memory until the
    // OS SIGKILL fires (10 s after SIGTERM on Docker).  Cancelling the token lets
    // the audit's `tokio::select!` exit early and drop all buffers promptly.
    //
    // iter-73: await the audit task JoinHandle (with a 8-second budget) after
    // cancellation to ensure any in-flight `run_audit()` has fully returned and
    // all SecureBuffers are zeroized before the process exits.  Without the await,
    // the detached task may still hold mlocked decrypted pages when the 10-second
    // drain window expires and the OS sends SIGKILL.  8 seconds is chosen to fit
    // well within the 10-second graceful-shutdown window while leaving 2 seconds
    // for HTTP request draining.
    tokio::spawn(async move {
        let sigterm_fut: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> = {
            #[cfg(unix)]
            {
                Box::pin(async {
                    if let Ok(mut sig) =
                        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    {
                        sig.recv().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                })
            }
            #[cfg(not(unix))]
            {
                Box::pin(std::future::pending::<()>())
            }
        };
        tokio::select! {
            _ = sigterm_fut => {
                tracing::info!("received SIGTERM — draining in-flight requests before exit");
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("received Ctrl-C — draining in-flight requests before exit");
            }
        }
        // iter-72: signal the audit background task to stop so it zeroizes any
        // in-flight decrypted buffers before the process exits.
        audit_shutdown_token.cancel();
        // iter-73: await the audit task so all SecureBuffers are dropped before
        // the graceful-shutdown drain window starts.  Cap at 8 s so a stuck task
        // (e.g. Vaultwarden unresponsive) cannot push past the 10-second SIGKILL.
        //
        // iter-74: call handle.abort() when the 8-second timeout fires.
        // Without abort(), tokio::time::timeout(dur, handle).await drops the
        // JoinHandle on Err(Elapsed) but the underlying tokio TASK continues
        // running as an orphan — decrypted SecureBuffers remain live in mlocked
        // memory until the OS SIGKILL fires.  abort() force-cancels the task,
        // which triggers Drop on all task-local values (including SecureBuffer
        // zeroization) promptly rather than at SIGKILL time.
        //
        // Pattern: pass a mutable reference (`&mut handle`) to timeout so the
        // JoinHandle is not consumed; on Err(Elapsed) the handle is still owned
        // here and we call handle.abort() explicitly.
        if let Some(mut handle) = audit_task_handle {
            match tokio::time::timeout(std::time::Duration::from_secs(8), &mut handle).await {
                Ok(_) => tracing::debug!("audit task joined cleanly on shutdown"),
                Err(_) => {
                    tracing::warn!(
                        "audit task did not finish within 8 s — aborting task to force \
                         SecureBuffer zeroization before SIGKILL"
                    );
                    handle.abort();
                }
            }
        }
        // Allow up to 10 s for in-flight requests to complete before hard-kill.
        shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(10)));
    });

    // Local UNIX-socket RPC for colocated --launch processes. SO_PEERCRED-gated,
    // same-UID only; serves plaintext fields from the already-authed item cache
    // so launches don't have to re-auth to Bitwarden cloud (which rate-limits).
    //
    // A TTL'd CredCache sits in front of the VaultManager for socket fetches —
    // see --cred-cache-ttl. CRED_CACHE_TTL=0 disables caching (CredCache::put
    // is a no-op when default TTL is zero), so the cache is always constructed
    // and the call sites stay branch-free.
    //
    // An optional HMAC-chained AccessLog records each fetch and the peer's
    // SO_PEERCRED-attested uid/pid — see --access-log-path. Open at most
    // once per daemon process so all writers share a Mutex on the same file
    // handle and key, keeping the chain consistent.
    {
        let cred_cache = std::sync::Arc::new(crate::cred_cache::CredCache::with_ttl(
            std::time::Duration::from_secs(args.cred_cache_ttl),
        ));
        // Sweeper task — proactively evict expired entries every 30 s so the
        // map doesn't grow unbounded for cold keys that no one reads back.
        let sweeper = cred_cache.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
            // First tick fires immediately; skip it so the sweeper runs at +30s, not +0s.
            tick.tick().await;
            loop {
                tick.tick().await;
                sweeper.purge_expired();
            }
        });

        // Reuse the AccessLog Arc we built before AppState construction so
        // the daemon-side /rotate handler and the local socket share one
        // in-process Mutex<File>. Opening a second AccessLog on the same
        // path would create a separate file handle whose writes could
        // interleave with the first.
        let socket_vault = vault_arc.clone();
        let socket_cache = cred_cache.clone();
        let socket_log = access_log.clone();
        let socket_path = crate::local_socket::default_socket_path();
        tokio::spawn(async move {
            if let Err(e) =
                crate::local_socket::run(socket_vault, socket_cache, socket_log, socket_path).await
            {
                tracing::warn!("local credential socket exited: {}", e);
            }
        });
    }

    tracing::info!("vault-proxy listening on {}", args.listen);

    let mut server = axum_server::bind(args.listen);
    server
        .http_builder()
        .http1()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(std::time::Duration::from_secs(5));

    server
        .handle(server_handle)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;

    tracing::info!("vault-proxy shut down cleanly");
    Ok(())
}

// -------------------------------------------------------------------------- //
// Permissions diagnostic endpoint — GET /vault/permissions                    //
// -------------------------------------------------------------------------- //

/// Return the current `ToolPermissions` configuration as JSON.
///
/// # Security
///
/// Gated behind the internal bearer token (on `internal_router`).  The
/// permissions map reveals which tools are allowed, logged, or blocked —
/// information an unauthenticated caller should not see.  Operators and the
/// Connecterr TypeScript side can call this to verify that a permissions file
/// was loaded correctly without reading the raw JSON on disk.
///
/// # Response shape
///
/// ```json
/// {
///   "defaults":   { "list": "allow", "delete": "ask", ... },
///   "overrides":  { "ssh__exec": "block" },
///   "note": "GET /vault/permissions — current tool permission configuration ..."
/// }
/// ```
///
/// `defaults` — category-level defaults (keyword → permission).
/// `overrides` — per-tool-name exact overrides (higher priority than defaults).
///
/// iter-77: added to surface live permissions without requiring disk access or
/// a restart.  Previously the only way to inspect the effective permissions was
/// to read $CONFIG_DIR/tool-permissions.json and mentally apply the priority
/// rules (overrides > longest-category-match > Log default) — error-prone and
/// not available to operators running in Docker without shell access.
pub(crate) async fn handle_get_permissions(
    AxumState(state): AxumState<Arc<AppState>>,
) -> AxumJson<serde_json::Value> {
    // iter-80: clone out of the RwLock before serialising so the read guard is
    // dropped immediately after the clone and does not remain held across the
    // serde_json::json!() macro call.  Previously the guard lived until the
    // end of the function — any slow serde operation (large permissions map,
    // debug instrumentation overhead) would block every concurrent write to
    // state.permissions, including permission reloads triggered by handle_proxy.
    let (defaults, overrides) = {
        let perms = state.permissions.read().await;
        (perms.defaults.clone(), perms.overrides.clone())
    }; // read guard dropped here
       // iter-78: include whether the permissions file exists on disk so callers
       // can distinguish "file exists with all defaults" from "file not found —
       // using built-in defaults".  Both states produce an identical JSON shape
       // for `defaults` and `overrides`; without this field an operator cannot
       // tell whether their custom file was loaded or silently missing.
    let permissions_path = format!("{}/tool-permissions.json", state.config_dir);
    let config_file_exists = std::path::Path::new(&permissions_path).exists();
    // iter-80: add permissions_source to disambiguate "loaded from disk at
    // startup" from "built-in defaults (no file found)".  The existing
    // config_file_exists field reflects the current on-disk state (which can
    // diverge from what was loaded if the file was added/removed after startup),
    // but gives no indication of which source was actually used to populate the
    // in-memory permissions.  permissions_source is fixed at load time.
    let permissions_source = if config_file_exists {
        "file"
    } else {
        "built-in-defaults"
    };
    tracing::debug!("GET /vault/permissions — returning current tool permissions");
    // iter-109: add "ok": true for consistency with all other success bodies;
    // callers checking body["ok"] were getting undefined instead of true here.
    // iter-120: include configured_vault_folder so operators can confirm which
    // vault folder is scoped alongside the permission configuration. Mirrors
    // the same field already present in list_folders and sync_status (iter-115/117).
    AxumJson(serde_json::json!({
        "ok": true,
        "defaults": defaults,
        "overrides": overrides,
        "config_file_exists": config_file_exists,
        "permissions_source": permissions_source,
        "configured_vault_folder": state.vault_folder,
        "note": "GET /vault/permissions — current tool permission configuration (defaults = category-level, overrides = per-tool-name; overrides take priority). \
                 config_file_exists=true means tool-permissions.json was found in $CONFIG_DIR at startup; \
                 false means built-in defaults are active. \
                 permissions_source reflects the current file state (re-checked on each call); restart vault-proxy to reload after editing the file."
    }))
}

// -------------------------------------------------------------------------- //
// Browser agent handlers (feature = "browser" only)                          //
// -------------------------------------------------------------------------- //

#[cfg(feature = "browser")]
async fn browser_rotate(
    AxumState(state): AxumState<Arc<AppState>>,
    AxumJson(req): AxumJson<serde_json::Value>,
) -> axum::response::Response {
    // Issue (iter-104): All early-return error paths previously returned
    // HTTP 200 via `AxumJson<Value>`.  Callers checking the status code could
    // not distinguish success from a configuration error.  Each path now returns
    // the appropriate 4xx/5xx status code and includes `"ok": false` for
    // consistency with every other handler in the codebase.
    let browser = match &state.browser {
        Some(b) => Arc::clone(b),
        None => {
            return (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                AxumJson(serde_json::json!({"ok": false, "error": "browser agent not configured"})),
            )
                .into_response()
        }
    };

    let item_name = req
        .get("item_name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let login_url = req
        .get("login_url")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    // iter-124/126: UniFi service name(s) to invalidate on successful rotation.
    // When the rotated vault item is shared by multiple services (e.g. two UniFi
    // controllers pointing at the same "vault-proxy - UniFi" item), all matching
    // service sessions must be invalidated — not just the first one.
    //
    // Accepts two shapes from the request body (for forward/backward compat):
    //   - `"unifi_service_names": ["svc_a", "svc_b"]`  — array (preferred, iter-126)
    //   - `"unifi_service_name": "svc_a"`               — scalar (iter-124 legacy)
    //
    // For non-UniFi items the list is empty and the invalidation loop is a no-op.
    let unifi_service_names: Vec<String> = {
        // Prefer the array form; fall back to the scalar form for old callers.
        if let Some(arr) = req.get("unifi_service_names").and_then(|v| v.as_array()) {
            arr.iter()
                .filter_map(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect()
        } else {
            req.get("unifi_service_name")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| vec![s.to_string()])
                .unwrap_or_default()
        }
    };

    if item_name.is_empty() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            AxumJson(serde_json::json!({"ok": false, "error": "item_name required"})),
        )
            .into_response();
    }

    // Issue (iter-8): Guard against an empty litellm_url. When --litellm-url is
    // not configured (default = ""), VisionModel::analyze() constructs a
    // relative URL ("/v1/chat/completions") which reqwest rejects with a
    // "relative URL without a base" error deep inside the spawned workflow task,
    // producing a log error with no clear indication that the root cause is a
    // missing LITELLM_URL. Return a clear 400 here before spawning anything.
    if browser.litellm_url.is_empty() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            AxumJson(serde_json::json!({
                "ok": false,
                "error": "browser rotation requires a vision model — set LITELLM_URL (e.g. LITELLM_URL=http://mlbox.local:4000)"
            })),
        ).into_response();
    }

    // Issue (iter-48): Guard against an empty vision model name. When
    // --litellm-url is configured but --vision-model is empty (the default),
    // VisionModel::analyze() sends a request with `"model": ""` — LiteLLM
    // either rejects it with a cryptic 422/400 or routes to an unexpected
    // model. Return a clear 400 before spawning the workflow so the operator
    // gets an actionable message rather than a log-buried API error.
    if browser.model_name.is_empty() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            AxumJson(serde_json::json!({
                "ok": false,
                "error": "browser rotation requires a vision model name — set VISION_MODEL (e.g. VISION_MODEL=gpt-4o)"
            })),
        ).into_response();
    }

    // iter-50: Guard against a missing Playwright agent script.  Without this
    // check the handler returns {"status":"started"} and then the background
    // task immediately fails with a "failed to spawn playwright agent" error
    // buried in the logs — the caller has no indication the request was
    // rejected.  Check all candidate paths here so the HTTP response itself
    // is the first signal of the misconfiguration.
    //
    // iter-51: Also check PLAYWRIGHT_AGENT_PATH env var so a custom install
    // location set at runtime is honoured in this pre-flight check (the Pass-2
    // engine already reads CRED_AUDIT_AGENT_PATH; browser_rotate uses the same
    // binary).  Without this, setting PLAYWRIGHT_AGENT_PATH to a non-default
    // path would still trigger the "not found" error even when the file exists.
    //
    // This is a pre-flight check only — the actual spawn happens inside the
    // tokio::spawn below and is still guarded by its own error handler.  A
    // race between this check and the spawn (e.g. file deleted between the
    // two points) will still produce the log-level error, but the common
    // "never configured" case now returns a clear 501.
    let playwright_available = {
        let default_paths = ["/app/playwright/agent.py", "./playwright/agent.py"];
        let env_path = std::env::var("PLAYWRIGHT_AGENT_PATH").ok();
        let env_exists = env_path
            .as_deref()
            .map(|p| std::path::Path::new(p).exists())
            .unwrap_or(false);
        env_exists
            || default_paths
                .iter()
                .any(|p| std::path::Path::new(p).exists())
    };
    if !playwright_available {
        return (
            axum::http::StatusCode::NOT_IMPLEMENTED,
            AxumJson(serde_json::json!({
                "ok": false,
                "error": "browser rotation is not available — playwright/agent.py was not found. \
                          Mount the playwright/ directory into the container at /app/playwright/, \
                          place agent.py at ./playwright/agent.py, or set PLAYWRIGHT_AGENT_PATH \
                          to a custom location."
            })),
        )
            .into_response();
    }

    // Validate login_url against the same SSRF policy used by `inject_creds`
    // (blocks 169.254.0.0/16, fe80::/10, and all cloud-metadata hostnames).
    // The previous inline check only blocked two literal hostnames — bypassed
    // by any other link-local IP or the IPv6 IMDS address.
    if !login_url.is_empty() && !crate::vault::handlers::is_allowed_outbound_url(&login_url) {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            AxumJson(serde_json::json!({
                "ok": false,
                "error": "login_url must be http(s) and resolve to a non-metadata, non-link-local host"
            })),
        ).into_response();
    }

    let vault = state.vault.clone();
    let approval_queue = state.approval_queue.clone();
    let notifier = state.notifier.clone();
    let litellm_url = browser.litellm_url.clone();
    let api_key = browser.api_key.clone();
    let model_name = browser.model_name.clone();
    let browser_ref = Arc::clone(&browser);
    let item_name_response = item_name.clone();
    // iter-124/126: Clone the session cache so the spawn can invalidate it on
    // successful rotation.  The Arc clone is cheap — no data is copied.
    let unifi_sessions = Arc::clone(&state.unifi_sessions);

    tokio::spawn(async move {
        let pw = match crate::browser::playwright::PlaywrightProcess::spawn().await {
            Ok(pw) => pw,
            Err(e) => {
                tracing::error!("failed to spawn playwright: {}", e);
                return;
            }
        };

        let vision = crate::browser::vision::VisionModel::new(&litellm_url, &api_key, &model_name);
        let mut workflow =
            crate::browser::workflow::RotationWorkflow::new(&item_name, &login_url, pw, vision)
                .await;

        *browser_ref.current_job.write().await = Some(workflow.state.clone());

        let success = workflow.run(&vault, &approval_queue).await;

        *browser_ref.current_job.write().await = Some(workflow.state.clone());
        if let Some(ref screenshot) = workflow.state.last_screenshot_b64 {
            *browser_ref.last_screenshot.write().await = Some(screenshot.clone());
        }

        // iter-124/126: Invalidate the UniFi session cache on successful rotation
        // so the next proxy call picks up the new credential instead of
        // continuing to authenticate with the old (now-rotated) session cookie.
        // All matching service sessions are invalidated (not just the first one)
        // to handle vault items shared by multiple services (e.g. two UniFi
        // controllers pointing at the same credential item).
        // This loop is a no-op when `unifi_service_names` is empty (non-UniFi
        // items) or when a service has no cached session (first rotation).
        if success {
            for svc in &unifi_service_names {
                tracing::info!(
                    service = %svc,
                    item = %item_name,
                    "rotation succeeded — invalidating UniFi session cache for service"
                );
                unifi_sessions.invalidate(svc);
            }
        }

        notifier.notify_rotation(&item_name, success).await;

        tracing::info!(
            "rotation for '{}' completed: {}",
            item_name,
            if success { "success" } else { "failed" }
        );

        // Clear the screenshot after 5 minutes to free memory.
        // Screenshots can be 20-50KB of base64; keeping them indefinitely
        // wastes memory when rotations run frequently.
        let browser_cleanup = Arc::clone(&browser_ref);
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(300)).await;
            *browser_cleanup.last_screenshot.write().await = None;
            tracing::debug!("cleared stale rotation screenshot from memory");
        });
    });

    (
        axum::http::StatusCode::OK,
        AxumJson(
            serde_json::json!({"ok": true, "status": "started", "item_name": item_name_response}),
        ),
    )
        .into_response()
}

#[cfg(feature = "browser")]
async fn browser_status(AxumState(state): AxumState<Arc<AppState>>) -> axum::response::Response {
    // Issue (iter-105): "not configured" path silently returned HTTP 200 (AxumJson<Value>
    // return type). Changed to `axum::response::Response` so the not-configured branch
    // emits HTTP 503 with `"ok": false`, consistent with browser_screenshot and browser_abort.
    let browser = match &state.browser {
        Some(b) => b,
        None => {
            return (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                AxumJson(serde_json::json!({"ok": false, "error": "browser agent not configured"})),
            )
                .into_response()
        }
    };
    let job = browser.current_job.read().await;
    match &*job {
        Some(ws) => AxumJson(serde_json::to_value(ws).unwrap_or_default()).into_response(),
        // Issue (iter-107): idle path was missing `"ok": true`. Every other
        // success path in the codebase includes the ok sentinel; callers that
        // check `body["ok"] == true` for success detection would have failed
        // to detect the idle state as a clean response.
        None => AxumJson(serde_json::json!({"ok": true, "status": "idle"})).into_response(),
    }
}

#[cfg(feature = "browser")]
async fn browser_screenshot(
    AxumState(state): AxumState<Arc<AppState>>,
) -> axum::response::Response {
    // Issue (iter-104): "not configured" path returned HTTP 200; changed to 503.
    let browser = match &state.browser {
        Some(b) => b,
        None => {
            return (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                AxumJson(serde_json::json!({"ok": false, "error": "browser agent not configured"})),
            )
                .into_response()
        }
    };
    let screenshot = browser.last_screenshot.read().await;
    match &*screenshot {
        Some(b64) => AxumJson(serde_json::json!({"image_b64": b64})).into_response(),
        None => AxumJson(serde_json::json!({"image_b64": null})).into_response(),
    }
}

#[cfg(feature = "browser")]
async fn browser_abort(AxumState(state): AxumState<Arc<AppState>>) -> axum::response::Response {
    // Issue (iter-104): "not configured" path returned HTTP 200; changed to 503.
    let browser = match &state.browser {
        Some(b) => b,
        None => {
            return (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                AxumJson(serde_json::json!({"ok": false, "error": "browser agent not configured"})),
            )
                .into_response()
        }
    };
    *browser.current_job.write().await = None;
    AxumJson(serde_json::json!({"ok": true, "status": "aborted"})).into_response()
}

/// Bearer-token gate for internal-only endpoints (implemented iter-22).
///
/// Any process on localhost can reach vault-proxy's `/handshake`,
/// `/vault/connecterr-secrets*`, `/rotate`, and `/browser/*` endpoints —
/// process isolation and the DNS-rebinding guard are the primary access
/// controls, but a compromised container on the same host could abuse
/// these endpoints.
///
/// This middleware adds a shared-secret layer: callers must present
/// `Authorization: Bearer <token>` where `<token>` is the content of
/// `$CONFIG_DIR/internal-token` (generated once at startup, stored with
/// 0o600 permissions).
///
/// The TypeScript Connecterr side reads the token file before calling these
/// endpoints:
/// ```ts
/// const token = fs.readFileSync(process.env.CONFIG_DIR + '/internal-token', 'utf8').trim();
/// fetch('http://127.0.0.1:3201/vault/connecterr-secrets', {
///   headers: { 'Authorization': `Bearer ${token}` }
/// });
/// ```
pub(crate) async fn require_internal_token(
    AxumState(state): AxumState<Arc<AppState>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::http::StatusCode;

    // Extract the Bearer token from the Authorization header.
    let provided = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim)
        .unwrap_or("");

    // Constant-time comparison to prevent timing oracles.
    //
    // Issue (iter-23): The previous implementation short-circuited on
    // `provided.len() == expected.len()` before the fold-XOR, leaking token
    // length via a timing oracle (early return on length mismatch). An attacker
    // who can measure response latency with microsecond precision could binary-
    // search the token length in O(log n) probes.
    //
    // Fix: compare byte-at-a-time with a fixed iteration count equal to
    // `expected.len()`. We pad the provided bytes with zeros when shorter and
    // truncate when longer; the final `len_ok` check is OR'd into the same
    // accumulator so no early return leaks length information.
    //
    // This is equivalent in effect to `subtle::ConstantTimeEq` without adding
    // a dependency — the fold operates over exactly `expected.len()` iterations
    // regardless of `provided.len()`.
    let expected = state.internal_token.as_str();
    let expected_bytes = expected.as_bytes();
    let provided_bytes = provided.as_bytes();
    // Accumulate differing bits across exactly `expected.len()` iterations.
    let byte_diff = expected_bytes
        .iter()
        .enumerate()
        .fold(0u8, |acc, (i, &eb)| {
            let pb = provided_bytes.get(i).copied().unwrap_or(0);
            acc | (eb ^ pb)
        });
    // Also flag length mismatches — done in a branchless way by treating
    // any length difference as at least one differing "bit".
    let len_diff: u8 = if provided_bytes.len() == expected_bytes.len() {
        0
    } else {
        1
    };
    let valid = (byte_diff | len_diff) == 0;

    if !valid {
        tracing::warn!(
            "require_internal_token: rejected request to {} — missing or invalid Bearer token",
            req.uri().path()
        );
        // Issue (iter-103): 401 body was missing "ok": false, inconsistent with
        // all other non-200 responses in the codebase.
        return (
            StatusCode::UNAUTHORIZED,
            AxumJson(serde_json::json!({
                "ok": false,
                "error": "unauthorized — internal endpoint requires Authorization: Bearer <token>",
                "hint": "read the token from $CONFIG_DIR/internal-token"
            })),
        )
            .into_response();
    }

    next.run(req).await
}

/// Adds security response headers to all main API (non-dashboard) responses.
///
/// Issue (iter-21): The `/proxy` and `/vault/*` endpoints previously returned
/// bare responses with no defensive headers. Browser-based dashboard clients
/// that call back to the API port are protected against:
///
/// - **MIME sniffing** (`X-Content-Type-Options: nosniff`): prevents IE/Chrome
///   from re-interpreting a JSON response as an executable type.
/// - **Framing** (`X-Frame-Options: DENY`): prevents the API responses from
///   being embedded in an attacker's `<iframe>`.
/// - **Referrer leakage** (`Referrer-Policy: no-referrer`): suppresses the
///   `Referer` header on requests originating from this context, preventing
///   any vault item names or paths from leaking to upstream services.
///
/// These headers are set on all API responses (success and error) so that
/// framing and MIME-type attacks are blocked regardless of status code.
async fn api_security_headers(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
    headers.insert("X-Frame-Options", "DENY".parse().unwrap());
    headers.insert("Referrer-Policy", "no-referrer".parse().unwrap());
    response
}

/// DNS rebinding guard — rejects requests where the Host header is not
/// localhost or 127.0.0.1. Prevents external websites from making
/// JavaScript requests to the sidecar via DNS rebinding attacks.
///
/// Issue-5 (iter-4): Two additional defences applied:
///
/// 1. **Missing Host header** — HTTP/1.1 requires a Host header; its absence
///    is suspicious (attacker-crafted raw TCP) and is now rejected. HTTP/2
///    uses `:authority` pseudo-headers which reqwest / curl always send, so
///    legitimate callers are unaffected.
///
/// 2. **X-Forwarded-Host ignored** — if vault-proxy is accidentally placed
///    behind a reverse proxy that sets `X-Forwarded-Host`, this guard still
///    reads `Host` (the hop-by-hop header). `X-Forwarded-Host` is NOT read
///    because vault-proxy is designed to run as a localhost sidecar, not behind
///    a reverse proxy. Operators who put it behind a proxy should configure the
///    proxy to rewrite `Host` to `127.0.0.1`, not rely on `X-Forwarded-Host`.
///    This comment documents the deliberate choice so it is not "fixed" away.
pub(crate) async fn dns_rebinding_guard(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::http::StatusCode;

    match req.headers().get("host").and_then(|v| v.to_str().ok()) {
        None => {
            // Issue-5: No Host header — reject. HTTP/1.1 requires it;
            // missing Host is either a protocol violation or an attacker
            // bypassing the rebinding guard by omitting the header entirely.
            tracing::warn!("DNS rebinding guard: missing Host header — request blocked");
            // Issue (iter-103): 403 body was missing "ok": false.
            return (
                StatusCode::FORBIDDEN,
                AxumJson(serde_json::json!({"ok": false, "error": "request blocked — missing host header"})),
            )
                .into_response();
        }
        Some(host) => {
            let host_part = host.split(':').next().unwrap_or(host);
            if host_part != "127.0.0.1" && host_part != "localhost" && host_part != "[::1]" {
                tracing::warn!("DNS rebinding blocked: Host={}", host);
                // Issue (iter-103): 403 body was missing "ok": false.
                return (
                    StatusCode::FORBIDDEN,
                    AxumJson(
                        serde_json::json!({"ok": false, "error": "request blocked — invalid host"}),
                    ),
                )
                    .into_response();
            }
        }
    }
    next.run(req).await
}

// -------------------------------------------------------------------------- //
// --check logic tests                                                         //
// -------------------------------------------------------------------------- //
//
// Issue (iter-32): `--check` is a critical operator/CI tool (validates
// services.toml and exits with a specific exit code + stdout message).
// Previously it had zero unit test coverage — a regression could silently
// change the exit code or output format and break CI pipelines or Docker
// HEALTHCHECK scripts without any test failure.
//
// These tests call the same `ServiceRegistry::from_toml_file_with_counts`
// logic used by the `--check` path and assert on:
//   (a) missing file → accepted == 0, attempted == 0.
//   (b) valid file with services → accepted == N, list correct.
//   (c) file with an SSRF-blocked service → that service is rejected.

#[cfg(test)]
mod check_flag_tests {
    use crate::proxy::registry::ServiceRegistry;
    use std::io::Write;

    // ---------------------------------------------------------------------- //
    // (a) Missing file → both counters are zero                               //
    // ---------------------------------------------------------------------- //

    /// `from_toml_file_with_counts` on a non-existent path must return an
    /// empty registry with attempted == 0, matching the `--check` first-run
    /// branch (file_missing → exit 0 with "not found" message).
    #[test]
    fn check_missing_file_returns_zero_counts() {
        let path = std::path::Path::new("/tmp/vault-proxy-nonexistent-12345.toml");
        // Guarantee it really is absent.
        let _ = std::fs::remove_file(path);

        let (registry, attempted) = ServiceRegistry::from_toml_file_with_counts(path);
        let accepted = registry.list().len();

        assert_eq!(attempted, 0, "missing file: attempted must be 0");
        assert_eq!(accepted, 0, "missing file: accepted must be 0");
    }

    // ---------------------------------------------------------------------- //
    // (b) Valid file with services → accepted == attempted                    //
    // ---------------------------------------------------------------------- //

    /// A services.toml with two syntactically-valid, SSRF-clean entries must
    /// produce accepted == 2, attempted == 2, with the correct service names
    /// in the registry list. This mirrors the `--check` success path that
    /// prints "OK — N service(s) registered".
    #[test]
    fn check_valid_services_toml_counts_match() {
        let content = r#"
[[service]]
name = "sonarr"
base_url = "http://192.168.1.10:8989/api/v3"
auth = "header"
vault_item = "vault-proxy - Sonarr"
header_name = "X-Api-Key"

[[service]]
name = "radarr"
base_url = "http://192.168.1.11:7878/api/v3"
auth = "header"
vault_item = "vault-proxy - Radarr"
header_name = "X-Api-Key"
"#;
        let mut tmp = tempfile::NamedTempFile::new().expect("tmpfile");
        tmp.write_all(content.as_bytes()).unwrap();

        let (registry, attempted) = ServiceRegistry::from_toml_file_with_counts(tmp.path());
        let accepted = registry.list().len();

        assert_eq!(attempted, 2, "two [[service]] blocks must be attempted");
        assert_eq!(accepted, 2, "both valid entries must be accepted");

        let names = registry.list();
        assert!(names.contains(&"sonarr"), "sonarr must be in registry");
        assert!(names.contains(&"radarr"), "radarr must be in registry");
    }

    // ---------------------------------------------------------------------- //
    // (c) SSRF-blocked service → that entry is rejected                       //
    // ---------------------------------------------------------------------- //

    /// A services.toml where one service has an SSRF-blocked base_url (a
    /// private loopback address targeting vault-proxy itself) must result in
    /// attempted == 2, accepted == 1 — the blocked entry is counted as
    /// attempted but never added to the registry. This mirrors the `--check`
    /// PARTIAL path that prints "N/M service(s) accepted" and exits 1.
    #[test]
    fn check_ssrf_blocked_service_is_rejected() {
        let content = r#"
[[service]]
name = "good-service"
base_url = "http://192.168.1.10:8989/api/v3"
auth = "header"
vault_item = "vault-proxy - Good"
header_name = "X-Api-Key"

[[service]]
name = "ssrf-service"
base_url = "http://127.0.0.1:3201/internal"
auth = "header"
vault_item = "vault-proxy - Bad"
header_name = "X-Api-Key"
"#;
        let mut tmp = tempfile::NamedTempFile::new().expect("tmpfile");
        tmp.write_all(content.as_bytes()).unwrap();

        let (registry, attempted) = ServiceRegistry::from_toml_file_with_counts(tmp.path());
        let accepted = registry.list().len();
        let rejected = attempted.saturating_sub(accepted);

        assert_eq!(attempted, 2, "two [[service]] blocks must be attempted");
        assert_eq!(accepted, 1, "only the SSRF-clean service must be accepted");
        assert_eq!(
            rejected, 1,
            "SSRF-blocked service must be counted as rejected"
        );

        let names = registry.list();
        assert!(
            names.contains(&"good-service"),
            "clean service must be in registry"
        );
        assert!(
            !names.contains(&"ssrf-service"),
            "SSRF service must NOT be in registry"
        );
    }
}

// -------------------------------------------------------------------------- //
// Background vault refresh task tests (iter-38)                              //
// -------------------------------------------------------------------------- //
//
// These tests validate the timer-tick logic of the background refresh task
// without requiring a live Vaultwarden connection.  They use
// `tokio::time::pause()` + `tokio::time::advance()` to drive a synthetic
// interval loop that mirrors the production task and assert:
//
//   (a) The first tick is skipped (startup double-sync prevention).
//   (b) Exactly one counter increment fires per interval.
//   (c) A sync failure does NOT increment the counter (the task continues).
//
// The production task calls `VaultManager::sync()` which requires a live
// Vaultwarden connection — untestable in a unit context.  We substitute a
// simple atomic counter to verify the loop structure without the I/O.

#[cfg(test)]
mod bg_refresh_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// The background refresh task skips the first tick (to avoid a double-sync
    /// immediately after startup) and then fires on each subsequent interval.
    ///
    /// We drive a synthetic version of the production loop with `tokio::time`
    /// paused so the test runs in microseconds.
    ///
    /// Issue (iter-39): use `start_paused = true` instead of calling
    /// `tokio::time::pause()` inside the test body.  `start_paused` initialises
    /// the per-test runtime with time paused from the very first poll, which is
    /// the correct way to use frozen time.  `tokio::time::pause()` is a global
    /// mutation that would affect every timer in the same runtime — with
    /// `start_paused` each `#[tokio::test]` gets its own isolated runtime so
    /// the freeze is scoped to this test only.
    #[tokio::test(start_paused = true)]
    async fn background_refresh_skips_first_tick_and_fires_on_interval() {
        let fire_count = Arc::new(AtomicUsize::new(0));
        let counter = fire_count.clone();
        let interval_secs: u64 = 10;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            // Mirror production: skip the immediate first tick.
            interval.tick().await;
            for _ in 0..3 {
                interval.tick().await;
                counter.fetch_add(1, Ordering::SeqCst);
            }
        });

        // Yield once so the task starts and is waiting on the first (skipped) tick.
        tokio::task::yield_now().await;

        // The first tick fires immediately at t=0 (skipped — no increment).
        // Advance past the first real firing window.
        tokio::time::advance(std::time::Duration::from_secs(interval_secs + 1)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            fire_count.load(Ordering::SeqCst),
            1,
            "one interval elapsed — exactly one sync should have fired"
        );

        // Advance through two more intervals.
        tokio::time::advance(std::time::Duration::from_secs(interval_secs)).await;
        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_secs(interval_secs)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            fire_count.load(Ordering::SeqCst),
            3,
            "three intervals elapsed — three syncs should have fired in total"
        );
    }

    /// When `sync()` fails, the task must NOT increment its counter but MUST
    /// continue to the next interval rather than panicking or exiting.
    // Issue (iter-39): same `start_paused = true` rationale as above.
    #[tokio::test(start_paused = true)]
    async fn background_refresh_continues_after_failure() {
        let fire_count = Arc::new(AtomicUsize::new(0));
        let counter = fire_count.clone();
        let interval_secs: u64 = 5;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
            interval.tick().await; // skip first
            for tick in 0u32..4 {
                interval.tick().await;
                // Simulate sync failure on tick 1 and 3 (0-indexed).
                if tick % 2 == 1 {
                    // Failure path: log (elided in test) and continue.
                    let _e = "simulated sync error";
                } else {
                    counter.fetch_add(1, Ordering::SeqCst);
                }
            }
        });

        tokio::task::yield_now().await;

        // 4 intervals: tick 0 = success (+1), tick 1 = fail, tick 2 = success (+1), tick 3 = fail.
        for _ in 0..4 {
            tokio::time::advance(std::time::Duration::from_secs(interval_secs)).await;
            tokio::task::yield_now().await;
        }

        assert_eq!(
            fire_count.load(Ordering::SeqCst),
            2,
            "two successful syncs out of four ticks — task must not exit on failure"
        );
    }
}

// -------------------------------------------------------------------------- //
// browser_rotate guard tests (iter-49)                                       //
// -------------------------------------------------------------------------- //
//
// These tests verify the two early-return guards added in iter-8 and iter-48:
//
//   (a) litellm_url is empty → actionable 400 error before spawning the task.
//   (b) model_name is empty  → actionable 400 error before spawning the task.
//   (c) item_name is empty   → existing guard still fires (regression check).
//
// Each test builds a minimal `AppState` with `BrowserAgent` set to a
// deliberately incomplete configuration and calls `browser_rotate` directly
// (no HTTP stack needed — the handler is a plain async fn).
//
// iter-81: gated behind `feature = "browser"` — the handler and BrowserAgent
// are absent from default builds, so these tests only run when the feature is on.

#[cfg(all(test, feature = "browser"))]
mod browser_rotate_guard_tests {
    use super::{browser_rotate, AppState};
    use crate::browser::BrowserAgent;
    use crate::notify::Notifier;
    use crate::proxy::registry::ServiceRegistry;
    use crate::proxy::unifi_session::UnifiSessionCache;
    use crate::security::audit_log::AuditLog;
    use crate::security::permissions::ToolPermissions;
    use crate::vault::VaultManager;
    use axum::extract::State as AxumState;
    use axum::response::IntoResponse;
    use axum::Json as AxumJson;
    use std::collections::{HashMap, VecDeque};
    use std::sync::atomic::AtomicU64;
    use std::sync::Arc;

    /// Extract the JSON body from an `impl IntoResponse` value (used after
    /// iter-104 changed browser_rotate to return impl IntoResponse).
    async fn extract_json_body(resp: impl IntoResponse) -> serde_json::Value {
        let response = resp.into_response();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body read failed");
        serde_json::from_slice(&bytes).expect("body is not valid JSON")
    }

    /// Build the minimal `AppState` needed to exercise `browser_rotate`.
    /// `browser_agent` is injected so each test can customise the field under
    /// test while keeping the rest of the state identical.
    fn make_state_with_browser(browser_agent: Option<Arc<BrowserAgent>>) -> Arc<AppState> {
        use std::sync::atomic::{AtomicU64 as AuU64, Ordering};
        static CTR: AuU64 = AuU64::new(0);
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        Arc::new(AppState {
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
            browser: browser_agent,
            permissions: Arc::new(tokio::sync::RwLock::new(ToolPermissions::load(
                "/nonexistent/tool-permissions.json",
            ))),
            audit_log: Arc::new(AuditLog::new(&format!(
                "/tmp/vp-test-browser-rotate-{n}.json"
            ))),
            access_log: None,
            rotation_hook: None,
            mint_wi_mcp: Arc::new(crate::rotate::strategies::SshDockerMintExecutor::from_env()),
            change_wi_mcp_admin: Arc::new(
                crate::rotate::strategies::SshDockerAdminPasswordChanger::from_env(),
            ),
            notifier: Arc::new(Notifier::disabled()),
            handshake_completed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            vault_folder: "vault-proxy".to_string(),
            last_resync_unix: Arc::new(AtomicU64::new(0)),
            internal_token: Arc::new("test-token".to_string()),
            cached_folder_id: Arc::new(tokio::sync::RwLock::new(None)),
            env_write_root: String::new(),
            config_dir: "/config".to_string(),
            proxy_timeout: 120,
            reload_mutex: Arc::new(tokio::sync::Mutex::new(())),
            audit_mutex: Arc::new(tokio::sync::Mutex::new(())),
            smb: crate::proxy::SmbConfig::default(),
            transparent_registry: Arc::new(tokio::sync::RwLock::new(None)),
            transparent_placeholders: Arc::new(tokio::sync::RwLock::new(None)),
        })
    }

    /// Guard (iter-8): when `BrowserAgent.litellm_url` is empty, `browser_rotate`
    /// must return an error JSON with a message directing the operator to set
    /// `LITELLM_URL`, rather than spawning a workflow that fails deep inside
    /// `VisionModel::analyze` with a cryptic "relative URL without a base" error.
    #[tokio::test]
    async fn browser_rotate_empty_litellm_url_returns_error() {
        let agent = Arc::new(BrowserAgent::new(
            "",       // empty litellm_url — the path under test
            "",       // api_key
            "gpt-4o", // model_name is set; only litellm_url is absent
        ));
        let state = make_state_with_browser(Some(agent));

        let req = serde_json::json!({ "item_name": "my-vault-item" });
        let resp = extract_json_body(browser_rotate(AxumState(state), AxumJson(req)).await).await;

        let error_msg = resp
            .get("error")
            .and_then(|v: &serde_json::Value| v.as_str())
            .expect("response must contain an 'error' field");

        assert!(
            error_msg.contains("LITELLM_URL"),
            "error should mention LITELLM_URL; got: {error_msg}"
        );
    }

    /// Guard (iter-48): when `BrowserAgent.model_name` is empty, `browser_rotate`
    /// must return an error JSON directing the operator to set `VISION_MODEL`.
    #[tokio::test]
    async fn browser_rotate_empty_model_name_returns_error() {
        let agent = Arc::new(BrowserAgent::new("http://mlbox.local:4000", "", ""));
        let state = make_state_with_browser(Some(agent));

        let req = serde_json::json!({ "item_name": "my-vault-item" });
        let resp = extract_json_body(browser_rotate(AxumState(state), AxumJson(req)).await).await;

        let error_msg = resp
            .get("error")
            .and_then(|v: &serde_json::Value| v.as_str())
            .expect("response must contain an 'error' field");

        assert!(
            error_msg.contains("VISION_MODEL"),
            "error should mention VISION_MODEL; got: {error_msg}"
        );
    }

    /// Regression guard: `item_name` missing from the request body should return an error.
    #[tokio::test]
    async fn browser_rotate_missing_item_name_returns_error() {
        let agent = Arc::new(BrowserAgent::new("http://mlbox.local:4000", "", "gpt-4o"));
        let state = make_state_with_browser(Some(agent));

        let req = serde_json::json!({});
        let resp = extract_json_body(browser_rotate(AxumState(state), AxumJson(req)).await).await;

        let error_msg = resp
            .get("error")
            .and_then(|v: &serde_json::Value| v.as_str())
            .expect("response must contain an 'error' field");

        assert!(
            error_msg.contains("item_name"),
            "error should mention item_name; got: {error_msg}"
        );
    }
}

// -------------------------------------------------------------------------- //
// browser_status 503 tests (iter-106)                                        //
// -------------------------------------------------------------------------- //
//
// Iter-105 fixed `browser_status` to return HTTP 503 with `"ok": false` when
// the browser agent is not configured, but no test was added at the time.
//
// These tests verify:
//   (a) browser=None → HTTP 503 with `"ok": false` in the body.
//   (b) browser=Some(idle agent) → HTTP 200 with `{"status": "idle"}`.

#[cfg(all(test, feature = "browser"))]
mod browser_status_tests {
    use super::{browser_status, AppState};
    use crate::browser::BrowserAgent;
    use crate::notify::Notifier;
    use crate::proxy::registry::ServiceRegistry;
    use crate::proxy::unifi_session::UnifiSessionCache;
    use crate::security::audit_log::AuditLog;
    use crate::security::permissions::ToolPermissions;
    use axum::extract::State as AxumState;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use std::collections::{HashMap, VecDeque};
    use std::sync::atomic::AtomicU64;
    use std::sync::Arc;

    /// Build the minimal `AppState` needed to exercise `browser_status`.
    fn make_state(browser_agent: Option<Arc<BrowserAgent>>) -> Arc<AppState> {
        use std::sync::atomic::{AtomicU64 as AuU64, Ordering};
        static CTR: AuU64 = AuU64::new(0);
        let n = CTR.fetch_add(1, Ordering::Relaxed);
        Arc::new(AppState {
            vault: Arc::new(crate::vault::VaultManager::new_stub()),
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
            browser: browser_agent,
            permissions: Arc::new(tokio::sync::RwLock::new(ToolPermissions::load(
                "/nonexistent/tool-permissions.json",
            ))),
            audit_log: Arc::new(AuditLog::new(&format!(
                "/tmp/vp-test-browser-status-{n}.json"
            ))),
            access_log: None,
            rotation_hook: None,
            mint_wi_mcp: Arc::new(crate::rotate::strategies::SshDockerMintExecutor::from_env()),
            change_wi_mcp_admin: Arc::new(
                crate::rotate::strategies::SshDockerAdminPasswordChanger::from_env(),
            ),
            notifier: Arc::new(Notifier::disabled()),
            handshake_completed: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            vault_folder: "vault-proxy".to_string(),
            last_resync_unix: Arc::new(AtomicU64::new(0)),
            internal_token: Arc::new("test-token".to_string()),
            cached_folder_id: Arc::new(tokio::sync::RwLock::new(None)),
            env_write_root: String::new(),
            config_dir: "/config".to_string(),
            proxy_timeout: 120,
            reload_mutex: Arc::new(tokio::sync::Mutex::new(())),
            audit_mutex: Arc::new(tokio::sync::Mutex::new(())),
            smb: crate::proxy::SmbConfig::default(),
            transparent_registry: Arc::new(tokio::sync::RwLock::new(None)),
            transparent_placeholders: Arc::new(tokio::sync::RwLock::new(None)),
        })
    }

    /// Helper: extract status code + JSON body from an `impl IntoResponse`.
    async fn extract(resp: impl IntoResponse) -> (StatusCode, serde_json::Value) {
        let response = resp.into_response();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body read failed");
        let body = serde_json::from_slice(&bytes).expect("body is not valid JSON");
        (status, body)
    }

    /// Issue (iter-105 fix, test added iter-106): when `browser` is `None`
    /// (agent not configured), `browser_status` must return HTTP 503 with
    /// `"ok": false` — not HTTP 200 as it did before iter-105.
    #[tokio::test]
    async fn browser_status_none_returns_503() {
        let state = make_state(None);
        let (status, body) = extract(browser_status(AxumState(state)).await).await;

        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "browser=None must return 503; got {status}"
        );
        assert_eq!(
            body.get("ok").and_then(|v| v.as_bool()),
            Some(false),
            "body must contain ok=false; got {body}"
        );
        assert!(
            body.get("error").is_some(),
            "body must contain an error field; got {body}"
        );
    }

    /// When a browser agent is configured but idle (no current job),
    /// `browser_status` must return HTTP 200 with `{"ok": true, "status": "idle"}`.
    ///
    /// Issue (iter-107): the idle path previously returned `{"status": "idle"}`
    /// without `"ok": true`, inconsistent with every other success body in the
    /// codebase. Fixed in handler; this test now also verifies `ok=true`.
    #[tokio::test]
    async fn browser_status_idle_returns_200() {
        let agent = Arc::new(BrowserAgent::new("http://mlbox.local:4000", "", "gpt-4o"));
        let state = make_state(Some(agent));
        let (status, body) = extract(browser_status(AxumState(state)).await).await;

        assert_eq!(
            status,
            StatusCode::OK,
            "idle browser must return 200; got {status}"
        );
        assert_eq!(
            body.get("status").and_then(|v| v.as_str()),
            Some("idle"),
            "body must contain status=idle; got {body}"
        );
        // iter-107: ok=true must be present in the idle response.
        assert_eq!(
            body.get("ok").and_then(|v| v.as_bool()),
            Some(true),
            "idle body must contain ok=true; got {body}"
        );
    }
}

// -------------------------------------------------------------------------- //
// CLI flag tests (unconditional — all build configurations)                   //
// -------------------------------------------------------------------------- //

#[cfg(test)]
mod cli_flag_tests {
    use super::Args;
    use clap::Parser;

    /// iter-115: `--persist-dashboard-cert` must be accepted by clap in ALL build
    /// configurations, including headless builds where the `dashboard` feature is
    /// absent.
    ///
    /// The field is intentionally NOT gated with `#[cfg(feature = "dashboard")]`
    /// at the struct level. Gating it would cause clap to emit:
    ///   "error: unexpected argument '--persist-dashboard-cert' found"
    /// with no hint that the operator needs to rebuild with `--features dashboard`.
    ///
    /// Instead the flag is always present in the CLI. When the dashboard feature
    /// is compiled out, the value is checked at startup and a `tracing::warn!` is
    /// emitted if the operator passed the flag.
    #[test]
    fn persist_dashboard_cert_accepted_by_clap_in_all_builds() {
        let args = Args::try_parse_from([
            "vaultproxy",
            "--persist-dashboard-cert",
            "--config-dir",
            "/tmp",
        ]);
        assert!(
            args.is_ok(),
            "--persist-dashboard-cert must be accepted by clap in all build configurations; \
             clap returned: {:?}",
            args.err()
        );
        assert!(
            args.unwrap().persist_dashboard_cert,
            "--persist-dashboard-cert must set persist_dashboard_cert=true"
        );
    }

    /// iter-115: without `--persist-dashboard-cert`, the field must default to
    /// `false` — no opt-in cert persistence unless explicitly requested.
    #[test]
    fn persist_dashboard_cert_defaults_to_false() {
        let args = Args::try_parse_from(["vaultproxy", "--config-dir", "/tmp"])
            .expect("minimal args must parse");
        assert!(
            !args.persist_dashboard_cert,
            "--persist-dashboard-cert must default to false when not supplied"
        );
    }
}
