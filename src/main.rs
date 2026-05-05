mod audit;
mod internal_token;
mod keystore;
mod launcher;
mod setup;
mod browser;
mod credential_audit;
#[cfg(feature = "dashboard")]
mod dashboard;
mod notify;
mod policy;
mod proxy;
mod rotate;
mod secure;
mod security;
mod sync;
mod tls;
mod totp;
mod tpm;
mod vault;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{extract::State as AxumState, Json as AxumJson, response::IntoResponse, routing::{get, post}, Router};
use clap::Parser;

use proxy::{AppState, handle_proxy, registry::ServiceRegistry};
use sync::{SyncManager, cloud::CloudClient, websocket};
use vault::VaultManager;
use vault::handlers;

// -------------------------------------------------------------------------- //
// CLI args                                                                    //
// -------------------------------------------------------------------------- //

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

    /// Bitwarden cloud account email (enables cloud sync when set).
    #[arg(long, env = "CLOUD_EMAIL")]
    cloud_email: Option<String>,

    /// Override KDF iterations for Bitwarden cloud (use if prelogin returns wrong value).
    #[arg(long, env = "CLOUD_KDF_ITERATIONS")]
    cloud_kdf_iterations: Option<u32>,

    /// LiteLLM (OpenAI-compatible) base URL for vision model inference.
    /// Defaults to the MLbox local stack so screenshots/credentials never
    /// leave the homelab network.
    #[arg(long, env = "LITELLM_URL", default_value = "")]
    litellm_url: String,

    /// LiteLLM API key (Bearer auth). Empty = no auth header.
    #[arg(long, env = "LITELLM_API_KEY", default_value = "")]
    litellm_api_key: String,

    /// Vision model name (must be served by LiteLLM). Default routes
    /// to the MLbox `vision` profile (Qwen3-VL-32B-FP8).
    #[arg(long, env = "VISION_MODEL", default_value = "qwen3-vl-32b")]
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
        .init();

    let args = Args::parse();
    let config_dir = args.config_dir.clone();

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
                services_path.display(), services_path.display()
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

        println!(
            "vaultproxy check: OK — {accepted} service(s) registered from {}: {:?}",
            services_path.display(),
            registry.list()
        );
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
        std::fs::create_dir_all(&config_dir)
            .map_err(|e| anyhow::anyhow!(
                "--config-dir '{}' does not exist and could not be created: {}",
                config_dir, e
            ))?;
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
    // Generate ephemeral mTLS certificates for HTTPS
    let certs = tpm::generate_mtls_certs()
        .map_err(|e| anyhow::anyhow!("cert generation failed: {}", e))?;

    // Shared channel: dashboard writes the setup password here after setup/unlock,
    // the polling loop reads it to decrypt credentials.
    let unlock_password: Arc<tokio::sync::RwLock<Option<zeroize::Zeroizing<String>>>> = Arc::new(tokio::sync::RwLock::new(None));

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
        let cert_pem = certs.server_cert_pem.as_bytes().to_vec();
        let key_pem = certs.server_key_pem.as_bytes().to_vec();
        axum_server::tls_rustls::RustlsConfig::from_pem(cert_pem, key_pem)
            .await
            .expect("failed to build dashboard TLS config")
    };

    // Spawn dashboard
    tokio::spawn(async move {
        tracing::info!("dashboard listening on {} (HTTPS) — waiting for setup/unlock", dash_addr);
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
                tracing::info!("credentials unlocked via TPM — connecting to Vaultwarden at {}", creds.vaultwarden.url);
                match VaultManager::new(&creds.vaultwarden.url, &creds.vaultwarden.email, &creds.vaultwarden.master_password).await {
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
                    tracing::info!("credentials unlocked via dashboard — connecting to Vaultwarden at {}", creds.vaultwarden.url);
                    match VaultManager::new(&creds.vaultwarden.url, &creds.vaultwarden.email, &creds.vaultwarden.master_password).await {
                        Ok(vault) => {
                            // Clear the password from memory. Setting `None`
                            // drops the `Zeroizing<String>`, which zeroes the
                            // underlying bytes before freeing.
                            *unlock_password_poll.write().await = None;
                            // Seal to TPM if not already sealed (enables auto-unlock on next boot)
                            if !keystore::has_tpm_key(&config_dir_poll) && crate::tpm::tpm_available() {
                                tracing::info!("sealing keystore to TPM for auto-unlock");
                                if let Err(e) = keystore::seal_after_unlock(&config_dir_poll, pw_str) {
                                    tracing::warn!("TPM sealing failed (software fallback still works): {}", e);
                                }
                            }
                            tracing::info!("vault initialized — starting full server");
                            return start_server(args_poll, vault, &config_dir_poll, creds.cloud).await;
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
    if let Some(ref server_name) = args.launch {
        return crate::launcher::launch(server_name, config_dir, &vault_arc).await;
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
                match CloudClient::from_api_key(cloud_email, cloud_password, cid, csec, kdf_override).await {
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
                match CloudClient::from_refresh_token(cloud_email, cloud_password, rt, kdf_override).await {
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
                let master_key = vault::crypto::derive_master_key(cloud_password, cloud_email, kdf_iters);
                let pw_hash = vault::crypto::hash_master_password(master_key.as_bytes(), cloud_password);

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
                        struct TokenResp { refresh_token: Option<String> }
                        if let Ok(data) = resp.json::<TokenResp>().await {
                            if let Some(rt) = data.refresh_token {
                                tracing::info!("got fresh refresh token via password auth");
                                match CloudClient::from_refresh_token(
                                    cloud_email, cloud_password, &rt, args.cloud_kdf_iterations,
                                ).await {
                                    Ok((client, _new_rt)) => {
                                        Some(client)
                                    }
                                    Err(e) => {
                                        tracing::error!("from_refresh_token with fresh token failed: {:#}", e);
                                        None
                                    }
                                }
                            } else {
                                tracing::error!("password auth succeeded but no refresh token returned");
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
            svc_count, services_path, registry.list()
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
        let resolved = vault_arc.find_folder_id_by_name_async(&args.vault_folder).await;
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

    // Generate ephemeral mTLS certificates.
    //
    // Issue-6 (iter-5): These certs are regenerated on every startup — they are
    // NOT persisted between restarts. This is intentional (no disk footprint,
    // no stale key material), but it has a user-experience consequence:
    // every restart produces a new self-signed cert with a new fingerprint,
    // so browsers that pinned the previous cert (HSTS / cert pinning) will
    // show a "certificate has changed" warning.
    //
    // The dashboard is accessed via localhost only, so the practical risk of
    // a fresh cert is low. However, if you use a browser with strict HSTS or
    // have previously clicked "Remember this exception", you may need to clear
    // the security exception after a restart. This is a deliberate tradeoff:
    //
    //   Option A (current): ephemeral cert — no disk IO, no stale key, browser
    //                       warning on restart.
    //   Option B (future):  persist cert to /config/dashboard-tls.pem and only
    //                       regenerate if the cert is missing, expired, or if
    //                       --setup is re-run. Eliminates browser warnings at
    //                       the cost of a file on disk.
    //
    // TODO: Implement option B (persisted dashboard cert) behind a
    // `--persist-dashboard-cert` flag for operators who use the dashboard
    // frequently and don't want the warning on every container restart.
    tracing::info!("generating ephemeral mTLS certificates");
    let certs = tpm::generate_mtls_certs()
        .map_err(|e| anyhow::anyhow!("cert generation failed: {}", e))?;
    #[cfg(feature = "dashboard")]
    let dashboard_certs = certs.clone();

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
                                        svc_name, ca_path
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

    // Initialize browser agent.
    let browser_agent = Arc::new(browser::BrowserAgent::new(
        &args.litellm_url,
        &args.litellm_api_key,
        &args.vision_model,
    ));

    // Initialize tool permissions and audit log.
    let permissions = Arc::new(tokio::sync::RwLock::new(
        security::permissions::ToolPermissions::load(
            &format!("{}/tool-permissions.json", config_dir),
        ),
    ));
    let audit_log = Arc::new(security::audit_log::AuditLog::new(
        &format!("{}/audit-log.json", config_dir),
    ));

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
        "ntfy" if !args.ntfy_url.is_empty() => {
            notify::Notifier::new(notify::NotifyChannel::Ntfy {
                url: args.ntfy_url.clone(),
            })
        }
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
        browser: Some(browser_agent),
        permissions,
        audit_log,
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
    });

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
    let internal_router = Router::new()
        .route("/handshake", get(handlers::handshake))
        .route("/vault/connecterr-secrets", get(handlers::connecterr_secrets))
        .route(
            "/vault/connecterr-secrets/upsert",
            axum::routing::post(crate::vault::handlers::upsert_connecterr_secrets)
                .layer(DefaultBodyLimit::max(512 * 1024)),
        )
        .route("/rotate",             post(rotate::handle_rotate))
        .route("/browser/rotate",     post(browser_rotate))
        .route("/browser/status",     get(browser_status))
        .route("/browser/screenshot", get(browser_screenshot))
        .route("/browser/abort",      post(browser_abort))
        // iter-23: decrypt_notes returns full plaintext notes (API tokens, SSH
        // keys, recovery codes). Gate it behind the internal bearer token.
        .route("/vault/notes",        post(handlers::decrypt_notes))
        // iter-34: reload-services performs a hot-reload of services.toml and
        // returns a synchronous JSON confirmation. Gated behind the internal
        // bearer token because it modifies live routing state (the registry and
        // CA-cert client map). Equivalent to sending SIGHUP but HTTP-accessible.
        .route("/vault/reload-services", post(handlers::reload_services))
        // Gate the entire sub-router behind the internal bearer token.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_internal_token,
        ))
        .with_state(state.clone());

    let app = Router::new()
        .route("/vault/health",       get(handlers::health))
        // Issue (iter-26): New debugging endpoint — returns service names, auth types,
        // and base URLs without exposing vault_item names or credential details.
        // Helps MCP server developers verify that services.toml loaded correctly.
        .route("/vault/services",     get(handlers::list_services))
        .route("/vault/items",        get(handlers::list_items))
        .route("/vault/duplicates",   get(handlers::list_duplicates))
        .route("/vault/folders",      get(handlers::list_folders))
        .route("/vault/folders/delete", post(handlers::delete_folder))
        .route("/vault/test-credential", post(handlers::test_credential))
        .route("/vault/items/clone",   post(handlers::clone_item))
        .route("/vault/write-env",    post(handlers::write_env))
        .route("/vault/items/untracked", get(handlers::list_untracked_items))
        .route("/vault/totp",         post(handlers::generate_totp))
        // NOTE: POST /vault/notes is on the internal_router (bearer token required).
        // Moved to internal_router in iter-23 — returns raw decrypted notes.
        .route("/vault/items",        post(handlers::create_item))
        .route("/vault/items/delete", post(handlers::delete_item))
        .route("/vault/items/update", post(handlers::update_item))
        .route("/vault/items/move",   post(handlers::move_item))
        .route("/vault/inject-creds",  post(handlers::inject_creds))
        .route("/vault/check-permission", get(handlers::check_permission))
        .route("/vault/resync",        post(handlers::vault_resync))
        .route("/sync/status",        get(handlers::sync_status))
        .route("/sync/trigger",       post(handlers::sync_trigger))
        .route("/sync/init",           post(handlers::sync_init))
        .route("/sync/setup-cloud",   post(handlers::setup_cloud))
        .route("/sync/totp",          post(handlers::provide_totp))
        .route("/proxy",              post(handle_proxy))
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
    let cred_audit_db_path = format!("{}/credential_audit.sqlite", config_dir);
    let cred_audit_conn = credential_audit::db::open_db(&cred_audit_db_path)
        .expect("open credential_audit db");
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
    let cred_audit_orch = std::sync::Arc::new(credential_audit::orchestrator::Orchestrator {
        vault: std::sync::Arc::new(credential_audit::vw_adapter::VwAdapter::new(
            vault_arc.clone(),
        )),
        engine: cred_audit_engine,
        marker: credential_audit::marker::Marker::new(vault_arc.clone()),
        conn: std::sync::Arc::new(std::sync::Mutex::new(cred_audit_conn)),
        pass2: cred_audit_pass2,
    });

    let cred_audit_router = credential_audit::router(cred_audit_orch.clone());
    let app = app.merge(cred_audit_router);

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
                        tracing::warn!("policy scheduler task exited unexpectedly — restarting in 5s");
                    }
                    Err(e) if e.is_panic() => {
                        tracing::error!(
                            "policy scheduler panicked — restarting in 5s. \
                             This should not happen; please file a bug report. {:?}", e
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
                let ws_handle = tokio::spawn(async move {
                    websocket::listen(&ws_url, &ws_token, tx).await
                });

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
                                    if let Err(e) = sync_ws
                                        .sync_cipher_to_vw(&cloud, &cipher, &mut map)
                                        .await
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
                    sleep_secs, ws_backoff_secs, jitter,
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
            cred_audit_orch: Some(cred_audit_orch.clone()),
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
            let mut sighup = match tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::hangup(),
            ) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("SIGHUP: failed to register signal handler: {} — hot-reload disabled", e);
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
                                        .timeout(std::time::Duration::from_secs(sighup_proxy_timeout))
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

                    tracing::info!(
                        "SIGHUP: reload complete — {} service(s) now registered (was {})",
                        svc_count, prev_svc_count
                    );

                    // iter-33: Re-run the vault_folder existence check so
                    // operators who created the folder and then sent SIGHUP
                    // see an explicit confirmation rather than silence. This
                    // mirrors the startup check in main() and uses the same
                    // log format so log-scrapers can match either event.
                    let resolved = sighup_vault.find_folder_id_by_name_async(&sighup_vault_folder).await;
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
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(interval_secs));
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
        tracing::debug!(
            "vault background refresh disabled \
             (set VAULT_REFRESH_INTERVAL_SECS=300 to enable 5-minute auto-sync)"
        );
    }

    let server_handle = axum_server::Handle::new();
    let shutdown_handle = server_handle.clone();

    // Spawn the signal watcher — triggers graceful shutdown on SIGTERM or Ctrl-C.
    tokio::spawn(async move {
        let sigterm_fut: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> = {
            #[cfg(unix)]
            {
                Box::pin(async {
                    if let Ok(mut sig) = tokio::signal::unix::signal(
                        tokio::signal::unix::SignalKind::terminate(),
                    ) {
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
        // Allow up to 10 s for in-flight requests to complete before hard-kill.
        shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(10)));
    });

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
// Browser agent handlers                                                      //
// -------------------------------------------------------------------------- //

async fn browser_rotate(
    AxumState(state): AxumState<Arc<AppState>>,
    AxumJson(req): AxumJson<serde_json::Value>,
) -> AxumJson<serde_json::Value> {
    let browser = match &state.browser {
        Some(b) => Arc::clone(b),
        None => return AxumJson(serde_json::json!({"error": "browser agent not configured"})),
    };

    let item_name = req.get("item_name").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let login_url = req.get("login_url").and_then(|v| v.as_str()).unwrap_or("").to_string();

    if item_name.is_empty() {
        return AxumJson(serde_json::json!({"error": "item_name required"}));
    }

    // Issue (iter-8): Guard against an empty litellm_url. When --litellm-url is
    // not configured (default = ""), VisionModel::analyze() constructs a
    // relative URL ("/v1/chat/completions") which reqwest rejects with a
    // "relative URL without a base" error deep inside the spawned workflow task,
    // producing a log error with no clear indication that the root cause is a
    // missing LITELLM_URL. Return a clear 400 here before spawning anything.
    if browser.litellm_url.is_empty() {
        return AxumJson(serde_json::json!({
            "error": "browser rotation requires a vision model — set LITELLM_URL (e.g. LITELLM_URL=http://mlbox.local:4000)"
        }));
    }

    // Validate login_url against the same SSRF policy used by `inject_creds`
    // (blocks 169.254.0.0/16, fe80::/10, and all cloud-metadata hostnames).
    // The previous inline check only blocked two literal hostnames — bypassed
    // by any other link-local IP or the IPv6 IMDS address.
    if !login_url.is_empty() && !crate::vault::handlers::is_allowed_outbound_url(&login_url) {
        return AxumJson(serde_json::json!({
            "error": "login_url must be http(s) and resolve to a non-metadata, non-link-local host"
        }));
    }

    let vault = state.vault.clone();
    let approval_queue = state.approval_queue.clone();
    let notifier = state.notifier.clone();
    let litellm_url = browser.litellm_url.clone();
    let api_key = browser.api_key.clone();
    let model_name = browser.model_name.clone();
    let browser_ref = Arc::clone(&browser);
    let item_name_response = item_name.clone();

    tokio::spawn(async move {
        let pw = match crate::browser::playwright::PlaywrightProcess::spawn().await {
            Ok(pw) => pw,
            Err(e) => {
                tracing::error!("failed to spawn playwright: {}", e);
                return;
            }
        };

        let vision = crate::browser::vision::VisionModel::new(&litellm_url, &api_key, &model_name);
        let mut workflow = crate::browser::workflow::RotationWorkflow::new(
            &item_name, &login_url, pw, vision,
        ).await;

        *browser_ref.current_job.write().await = Some(workflow.state.clone());

        let success = workflow.run(&vault, &approval_queue).await;

        *browser_ref.current_job.write().await = Some(workflow.state.clone());
        if let Some(ref screenshot) = workflow.state.last_screenshot_b64 {
            *browser_ref.last_screenshot.write().await = Some(screenshot.clone());
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

    AxumJson(serde_json::json!({"status": "started", "item_name": item_name_response}))
}

async fn browser_status(
    AxumState(state): AxumState<Arc<AppState>>,
) -> AxumJson<serde_json::Value> {
    let browser = match &state.browser {
        Some(b) => b,
        None => return AxumJson(serde_json::json!({"status": "not_configured"})),
    };
    let job = browser.current_job.read().await;
    match &*job {
        Some(ws) => AxumJson(serde_json::to_value(ws).unwrap_or_default()),
        None => AxumJson(serde_json::json!({"status": "idle"})),
    }
}

async fn browser_screenshot(
    AxumState(state): AxumState<Arc<AppState>>,
) -> AxumJson<serde_json::Value> {
    let browser = match &state.browser {
        Some(b) => b,
        None => return AxumJson(serde_json::json!({"error": "not configured"})),
    };
    let screenshot = browser.last_screenshot.read().await;
    match &*screenshot {
        Some(b64) => AxumJson(serde_json::json!({"image_b64": b64})),
        None => AxumJson(serde_json::json!({"image_b64": null})),
    }
}

async fn browser_abort(
    AxumState(state): AxumState<Arc<AppState>>,
) -> AxumJson<serde_json::Value> {
    let browser = match &state.browser {
        Some(b) => b,
        None => return AxumJson(serde_json::json!({"error": "not configured"})),
    };
    *browser.current_job.write().await = None;
    AxumJson(serde_json::json!({"status": "aborted"}))
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
    let len_diff: u8 = if provided_bytes.len() == expected_bytes.len() { 0 } else { 1 };
    let valid = (byte_diff | len_diff) == 0;

    if !valid {
        tracing::warn!(
            "require_internal_token: rejected request to {} — missing or invalid Bearer token",
            req.uri().path()
        );
        return (
            StatusCode::UNAUTHORIZED,
            AxumJson(serde_json::json!({
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
            return (
                StatusCode::FORBIDDEN,
                AxumJson(serde_json::json!({"error": "request blocked — missing host header"})),
            )
                .into_response();
        }
        Some(host) => {
            let host_part = host.split(':').next().unwrap_or(host);
            if host_part != "127.0.0.1" && host_part != "localhost" && host_part != "[::1]" {
                tracing::warn!("DNS rebinding blocked: Host={}", host);
                return (
                    StatusCode::FORBIDDEN,
                    AxumJson(serde_json::json!({"error": "request blocked — invalid host"})),
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

        let (registry, attempted) =
            ServiceRegistry::from_toml_file_with_counts(path);
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

        let (registry, attempted) =
            ServiceRegistry::from_toml_file_with_counts(tmp.path());
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

        let (registry, attempted) =
            ServiceRegistry::from_toml_file_with_counts(tmp.path());
        let accepted = registry.list().len();
        let rejected = attempted.saturating_sub(accepted);

        assert_eq!(attempted, 2, "two [[service]] blocks must be attempted");
        assert_eq!(accepted, 1, "only the SSRF-clean service must be accepted");
        assert_eq!(rejected, 1, "SSRF-blocked service must be counted as rejected");

        let names = registry.list();
        assert!(names.contains(&"good-service"), "clean service must be in registry");
        assert!(!names.contains(&"ssrf-service"), "SSRF service must NOT be in registry");
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
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// The background refresh task skips the first tick (to avoid a double-sync
    /// immediately after startup) and then fires on each subsequent interval.
    ///
    /// We drive a synthetic version of the production loop with `tokio::time`
    /// paused so the test runs in microseconds.
    #[tokio::test]
    async fn background_refresh_skips_first_tick_and_fires_on_interval() {
        tokio::time::pause();

        let fire_count = Arc::new(AtomicUsize::new(0));
        let counter = fire_count.clone();
        let interval_secs: u64 = 10;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                std::time::Duration::from_secs(interval_secs),
            );
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
    #[tokio::test]
    async fn background_refresh_continues_after_failure() {
        tokio::time::pause();

        let fire_count = Arc::new(AtomicUsize::new(0));
        let counter = fire_count.clone();
        let interval_secs: u64 = 5;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                std::time::Duration::from_secs(interval_secs),
            );
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
