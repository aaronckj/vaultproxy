//! Setup flow for first-time Connecterr credential configuration.
//!
//! Provides both a CLI interactive wizard and shared state for the web setup flow.

use std::io::{self, BufRead, Write};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio::sync::RwLock;
use zeroize::Zeroizing;

use crate::keystore::{self, Credentials, VaultwardenCreds};
use crate::vault::VaultManager;

/// Shared state for the web-based setup wizard.
pub struct SetupState {
    pub config_dir: String,
    pub completed: Arc<RwLock<bool>>,
}

impl SetupState {
    pub fn new(config_dir: &str) -> Self {
        Self {
            config_dir: config_dir.to_string(),
            completed: Arc::new(RwLock::new(false)),
        }
    }
}

/// Validate Vaultwarden credentials by attempting to authenticate.
///
/// Issue-9 (iter-4): Errors are annotated with the URL and a human-readable
/// hint so operators know immediately whether the problem is a wrong URL
/// (network unreachable / DNS failure), wrong email/password (401 from
/// Vaultwarden), or a TLS issue (self-signed cert without accept_invalid_certs).
/// Previously all three cases surfaced the same opaque "vault init failed" line
/// in the setup wizard output.
pub async fn validate_vaultwarden_creds(url: &str, email: &str, password: &str) -> Result<()> {
    // Guard against an SSRF-style setup where the operator is tricked into
    // pointing the wizard at a link-local/cloud-metadata endpoint. Every
    // other handler that takes an operator URL already uses this gate
    // (iter-9 for inject_creds, iter-15 for browser_rotate); setup was the
    // last place an unchecked URL reached `reqwest`.
    if !crate::vault::handlers::is_allowed_outbound_url(url) {
        return Err(anyhow!(
            "vaultwarden URL must be http(s) and resolve to a non-metadata, non-link-local host"
        ));
    }
    VaultManager::new(url, email, password).await.map_err(|e| {
        // Classify the error into actionable buckets for the operator.
        let detail = e.to_string();
        let hint = if detail.contains("authentication failed") || detail.contains("401") {
            "wrong email or master password — verify your Vaultwarden login credentials"
        } else if detail.contains("prelogin request failed")
            || detail.contains("connection refused")
            || detail.contains("dns error")
            || detail.contains("No such host")
            || detail.contains("tcp connect")
        {
            "cannot reach Vaultwarden — check the URL, ensure the server is running and reachable from this host"
        } else if detail.contains("certificate")
            || detail.contains("tls")
            || detail.contains("ssl")
        {
            "TLS/certificate error — if your Vaultwarden uses a self-signed cert, this is expected (vault-proxy accepts self-signed certs)"
        } else {
            "check URL, credentials, and Vaultwarden server status"
        };
        anyhow!(
            "failed to connect to Vaultwarden at '{}': {} — hint: {}",
            url, detail, hint
        )
    })?;
    Ok(())
}

/// Reject obviously-weak setup passwords. 12 chars is the new minimum —
/// 8 was too short for a keystore root secret that protects Vaultwarden
/// credentials and every integration token. The bcrypt DEFAULT_COST (10)
/// offline-cracks an 8-char ASCII password in ~1 year on commodity GPU;
/// 12 pushes it out of reach on the same threat model.
pub(crate) fn validate_setup_password(pw: &str) -> Result<()> {
    if pw.len() < 12 {
        return Err(anyhow!("setup password must be at least 12 characters"));
    }
    let has_upper = pw.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = pw.chars().any(|c| c.is_ascii_digit());
    let has_symbol = pw.chars().any(|c| !c.is_ascii_alphanumeric());
    let classes = [has_upper, has_digit, has_symbol]
        .iter()
        .filter(|b| **b)
        .count();
    if classes < 2 {
        return Err(anyhow!(
            "setup password must contain at least two of: uppercase letter, digit, non-alphanumeric"
        ));
    }
    Ok(())
}

/// Run the interactive CLI setup wizard. Returns the credentials on success.
pub async fn run_cli_setup(config_dir: &str) -> Result<Credentials> {
    let stdin = io::stdin();
    let mut reader = stdin.lock();

    println!("\n=== Connecterr Setup ===\n");
    println!("This wizard will configure your Vaultwarden credentials.");
    println!("Your credentials will be encrypted and stored locally.\n");

    print!("Vaultwarden URL (e.g., https://vault.example.com): ");
    io::stdout().flush()?;
    let mut url = String::new();
    reader.read_line(&mut url)?;
    let url = url.trim().trim_end_matches('/').to_string();
    if url.is_empty() {
        return Err(anyhow!("URL cannot be empty"));
    }

    // Warn if the operator enters a plain HTTP URL. Vaultwarden traffic
    // contains the master password hash; transmitting it over unencrypted
    // HTTP allows any LAN observer to capture and replay it. We do NOT
    // hard-reject HTTP here because some self-hosted setups run on an
    // isolated LAN segment and terminate TLS at the router — but the
    // operator must make that choice consciously.
    if url.starts_with("http://") {
        println!();
        println!("WARNING: You entered an http:// URL.");
        println!("  Vaultwarden traffic (including your master password hash) will");
        println!("  be sent in plaintext. Use https:// unless your network is fully");
        println!("  isolated and you understand the risk.");
        println!();
    }

    print!("Vaultwarden email: ");
    io::stdout().flush()?;
    let mut email = String::new();
    reader.read_line(&mut email)?;
    let email = email.trim().to_string();
    if email.is_empty() {
        return Err(anyhow!("email cannot be empty"));
    }

    // Read the master password with terminal echo disabled so it does not
    // appear on-screen or in shell scroll-back. Previously read_line() echoed
    // every keystroke of the most sensitive credential in the system.
    //
    // Wrap in Zeroizing<String> so the heap allocation is overwritten when the
    // binding goes out of scope. rpassword returns a plain String; we move it
    // into Zeroizing immediately so plaintext never lives on the heap without
    // zeroize-on-drop semantics. The trim() call produces a &str view into the
    // same allocation — we re-own with to_string() inside Zeroizing so the
    // trimmed copy is also covered.
    //
    // iter-11: Non-TTY stdin handling.
    // `rpassword::prompt_password()` disables terminal echo by calling
    // `tcsetattr()` on stdin's fd. When stdin is not a TTY (e.g. piped input,
    // Docker `-i` without `-t`, CI pipelines), `tcsetattr()` returns ENOTTY and
    // rpassword returns `Err(io::Error { kind: Other, "not a tty" })`. We map
    // this specific error to an actionable message — the original I/O error
    // message ("not a tty") is cryptic to operators who are confused about why
    // `--setup` fails in a container without `-t`.
    //
    // If a non-interactive setup is genuinely needed (Docker build, CI), use
    // `docker run -it` to allocate a pseudo-TTY, or use the web-based setup
    // flow (start without --setup; configure via the dashboard at
    // https://localhost:3202).
    let master_password: Zeroizing<String> = Zeroizing::new(
        rpassword::prompt_password("Vaultwarden master password: ")
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("not a tty") || msg.contains("inappropriate ioctl") {
                    anyhow!(
                        "failed to read master password: stdin is not a TTY. \
                         Run with `docker run -it` (or equivalent) to allocate a \
                         pseudo-TTY, or use the web-based setup flow instead: \
                         start vault-proxy without --setup and configure via the \
                         dashboard at https://localhost:3202"
                    )
                } else {
                    anyhow!("failed to read master password: {}", e)
                }
            })?
            .trim()
            .to_string(),
    );
    if master_password.is_empty() {
        return Err(anyhow!("master password cannot be empty"));
    }

    println!("\nValidating credentials...");
    validate_vaultwarden_creds(&url, &email, &master_password).await?;
    println!("Credentials valid!\n");

    // Setup password is also echo-off — it protects the keystore.
    let setup_password: Zeroizing<String> = Zeroizing::new(
        rpassword::prompt_password(
            "Choose a setup password (min 12 chars, ≥2 character classes — unlocks keystore + dashboard): ",
        )
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("not a tty") || msg.contains("inappropriate ioctl") {
                anyhow!(
                    "failed to read setup password: stdin is not a TTY. \
                     Run with `docker run -it` (or equivalent) to allocate a \
                     pseudo-TTY, or use the web-based setup flow instead: \
                     start vault-proxy without --setup and configure via the \
                     dashboard at https://localhost:3202"
                )
            } else {
                anyhow!("failed to read setup password: {}", e)
            }
        })?
        .trim()
        .to_string(),
    );
    validate_setup_password(&setup_password)?;

    let setup_hash = bcrypt::hash(setup_password.as_str(), bcrypt::DEFAULT_COST)
        .map_err(|e| anyhow!("bcrypt hash failed: {}", e))?;

    let creds = Credentials {
        version: 1,
        vaultwarden: VaultwardenCreds {
            url,
            email,
            master_password: master_password.to_string(),
        },
        cloud: None,
        setup_password_hash: Some(setup_hash.clone()),
    };

    keystore::setup_keystore(config_dir, creds.clone(), &setup_password)?;
    // master_password and setup_password Zeroizing<String> bindings are dropped
    // (zeroized) here — after setup_keystore has consumed what it needs from them.

    let dashboard_config = format!("{}/dashboard.json", config_dir);
    let dashboard_json = serde_json::json!({ "password_hash": setup_hash });
    crate::secure::safe_write_config(
        &dashboard_config,
        serde_json::to_vec_pretty(&dashboard_json)?.as_slice(),
    )?;

    println!("\nSetup complete! Credentials encrypted and stored.");
    if crate::tpm::tpm_available() {
        println!("TPM detected — private key sealed for unattended restarts.");
    } else {
        println!("No TPM detected — you will need your setup password on restart.");
    }
    println!("Your Vaultwarden master password is your recovery path — keep it safe.");
    println!();
    println!("Next steps:");
    println!(
        "  1. In Vaultwarden, create a folder named 'vault-proxy' (or your --vault-folder value)."
    );
    println!("     Add your service credentials as Login items inside that folder.");
    println!("     Item names must match the `vault_item` field in services.toml");
    println!("     (e.g. an item named 'vault-proxy - Home Assistant' for vault_item = \"vault-proxy - Home Assistant\").");
    println!();
    println!(
        "  2. Copy services.example.toml to {}/services.toml and edit to match your setup.",
        config_dir
    );
    println!(
        "     Each [[service]] block needs a `vault_item` that matches a Vaultwarden item name."
    );
    println!();
    println!("  3. Remove --setup from your start command and restart to begin proxying.");
    println!();
    println!("  4. Test with: curl -s http://127.0.0.1:3201/vault/health | jq .");
    println!("     A successful first proxy call looks like:");
    println!("     curl -s -X POST http://127.0.0.1:3201/proxy \\");
    println!("       -H 'Content-Type: application/json' \\");
    println!(
        "       -d '{{\"service\":\"ha_home\",\"method\":\"GET\",\"path\":\"/api/\"}}' | jq ."
    );
    println!();
    println!("  Common first-run problems:");
    println!(
        "    - 'unknown service'  → service name in request doesn't match services.toml `name`"
    );
    println!("    - 'upstream request failed' → base_url is wrong or the service is unreachable");
    println!("    - 'credential not found'    → vault_item name doesn't match a Vaultwarden item");
    println!("    - 'vault unavailable' (503) → check GET /vault/health for sync status");

    Ok(creds)
}

/// Run the web-based setup. Called from dashboard API handler.
pub async fn run_web_setup(
    config_dir: &str,
    url: &str,
    email: &str,
    master_password: &str,
    setup_password: &str,
) -> Result<Credentials> {
    validate_setup_password(setup_password)?;

    validate_vaultwarden_creds(url, email, master_password).await?;

    let setup_hash = bcrypt::hash(setup_password, bcrypt::DEFAULT_COST)
        .map_err(|e| anyhow!("bcrypt hash failed: {}", e))?;

    let creds = Credentials {
        version: 1,
        vaultwarden: VaultwardenCreds {
            url: url.trim_end_matches('/').to_string(),
            email: email.to_string(),
            master_password: master_password.to_string(),
        },
        cloud: None,
        setup_password_hash: Some(setup_hash.clone()),
    };

    keystore::setup_keystore(config_dir, creds.clone(), setup_password)?;

    let dashboard_config = format!("{}/dashboard.json", config_dir);
    let dashboard_json = serde_json::json!({ "password_hash": setup_hash });
    crate::secure::safe_write_config(
        &dashboard_config,
        serde_json::to_vec_pretty(&dashboard_json)?.as_slice(),
    )?;

    Ok(creds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_setup_password_accepts_strong_password() {
        // 12+ chars with upper + digit = 2 classes → OK
        assert!(validate_setup_password("Str0ngPassword").is_ok());
        // 12+ chars with digit + symbol = 2 classes → OK
        assert!(validate_setup_password("abcdefghijk1!").is_ok());
        // 12+ chars with upper + symbol = 2 classes → OK
        assert!(validate_setup_password("ABCDefghijkl!").is_ok());
    }

    #[test]
    fn validate_setup_password_rejects_too_short() {
        assert!(validate_setup_password("Short1!").is_err());
        assert!(validate_setup_password("11charPass!").is_err()); // 11 chars
        assert!(validate_setup_password("12charPass1!").is_ok()); // 12 chars, has digit + symbol
    }

    #[test]
    fn validate_setup_password_rejects_insufficient_char_classes() {
        // Only lowercase — fails (0 non-lowercase classes)
        assert!(validate_setup_password("abcdefghijkl").is_err());
        // Lowercase + uppercase only — fails (1 class: upper; no digit, no symbol)
        assert!(validate_setup_password("Abcdefghijkl").is_err());
        // Lowercase + digit — passes (digit = 1 class, symbol = 1 class, total ≥ 2 if combined)
        // Note: "digit" and "symbol" are separate classes; lowercase alone doesn't count.
        // digit only = 1 class → fails. digit + symbol = 2 classes → passes.
        assert!(validate_setup_password("abcdefghijk1!").is_ok()); // digit + symbol = 2 classes
        assert!(validate_setup_password("abcdefghijk11").is_err()); // digit only = 1 class
    }

    #[test]
    fn web_setup_uses_same_policy_as_cli_setup() {
        // Both paths now delegate to validate_setup_password, so the 8-char
        // web minimum is gone. Verify that a previously-accepted 10-char
        // password is now correctly rejected.
        let short = "Pass1word!"; // 10 chars, has upper + digit + symbol
        let result = validate_setup_password(short);
        assert!(
            result.is_err(),
            "10-char password should be rejected by new 12-char minimum"
        );
    }
}
