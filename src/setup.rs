//! Setup flow for first-time Connecterr credential configuration.
//!
//! Provides both a CLI interactive wizard and shared state for the web setup flow.

use std::io::{self, BufRead, Write};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio::sync::RwLock;

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
    let _vault = VaultManager::new(url, email, password).await?;
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
    let classes = [has_upper, has_digit, has_symbol].iter().filter(|b| **b).count();
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
    let master_password = rpassword::prompt_password("Vaultwarden master password: ")
        .map_err(|e| anyhow!("failed to read master password: {}", e))?
        .trim()
        .to_string();
    if master_password.is_empty() {
        return Err(anyhow!("master password cannot be empty"));
    }

    println!("\nValidating credentials...");
    validate_vaultwarden_creds(&url, &email, &master_password).await?;
    println!("Credentials valid!\n");

    // Setup password is also echo-off — it protects the keystore.
    let setup_password = rpassword::prompt_password(
        "Choose a setup password (min 12 chars, ≥2 character classes — unlocks keystore + dashboard): ",
    )
    .map_err(|e| anyhow!("failed to read setup password: {}", e))?
    .trim()
    .to_string();
    validate_setup_password(&setup_password)?;

    let setup_hash = bcrypt::hash(&setup_password, bcrypt::DEFAULT_COST)
        .map_err(|e| anyhow!("bcrypt hash failed: {}", e))?;

    let creds = Credentials {
        version: 1,
        vaultwarden: VaultwardenCreds {
            url,
            email,
            master_password,
        },
        cloud: None,
        setup_password_hash: Some(setup_hash.clone()),
    };

    keystore::setup_keystore(config_dir, creds.clone(), &setup_password)?;

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
    println!("Your Vaultwarden master password is your recovery path — keep it safe.\n");

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
    if setup_password.len() < 8 {
        return Err(anyhow!("setup password must be at least 8 characters"));
    }

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
