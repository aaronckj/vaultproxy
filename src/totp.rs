//! TOTP code generation from vault-stored seeds.

use anyhow::{Context, Result};
use totp_rs::{Algorithm, Secret, TOTP};

/// Generate a TOTP code from a seed string (otpauth URI or base32 secret).
pub fn generate_code(seed: &str) -> Result<String> {
    let totp = if seed.starts_with("otpauth://") {
        TOTP::from_url_unchecked(seed).context("invalid otpauth URI")?
    } else {
        // Assume base32 encoded secret
        let secret = Secret::Encoded(seed.to_string())
            .to_bytes()
            .context("invalid base32 secret")?;
        TOTP::new_unchecked(Algorithm::SHA1, 6, 1, 30, secret, None, String::new())
    };

    let code = totp
        .generate_current()
        .context("failed to generate TOTP code")?;
    Ok(code)
}

/// Get seconds remaining until the current code expires.
pub fn seconds_remaining() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    30 - (now % 30)
}
