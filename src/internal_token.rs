//! Shared-secret bearer token for internal-only endpoints.
//!
//! # Purpose
//!
//! vault-proxy's security model is localhost-only process isolation: every
//! endpoint is guarded by the `dns_rebinding_guard` (rejects non-localhost
//! Host headers) and a rate limiter, but there is **no authentication layer**.
//! Any process running as the same OS user that can reach 127.0.0.1:3201 can
//! call `/handshake`, `/vault/connecterr-secrets`, `/rotate`, `/browser/*`,
//! and related internal endpoints.
//!
//! For homelab single-machine deployments this is acceptable — process
//! isolation provides the primary boundary. For public/multi-user deployments,
//! this is insufficient: a compromised container on the same host could trigger
//! credential rotation or exfiltrate the vault folder structure.
//!
//! # Mechanism
//!
//! 1. At startup, `load_or_generate` either reads an existing token from
//!    `$CONFIG_DIR/internal-token` or generates a fresh 32-byte random hex
//!    string and writes it to that path with `0o600` permissions.
//! 2. The token is stored in `AppState::internal_token`.
//! 3. The `require_internal_token` axum middleware (in `main.rs`) checks
//!    `Authorization: Bearer <token>` on every internal route. Requests
//!    without the header, or with the wrong token, receive 401.
//! 4. The TypeScript Connecterr side reads the token from the same file path
//!    (`$CONFIG_DIR/internal-token`, default `/config/internal-token`) before
//!    calling these endpoints.
//!
//! # File format
//!
//! A 64-character lowercase hex string (32 random bytes encoded as hex),
//! followed by a single newline. The file has `0o600` Unix permissions
//! (owner read/write only). The path is logged at startup so operators know
//! where to find it.

use std::path::PathBuf;

use anyhow::{Context, Result};
use rand::Rng;

/// Load the internal token from `$config_dir/internal-token`, or generate
/// and persist a new one if the file does not exist.
///
/// Returns the token as a 64-character hex string (32 random bytes).
///
/// # Errors
///
/// Returns an error if:
/// - The file exists but cannot be read (permissions, I/O error).
/// - The file exists but its content is not a valid hex string.
/// - A new token cannot be written (I/O error, permission denied).
pub fn load_or_generate(config_dir: &str) -> Result<String> {
    let token_path: PathBuf = [config_dir, "internal-token"].iter().collect();

    if token_path.exists() {
        // Read and validate the existing token.
        let raw = std::fs::read_to_string(&token_path)
            .with_context(|| format!("read internal-token from '{}'", token_path.display()))?;
        let token = raw.trim().to_string();
        if token.len() != 64 || !token.chars().all(|c| c.is_ascii_hexdigit()) {
            anyhow::bail!(
                "internal-token at '{}' is not a valid 64-char hex string — \
                 delete the file to regenerate it",
                token_path.display()
            );
        }
        tracing::info!(
            path = %token_path.display(),
            "loaded existing internal bearer token"
        );
        return Ok(token);
    }

    // Generate a fresh 32-byte token.
    let bytes: [u8; 32] = rand::thread_rng().gen();
    let token = hex_encode(&bytes);

    // Write with 0o600 permissions so only the owner can read it.
    write_token_file(&token_path, &token)
        .with_context(|| format!("write internal-token to '{}'", token_path.display()))?;

    tracing::info!(
        path = %token_path.display(),
        "generated new internal bearer token (0o600)"
    );

    Ok(token)
}

/// Encode bytes as lowercase hex.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Write `token` to `path` with mode 0o600 (owner read/write only).
fn write_token_file(path: &PathBuf, token: &str) -> Result<()> {
    // Write the token content.
    let content = format!("{}\n", token);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("open '{}' for writing", path.display()))?;
        use std::io::Write;
        f.write_all(content.as_bytes())
            .with_context(|| format!("write to '{}'", path.display()))?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, &content).with_context(|| format!("write to '{}'", path.display()))?;
        // On non-Unix platforms we cannot set 0o600; log a warning so operators
        // know the file does not have restrictive permissions.
        tracing::warn!(
            path = %path.display(),
            "platform does not support 0o600 file permissions — internal-token file is not restricted to owner-only access"
        );
    }

    Ok(())
}
