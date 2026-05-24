//! Typed error envelope for the transparent listener. Centralises
//! the HTTP status + `transparent_error_code` discriminator that the
//! agent sees in the JSON body of every error response.
//!
//! Clients should branch on `code()` (the stable string), not on
//! the HTTP status, since multiple cases share the same status.

use std::fmt;

// Reserved variants are constructed only by future timeout / vault
// failure paths; tests exercise them via Display + envelope().
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransparentErrorCode {
    /// Malformed CONNECT line, oversized headers, unsupported HTTP
    /// version. HTTP 400.
    MalformedConnect,
    /// Upstream TCP connect failed or TLS handshake failed. HTTP 502.
    UpstreamUnreachable,
    /// Allowlist mode + host has no `[[service]]` block. HTTP 502.
    UnregisteredHostBlocked,
    /// `inject_placeholder` saw a `__vault.X__` token with no
    /// matching `[[transparent_placeholder]]`. HTTP 502.
    PlaceholderUnresolved,
    /// Vault item or required field could not be resolved. HTTP 502.
    VaultResolutionFailed,
    /// Agent did not send a complete request within the deadline.
    /// HTTP 504.
    AgentReadTimeout,
}

impl TransparentErrorCode {
    pub fn http_status(self) -> u16 {
        match self {
            Self::MalformedConnect => 400,
            Self::AgentReadTimeout => 504,
            _ => 502,
        }
    }

    pub fn code(self) -> &'static str {
        match self {
            Self::MalformedConnect => "malformed_connect",
            Self::UpstreamUnreachable => "upstream_unreachable",
            Self::UnregisteredHostBlocked => "unregistered_host_blocked",
            Self::PlaceholderUnresolved => "placeholder_unresolved",
            Self::VaultResolutionFailed => "vault_resolution_failed",
            Self::AgentReadTimeout => "agent_read_timeout",
        }
    }

    pub fn reason(self) -> &'static str {
        match self.http_status() {
            400 => "Bad Request",
            502 => "Bad Gateway",
            504 => "Gateway Timeout",
            _ => "Error",
        }
    }
}

impl fmt::Display for TransparentErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

/// Serialise to the JSON envelope vault-proxy writes back to the
/// agent: `{"ok": false, "error": <message>, "transparent_error_code": <code>}`.
pub fn envelope(code: TransparentErrorCode, message: &str) -> Vec<u8> {
    let body = serde_json::json!({
        "ok": false,
        "error": message,
        "transparent_error_code": code.code(),
    });
    serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec())
}

/// Write a complete HTTP/1.1 error response (status line + headers +
/// JSON body) to a writable stream. Used by both the plaintext (mod.rs
/// `reply_error`) and post-TLS (mitm.rs `write_error_over_tls`) paths.
pub async fn write_error_response<S>(
    stream: &mut S,
    code: TransparentErrorCode,
    message: &str,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let body = envelope(code, message);
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        code.http_status(),
        code.reason(),
        body.len(),
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&body).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_map_to_expected_status() {
        assert_eq!(TransparentErrorCode::MalformedConnect.http_status(), 400);
        assert_eq!(
            TransparentErrorCode::UnregisteredHostBlocked.http_status(),
            502
        );
        assert_eq!(
            TransparentErrorCode::PlaceholderUnresolved.http_status(),
            502
        );
        assert_eq!(TransparentErrorCode::AgentReadTimeout.http_status(), 504);
    }

    #[test]
    fn codes_have_stable_strings() {
        assert_eq!(
            TransparentErrorCode::PlaceholderUnresolved.code(),
            "placeholder_unresolved"
        );
        assert_eq!(
            TransparentErrorCode::UnregisteredHostBlocked.code(),
            "unregistered_host_blocked"
        );
    }

    #[test]
    fn envelope_contains_code_and_message() {
        let bytes = envelope(TransparentErrorCode::MalformedConnect, "oops");
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["transparent_error_code"], "malformed_connect");
        assert_eq!(v["error"], "oops");
        assert_eq!(v["ok"], false);
    }
}
