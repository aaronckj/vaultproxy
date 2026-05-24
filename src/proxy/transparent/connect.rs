//! Parse a single HTTP/1.1 `CONNECT host:port HTTP/1.1` line.
//!
//! This is intentionally narrow — only enough HTTP/1 to support the
//! CONNECT verb used by HTTPS_PROXY clients. Any other method, version,
//! or malformed input is rejected with a descriptive error so the caller
//! can return an HTTP 400 to the agent.

use anyhow::{bail, Context, Result};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::time::timeout;

/// Resolved target of a CONNECT request: `host:port` after validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectTarget {
    pub host: String,
    pub port: u16,
}

impl std::fmt::Display for ConnectTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Bracket IPv6 literals.
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// Read and parse a `CONNECT host:port HTTP/1.1\r\n…\r\n\r\n` request
/// from the stream, including all subsequent request headers until the
/// blank line. Headers are read but ignored. Times out after 5 seconds
/// (slowloris guard).
///
/// Returns the parsed target. Errors describe what was malformed so the
/// caller can surface them in the 400 response body.
pub async fn read_connect_line<S: AsyncRead + Unpin>(stream: &mut S) -> Result<ConnectTarget> {
    let read = async {
        let mut reader = BufReader::new(stream);
        let mut request_line = String::new();
        let n = reader
            .read_line(&mut request_line)
            .await
            .context("read CONNECT request line")?;
        if n == 0 {
            bail!("client closed before sending request line");
        }
        if !request_line.ends_with("\r\n") {
            bail!("request line did not terminate with CRLF");
        }
        if request_line.len() > 8192 {
            bail!("request line exceeds 8192 bytes");
        }

        // Drain header block (up to blank line). Cap total to prevent
        // memory exhaustion via giant header sets.
        let mut header_bytes = 0usize;
        loop {
            let mut hdr = String::new();
            let n = reader
                .read_line(&mut hdr)
                .await
                .context("read header line")?;
            if n == 0 {
                bail!("client closed mid-headers");
            }
            header_bytes += n;
            if header_bytes > 32 * 1024 {
                bail!("CONNECT headers exceed 32 KiB");
            }
            if hdr == "\r\n" {
                break;
            }
        }

        parse_request_line(request_line.trim_end_matches("\r\n"))
    };

    timeout(Duration::from_secs(5), read)
        .await
        .map_err(|_| anyhow::anyhow!("CONNECT line read timed out after 5s"))?
}

fn parse_request_line(line: &str) -> Result<ConnectTarget> {
    let mut parts = line.splitn(3, ' ');
    let method = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("empty request line"))?;
    let target = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing request target"))?;
    let version = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing HTTP version"))?;

    if method != "CONNECT" {
        bail!("only CONNECT supported; got '{}'", method);
    }
    if version != "HTTP/1.1" {
        bail!("only HTTP/1.1 supported; got '{}'", version);
    }
    parse_host_port(target)
}

fn parse_host_port(s: &str) -> Result<ConnectTarget> {
    // IPv6: [::1]:443
    if let Some(rest) = s.strip_prefix('[') {
        let (ip, port_part) = rest
            .rsplit_once("]:")
            .ok_or_else(|| anyhow::anyhow!("malformed IPv6 target: {}", s))?;
        let port: u16 = port_part
            .parse()
            .with_context(|| format!("invalid port: {}", port_part))?;
        if port == 0 {
            bail!("port must be > 0");
        }
        return Ok(ConnectTarget {
            host: ip.to_string(),
            port,
        });
    }
    // Hostname or IPv4: example.com:443
    let (host, port_part) = s
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("CONNECT target missing port: {}", s))?;
    if host.is_empty() {
        bail!("CONNECT target has empty host");
    }
    let port: u16 = port_part
        .parse()
        .with_context(|| format!("invalid port: {}", port_part))?;
    if port == 0 {
        bail!("port must be > 0");
    }
    Ok(ConnectTarget {
        host: host.to_string(),
        port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    async fn feed(input: &[u8]) -> Result<ConnectTarget> {
        // Use a 64 KiB buffer (larger than any test input) and spawn the
        // write so writer+reader can interleave. Required because the
        // `rejects_oversize_request_line` case sends ~9 KiB without any
        // newlines — a synchronous write_all would deadlock against the
        // not-yet-running reader otherwise.
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        let payload = input.to_vec();
        tokio::spawn(async move {
            let _ = client.write_all(&payload).await;
            drop(client);
        });
        read_connect_line(&mut server).await
    }

    #[tokio::test]
    async fn parses_basic_connect() {
        let r = feed(b"CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n")
            .await
            .unwrap();
        assert_eq!(r.host, "api.github.com");
        assert_eq!(r.port, 443);
    }

    #[tokio::test]
    async fn parses_ipv6_target() {
        let r = feed(b"CONNECT [2001:db8::1]:8443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        assert_eq!(r.host, "2001:db8::1");
        assert_eq!(r.port, 8443);
    }

    #[tokio::test]
    async fn rejects_non_connect() {
        let r = feed(b"GET / HTTP/1.1\r\n\r\n").await;
        assert!(r
            .unwrap_err()
            .to_string()
            .contains("only CONNECT supported"));
    }

    #[tokio::test]
    async fn rejects_http2_prelude() {
        let r = feed(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await;
        assert!(r
            .unwrap_err()
            .to_string()
            .contains("only CONNECT supported"));
    }

    #[tokio::test]
    async fn rejects_missing_port() {
        let r = feed(b"CONNECT api.github.com HTTP/1.1\r\n\r\n").await;
        assert!(r.unwrap_err().to_string().contains("missing port"));
    }

    #[tokio::test]
    async fn rejects_port_zero() {
        let r = feed(b"CONNECT api.github.com:0 HTTP/1.1\r\n\r\n").await;
        assert!(r.unwrap_err().to_string().contains("port must be > 0"));
    }

    #[tokio::test]
    async fn rejects_oversize_request_line() {
        let mut buf = vec![b'A'; 9000];
        buf.extend_from_slice(b" HTTP/1.1\r\n\r\n");
        let mut prefixed = b"CONNECT ".to_vec();
        prefixed.extend_from_slice(&buf);
        let r = feed(&prefixed).await;
        assert!(r.unwrap_err().to_string().contains("exceeds"));
    }

    #[test]
    fn display_brackets_ipv6() {
        let t = ConnectTarget {
            host: "::1".into(),
            port: 443,
        };
        assert_eq!(t.to_string(), "[::1]:443");
    }
}
