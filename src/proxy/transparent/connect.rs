//! Parse a single HTTP/1.1 `CONNECT host:port HTTP/1.1` line.
//!
//! This is intentionally narrow — only enough HTTP/1 to support the
//! CONNECT verb used by HTTPS_PROXY clients. Any other method, version,
//! or malformed input is rejected with a descriptive error so the caller
//! can return an HTTP 400 to the agent.

use anyhow::{bail, Context, Result};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
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
/// **Reads byte-by-byte, never buffering past CRLFCRLF.** This is
/// critical: HTTPS_PROXY clients send the next protocol payload (TLS
/// ClientHello bytes) immediately after the CONNECT headers, and any
/// over-read would consume those bytes and leave the agent's
/// subsequent TLS handshake reading nothing. A BufReader-based
/// implementation that pulls 8 KiB chunks would silently swallow the
/// first 8 KiB of ClientHello.
pub async fn read_connect_line<S: AsyncRead + Unpin>(stream: &mut S) -> Result<ConnectTarget> {
    let read = async {
        let mut buf: Vec<u8> = Vec::with_capacity(512);
        let mut byte = [0u8; 1];
        loop {
            let n = stream.read(&mut byte).await.context("read CONNECT byte")?;
            if n == 0 {
                bail!("client closed before request was complete");
            }
            buf.push(byte[0]);
            if buf.len() > 40 * 1024 {
                bail!("CONNECT request exceeds 40 KiB");
            }
            if buf.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let head = std::str::from_utf8(&buf).context("CONNECT block not UTF-8")?;
        let mut lines = head.split("\r\n");
        let request_line = lines
            .next()
            .ok_or_else(|| anyhow::anyhow!("empty request"))?;
        if request_line.len() > 8192 {
            bail!("request line exceeds 8192 bytes");
        }
        parse_request_line(request_line)
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
        // 64 KiB buffer + spawn the writer so reader+writer interleave;
        // some test inputs exceed the default duplex capacity (the
        // oversized-line case sends ~9 KiB without any CRLF).
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
    async fn rejects_oversize_request() {
        // 40 KiB+ of junk with no CRLFCRLF.
        let buf = vec![b'A'; 50 * 1024];
        let r = feed(&buf).await;
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
