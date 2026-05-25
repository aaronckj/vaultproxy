//! Raw TCP relay between agent and upstream. Used when the registry
//! routes a CONNECT target to passthrough (either unregistered host in
//! default policy, or a service with transparent_mode = "passthrough").
//!
//! No TLS interception. No body inspection. Bytes flow both directions
//! until either side closes.

use anyhow::{Context, Result};
use std::time::{Duration, Instant};
use tokio::io::{copy_bidirectional, AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::info;

use super::connect::ConnectTarget;

/// Open a TCP connection to the upstream and relay bytes both directions
/// until close. Returns when both halves are closed or a timeout fires.
///
/// The 200 Connection-established reply is written AFTER upstream connect
/// succeeds: a failed upstream connect surfaces to the agent as 502 Bad
/// Gateway rather than a stuck TLS handshake after a phantom 200.
#[allow(dead_code)]
pub async fn tunnel(agent: TcpStream, target: ConnectTarget) -> Result<()> {
    tunnel_with_audit(agent, target, None).await
}

/// Same as `tunnel` but logs an audit entry on successful close when
/// `audit_log` is supplied. Used by the transparent listener (Phase 7)
/// so passthrough traffic is recorded with `trigger=transparent`,
/// `transparent_mode="passthrough"`.
///
/// Generic over the agent-side stream so the UDS listener variant can
/// share this path with the TCP listener. Upstream is always TCP.
pub async fn tunnel_with_audit<A>(
    mut agent: A,
    target: ConnectTarget,
    audit_log: Option<std::sync::Arc<crate::security::audit_log::AuditLog>>,
) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
{
    let start = Instant::now();

    // Connect upstream with 10s budget.
    let upstream = match timeout(
        Duration::from_secs(10),
        TcpStream::connect((target.host.as_str(), target.port)),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            reply_502(&mut agent, &format!("connect to {}: {}", target, e)).await?;
            return Err(anyhow::Error::new(e).context(format!("connect to {}", target)));
        }
        Err(_) => {
            reply_502(&mut agent, "upstream connect timed out after 10s").await?;
            return Err(anyhow::anyhow!("upstream connect timed out after 10s"));
        }
    };

    // Tell the agent the tunnel is open.
    agent
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await
        .context("write 200 to agent")?;

    let mut upstream = upstream;
    let (bytes_in, bytes_out) = copy_bidirectional(&mut agent, &mut upstream)
        .await
        .context("bidirectional copy")?;

    let duration_ms = start.elapsed().as_millis() as u64;
    info!(
        target = %target,
        bytes_in = bytes_in,
        bytes_out = bytes_out,
        duration_ms = duration_ms,
        mode = "passthrough",
        "transparent tunnel closed",
    );

    if let Some(al) = audit_log {
        al.log_transparent(
            "passthrough",
            &target.host,
            None,
            bytes_in,
            bytes_out,
            duration_ms,
        );
    }

    Ok(())
}

async fn reply_502<S: tokio::io::AsyncWrite + Unpin>(stream: &mut S, msg: &str) -> Result<()> {
    super::errors::write_error_response(
        stream,
        super::errors::TransparentErrorCode::UpstreamUnreachable,
        msg,
    )
    .await
}
