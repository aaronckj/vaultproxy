//! Stdio JSON-RPC server for the mcp-rpc-bridge binary. Reads
//! newline-delimited JSON-RPC requests from stdin, forwards each via
//! the injected `Forwarder` (Task 11 supplies the real HTTP impl), and
//! writes responses to stdout. One line per message in each direction.
//!
//! Tracing goes to stderr. Stdout is reserved for the JSON-RPC stream;
//! any framing corruption there will confuse the local MCP client.

use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use super::Forwarder;

/// Serve a stdio JSON-RPC bridge until stdin is closed (EOF) or an
/// unrecoverable error occurs. Each line on stdin is one request; the
/// response goes back as a single line on stdout.
///
/// Per-request errors (parse failure, forwarder error) are surfaced to
/// the local client as JSON-RPC errors with code `-32099` (server
/// implementation error). The server keeps running on per-request
/// errors — only stdin-side IO failures cause the function to return.
pub async fn serve<F: Forwarder>(forwarder: Arc<F>) -> Result<()> {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    serve_streams(stdin, stdout, forwarder).await
}

/// Test-injectable form of `serve`. The production entry point wraps
/// this with `tokio::io::stdin()` / `tokio::io::stdout()`.
pub async fn serve_streams<R, W, F>(reader: R, mut writer: W, forwarder: Arc<F>) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin + Send,
    W: tokio::io::AsyncWrite + Unpin + Send,
    F: Forwarder,
{
    let mut buf = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        let n = buf.read_line(&mut line).await.context("read from stdin")?;
        if n == 0 {
            tracing::debug!("stdin EOF — exiting stdio server");
            return Ok(());
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Parse the request once so we can pull out the id for an
        // error envelope, then forward the unmodified value.
        let req: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, line = %trimmed, "failed to parse JSON-RPC request");
                write_error(
                    &mut writer,
                    serde_json::Value::Null,
                    -32700,
                    format!("Parse error: {e}"),
                )
                .await?;
                continue;
            }
        };
        // JSON-RPC notifications have no `id` — fire-and-forget with no
        // response written to stdout.
        let is_notification = !req.as_object().map_or(false, |o| o.contains_key("id"));
        if is_notification {
            if let Err(e) = forwarder.forward(req).await {
                tracing::debug!(error = %e, "notification forward (non-fatal)");
            }
            continue;
        }

        let id = req.get("id").cloned().unwrap_or(serde_json::Value::Null);
        let resp = match forwarder.forward(req).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "forwarder error");
                write_error(&mut writer, id, -32099, format!("Forwarder error: {e}")).await?;
                continue;
            }
        };
        let line_out = serde_json::to_string(&resp).context("serialize response")?;
        writer.write_all(line_out.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
    }
}

async fn write_error<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    id: serde_json::Value,
    code: i64,
    message: String,
) -> Result<()> {
    let envelope = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message },
    });
    let line = serde_json::to_string(&envelope)?;
    writer.write_all(line.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}
