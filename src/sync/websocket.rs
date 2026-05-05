//! SignalR websocket listener for Bitwarden cloud change notifications.

use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, Message},
};

// -------------------------------------------------------------------------- //
// SyncNotification                                                            //
// -------------------------------------------------------------------------- //

/// Notification types emitted by the Bitwarden push notification service.
#[derive(Debug, Clone)]
pub enum SyncNotification {
    CipherUpdate(String),
    CipherCreate(String),
    CipherDelete(String),
    VaultSync,
    Unknown(String),
}

// -------------------------------------------------------------------------- //
// listen                                                                      //
// -------------------------------------------------------------------------- //

/// Connect to the Bitwarden notifications hub and forward parsed notifications
/// onto `tx` until the connection closes or an error occurs.
///
/// `notifications_url` – base URL of the notifications service
///   (e.g. `https://notifications.bitwarden.com`).
/// `access_token` – a valid Bitwarden access token used to authenticate the
///   SignalR connection.
pub async fn listen(
    notifications_url: &str,
    access_token: &str,
    tx: tokio::sync::mpsc::Sender<SyncNotification>,
) -> Result<()> {
    // Build the hub URL (no query-string token — that would land in logs and
    // any upstream access log). Convert http(s) → ws(s).
    let hub_url = format!("{}/hub", notifications_url);
    let ws_url = hub_url
        .replace("https://", "wss://")
        .replace("http://", "ws://");

    tracing::debug!(url = %ws_url, "connecting to Bitwarden notifications hub");

    // Pass the access token via Authorization header so it does not appear in
    // URL-level logs or upstream traces.
    let mut request = ws_url
        .as_str()
        .into_client_request()
        .context("build websocket request")?;
    request.headers_mut().insert(
        "Authorization",
        format!("Bearer {}", access_token)
            .parse()
            .context("bearer header parse")?,
    );

    let (ws_stream, _response) = connect_async(request)
        .await
        .context("failed to connect to notifications websocket")?;

    let (mut write, mut read) = ws_stream.split();

    // SignalR handshake: negotiate JSON protocol, version 1.
    // The record separator 0x1e terminates every SignalR frame.
    let handshake = "{\"protocol\":\"json\",\"version\":1}\x1e".to_string();
    write
        .send(Message::Text(handshake))
        .await
        .context("failed to send SignalR handshake")?;

    tracing::debug!("SignalR handshake sent");

    // Message loop.
    while let Some(msg) = read.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                // SignalR frames are separated by the record separator (0x1e).
                for frame in text.split('\x1e') {
                    let trimmed = frame.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    handle_frame(trimmed, &tx).await;
                }
            }
            Ok(Message::Ping(data)) => {
                if let Err(e) = write.send(Message::Pong(data)).await {
                    tracing::warn!("failed to send pong: {}", e);
                }
            }
            Ok(Message::Close(frame)) => {
                tracing::info!(frame = ?frame, "websocket closed by server");
                return Ok(());
            }
            Ok(_) => {
                // Binary or other message types — ignore.
            }
            Err(e) => {
                return Err(e).context("websocket receive error");
            }
        }
    }

    tracing::info!("websocket stream ended");
    Ok(())
}

// -------------------------------------------------------------------------- //
// frame handling                                                              //
// -------------------------------------------------------------------------- //

async fn handle_frame(frame: &str, tx: &tokio::sync::mpsc::Sender<SyncNotification>) {
    // Attempt to parse as JSON; silently skip malformed frames.
    let value: serde_json::Value = match serde_json::from_str(frame) {
        Ok(v) => v,
        Err(e) => {
            tracing::trace!(frame = %frame, err = %e, "ignoring non-JSON SignalR frame");
            return;
        }
    };

    // SignalR message type 1 = Invocation.
    // Handshake responses and keep-alive pings have different types.
    let msg_type = value.get("type").and_then(|v| v.as_u64()).unwrap_or(0);
    if msg_type != 1 {
        tracing::trace!(msg_type, "ignoring non-invocation SignalR message");
        return;
    }

    // We only care about "ReceiveMessage" invocations.
    let target = value
        .get("target")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    if target != "ReceiveMessage" {
        tracing::trace!(target, "ignoring non-ReceiveMessage invocation");
        return;
    }

    // arguments[0] carries the notification payload.
    let args = match value.get("arguments").and_then(|v| v.as_array()) {
        Some(a) => a,
        None => {
            tracing::warn!("ReceiveMessage invocation missing arguments array");
            return;
        }
    };

    let arg0 = match args.first() {
        Some(a) => a,
        None => {
            tracing::warn!("ReceiveMessage arguments array is empty");
            return;
        }
    };

    // notification type integer
    let notif_type = arg0.get("type").and_then(|v| v.as_u64()).unwrap_or(255);

    // Optional cipher ID from payload.id
    let cipher_id = arg0
        .get("payload")
        .and_then(|p| p.get("id"))
        .and_then(|id| id.as_str())
        .unwrap_or_default()
        .to_string();

    let notification = match notif_type {
        0 => {
            tracing::debug!(cipher_id = %cipher_id, "SyncCipherUpdate notification");
            SyncNotification::CipherUpdate(cipher_id)
        }
        1 => {
            tracing::debug!(cipher_id = %cipher_id, "SyncCipherCreate notification");
            SyncNotification::CipherCreate(cipher_id)
        }
        2 => {
            tracing::debug!(cipher_id = %cipher_id, "SyncCipherDelete notification");
            SyncNotification::CipherDelete(cipher_id)
        }
        12 => {
            tracing::debug!("SyncVault (full re-sync) notification");
            SyncNotification::VaultSync
        }
        other => {
            tracing::debug!(notif_type = other, "unknown notification type");
            SyncNotification::Unknown(format!("type={}", other))
        }
    };

    if let Err(e) = tx.send(notification).await {
        tracing::warn!("notification channel closed, dropping message: {}", e);
    }
}
