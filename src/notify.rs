//! Push notifications via multiple channels: ntfy.sh, email queue (for Gmail integration).

use anyhow::Result;
use std::sync::Mutex;
use std::time::Instant;

#[derive(Debug, Clone)]
pub enum NotifyChannel {
    Ntfy { url: String },
    Email { to: String },
    Disabled,
}

/// Rate limiter: allows at most `max_count` sends within `window`.
struct RateLimiter {
    timestamps: Vec<Instant>,
    max_count: usize,
    window: std::time::Duration,
}

impl RateLimiter {
    fn new(max_count: usize, window: std::time::Duration) -> Self {
        Self {
            timestamps: Vec::new(),
            max_count,
            window,
        }
    }

    /// Returns `true` if the send is allowed, `false` if rate-limited.
    fn check_and_record(&mut self) -> bool {
        let now = Instant::now();
        self.timestamps.retain(|t| now.duration_since(*t) < self.window);
        if self.timestamps.len() >= self.max_count {
            return false;
        }
        self.timestamps.push(now);
        true
    }
}

pub struct Notifier {
    channel: NotifyChannel,
    http: reqwest::Client,
    rate_limiter: Mutex<RateLimiter>,
}

impl Notifier {
    pub fn new(channel: NotifyChannel) -> Self {
        Self {
            channel,
            // Explicit 30s timeout — `reqwest::Client::new()` has none, so a
            // slow/unresponsive ntfy server would previously block the async
            // task indefinitely. Matches the timeout policy now applied to
            // every reqwest client in the codebase (iter-18+19 sweep).
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            // Allow at most 5 notifications per 5 minutes to prevent
            // flood attacks or runaway loops.
            rate_limiter: Mutex::new(RateLimiter::new(5, std::time::Duration::from_secs(300))),
        }
    }

    pub fn disabled() -> Self {
        Self::new(NotifyChannel::Disabled)
    }

    /// Returns the current channel type as a string for the dashboard.
    pub fn channel_name(&self) -> &str {
        match &self.channel {
            NotifyChannel::Ntfy { .. } => "ntfy",
            NotifyChannel::Email { .. } => "email",
            NotifyChannel::Disabled => "disabled",
        }
    }

    /// Returns channel-specific details for the dashboard.
    pub fn channel_detail(&self) -> String {
        match &self.channel {
            NotifyChannel::Ntfy { url } => url.clone(),
            NotifyChannel::Email { to } => to.clone(),
            NotifyChannel::Disabled => String::new(),
        }
    }

    pub async fn send(&self, title: &str, message: &str, priority: u8) -> Result<()> {
        // Enforce rate limit to prevent notification floods.
        {
            let mut limiter = self.rate_limiter.lock().unwrap();
            if !limiter.check_and_record() {
                tracing::warn!(
                    "notification rate-limited — suppressing '{}' (max 5 per 5 min)",
                    title
                );
                return Ok(());
            }
        }

        match &self.channel {
            NotifyChannel::Ntfy { url } => {
                self.http
                    .post(url)
                    .header("Title", title)
                    .header("Priority", priority.to_string())
                    .body(message.to_string())
                    .send()
                    .await?;
                Ok(())
            }
            NotifyChannel::Email { to } => {
                // Queue the notification as a JSON file for the Connecterr Node.js
                // side to pick up and send via Gmail MCP. The sidecar cannot send
                // emails directly (no OAuth tokens).
                let notification = serde_json::json!({
                    "to": to,
                    "subject": title,
                    "body": message,
                    "priority": priority,
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                });

                let queue_path = "/config/notification-queue.json";
                let mut queue: Vec<serde_json::Value> = std::fs::read_to_string(queue_path)
                    .ok()
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or_default();
                queue.push(notification);
                // Keep only last 50 entries
                if queue.len() > 50 {
                    queue.drain(..queue.len() - 50);
                }
                let json_bytes = serde_json::to_string_pretty(&queue)?;
                crate::secure::safe_write_config(queue_path, json_bytes.as_bytes())?;

                tracing::info!("queued email notification to {}", to);
                Ok(())
            }
            NotifyChannel::Disabled => Ok(()),
        }
    }

    #[allow(dead_code)] // will be wired when workflow passes notifier for 2FA prompts
    pub async fn notify_2fa(&self, prompt: &str) {
        self.send(
            "2FA Approval Needed",
            &format!(
                "Connecterr needs your approval: {}. Open the dashboard to respond.",
                prompt
            ),
            4, // high priority
        )
        .await
        .ok();
    }

    pub async fn notify_rotation(&self, item: &str, success: bool) {
        let (title, msg) = if success {
            (
                "Password Rotated",
                format!("{} password changed successfully", item),
            )
        } else {
            (
                "Rotation Failed",
                format!("{} password rotation failed -- check dashboard", item),
            )
        };
        self.send(title, &msg, if success { 3 } else { 4 })
            .await
            .ok();
    }
}
