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
        self.timestamps
            .retain(|t| now.duration_since(*t) < self.window);
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
    #[allow(dead_code)] // called by dashboard notify-status endpoint (#[cfg(feature = "dashboard")])
    pub fn channel_name(&self) -> &str {
        match &self.channel {
            NotifyChannel::Ntfy { .. } => "ntfy",
            NotifyChannel::Email { .. } => "email",
            NotifyChannel::Disabled => "disabled",
        }
    }

    /// Returns channel-specific details for the dashboard.
    #[allow(dead_code)] // called by dashboard notify-status endpoint (#[cfg(feature = "dashboard")])
    pub fn channel_detail(&self) -> String {
        match &self.channel {
            NotifyChannel::Ntfy { url } => url.clone(),
            NotifyChannel::Email { to } => to.clone(),
            NotifyChannel::Disabled => String::new(),
        }
    }

    /// ntfy.sh enforces a 4096-byte limit on the message body and a 255-byte
    /// limit on the Title header.  Vault item names or error descriptions that
    /// exceed these limits would cause the POST to return a 400 Bad Request,
    /// silently dropping the notification.
    ///
    /// We truncate at safe byte boundaries (not char boundaries, to avoid
    /// splitting a multi-byte UTF-8 sequence — `truncate_utf8` handles this).
    const NTFY_TITLE_MAX_BYTES: usize = 255;
    const NTFY_BODY_MAX_BYTES: usize = 4096;

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
                // Issue (iter-17): Truncate title and body to ntfy.sh's hard
                // limits (255 bytes for Title, 4096 bytes for body).  A vault
                // item name or error description that exceeds these limits
                // causes ntfy.sh to return 400 Bad Request, silently dropping
                // the notification.
                let title_safe = truncate_utf8(title, Self::NTFY_TITLE_MAX_BYTES);
                let body_safe = truncate_utf8(message, Self::NTFY_BODY_MAX_BYTES);
                if title_safe.len() < title.len() || body_safe.len() < message.len() {
                    tracing::debug!(
                        "notification truncated to fit ntfy.sh limits \
                         (title: {} → {} bytes, body: {} → {} bytes)",
                        title.len(),
                        title_safe.len(),
                        message.len(),
                        body_safe.len(),
                    );
                }
                self.http
                    .post(url)
                    .header("Title", title_safe)
                    .header("Priority", priority.to_string())
                    .body(body_safe.to_string())
                    .send()
                    .await?;
                Ok(())
            }
            NotifyChannel::Email { to } => {
                // Queue the notification for the Connecterr Node.js side to
                // deliver via Gmail MCP.  The Rust sidecar has no OAuth tokens
                // so it cannot send email directly; it writes to a shared file
                // that the TypeScript layer polls.
                //
                // ## File format: /config/notification-queue.json
                //
                // The file is a JSON array of notification objects.  Each entry:
                //
                //   {
                //     "to":        string   — recipient email address,
                //     "subject":   string   — notification title,
                //     "body":      string   — notification body text,
                //     "priority":  u8       — 1 (lowest) … 5 (highest),
                //     "timestamp": string   — RFC 3339 UTC, e.g. "2026-05-05T12:00:00Z"
                //   }
                //
                // The array is **append-only** (new entries pushed to the end)
                // and capped at 50 entries — older entries are dropped when the
                // cap is exceeded.  Each write is atomic via `safe_write_config`
                // (tempfile + fsync + rename), so a mid-write crash cannot leave
                // a truncated file.
                //
                // The TypeScript consumer must:
                //   1. Read the file atomically.
                //   2. Process each entry (send via Gmail MCP).
                //   3. Remove or truncate processed entries to prevent re-delivery.
                //   4. Write the updated array back atomically.
                //
                // There is no lock file — the consumer must handle races by
                // writing back before vault-proxy appends a new entry.  If a
                // race is a concern, use an exclusive file lock (fcntl/flock)
                // around read-process-write.
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
                // Issue (iter-53): Explicitly surface write failures rather than
                // propagating a bare `?` that the caller may swallow with `.ok()`.
                // If the filesystem is full or /config is read-only, the caller
                // (notify_rotation, notify_2fa) uses `.ok()` — the error is
                // propagated as Err from send() but silently dropped there.
                // Logging the error here ensures it appears in structured logs
                // even when the caller ignores the Result.
                if let Err(e) = crate::secure::safe_write_config(queue_path, json_bytes.as_bytes())
                {
                    tracing::error!(
                        to = %to,
                        path = queue_path,
                        "failed to write notification queue — email notification \
                         to '{}' WILL BE LOST. Check that /config is writable \
                         and not full. Error: {:#}",
                        to,
                        e
                    );
                    return Err(e);
                }

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

    /// Send a rotation-result notification.
    ///
    /// # Privacy note (iter-6 audit)
    ///
    /// `item` is the vault item name (e.g. `"vault-proxy - UniFi"`,
    /// `"radarr"`). When the channel is `Ntfy`, this string is sent verbatim
    /// to the operator-configured ntfy.sh topic — which may be a **public
    /// third-party server** (`ntfy.sh`). This leaks the internal service
    /// topology (which services exist, when they were rotated) to the ntfy.sh
    /// operator.
    ///
    /// If this is a concern, operators should use a self-hosted ntfy instance
    /// or the `email` channel, which queues to a local JSON file and never
    /// contacts an external server directly.
    ///
    /// For the `Disabled` channel nothing is sent, so the item name is never
    /// transmitted externally.
    // iter-81: called from browser/rotate handler (feature = "browser"). Dead in default builds.
    #[allow(dead_code)]
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

/// Truncate `s` to at most `max_bytes` bytes, respecting UTF-8 char boundaries.
///
/// Returns a `&str` slice of `s` — no allocation if already within the limit.
/// Truncation is performed at the last valid UTF-8 char boundary at or below
/// `max_bytes`, so the result is always valid UTF-8.
fn truncate_utf8(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    // Walk back from max_bytes to find a valid char boundary.
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod tests {
    use super::truncate_utf8;

    #[test]
    fn ascii_within_limit_unchanged() {
        assert_eq!(truncate_utf8("hello", 10), "hello");
    }

    #[test]
    fn ascii_truncated_at_boundary() {
        assert_eq!(truncate_utf8("hello world", 5), "hello");
    }

    #[test]
    fn multibyte_not_split() {
        // "é" is 2 bytes (U+00E9). Truncating at 1 byte must not split it.
        let s = "aébcd";
        let r = truncate_utf8(s, 2); // 'a' = 1 byte, 'é' = 2 bytes → fits 'a' only
        assert_eq!(r, "a");
        assert!(r.is_ascii()); // verify no invalid bytes
    }

    #[test]
    fn empty_string_unchanged() {
        assert_eq!(truncate_utf8("", 10), "");
    }

    #[test]
    fn exact_limit_unchanged() {
        assert_eq!(truncate_utf8("hello", 5), "hello");
    }
}
