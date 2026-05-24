//! Post-rotation subprocess hooks. When the daemon is started with
//! `--on-rotation <script>`, every successful rotation fires the script
//! with arguments `<service> <item_id>` and a small set of env vars:
//!
//! - `VP_ROTATION_SERVICE` — service name (e.g. "wi-mcp")
//! - `VP_ROTATION_ITEM_ID` — opaque identifier the strategy returned
//! - `VP_ROTATION_TS`      — RFC3339 timestamp of the rotation
//!
//! Stdin is closed. Stdout and stderr are captured and logged at INFO
//! (stdout) / WARN (stderr or non-zero exit). A 30 s timeout kills the
//! child if it hangs. The hook runs AFTER the rotation has already been
//! committed; a non-zero exit code is logged but does NOT undo the
//! rotation.

use anyhow::{anyhow, Context, Result};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

#[derive(Clone, Debug)]
pub struct RotationHook {
    pub script: PathBuf,
}

impl RotationHook {
    pub fn new(script: PathBuf) -> Self {
        Self { script }
    }

    pub async fn fire(&self, service: &str, item_id: &str) -> Result<()> {
        let ts = chrono::Utc::now().to_rfc3339();
        let mut cmd = Command::new(&self.script);
        cmd.arg(service)
            .arg(item_id)
            .env("VP_ROTATION_SERVICE", service)
            .env("VP_ROTATION_ITEM_ID", item_id)
            .env("VP_ROTATION_TS", &ts)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Retry spawn on ETXTBSY (os error 26). The script may have been
        // written + chmod'd milliseconds before fire() runs; under heavy
        // parallel load on tmpfs the kernel can still see a lingering open
        // writer on the inode and refuse exec. Five attempts with linear
        // backoff (20/40/60/80/100ms = ~300ms max) covers the observed CI
        // race without hiding genuine "binary is being rewritten right now"
        // misconfigurations.
        let mut attempts: u32 = 0;
        let child = loop {
            match cmd.spawn() {
                Ok(c) => break c,
                Err(e) if e.raw_os_error() == Some(26) && attempts < 5 => {
                    attempts += 1;
                    tokio::time::sleep(Duration::from_millis(20 * attempts as u64)).await;
                    continue;
                }
                Err(e) => {
                    return Err(anyhow::Error::new(e)
                        .context(format!("spawn rotation hook {}", self.script.display())));
                }
            }
        };

        let out = timeout(Duration::from_secs(30), child.wait_with_output())
            .await
            .map_err(|_| anyhow!("rotation hook timed out after 30s"))?
            .with_context(|| format!("wait for hook {}", self.script.display()))?;

        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);

        if out.status.success() {
            tracing::info!(
                service = %service,
                item_id = %item_id,
                stdout = %stdout.trim(),
                "rotation hook ok",
            );
        } else {
            tracing::warn!(
                service = %service,
                item_id = %item_id,
                exit = ?out.status.code(),
                stdout = %stdout.trim(),
                stderr = %stderr.trim(),
                "rotation hook returned non-zero",
            );
        }
        Ok(())
    }
}
