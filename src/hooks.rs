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

        let child = cmd
            .spawn()
            .with_context(|| format!("spawn rotation hook {}", self.script.display()))?;

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
