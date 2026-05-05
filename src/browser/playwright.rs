use anyhow::{Context, Result, bail};
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use serde_json::Value;

pub struct PlaywrightProcess {
    #[allow(dead_code)] // held to keep the subprocess alive
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl PlaywrightProcess {
    /// Spawn the Python Playwright agent subprocess.
    pub async fn spawn() -> Result<Self> {
        let script = if std::path::Path::new("/app/playwright/agent.py").exists() {
            "/app/playwright/agent.py"
        } else {
            "./playwright/agent.py"
        };

        let mut child = Command::new("python3")
            .arg(script)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to spawn playwright agent: {}", script))?;

        let stdin = child
            .stdin
            .take()
            .context("failed to take child stdin")?;
        let stdout = child
            .stdout
            .take()
            .context("failed to take child stdout")?;

        Ok(Self {
            child,
            stdin,
            stdout: BufReader::new(stdout),
        })
    }

    /// Send a JSON command and return the parsed JSON response.
    pub async fn send(&mut self, cmd: Value) -> Result<Value> {
        let mut line = serde_json::to_string(&cmd).context("failed to serialize command")?;
        line.push('\n');
        self.stdin
            .write_all(line.as_bytes())
            .await
            .context("failed to write to playwright agent stdin")?;
        self.stdin
            .flush()
            .await
            .context("failed to flush playwright agent stdin")?;

        let mut response = String::new();
        self.stdout
            .read_line(&mut response)
            .await
            .context("failed to read from playwright agent stdout")?;

        let value: Value =
            serde_json::from_str(response.trim()).context("failed to parse playwright agent response")?;

        if value.get("status").and_then(|s| s.as_str()) == Some("error") {
            let msg = value
                .get("error")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown error from playwright agent");
            bail!("playwright agent error: {}", msg);
        }

        Ok(value)
    }

    /// Navigate the browser to a URL, returning the final page URL.
    pub async fn navigate(&mut self, url: &str) -> Result<String> {
        let resp = self
            .send(serde_json::json!({ "action": "navigate", "url": url }))
            .await?;
        let page_url = resp
            .get("url")
            .and_then(|u| u.as_str())
            .unwrap_or(url)
            .to_string();
        Ok(page_url)
    }

    /// Take a screenshot, returning base64-encoded PNG data.
    pub async fn screenshot(&mut self) -> Result<String> {
        let resp = self
            .send(serde_json::json!({ "action": "screenshot" }))
            .await?;
        let data = resp
            .get("image_b64")
            .and_then(|d| d.as_str())
            .context("screenshot response missing 'image_b64' field")?
            .to_string();
        Ok(data)
    }

    /// Fill a form field identified by `selector` with `value`.
    pub async fn fill(&mut self, selector: &str, value: &str) -> Result<()> {
        self.send(serde_json::json!({
            "action": "fill",
            "selector": selector,
            "value": value,
        }))
        .await?;
        Ok(())
    }

    /// Type a sequence of keys into the element identified by `selector`.
    pub async fn type_keys(&mut self, selector: &str, keys: &[String]) -> Result<()> {
        self.send(serde_json::json!({
            "action": "type_keys",
            "selector": selector,
            "keys": keys,
        }))
        .await?;
        Ok(())
    }

    /// Click the element identified by `selector`.
    pub async fn click(&mut self, selector: &str) -> Result<()> {
        self.send(serde_json::json!({
            "action": "click",
            "selector": selector,
        }))
        .await?;
        Ok(())
    }

    /// Wait for the element identified by `selector` to appear, up to `timeout_ms` milliseconds.
    #[allow(dead_code)]
    pub async fn wait_for(&mut self, selector: &str, timeout_ms: u64) -> Result<()> {
        self.send(serde_json::json!({
            "action": "wait_for",
            "selector": selector,
            "timeout_ms": timeout_ms,
        }))
        .await?;
        Ok(())
    }

    /// Return the current page URL.
    #[allow(dead_code)]
    pub async fn get_url(&mut self) -> Result<String> {
        let resp = self
            .send(serde_json::json!({ "action": "get_url" }))
            .await?;
        let url = resp
            .get("url")
            .and_then(|u| u.as_str())
            .context("get_url response missing 'url' field")?
            .to_string();
        Ok(url)
    }

    /// Kill the child process.
    #[allow(dead_code)]
    pub(crate) fn kill(&mut self) {
        let _ = self.child.start_kill();
    }
}

impl Drop for PlaywrightProcess {
    fn drop(&mut self) {
        // Ensure the Python Playwright subprocess (and its headless Chromium
        // child) is killed when this handle is dropped, even on panic or
        // early-return errors.  Without this, zombie processes accumulate.
        let _ = self.child.start_kill();
    }
}
