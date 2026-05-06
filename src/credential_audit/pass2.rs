//! Pass-2 login-attempt orchestration.
//!
//! For each `needs_pass_2` item: spawn agent.py through the egress proxy,
//! navigate to the item's URL, fill the cred, click submit, capture screenshot
//! + DOM, ask the engine's /judge_login, persist the verdict and evidence.
//!
//! Per-host rate limit (1 attempt / 5 min / host) and 2-strike blacklist on
//! captcha/lockout/blocked verdicts.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::credential_audit::{engine_client::EngineClient, types::Pass2Verdict};

#[allow(dead_code)] // iter-82: used by rate_limit_remaining and is_blacklisted (scaffold; v1.0: wire to Pass-2 HTTP route)
const RATE_LIMIT_PER_HOST: Duration = Duration::from_secs(5 * 60);
#[allow(dead_code)] // iter-82: used by is_blacklisted / record_strike (scaffold; v1.0: wire to Pass-2 HTTP route)
const HOST_BLACKLIST_THRESHOLD: u32 = 2;

#[allow(dead_code)] // iter-82: all fields read by scaffold methods; v1.0: wired when Pass-2 HTTP route lands
pub struct Pass2Engine {
    pub engine: Arc<EngineClient>,
    pub agent_path: String,
    pub egress_proxy_url: Option<String>,
    pub host_last_attempt: tokio::sync::Mutex<HashMap<String, Instant>>,
    pub host_strike_count: tokio::sync::Mutex<HashMap<String, u32>>,
}

impl Pass2Engine {
    pub fn new(
        engine: Arc<EngineClient>,
        agent_path: String,
        egress_proxy_url: Option<String>,
    ) -> Self {
        Self {
            engine,
            agent_path,
            egress_proxy_url,
            host_last_attempt: tokio::sync::Mutex::new(HashMap::new()),
            host_strike_count: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Verdict severity classifier — captcha/lockout/no_login_form increment a
    /// host's strike counter. Hitting `HOST_BLACKLIST_THRESHOLD` marks the
    /// host as blacklisted for the rest of the run.
    #[allow(dead_code)] // iter-82: called from pass2_run_worker (scaffold); v1.0: wired when Pass-2 route lands
    pub fn is_strike(verdict: &Pass2Verdict) -> bool {
        matches!(
            verdict,
            Pass2Verdict::Captcha | Pass2Verdict::Lockout | Pass2Verdict::NoLoginForm
        )
    }

    #[allow(dead_code)] // iter-82: gating logic in pass2_run_worker (scaffold); v1.0: wire to Pass-2 route
    pub async fn is_blacklisted(&self, host: &str) -> bool {
        let map = self.host_strike_count.lock().await;
        map.get(host).copied().unwrap_or(0) >= HOST_BLACKLIST_THRESHOLD
    }

    /// Returns `Some(remaining_wait)` if rate limited, `None` if free to proceed.
    #[allow(dead_code)] // iter-82: gating logic in pass2_run_worker (scaffold); v1.0: wire to Pass-2 route
    pub async fn rate_limit_remaining(&self, host: &str) -> Option<Duration> {
        let map = self.host_last_attempt.lock().await;
        let last = match map.get(host) {
            Some(t) => *t,
            None => return None,
        };
        let elapsed = last.elapsed();
        if elapsed < RATE_LIMIT_PER_HOST {
            Some(RATE_LIMIT_PER_HOST - elapsed)
        } else {
            None
        }
    }

    #[allow(dead_code)] // iter-82: called from pass2_run_worker (scaffold); v1.0: wire to Pass-2 route
    pub async fn record_attempt(&self, host: &str) {
        let mut map = self.host_last_attempt.lock().await;
        map.insert(host.to_string(), Instant::now());
    }

    #[allow(dead_code)] // iter-82: called from pass2_run_worker (scaffold); v1.0: wire to Pass-2 route
    pub async fn record_strike(&self, host: &str) {
        let mut map = self.host_strike_count.lock().await;
        *map.entry(host.to_string()).or_insert(0) += 1;
    }

    /// Drive agent.py end-to-end for ONE login attempt:
    ///   spawn → navigate → fill user → fill pass → click → sleep → screenshot
    ///   → dom_excerpt → close → engine.judge_login → return verdict.
    ///
    /// Caller is responsible for rate-limiting (see `record_attempt`),
    /// blacklist gating (see `is_blacklisted`), and persisting the result.
    #[allow(dead_code)] // iter-82: called from pass2_run_worker (scaffold); v1.0: wired when Pass-2 HTTP route lands
    pub async fn judge_one(
        &self,
        run_id: &str,
        item_id: &str,
        url: &str,
        username: &str,
        password: &secrecy::SecretString,
    ) -> anyhow::Result<crate::credential_audit::types::Pass2Verdict> {
        use anyhow::Context;
        use secrecy::ExposeSecret;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::process::Command;

        let mut cmd = Command::new("python3");
        cmd.arg(&self.agent_path);
        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        if let Some(proxy) = &self.egress_proxy_url {
            cmd.env("MLBOX_AGENT_PROXY", proxy);
        }
        let mut child = cmd.spawn().context("spawn agent.py")?;
        let mut stdin = child.stdin.take().context("agent.py: no stdin")?;
        let stdout = child.stdout.take().context("agent.py: no stdout")?;
        let mut reader = BufReader::new(stdout).lines();

        async fn send(
            stdin: &mut tokio::process::ChildStdin,
            msg: &serde_json::Value,
        ) -> anyhow::Result<()> {
            let line = serde_json::to_string(msg)? + "\n";
            stdin.write_all(line.as_bytes()).await?;
            Ok(())
        }
        async fn recv(
            reader: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
        ) -> anyhow::Result<serde_json::Value> {
            let line = reader
                .next_line()
                .await?
                .context("agent.py closed stdout before reply")?;
            serde_json::from_str(&line).context("agent.py emitted non-JSON line")
        }

        // 1) navigate
        send(
            &mut stdin,
            &serde_json::json!({"action": "navigate", "url": url, "timeout": 30000}),
        )
        .await?;
        let nav = recv(&mut reader).await?;
        if nav.get("status").and_then(|v| v.as_str()) != Some("ok") {
            let _ = send(&mut stdin, &serde_json::json!({"action": "close"})).await;
            let _ = child.kill().await;
            return Ok(crate::credential_audit::types::Pass2Verdict::PageTimeout);
        }

        // 2) fill username — try common selectors. The first selector that
        //    matches succeeds; the rest are tolerated as failures.
        let user_selectors = "input[type=email],input[name=username],input[autocomplete=username],input[id=username],input[id=email]";
        send(
            &mut stdin,
            &serde_json::json!({"action": "fill", "selector": user_selectors, "value": username, "timeout": 5000}),
        )
        .await?;
        let _ = recv(&mut reader).await?;

        // 3) fill password
        send(
            &mut stdin,
            &serde_json::json!({"action": "fill", "selector": "input[type=password]", "value": password.expose_secret(), "timeout": 5000}),
        )
        .await?;
        let fill_pw = recv(&mut reader).await?;
        if fill_pw.get("status").and_then(|v| v.as_str()) != Some("ok") {
            let _ = send(&mut stdin, &serde_json::json!({"action": "close"})).await;
            let _ = child.kill().await;
            return Ok(crate::credential_audit::types::Pass2Verdict::NoLoginForm);
        }

        // 4) click submit
        send(
            &mut stdin,
            &serde_json::json!({"action": "click", "selector": "button[type=submit],input[type=submit]", "timeout": 5000}),
        )
        .await?;
        let _ = recv(&mut reader).await?;

        // 5) sleep so the login response renders
        send(
            &mut stdin,
            &serde_json::json!({"action": "sleep", "seconds": 5}),
        )
        .await?;
        let _ = recv(&mut reader).await?;

        // 6) screenshot
        send(&mut stdin, &serde_json::json!({"action": "screenshot"})).await?;
        let snap = recv(&mut reader).await?;
        let screenshot_b64 = snap
            .get("image_b64")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // 7) dom_excerpt
        send(&mut stdin, &serde_json::json!({"action": "dom_excerpt"})).await?;
        let dom = recv(&mut reader).await?;
        let dom_excerpt = dom
            .get("dom")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        // 8) close
        let _ = send(&mut stdin, &serde_json::json!({"action": "close"})).await;
        let _ = child.wait().await;

        // 9) ask the engine
        let verdict = self
            .engine
            .judge_login(run_id, item_id, url, &dom_excerpt, &screenshot_b64)
            .await?;
        Ok(verdict)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rate_limit_starts_unset() {
        let dummy = Arc::new(EngineClient::new("http://localhost:9"));
        let p2 = Pass2Engine::new(dummy, "agent.py".to_string(), None);
        assert!(p2.rate_limit_remaining("example.com").await.is_none());
    }

    #[tokio::test]
    async fn record_attempt_then_rate_limited() {
        let dummy = Arc::new(EngineClient::new("http://localhost:9"));
        let p2 = Pass2Engine::new(dummy, "agent.py".to_string(), None);
        p2.record_attempt("example.com").await;
        let r = p2.rate_limit_remaining("example.com").await;
        assert!(r.is_some());
        assert!(r.unwrap() <= RATE_LIMIT_PER_HOST);
    }

    #[tokio::test]
    async fn blacklist_triggers_at_threshold() {
        let dummy = Arc::new(EngineClient::new("http://localhost:9"));
        let p2 = Pass2Engine::new(dummy, "agent.py".to_string(), None);
        for _ in 0..HOST_BLACKLIST_THRESHOLD {
            p2.record_strike("evil.example.com").await;
        }
        assert!(p2.is_blacklisted("evil.example.com").await);
        assert!(!p2.is_blacklisted("clean.example.com").await);
    }

    #[test]
    fn captcha_lockout_no_login_form_count_as_strikes() {
        assert!(Pass2Engine::is_strike(&Pass2Verdict::Captcha));
        assert!(Pass2Engine::is_strike(&Pass2Verdict::Lockout));
        assert!(Pass2Engine::is_strike(&Pass2Verdict::NoLoginForm));
        assert!(!Pass2Engine::is_strike(&Pass2Verdict::Success));
        assert!(!Pass2Engine::is_strike(&Pass2Verdict::Failure));
        assert!(!Pass2Engine::is_strike(&Pass2Verdict::MfaRequired));
        assert!(!Pass2Engine::is_strike(&Pass2Verdict::Unknown));
    }
}
