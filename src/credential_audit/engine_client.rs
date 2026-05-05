use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Clone)]
pub struct EngineClient {
    base_url: String,
    http: reqwest::Client,
}

impl EngineClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            // 300s client-level timeout covers long LLM inference runs.
            // Individual requests that do NOT involve LLM inference (health,
            // telemetry) override this with shorter per-request timeouts —
            // see each call site. The `run()` and `judge_login()` calls
            // intentionally inherit the full 300s window because they invoke
            // the LLM engine and may take several minutes per batch.
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(300))
                .build()
                .expect("build reqwest client"),
        }
    }

    pub async fn health(&self) -> Result<bool> {
        let resp = self
            .http
            .get(format!("{}/health", self.base_url))
            .timeout(Duration::from_secs(2))
            .send()
            .await
            .context("health request")?;
        Ok(resp.status().is_success())
    }

    pub async fn run(&self, body: &EngineRunRequest) -> Result<EngineRunResponse> {
        let resp = self
            .http
            .post(format!("{}/audit/run", self.base_url))
            .json(body)
            .send()
            .await
            .context("run request")?;
        resp.error_for_status_ref()
            .context("engine /audit/run returned error")?;
        let parsed: EngineRunResponse = resp.json().await.context("parse run response")?;
        Ok(parsed)
    }

    pub async fn telemetry(&self, run_id: &str) -> Result<serde_json::Value> {
        // Issue (iter-14): Telemetry is a lightweight metadata fetch — no LLM
        // inference involved. Override the 300s client default with a 10s
        // per-request limit so a slow/hung engine does not stall audit
        // orchestration for up to 5 minutes.
        let resp = self
            .http
            .get(format!("{}/audit/telemetry/{run_id}", self.base_url))
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .context("telemetry request")?;
        resp.error_for_status_ref()
            .context("engine /audit/telemetry returned error")?;
        let parsed: serde_json::Value = resp.json().await.context("parse telemetry response")?;
        Ok(parsed)
    }

    pub async fn judge_login(
        &self,
        run_id: &str,
        item_id: &str,
        url: &str,
        dom_excerpt: &str,
        screenshot_b64: &str,
    ) -> Result<crate::credential_audit::types::Pass2Verdict> {
        let body = serde_json::json!({
            "run_id": run_id,
            "item_id": item_id,
            "url": url,
            "dom_excerpt": dom_excerpt,
            "screenshot_b64": screenshot_b64,
        });
        let resp = self
            .http
            .post(format!("{}/judge_login", self.base_url))
            .json(&body)
            .send()
            .await
            .context("judge_login request")?;
        resp.error_for_status_ref()
            .context("engine /judge_login returned error")?;
        let parsed: serde_json::Value = resp.json().await.context("parse judge_login response")?;
        let verdict_str = parsed
            .get("verdict")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let v = serde_json::from_str::<crate::credential_audit::types::Pass2Verdict>(
            &format!("\"{}\"", verdict_str),
        )
        .unwrap_or(crate::credential_audit::types::Pass2Verdict::Unknown);
        Ok(v)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EngineRunRequest {
    pub run_id: String,
    pub items: Vec<EngineInputItem>,
    pub secrets_for_test: serde_json::Value,
    pub dedup_keys: Vec<EngineDedupKey>,
    pub proxy: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EngineInputItem {
    pub id: String,
    pub name: String,
    pub url: Option<String>,
    pub folder: Option<String>,
    pub item_type: String,
    pub custom_field_names: Vec<String>,
    pub has_password: bool,
    pub has_totp: bool,
    pub has_ssh_key: bool,
    pub has_attachments: bool,
    pub notes_excerpt: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EngineDedupKey {
    pub item_id: String,
    pub url_host: String,
    pub username: String,
    pub password_hash: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EngineRunResponse {
    pub run_id: String,
    pub items: Vec<EngineItemResult>,
    pub telemetry_summary: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EngineItemResult {
    pub item_id: String,
    pub category: String,
    pub status: String,
    pub reason: String,
    pub evidence: serde_json::Value,
    pub dedup_cluster_id: Option<String>,
    pub marked_for_delete: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn health_returns_true_on_200() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/health"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"status":"ok"})))
            .mount(&server)
            .await;
        let client = EngineClient::new(server.uri());
        assert!(client.health().await.unwrap());
    }

    #[tokio::test]
    async fn run_returns_results() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/audit/run"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "run_id": "r1",
                "items": [{
                    "item_id": "i1",
                    "category": "login",
                    "status": "alive",
                    "reason": "ok",
                    "evidence": {},
                    "dedup_cluster_id": null,
                    "marked_for_delete": false
                }],
                "telemetry_summary": {"total": 1}
            })))
            .mount(&server)
            .await;
        let client = EngineClient::new(server.uri());
        let body = EngineRunRequest {
            run_id: "r1".into(),
            items: vec![],
            secrets_for_test: serde_json::json!({}),
            dedup_keys: vec![],
            proxy: None,
        };
        let resp = client.run(&body).await.unwrap();
        assert_eq!(resp.run_id, "r1");
        assert_eq!(resp.items.len(), 1);
    }
}
