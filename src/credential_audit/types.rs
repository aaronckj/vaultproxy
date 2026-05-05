use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Running,
    PausedProxyDown,
    PausedEngineCrash,
    AbortedLlmLoop,
    AbortedVwReadFailure,
    AbortedEngineError,
    Completed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Pass2Verdict {
    Success,
    Failure,
    MfaRequired,
    Captcha,
    Lockout,
    PasswordResetRequired,
    Unknown,
    BrowserCrash,
    PageTimeout,
    NoLoginForm,
}

#[derive(Debug, Clone, Serialize)]
pub struct Pass2Result {
    pub item_id: String,
    pub verdict: Pass2Verdict,
    pub confidence: f64,
    pub reasoning: String,
    pub evidence_json: String,
    pub attempted_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Run {
    pub run_id: String,
    pub status: RunStatus,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub pass1_complete: bool,
    pub applied_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemResult {
    pub item_id: String,
    pub category: String,
    pub status: String,
    pub reason: String,
    pub evidence_json: String,
    pub dedup_cluster_id: Option<String>,
    pub marked_for_delete: bool,
    pub pass: i32,
}
