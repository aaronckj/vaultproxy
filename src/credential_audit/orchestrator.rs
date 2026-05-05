use crate::credential_audit::engine_client::{
    EngineClient, EngineDedupKey, EngineRunRequest,
};
use crate::credential_audit::marker::{MarkRequest, Marker};
use crate::credential_audit::pass2::Pass2Engine;
use crate::credential_audit::types::{ItemResult, Pass2Verdict};
use crate::credential_audit::vault_adapter::VaultAdapter;
use anyhow::Result;
use futures_util::stream::StreamExt;
use rusqlite::{params, Connection};
use secrecy::ExposeSecret;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Bounded concurrency for the per-item vault decrypts in the prep phase.
/// Higher = faster wall time but more contention on the vault read lock.
/// 64 was chosen empirically against ~3.6k items: prep dropped from ~10min
/// (serial) to ~25s without saturating CPU or starving the cloud-sync worker.
const PREP_CONCURRENCY: usize = 64;

pub struct Orchestrator<V: VaultAdapter + 'static> {
    pub vault: Arc<V>,
    pub engine: EngineClient,
    pub marker: Marker,
    pub conn: Arc<Mutex<Connection>>,
    pub pass2: Arc<Pass2Engine>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ApplyOutcome {
    pub applied: usize,
    pub would_apply: usize,
    pub failed: usize,
}

impl<V: VaultAdapter + 'static> Orchestrator<V> {
    pub async fn start_scan(&self) -> Result<String> {
        // Refuse if any run is currently active.
        {
            let conn = self.conn.lock().expect("lock conn");
            let active: i64 = conn.query_row(
                "SELECT count(*) FROM audit_runs WHERE status IN ('running','paused_proxy_down','paused_engine_crash')",
                [],
                |r| r.get(0),
            )?;
            if active > 0 {
                anyhow::bail!("another audit run is in progress");
            }
        }

        let run_id = Uuid::new_v4().to_string();
        let started = chrono::Utc::now().to_rfc3339();
        {
            let conn = self.conn.lock().expect("DB mutex poisoned");
            conn.execute(
                "INSERT INTO audit_runs(run_id, status, started_at) VALUES (?1, 'running', ?2)",
                params![&run_id, &started],
            )?;
        }

        // Engine precondition.
        //
        // iter-34: `engine.health()` returns Err when the engine is not
        // reachable (connection refused, DNS failure, etc.), not Ok(false).
        // The `?` operator previously propagated this as a cryptic reqwest
        // error message that the handler in handlers.rs could not match on
        // "engine is not reachable" → the caller received a 500 with the raw
        // reqwest error string instead of a 503.
        //
        // Fix: treat both Err(_) and Ok(false) as "engine unreachable" and
        // normalise to the bail message the handler expects. The actual reqwest
        // error is logged at debug level so operators who check logs can see
        // whether it is "connection refused" (engine never started) vs. a
        // transient DNS failure.
        let engine_reachable = match self.engine.health().await {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(
                    "credaudit: engine health check failed (engine likely not running): {:#}", e
                );
                false
            }
        };
        if !engine_reachable {
            self.fail_run(&run_id, "engine_unreachable")?;
            anyhow::bail!("engine is not reachable");
        }

        // 1) Read items (metadata-only).
        let items = self.vault.list_items_metadata().await?;

        // 2) Build dedup keys for items with passwords. Concurrent (PREP_CONCURRENCY)
        //    so the per-item decrypt latency parallelizes; per-item Errs are
        //    logged and skipped rather than bailing the whole scan.
        let vault = self.vault.clone();
        let dedup_inputs: Vec<crate::credential_audit::engine_client::EngineInputItem> = items
            .iter()
            .filter(|it| it.has_password)
            .cloned()
            .collect();
        let dedup_keys: Vec<EngineDedupKey> = futures_util::stream::iter(dedup_inputs)
        .map(|it| {
            let vault = vault.clone();
            async move {
                let host = match vault.item_url_host(&it.id).await {
                    Ok(Some(h)) => h,
                    Ok(None) => return None,
                    Err(e) => {
                        tracing::warn!(item_id=%it.id, error=%e, "dedup: item_url_host failed; skipping");
                        return None;
                    }
                };
                let user = match vault.item_username(&it.id).await {
                    Ok(Some(u)) => u,
                    Ok(None) => return None,
                    Err(e) => {
                        tracing::warn!(item_id=%it.id, error=%e, "dedup: item_username failed; skipping");
                        return None;
                    }
                };
                let hash = match vault.item_password_hash(&it.id).await {
                    Ok(Some(h)) => h,
                    Ok(None) => return None,
                    Err(e) => {
                        tracing::warn!(item_id=%it.id, error=%e, "dedup: item_password_hash failed; skipping");
                        return None;
                    }
                };
                Some(EngineDedupKey {
                    item_id: it.id.clone(),
                    url_host: host,
                    username: user,
                    password_hash: hash,
                })
            }
        })
        .buffer_unordered(PREP_CONCURRENCY)
        .filter_map(|x| async move { x })
        .collect()
        .await;

        // 3) Fetch secrets-for-test for items the engine needs (api_key, totp).
        //    Same concurrency + per-item resilience pattern as #2.
        let vault = self.vault.clone();
        let secrets_pairs: Vec<(String, serde_json::Map<String, serde_json::Value>)> =
            futures_util::stream::iter(items.iter().cloned())
                .map(|it| {
                    let vault = vault.clone();
                    async move {
                        let s = match vault.item_secrets(&it.id).await {
                            Ok(s) => s,
                            Err(e) => {
                                tracing::warn!(item_id=%it.id, error=%e, "secrets: item_secrets failed; skipping");
                                return None;
                            }
                        };
                        let mut entry = serde_json::Map::new();
                        if let Some(t) = s.totp_seed {
                            entry.insert(
                                "totp_seed".into(),
                                serde_json::Value::String(t.expose_secret().to_string()),
                            );
                        }
                        if let Some(p) = s.api_key_value {
                            entry.insert(
                                "api_key".into(),
                                serde_json::Value::String(p.expose_secret().to_string()),
                            );
                        }
                        if entry.is_empty() {
                            None
                        } else {
                            Some((it.id.clone(), entry))
                        }
                    }
                })
                .buffer_unordered(PREP_CONCURRENCY)
                .filter_map(|x| async move { x })
                .collect()
                .await;
        let mut secrets_for_test = serde_json::Map::new();
        for (id, entry) in secrets_pairs {
            secrets_for_test.insert(id, serde_json::Value::Object(entry));
        }

        // 4) Call engine /audit/run.
        let req = EngineRunRequest {
            run_id: run_id.clone(),
            items: items.clone(),
            secrets_for_test: serde_json::Value::Object(secrets_for_test),
            dedup_keys,
            proxy: None,
        };
        let resp = match self.engine.run(&req).await {
            Ok(r) => r,
            Err(e) => {
                self.fail_run(&run_id, &format!("engine_error: {e}"))?;
                anyhow::bail!("engine call failed: {e}");
            }
        };

        // 5) Persist results.
        {
            let mut conn = self.conn.lock().expect("DB mutex poisoned");
            let tx = conn.transaction()?;
            for r in &resp.items {
                tx.execute(
                    "INSERT INTO audit_run_items
                       (run_id, item_id, category, status, reason, evidence_json,
                        dedup_cluster_id, marked_for_delete, pass)
                       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1)",
                    params![
                        &run_id,
                        &r.item_id,
                        &r.category,
                        &r.status,
                        &r.reason,
                        serde_json::to_string(&r.evidence)?,
                        &r.dedup_cluster_id,
                        r.marked_for_delete as i32,
                    ],
                )?;
            }
            tx.execute(
                "UPDATE audit_runs SET pass1_complete=1, status='completed', finished_at=?1 WHERE run_id=?2",
                params![&chrono::Utc::now().to_rfc3339(), &run_id],
            )?;
            tx.commit()?;
        }

        Ok(run_id)
    }

    /// Mark a run as failed, recording the failure reason in `audit_runs.fail_reason`
    /// so operators can diagnose why a scan aborted.
    ///
    /// iter-9 fix: the `reason` parameter was previously prefixed with `_` (unused).
    /// It was passed at call sites (`"engine_unreachable"`, `"engine_error: …"`) but
    /// never stored, leaving `fail_reason` always NULL in the database.
    fn fail_run(&self, run_id: &str, reason: &str) -> Result<()> {
        let conn = self.conn.lock().expect("DB mutex poisoned");
        conn.execute(
            "UPDATE audit_runs SET status='aborted_engine_error', finished_at=?1, fail_reason=?2 WHERE run_id=?3",
            params![&chrono::Utc::now().to_rfc3339(), reason, run_id],
        )?;
        Ok(())
    }

    pub fn list_pending(&self, run_id: &str) -> Result<Vec<ItemResult>> {
        let conn = self.conn.lock().expect("DB mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT item_id, category, status, reason, evidence_json, dedup_cluster_id, marked_for_delete, pass
             FROM audit_run_items WHERE run_id=?1 AND marked_for_delete=1",
        )?;
        let rows = stmt.query_map(params![run_id], |r| {
            Ok(ItemResult {
                item_id: r.get(0)?,
                category: r.get(1)?,
                status: r.get(2)?,
                reason: r.get(3)?,
                evidence_json: r.get(4)?,
                dedup_cluster_id: r.get(5)?,
                marked_for_delete: r.get::<_, i32>(6)? != 0,
                pass: r.get(7)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub async fn apply(
        &self,
        run_id: &str,
        item_ids: Option<Vec<String>>,
        dry_run: bool,
        confirm_bulk: bool,
    ) -> Result<ApplyOutcome> {
        let pending = self.list_pending(run_id)?;
        let target: Vec<_> = match &item_ids {
            Some(ids) => pending.into_iter().filter(|p| ids.contains(&p.item_id)).collect(),
            None => pending,
        };
        if target.len() > 50 && item_ids.is_none() && !confirm_bulk {
            anyhow::bail!(
                "apply requires confirm_bulk=true for >50 items without explicit item_ids"
            );
        }
        if dry_run {
            return Ok(ApplyOutcome {
                applied: 0,
                would_apply: target.len(),
                failed: 0,
            });
        }
        let mut applied = 0;
        let mut failed = 0;
        for r in &target {
            let req = MarkRequest {
                item_id: &r.item_id,
                reason: &r.status,
                detail: &r.reason,
                pass: r.pass,
                run_id,
            };
            match self.marker.mark(&req).await {
                Ok(()) => applied += 1,
                Err(_) => failed += 1,
            }
        }
        if applied > 0 {
            let conn = self.conn.lock().expect("DB mutex poisoned");
            conn.execute(
                "UPDATE audit_runs SET applied_at=?1 WHERE run_id=?2",
                params![&chrono::Utc::now().to_rfc3339(), run_id],
            )?;
        }
        Ok(ApplyOutcome {
            applied,
            would_apply: 0,
            failed,
        })
    }

    pub async fn get_telemetry(&self, run_id: &str) -> Result<serde_json::Value> {
        self.engine.telemetry(run_id).await
    }

    /// List items that classified as `needs_pass_2` after Pass 1 — these are
    /// the input to the Pass-2 dispatch worker.
    pub fn list_needs_pass_2(&self, run_id: &str) -> Result<Vec<ItemResult>> {
        let conn = self.conn.lock().expect("DB mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT item_id, category, status, reason, evidence_json,
                    dedup_cluster_id, marked_for_delete, pass
             FROM audit_run_items
             WHERE run_id = ?1 AND status = 'needs_pass_2'",
        )?;
        let rows = stmt.query_map(params![run_id], |r| {
            Ok(ItemResult {
                item_id: r.get(0)?,
                category: r.get(1)?,
                status: r.get(2)?,
                reason: r.get(3)?,
                evidence_json: r.get(4)?,
                dedup_cluster_id: r.get(5)?,
                marked_for_delete: r.get::<_, i32>(6)? != 0,
                pass: r.get(7)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Pass-2 entry point. Counts `needs_pass_2` items, validates Pass-1
    /// completion, then spawns a background worker that drives each item
    /// through `Pass2Engine.judge_one` and persists the verdict. Returns
    /// the number of items dispatched (caller can poll the run detail to
    /// see verdicts as they land).
    pub async fn verify_start(self: Arc<Self>, run_id: &str) -> Result<usize> {
        let needs_items = self.list_needs_pass_2(run_id)?;
        if needs_items.is_empty() {
            return Ok(0);
        }
        // Pre-check: Pass-1 must be complete before Pass-2 can start.
        let pass1_done: i32 = {
            let conn = self.conn.lock().expect("lock conn");
            conn.query_row(
                "SELECT pass1_complete FROM audit_runs WHERE run_id = ?1",
                params![run_id],
                |r| r.get(0),
            )?
        };
        if pass1_done == 0 {
            anyhow::bail!("Pass 1 has not completed for run {run_id} — refuse to start Pass 2");
        }
        let n = needs_items.len();

        let run_id_owned = run_id.to_string();
        let orch = self.clone();
        tokio::spawn(async move {
            if let Err(e) = orch.pass2_run_worker(run_id_owned.clone(), needs_items).await {
                tracing::error!(run_id = %run_id_owned, "pass2 worker failed: {e:#}");
            }
        });
        Ok(n)
    }

    /// Background worker — drives one Pass-2 attempt per item and persists
    /// the verdict + evidence. Per-item errors are logged and the worker
    /// continues with the next item; whole-run failure (e.g. DB unreachable)
    /// returns Err and the run stays in `running` for operator inspection.
    async fn pass2_run_worker(
        self: Arc<Self>,
        run_id: String,
        items: Vec<ItemResult>,
    ) -> Result<()> {
        for item in items {
            let item_id = item.item_id.clone();
            // Look up URL + username + password from VW. Skip items missing any.
            let url = match self.vault.item_url(&item_id).await? {
                Some(u) => u,
                None => {
                    self.update_pass2_result(
                        &run_id,
                        &item_id,
                        &Pass2Verdict::NoLoginForm,
                        &serde_json::json!({"reason": "no url in vault"}).to_string(),
                        "untestable",
                        false,
                    )?;
                    continue;
                }
            };
            let host = match url::Url::parse(&url)
                .ok()
                .and_then(|p| p.host_str().map(String::from))
            {
                Some(h) => h,
                None => {
                    self.update_pass2_result(
                        &run_id,
                        &item_id,
                        &Pass2Verdict::NoLoginForm,
                        &serde_json::json!({"reason": "url unparseable"}).to_string(),
                        "untestable",
                        false,
                    )?;
                    continue;
                }
            };
            if self.pass2.is_blacklisted(&host).await {
                self.update_pass2_result(
                    &run_id,
                    &item_id,
                    &Pass2Verdict::Captcha,
                    &serde_json::json!({"reason": "host blacklisted for run"}).to_string(),
                    "untestable",
                    false,
                )?;
                continue;
            }
            if let Some(_wait) = self.pass2.rate_limit_remaining(&host).await {
                self.update_pass2_result(
                    &run_id,
                    &item_id,
                    &Pass2Verdict::Unknown,
                    &serde_json::json!({"reason": "rate limited"}).to_string(),
                    "untestable",
                    false,
                )?;
                continue;
            }
            let username = self.vault.item_username(&item_id).await?.unwrap_or_default();
            let secrets = self.vault.item_secrets(&item_id).await?;
            let password = match secrets.password {
                Some(p) => p,
                None => {
                    self.update_pass2_result(
                        &run_id,
                        &item_id,
                        &Pass2Verdict::NoLoginForm,
                        &serde_json::json!({"reason": "no password in vault"}).to_string(),
                        "untestable",
                        false,
                    )?;
                    continue;
                }
            };

            self.pass2.record_attempt(&host).await;
            let verdict = match self
                .pass2
                .judge_one(&run_id, &item_id, &url, &username, &password)
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(item_id = %item_id, "pass2 judge_one failed: {e:#}");
                    self.update_pass2_result(
                        &run_id,
                        &item_id,
                        &Pass2Verdict::BrowserCrash,
                        &serde_json::json!({"reason": "judge_one error", "detail": e.to_string()}).to_string(),
                        "untestable",
                        false,
                    )?;
                    continue;
                }
            };
            if Pass2Engine::is_strike(&verdict) {
                self.pass2.record_strike(&host).await;
            }
            let (new_status, marked_for_delete) = map_verdict_to_status(&verdict);
            let evidence = serde_json::json!({
                "url": url,
                "host": host,
                "verdict": verdict,
            })
            .to_string();
            self.update_pass2_result(
                &run_id,
                &item_id,
                &verdict,
                &evidence,
                new_status,
                marked_for_delete,
            )?;
        }
        // Mark run pass2-complete (best-effort — we don't have a pass2_complete
        // column on the schema yet, so we use status='completed' which is what
        // Pass-1 already sets; the difference is that audit_run_items now have
        // pass2_verdict populated for the items that went through Pass-2).
        let _ = run_id;
        Ok(())
    }

    fn update_pass2_result(
        &self,
        run_id: &str,
        item_id: &str,
        verdict: &Pass2Verdict,
        evidence_json: &str,
        new_status: &str,
        marked_for_delete: bool,
    ) -> Result<()> {
        let verdict_str = serde_json::to_string(verdict)?;
        // serde_json wraps enum in quotes — strip them for the DB column.
        let verdict_clean = verdict_str.trim_matches('"').to_string();
        let conn = self.conn.lock().expect("DB mutex poisoned");
        conn.execute(
            "UPDATE audit_run_items
             SET pass2_verdict = ?1,
                 pass2_evidence_json = ?2,
                 pass2_attempted_at = ?3,
                 status = ?4,
                 marked_for_delete = ?5,
                 pass = 2
             WHERE run_id = ?6 AND item_id = ?7",
            params![
                &verdict_clean,
                evidence_json,
                &chrono::Utc::now().to_rfc3339(),
                new_status,
                marked_for_delete as i32,
                run_id,
                item_id,
            ],
        )?;
        Ok(())
    }

    pub fn list_runs(&self) -> Result<Vec<crate::credential_audit::types::Run>> {
        let conn = self.conn.lock().expect("lock conn");
        let mut stmt = conn.prepare(
            "SELECT run_id, status, started_at, finished_at, pass1_complete, applied_at
             FROM audit_runs ORDER BY started_at DESC LIMIT 50",
        )?;
        let rows = stmt.query_map([], |r| {
            let status: String = r.get(1)?;
            let status = serde_json::from_str::<crate::credential_audit::types::RunStatus>(
                &format!("\"{}\"", status),
            )
            .unwrap_or(crate::credential_audit::types::RunStatus::AbortedVwReadFailure);
            Ok(crate::credential_audit::types::Run {
                run_id: r.get(0)?,
                status,
                started_at: r.get(2)?,
                finished_at: r.get(3)?,
                pass1_complete: r.get::<_, i32>(4)? != 0,
                applied_at: r.get(5)?,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn get_run_detail(&self, run_id: &str) -> Result<RunDetail> {
        let conn = self.conn.lock().expect("lock conn");

        let run = conn
            .query_row(
                "SELECT run_id, status, started_at, finished_at, pass1_complete, applied_at
                 FROM audit_runs WHERE run_id = ?1",
                rusqlite::params![run_id],
                |r| {
                    let status: String = r.get(1)?;
                    let status = serde_json::from_str::<crate::credential_audit::types::RunStatus>(
                        &format!("\"{}\"", status),
                    )
                    .unwrap_or(crate::credential_audit::types::RunStatus::AbortedVwReadFailure);
                    Ok(crate::credential_audit::types::Run {
                        run_id: r.get(0)?,
                        status,
                        started_at: r.get(2)?,
                        finished_at: r.get(3)?,
                        pass1_complete: r.get::<_, i32>(4)? != 0,
                        applied_at: r.get(5)?,
                    })
                },
            )
            .map_err(|e| anyhow::anyhow!("run not found: {e}"))?;

        let mut stmt = conn.prepare(
            "SELECT item_id, category, status, reason, evidence_json,
                    dedup_cluster_id, marked_for_delete, pass
             FROM audit_run_items WHERE run_id = ?1 ORDER BY id",
        )?;
        let rows = stmt.query_map(rusqlite::params![run_id], |r| {
            Ok(crate::credential_audit::types::ItemResult {
                item_id: r.get(0)?,
                category: r.get(1)?,
                status: r.get(2)?,
                reason: r.get(3)?,
                evidence_json: r.get(4)?,
                dedup_cluster_id: r.get(5)?,
                marked_for_delete: r.get::<_, i32>(6)? != 0,
                pass: r.get(7)?,
            })
        })?;
        let mut items = Vec::new();
        for row in rows {
            items.push(row?);
        }
        Ok(RunDetail { run, items })
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RunDetail {
    pub run: crate::credential_audit::types::Run,
    pub items: Vec<crate::credential_audit::types::ItemResult>,
}

/// Map a Pass-2 verdict to (new audit_run_items.status, marked_for_delete).
/// Used by the Pass-2 worker to translate the LLM verdict into the same
/// status vocabulary Pass-1 uses.
fn map_verdict_to_status(v: &Pass2Verdict) -> (&'static str, bool) {
    match v {
        Pass2Verdict::Success => ("alive", false),
        Pass2Verdict::Failure => ("dead", true),
        Pass2Verdict::PasswordResetRequired => ("alive", false),
        Pass2Verdict::MfaRequired => ("alive", false),
        Pass2Verdict::Captcha
        | Pass2Verdict::Lockout
        | Pass2Verdict::Unknown
        | Pass2Verdict::BrowserCrash
        | Pass2Verdict::PageTimeout
        | Pass2Verdict::NoLoginForm => ("untestable", false),
    }
}
