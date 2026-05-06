//! Dashboard authentication — password hashing and session management.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

// -------------------------------------------------------------------------- //
// Config persisted to disk                                                     //
// -------------------------------------------------------------------------- //

#[derive(Debug, Default, Serialize, Deserialize)]
struct DashboardConfig {
    #[serde(default)]
    password_hash: Option<String>,
}

// -------------------------------------------------------------------------- //
// SessionStore                                                                 //
// -------------------------------------------------------------------------- //

/// Manages dashboard password and login sessions.
#[derive(Clone)]
pub struct SessionStore {
    config_path: String,
    hash: Arc<RwLock<Option<String>>>,
    /// session_id -> expiry unix timestamp
    sessions: Arc<RwLock<HashMap<String, i64>>>,
    /// Timestamps of failed dashboard-login attempts.
    failed_attempts: Arc<RwLock<Vec<Instant>>>,
    /// Timestamps of failed keystore-unlock attempts (kept separate so
    /// dashboard-login throttling and keystore-unlock throttling don't
    /// interfere with each other).
    unlock_failed_attempts: Arc<RwLock<Vec<Instant>>>,
    /// Timestamps of successful config-write endpoint hits. Bounds burst
    /// rate on POST /api/policies, /api/permissions, /api/profiles,
    /// /api/settings/* (iter-12).
    config_write_attempts: Arc<RwLock<Vec<Instant>>>,
}

impl SessionStore {
    /// Load (or initialise) from the given config path.
    pub fn new(config_path: &str) -> Self {
        let hash = match std::fs::read_to_string(config_path) {
            Ok(data) => {
                let cfg: DashboardConfig = serde_json::from_str(&data).unwrap_or_default();
                cfg.password_hash
            }
            Err(_) => None,
        };

        SessionStore {
            config_path: config_path.to_string(),
            hash: Arc::new(RwLock::new(hash)),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            failed_attempts: Arc::new(RwLock::new(Vec::new())),
            unlock_failed_attempts: Arc::new(RwLock::new(Vec::new())),
            config_write_attempts: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Rate-limit check for keystore-unlock attempts.
    ///
    /// Returns `Err` when the caller should be throttled (HTTP 429).
    /// Call `record_unlock_failure` after a failed unlock.
    /// Call `reset_unlock_failures` after a successful unlock.
    pub async fn check_unlock_rate_limit(&self) -> Result<(), String> {
        let window = Duration::from_secs(300); // 5 minutes
        let mut attempts = self.unlock_failed_attempts.write().await;
        attempts.retain(|t| t.elapsed() < window);
        if attempts.len() >= 5 {
            tracing::warn!("keystore unlock rate-limited — too many failed attempts");
            return Err("too many failed unlock attempts — try again later".into());
        }
        Ok(())
    }

    pub async fn record_unlock_failure(&self) {
        self.unlock_failed_attempts
            .write()
            .await
            .push(Instant::now());
    }

    pub async fn reset_unlock_failures(&self) {
        self.unlock_failed_attempts.write().await.clear();
    }

    /// Rate-limit check for configuration-write endpoints (POST
    /// /api/policies, /api/permissions, /api/profiles, /api/settings/*).
    /// Returns `Err` when the caller should be throttled. 30 writes per
    /// 60-second window shared across endpoints per-process — generous
    /// enough for legitimate dashboard use, tight enough to keep a
    /// stolen-cookie attacker from hammering config changes fast enough
    /// to fly under an operator's audit-log refresh cadence.
    pub async fn check_config_write_rate(&self) -> Result<(), String> {
        let window = Duration::from_secs(60);
        let mut attempts = self.config_write_attempts.write().await;
        attempts.retain(|t| t.elapsed() < window);
        if attempts.len() >= 30 {
            tracing::warn!(
                "config-write rate limit exceeded ({} in {}s)",
                attempts.len(),
                window.as_secs()
            );
            return Err("config write rate limit exceeded — try again later".into());
        }
        attempts.push(Instant::now());
        Ok(())
    }

    /// Returns `true` when a password has been configured.
    pub async fn is_configured(&self) -> bool {
        self.hash.read().await.is_some()
    }

    /// Hash and persist a new dashboard password.
    pub async fn set_password(&self, password: &str) -> Result<(), String> {
        let hashed = bcrypt::hash(password, bcrypt::DEFAULT_COST)
            .map_err(|e| format!("bcrypt hash failed: {}", e))?;

        // Persist.
        let cfg = DashboardConfig {
            password_hash: Some(hashed.clone()),
        };
        let json =
            serde_json::to_string_pretty(&cfg).map_err(|e| format!("serialise config: {}", e))?;

        // Ensure parent directory exists.
        if let Some(parent) = std::path::Path::new(&self.config_path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        crate::secure::safe_write_config(&self.config_path, json.as_bytes())
            .map_err(|e| format!("write config: {}", e))?;

        *self.hash.write().await = Some(hashed);
        Ok(())
    }

    /// Verify password, create a session, return the session ID.
    ///
    /// Rate-limited: after 5 failed attempts within 5 minutes, login is
    /// blocked for the remainder of that window.
    pub async fn login(&self, password: &str) -> Result<String, String> {
        // --- Rate limiting ---
        let window = Duration::from_secs(300); // 5 minutes
        {
            let mut attempts = self.failed_attempts.write().await;
            // Prune attempts older than the window.
            attempts.retain(|t| t.elapsed() < window);
            if attempts.len() >= 5 {
                tracing::warn!("login rate limited — too many failed attempts");
                return Err("too many failed attempts — try again later".into());
            }
        }

        // If hash is not loaded yet, try re-reading from disk (setup may have
        // written it after this SessionStore was constructed).
        {
            let current = self.hash.read().await;
            if current.is_none() {
                drop(current);
                if let Ok(data) = std::fs::read_to_string(&self.config_path) {
                    if let Ok(cfg) = serde_json::from_str::<DashboardConfig>(&data) {
                        if cfg.password_hash.is_some() {
                            *self.hash.write().await = cfg.password_hash;
                        }
                    }
                }
            }
        }

        let hash_guard = self.hash.read().await;
        let hash = hash_guard
            .as_deref()
            .ok_or_else(|| "no password configured".to_string())?;

        let valid = bcrypt::verify(password, hash).map_err(|e| format!("bcrypt verify: {}", e))?;
        if !valid {
            // Record the failed attempt.
            self.failed_attempts.write().await.push(Instant::now());
            return Err("invalid password".into());
        }
        drop(hash_guard);

        let session_id = uuid::Uuid::new_v4().to_string();
        let expiry = chrono::Utc::now().timestamp() + 86400; // 24 hours

        // Cap the session map at MAX_SESSIONS so a caller that defeats or
        // outlasts the 5-per-5min login rate limit can't grow the HashMap
        // unboundedly (legitimate 24h sessions × frequent reconnects can
        // accumulate). When full, evict the session with the earliest
        // expiry timestamp — approximates LRU on a map of active sessions.
        const MAX_SESSIONS: usize = 100;
        let mut sessions = self.sessions.write().await;
        if sessions.len() >= MAX_SESSIONS {
            if let Some((oldest_id, _)) = sessions
                .iter()
                .min_by_key(|(_, &exp)| exp)
                .map(|(id, exp)| (id.clone(), *exp))
            {
                sessions.remove(&oldest_id);
                tracing::warn!(
                    "dashboard session map hit cap ({}) — evicted oldest session",
                    MAX_SESSIONS,
                );
            }
        }
        sessions.insert(session_id.clone(), expiry);

        Ok(session_id)
    }

    /// Check whether a session is still valid.
    pub async fn is_valid(&self, session_id: &str) -> bool {
        let mut sessions = self.sessions.write().await;
        if let Some(&expiry) = sessions.get(session_id) {
            if chrono::Utc::now().timestamp() < expiry {
                return true;
            }
            // Expired — remove it.
            sessions.remove(session_id);
        }
        false
    }

    /// Remove all expired sessions from the in-memory store.
    pub async fn cleanup_expired(&self) {
        let now = chrono::Utc::now().timestamp();
        let mut sessions = self.sessions.write().await;
        let before = sessions.len();
        sessions.retain(|_, &mut expiry| expiry > now);
        let removed = before - sessions.len();
        if removed > 0 {
            tracing::debug!("cleaned up {} expired sessions", removed);
        }
    }
}
