//! Holds the current bearer token in memory and re-fetches it from the
//! vault-proxy local socket on a configurable interval (default 5 min)
//! or on demand when the upstream returns 401. Token is wrapped in
//! `secrecy::SecretString` and exposed only at the point of header
//! serialization in `http_client.rs`.

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

pub struct HeaderInjector {
    socket: PathBuf,
    vault_item: String,
    field: String,
    refresh_interval: Duration,
    state: Arc<RwLock<State>>,
}

struct State {
    token: SecretString,
    fetched_at: Instant,
}

impl HeaderInjector {
    /// Construct an injector with an initial token fetch. Returns an
    /// error if the first fetch fails — callers should treat that as a
    /// hard startup failure rather than try to operate with no token.
    pub async fn new(
        socket: PathBuf,
        vault_item: String,
        field: String,
        refresh_interval: Duration,
    ) -> Result<Self> {
        let token = fetch(&socket, &vault_item, &field)
            .await
            .with_context(|| format!("initial token fetch for {vault_item}/{field}"))?;
        Ok(Self {
            socket,
            vault_item,
            field,
            refresh_interval,
            state: Arc::new(RwLock::new(State {
                token,
                fetched_at: Instant::now(),
            })),
        })
    }

    /// Return the current bearer token. If the TTL has expired, attempt
    /// a refresh first; a refresh failure does NOT clear the cached
    /// token (we prefer a stale token to an unauthenticated request).
    pub async fn current_token(&self) -> SecretString {
        {
            let s = self.state.read().await;
            if s.fetched_at.elapsed() < self.refresh_interval {
                return SecretString::from(s.token.expose_secret().to_string());
            }
        }
        let mut s = self.state.write().await;
        // Re-check under write lock — another task may have refreshed.
        if s.fetched_at.elapsed() >= self.refresh_interval {
            match fetch(&self.socket, &self.vault_item, &self.field).await {
                Ok(t) => {
                    s.token = t;
                    s.fetched_at = Instant::now();
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        item = %self.vault_item,
                        field = %self.field,
                        "token refresh failed, keeping stale token",
                    );
                }
            }
        }
        SecretString::from(s.token.expose_secret().to_string())
    }

    /// Forcibly re-fetch the token. Called by http_client on HTTP 401.
    /// Unlike `current_token`'s TTL-driven path, this DOES return an
    /// error on fetch failure — the caller can then surface a meaningful
    /// JSON-RPC error to the local MCP client.
    pub async fn force_refresh(&self) -> Result<()> {
        let new_token = fetch(&self.socket, &self.vault_item, &self.field)
            .await
            .context("force token refresh")?;
        let mut s = self.state.write().await;
        s.token = new_token;
        s.fetched_at = Instant::now();
        Ok(())
    }
}

async fn fetch(socket: &PathBuf, item: &str, field: &str) -> Result<SecretString> {
    let v = crate::local_socket::client::get_field(socket, item, field)
        .await
        .with_context(|| format!("fetch {item}/{field} from {}", socket.display()))?;
    Ok(SecretString::from(v))
}
