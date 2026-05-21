//! Production adapter wiring `AppState` into the `RotateContext` trait used
//! by `rotate_wi_mcp`. Kept in its own file so `strategies.rs` stays free of
//! `AppState` references (which simplifies unit-testing the orchestrator).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context as _;
use async_trait::async_trait;
use zeroize::Zeroizing;

use crate::proxy::AppState;
use crate::rotate::strategies::RotateContext;

pub struct AppStateRotateContext {
    state: Arc<AppState>,
    config_dir: PathBuf,
}

impl AppStateRotateContext {
    pub fn new(state: Arc<AppState>, config_dir: PathBuf) -> Self {
        Self { state, config_dir }
    }
}

#[async_trait]
impl RotateContext for AppStateRotateContext {
    fn decrypt_username(&self, item: &str) -> anyhow::Result<Zeroizing<String>> {
        let buf = self
            .state
            .vault
            .decrypt_username(item)
            .with_context(|| format!("decrypt_username('{}')", item))?
            .ok_or_else(|| anyhow::anyhow!("item '{}' has no username", item))?;
        let s = std::str::from_utf8(buf.as_bytes())
            .context("username is not valid UTF-8")?
            .to_string();
        Ok(Zeroizing::new(s))
    }

    fn decrypt_password(&self, item: &str) -> anyhow::Result<Zeroizing<String>> {
        let buf = self
            .state
            .vault
            .decrypt_password(item)
            .with_context(|| format!("decrypt_password('{}')", item))?;
        let s = std::str::from_utf8(buf.as_bytes())
            .context("password is not valid UTF-8")?
            .to_string();
        Ok(Zeroizing::new(s))
    }

    async fn update_password(&self, item: &str, new_password: &str) -> anyhow::Result<()> {
        self.state
            .vault
            .update_password_for_item(item, new_password)
            .await
            .with_context(|| format!("update_password_for_item('{}')", item))
    }

    fn config_dir(&self) -> &Path {
        &self.config_dir
    }
}
