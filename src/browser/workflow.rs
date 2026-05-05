//! Password rotation workflow engine — drives the browser agent through
//! login → password-change → vault-update as a state machine.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use chrono::Utc;
use tokio::sync::RwLock;
use tokio::time::{Duration, timeout};

use crate::browser::playwright::PlaywrightProcess;
use crate::browser::profiles::{SiteProfile, match_profile};
use crate::browser::vision::{VisionAction, VisionModel};
use crate::proxy::ApprovalRequest;
use crate::secure::{SecureBuffer, secure_random};
use crate::vault::VaultManager;

// -------------------------------------------------------------------------- //
// State types                                                                 //
// -------------------------------------------------------------------------- //

#[derive(Debug, Clone, serde::Serialize)]
pub enum WorkflowStep {
    NavigateToLogin,
    IdentifyLoginForm,
    FillUsername,
    FillPassword,
    ClickLogin,
    Check2FA,
    Handle2FA,
    NavigateToPasswordChange,
    IdentifyPasswordForm,
    FillCurrentPassword,
    GenerateNewPassword,
    FillNewPassword,
    FillConfirmPassword,
    ClickSave,
    VerifySuccess,
    UpdateVault,
    Done,
    Failed,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct WorkflowState {
    pub item_name: String,
    pub current_step: WorkflowStep,
    pub step_attempts: u32,
    pub started_at: String,
    pub last_screenshot_b64: Option<String>,
    pub action_log: Vec<String>,
    pub error: Option<String>,
}

// -------------------------------------------------------------------------- //
// Password generation helper                                                  //
// -------------------------------------------------------------------------- //

/// Generate a random password of `len` printable ASCII characters.
///
/// Uses `secure_random` as the entropy source and maps each byte into a
/// 72-character alphabet (upper, lower, digits, symbols).
fn generate_password(len: usize) -> SecureBuffer {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*-_";
    let raw = secure_random(len);
    let mut password = Vec::with_capacity(len);
    for &b in raw.as_bytes() {
        password.push(CHARSET[b as usize % CHARSET.len()]);
    }
    SecureBuffer::new(password)
}

// -------------------------------------------------------------------------- //
// RotationWorkflow                                                            //
// -------------------------------------------------------------------------- //

pub struct RotationWorkflow {
    pub state: WorkflowState,
    playwright: PlaywrightProcess,
    vision: VisionModel,
    profiles: HashMap<String, SiteProfile>,
    login_url: String,
    new_password: Option<SecureBuffer>,
}

impl RotationWorkflow {
    /// Create a new rotation workflow for the given vault item.
    pub async fn new(
        item_name: &str,
        login_url: &str,
        playwright: PlaywrightProcess,
        vision: VisionModel,
    ) -> Self {
        // Load from the canonical /config path — iter-17 aligned this with
        // the dashboard write path (`/config/site-profiles.json`). The
        // previous relative path ("site_profiles.json") never loaded any
        // profiles saved via the dashboard and depended on the process's
        // working directory, which is fragile across deployment modes.
        let profiles = crate::browser::profiles::load_profiles("/config/site-profiles.json");

        Self {
            state: WorkflowState {
                item_name: item_name.to_string(),
                current_step: WorkflowStep::NavigateToLogin,
                step_attempts: 0,
                started_at: Utc::now().to_rfc3339(),
                last_screenshot_b64: None,
                action_log: Vec::new(),
                error: None,
            },
            playwright,
            vision,
            profiles,
            login_url: login_url.to_string(),
            new_password: None,
        }
    }

    /// Run the full rotation workflow. Returns `true` on success.
    pub async fn run(
        &mut self,
        vault: &VaultManager,
        approval_queue: &Arc<RwLock<VecDeque<ApprovalRequest>>>,
    ) -> bool {
        self.log("workflow started");

        let total_timeout = Duration::from_secs(5 * 60);
        let result = timeout(total_timeout, self.run_inner(vault, approval_queue)).await;

        match result {
            Ok(true) => true,
            Ok(false) => false,
            Err(_) => {
                self.state.error = Some("workflow exceeded 5 minute timeout".to_string());
                self.state.current_step = WorkflowStep::Failed;
                self.log("workflow timed out after 5 minutes");
                false
            }
        }
    }

    async fn run_inner(
        &mut self,
        vault: &VaultManager,
        approval_queue: &Arc<RwLock<VecDeque<ApprovalRequest>>>,
    ) -> bool {
        let step_timeout = Duration::from_secs(30);
        let max_step_attempts: u32 = 3;

        loop {
            match self.state.current_step {
                WorkflowStep::Done => {
                    self.log("workflow completed successfully");
                    return true;
                }
                WorkflowStep::Failed => {
                    self.log("workflow failed");
                    return false;
                }
                _ => {}
            }

            let result = timeout(step_timeout, self.execute_step(vault, approval_queue)).await;

            match result {
                Ok(Ok(next_step)) => {
                    let changed = std::mem::discriminant(&self.state.current_step)
                        != std::mem::discriminant(&next_step);
                    if changed {
                        self.state.step_attempts = 0;
                    }
                    self.state.current_step = next_step;
                }
                Ok(Err(e)) => {
                    self.state.step_attempts += 1;
                    let step_name = format!("{:?}", self.state.current_step);
                    self.log(&format!(
                        "step {} failed (attempt {}): {}",
                        step_name, self.state.step_attempts, e
                    ));

                    if self.state.step_attempts >= max_step_attempts {
                        self.state.error =
                            Some(format!("step {} failed after {} attempts: {}", step_name, max_step_attempts, e));
                        self.state.current_step = WorkflowStep::Failed;
                    }
                }
                Err(_) => {
                    self.state.step_attempts += 1;
                    let step_name = format!("{:?}", self.state.current_step);
                    self.log(&format!(
                        "step {} timed out (attempt {})",
                        step_name, self.state.step_attempts
                    ));

                    if self.state.step_attempts >= max_step_attempts {
                        self.state.error =
                            Some(format!("step {} timed out after {} attempts", step_name, max_step_attempts));
                        self.state.current_step = WorkflowStep::Failed;
                    }
                }
            }
        }
    }

    /// Execute the current step and return the next step to transition to.
    async fn execute_step(
        &mut self,
        vault: &VaultManager,
        approval_queue: &Arc<RwLock<VecDeque<ApprovalRequest>>>,
    ) -> Result<WorkflowStep> {
        match self.state.current_step {
            WorkflowStep::NavigateToLogin => self.step_navigate_to_login().await,
            WorkflowStep::IdentifyLoginForm => self.step_identify_login_form().await,
            WorkflowStep::FillUsername => self.step_fill_username(vault).await,
            WorkflowStep::FillPassword => self.step_fill_password(vault).await,
            WorkflowStep::ClickLogin => self.step_click_login().await,
            WorkflowStep::Check2FA => self.step_check_2fa().await,
            WorkflowStep::Handle2FA => self.step_handle_2fa(vault, approval_queue).await,
            WorkflowStep::NavigateToPasswordChange => self.step_navigate_to_password_change().await,
            WorkflowStep::IdentifyPasswordForm => self.step_identify_password_form().await,
            WorkflowStep::FillCurrentPassword => self.step_fill_current_password(vault).await,
            WorkflowStep::GenerateNewPassword => self.step_generate_new_password(),
            WorkflowStep::FillNewPassword => self.step_fill_new_password().await,
            WorkflowStep::FillConfirmPassword => self.step_fill_confirm_password().await,
            WorkflowStep::ClickSave => self.step_click_save().await,
            WorkflowStep::VerifySuccess => self.step_verify_success().await,
            WorkflowStep::UpdateVault => self.step_update_vault(vault).await,
            WorkflowStep::Done => {
                self.log("done");
                Ok(WorkflowStep::Done)
            }
            WorkflowStep::Failed => {
                self.log("failed");
                Ok(WorkflowStep::Failed)
            }
        }
    }

    // ---------------------------------------------------------------------- //
    // Step implementations                                                     //
    // ---------------------------------------------------------------------- //

    async fn step_navigate_to_login(&mut self) -> Result<WorkflowStep> {
        let url = match match_profile(&self.profiles, &self.login_url) {
            Some(profile) => profile.login_url.clone().unwrap_or_else(|| self.login_url.clone()),
            None => self.login_url.clone(),
        };

        // Profile-override URLs can differ from the `browser_rotate` entry
        // URL that iter-15's SSRF guard validated. Re-check here so a
        // profile file (writable via `POST /api/profiles` — dashboard-auth'd,
        // but still user-controlled) can't aim the browser at a cloud
        // metadata host or link-local range.
        if !crate::vault::handlers::is_allowed_outbound_url(&url) {
            anyhow::bail!("profile login_url '{}' failed SSRF policy", url);
        }

        self.log(&format!("navigating to {}", url));
        self.playwright
            .navigate(&url)
            .await
            .context("failed to navigate to login URL")?;

        Ok(WorkflowStep::IdentifyLoginForm)
    }

    async fn step_identify_login_form(&mut self) -> Result<WorkflowStep> {
        // If a profile has selectors, skip vision analysis.
        if let Some(profile) = match_profile(&self.profiles, &self.login_url) {
            if profile.login_username_selector.is_some() && profile.login_password_selector.is_some()
            {
                self.log("using profile selectors for login form");
                return Ok(WorkflowStep::FillUsername);
            }
        }

        let screenshot = self.take_screenshot().await?;
        let action = self
            .vision
            .analyze(&screenshot, "login to the site", "identify the login form")
            .await
            .context("vision analysis failed")?;

        self.log(&format!("vision identified: {:?}", action));
        Ok(WorkflowStep::FillUsername)
    }

    async fn step_fill_username(&mut self, vault: &VaultManager) -> Result<WorkflowStep> {
        let username_buf = vault
            .decrypt_username(&self.state.item_name)
            .context("failed to decrypt username")?
            .ok_or_else(|| anyhow::anyhow!("vault item has no username"))?;

        let selector = self.get_login_username_selector().await?;
        self.log(&format!("filling username in {}", selector));
        self.fill_credential(&selector, &username_buf).await?;

        Ok(WorkflowStep::FillPassword)
    }

    async fn step_fill_password(&mut self, vault: &VaultManager) -> Result<WorkflowStep> {
        let password_buf = vault
            .decrypt_password(&self.state.item_name)
            .context("failed to decrypt password")?;

        let selector = self.get_login_password_selector().await?;
        self.log(&format!("filling password in {}", selector));
        self.fill_credential(&selector, &password_buf).await?;

        Ok(WorkflowStep::ClickLogin)
    }

    async fn step_click_login(&mut self) -> Result<WorkflowStep> {
        let selector = self.get_login_submit_selector().await?;
        self.log(&format!("clicking login button: {}", selector));
        self.playwright
            .click(&selector)
            .await
            .context("failed to click login button")?;

        // Brief wait for page to process login.
        tokio::time::sleep(Duration::from_secs(2)).await;

        Ok(WorkflowStep::Check2FA)
    }

    async fn step_check_2fa(&mut self) -> Result<WorkflowStep> {
        let screenshot = self.take_screenshot().await?;
        let action = self
            .vision
            .analyze(
                &screenshot,
                "check if 2FA is required after login",
                "look for 2FA prompt or successful login",
            )
            .await
            .context("vision analysis failed")?;

        match action {
            VisionAction::Need2FA { r#type, reason } => {
                self.log(&format!(
                    "2FA required — type: {}, reason: {}",
                    r#type,
                    reason.as_deref().unwrap_or("none")
                ));
                Ok(WorkflowStep::Handle2FA)
            }
            _ => {
                self.log("no 2FA required, proceeding to password change");
                Ok(WorkflowStep::NavigateToPasswordChange)
            }
        }
    }

    async fn step_handle_2fa(
        &mut self,
        vault: &VaultManager,
        approval_queue: &Arc<RwLock<VecDeque<ApprovalRequest>>>,
    ) -> Result<WorkflowStep> {
        // Try TOTP auto-generation from vault seed before falling back to manual approval.
        match vault.decrypt_totp(&self.state.item_name) {
            Ok(Some(seed_buf)) => {
                let seed = seed_buf
                    .as_str()
                    .map_err(|e| anyhow::anyhow!("TOTP seed is not valid UTF-8: {}", e))?
                    .to_string();
                drop(seed_buf);

                match crate::totp::generate_code(&seed) {
                    Ok(code) => {
                        self.log(&format!("auto-generated TOTP code ({} digits)", code.len()));

                        // Find the 2FA input field and fill it.
                        let screenshot = self.take_screenshot().await?;
                        let action = self
                            .vision
                            .analyze(&screenshot, "enter 2FA code", "find the 2FA input field")
                            .await?;

                        if let VisionAction::Fill { selector, .. } = action {
                            let code_buf = SecureBuffer::new(code.into_bytes());
                            self.fill_credential(&selector, &code_buf).await?;

                            // Find and click submit.
                            let screenshot = self.take_screenshot().await?;
                            let action = self
                                .vision
                                .analyze(&screenshot, "submit 2FA code", "find the submit button")
                                .await?;
                            if let VisionAction::Click { selector, .. } = action {
                                self.playwright.click(&selector).await?;
                            }

                            tokio::time::sleep(Duration::from_secs(2)).await;
                            return Ok(WorkflowStep::NavigateToPasswordChange);
                        } else {
                            self.log("could not find 2FA input field for auto-fill, falling back to manual approval");
                        }
                    }
                    Err(e) => {
                        self.log(&format!("TOTP auto-generation failed: {}, falling back to manual approval", e));
                    }
                }
            }
            Ok(None) => {
                self.log("no TOTP seed in vault for this item, requesting manual approval");
            }
            Err(e) => {
                self.log(&format!("failed to decrypt TOTP seed: {}, requesting manual approval", e));
            }
        }

        // For SMS/push or when TOTP auto-fill failed, queue an approval request.
        let screenshot = self.take_screenshot().await?;
        let request_id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();
        let expires = now + chrono::TimeDelta::minutes(5);

        let request = ApprovalRequest {
            id: request_id.clone(),
            screenshot_b64: Some(screenshot),
            prompt: format!(
                "2FA code needed for password rotation of '{}'",
                self.state.item_name
            ),
            created_at: now.to_rfc3339(),
            expires_at: expires.to_rfc3339(),
            status: "pending".to_string(),
            response: None,
        };

        {
            let mut queue = approval_queue.write().await;
            queue.push_back(request);
        }

        self.log(&format!(
            "2FA approval request queued (id: {}), polling for response",
            request_id
        ));

        // Poll for approval response.
        let poll_timeout = Duration::from_secs(4 * 60);
        let poll_result = timeout(poll_timeout, async {
            loop {
                tokio::time::sleep(Duration::from_secs(3)).await;
                let queue = approval_queue.read().await;
                if let Some(req) = queue.iter().find(|r| r.id == request_id) {
                    match req.status.as_str() {
                        "approved" => return Ok(req.response.clone()),
                        "denied" => return Err(anyhow::anyhow!("2FA approval denied")),
                        _ => continue,
                    }
                } else {
                    return Err(anyhow::anyhow!("2FA approval request not found in queue"));
                }
            }
        })
        .await;

        match poll_result {
            Ok(Ok(response)) => {
                if let Some(code) = response {
                    self.log(&format!("2FA code received, entering code"));
                    // Try to find 2FA input and fill it.
                    let screenshot = self.take_screenshot().await?;
                    let action = self
                        .vision
                        .analyze(&screenshot, "enter 2FA code", "find the 2FA input field")
                        .await?;

                    if let VisionAction::Fill { selector, .. } = action {
                        let code_buf = SecureBuffer::new(code.into_bytes());
                        self.fill_credential(&selector, &code_buf).await?;
                        // Look for submit button.
                        let screenshot = self.take_screenshot().await?;
                        let action = self
                            .vision
                            .analyze(&screenshot, "submit 2FA code", "find the submit button")
                            .await?;
                        if let VisionAction::Click { selector, .. } = action {
                            self.playwright.click(&selector).await?;
                        }
                    }
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
                Ok(WorkflowStep::NavigateToPasswordChange)
            }
            Ok(Err(e)) => Err(e),
            Err(_) => bail!("2FA approval timed out after 4 minutes"),
        }
    }

    async fn step_navigate_to_password_change(&mut self) -> Result<WorkflowStep> {
        // Check profile for a direct password change URL.
        let pw_change_url = match_profile(&self.profiles, &self.login_url)
            .and_then(|p| p.password_change_url.clone());
        if let Some(url) = pw_change_url {
            self.log(&format!("navigating to password change URL: {}", url));
            self.playwright.navigate(&url).await?;
            return Ok(WorkflowStep::IdentifyPasswordForm);
        }

        // Use vision to navigate to password change page.
        let screenshot = self.take_screenshot().await?;
        let action = self
            .vision
            .analyze(
                &screenshot,
                "navigate to password change page",
                "find link or button to change password, such as settings or account",
            )
            .await?;

        match action {
            VisionAction::Click { selector, reason } => {
                self.log(&format!(
                    "clicking to navigate to password change: {} ({})",
                    selector,
                    reason.as_deref().unwrap_or("no reason")
                ));
                self.playwright.click(&selector).await?;
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            _ => {
                self.log(&format!("vision returned {:?}, retrying", action));
                bail!("could not find navigation to password change page");
            }
        }

        Ok(WorkflowStep::IdentifyPasswordForm)
    }

    async fn step_identify_password_form(&mut self) -> Result<WorkflowStep> {
        if let Some(profile) = match_profile(&self.profiles, &self.login_url) {
            if profile.password_current_selector.is_some()
                && profile.password_new_selector.is_some()
            {
                self.log("using profile selectors for password form");
                return Ok(WorkflowStep::FillCurrentPassword);
            }
        }

        let screenshot = self.take_screenshot().await?;
        let action = self
            .vision
            .analyze(
                &screenshot,
                "change the account password",
                "identify the password change form fields",
            )
            .await?;

        self.log(&format!("vision identified password form: {:?}", action));
        Ok(WorkflowStep::FillCurrentPassword)
    }

    async fn step_fill_current_password(&mut self, vault: &VaultManager) -> Result<WorkflowStep> {
        let password_buf = vault
            .decrypt_password(&self.state.item_name)
            .context("failed to decrypt current password")?;

        let selector = self.get_password_current_selector().await?;
        self.log(&format!("filling current password in {}", selector));
        self.fill_credential(&selector, &password_buf).await?;

        Ok(WorkflowStep::GenerateNewPassword)
    }

    fn step_generate_new_password(&mut self) -> Result<WorkflowStep> {
        let new_pw = generate_password(24);
        self.log("generated new 24-character password");
        self.new_password = Some(new_pw);
        Ok(WorkflowStep::FillNewPassword)
    }

    async fn step_fill_new_password(&mut self) -> Result<WorkflowStep> {
        let pw_str = self
            .new_password
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("new password not generated"))?
            .as_str()
            .map_err(|e| anyhow::anyhow!("new password is not valid UTF-8: {}", e))?
            .to_string();

        let selector = self.get_password_new_selector().await?;
        self.log(&format!("filling new password in {}", selector));

        let pw_buf = SecureBuffer::new(pw_str.into_bytes());
        self.fill_credential(&selector, &pw_buf).await?;

        Ok(WorkflowStep::FillConfirmPassword)
    }

    async fn step_fill_confirm_password(&mut self) -> Result<WorkflowStep> {
        let pw_str = self
            .new_password
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("new password not generated"))?
            .as_str()
            .map_err(|e| anyhow::anyhow!("new password is not valid UTF-8: {}", e))?
            .to_string();

        let selector = self.get_password_confirm_selector().await?;
        self.log(&format!("filling confirm password in {}", selector));

        let pw_buf = SecureBuffer::new(pw_str.into_bytes());
        self.fill_credential(&selector, &pw_buf).await?;

        Ok(WorkflowStep::ClickSave)
    }

    async fn step_click_save(&mut self) -> Result<WorkflowStep> {
        let selector = self.get_password_submit_selector().await?;
        self.log(&format!("clicking save button: {}", selector));
        self.playwright
            .click(&selector)
            .await
            .context("failed to click save button")?;

        tokio::time::sleep(Duration::from_secs(2)).await;
        Ok(WorkflowStep::VerifySuccess)
    }

    async fn step_verify_success(&mut self) -> Result<WorkflowStep> {
        let screenshot = self.take_screenshot().await?;
        let action = self
            .vision
            .analyze(
                &screenshot,
                "verify password was changed",
                "check for success confirmation or error message",
            )
            .await
            .context("vision verification failed")?;

        match action {
            VisionAction::Done { success: true, reason } => {
                self.log(&format!(
                    "password change verified: {}",
                    reason.as_deref().unwrap_or("success")
                ));
                Ok(WorkflowStep::UpdateVault)
            }
            VisionAction::Done { success: false, reason } => {
                self.log(&format!(
                    "password change failed: {}",
                    reason.as_deref().unwrap_or("unknown")
                ));
                Ok(WorkflowStep::Failed)
            }
            other => {
                self.log(&format!("unexpected vision response during verification: {:?}", other));
                bail!("could not verify password change result");
            }
        }
    }

    async fn step_update_vault(&mut self, vault: &VaultManager) -> Result<WorkflowStep> {
        // Persist the newly-generated password to Vaultwarden. The target
        // site already has the new credential; without this write the vault
        // would still hold the old one and the next use would lock out.
        // iter-12 landed the real implementation (was a safe `bail!` stub
        // in iter-9 after an earlier silent-success bug was caught).
        let new_pw = self
            .new_password
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("new password missing from workflow state"))?;
        let pw_plaintext = new_pw
            .as_str()
            .map_err(|e| anyhow::anyhow!("new password not valid UTF-8: {}", e))?
            .to_string();

        vault
            .update_password_for_item(&self.state.item_name, &pw_plaintext)
            .await
            .map_err(|e| anyhow::anyhow!("vault update for '{}' failed: {}", self.state.item_name, e))?;

        // Refresh the in-memory cipher map so subsequent decrypt_password
        // calls see the new value. Sync failure is logged but not fatal —
        // the remote write already succeeded and the next scheduled sync
        // will pick it up.
        if let Err(e) = vault.sync().await {
            self.log(&format!(
                "warning: post-update vault sync failed (upstream write ok): {}",
                e
            ));
        }

        self.new_password = None;
        self.log("vault updated successfully with new password");
        Ok(WorkflowStep::Done)
    }

    // ---------------------------------------------------------------------- //
    // Helpers                                                                  //
    // ---------------------------------------------------------------------- //

    /// Fill a form field with a credential value. Falls back to key-by-key
    /// typing if Playwright's `fill` command fails.
    async fn fill_credential(&mut self, selector: &str, credential: &SecureBuffer) -> Result<()> {
        let value = credential
            .as_str()
            .map_err(|e| anyhow::anyhow!("credential is not valid UTF-8: {}", e))?;

        match self.playwright.fill(selector, value).await {
            Ok(()) => Ok(()),
            Err(fill_err) => {
                self.log(&format!(
                    "fill failed ({}), falling back to type_keys",
                    fill_err
                ));
                let chars: Vec<String> = value.chars().map(|c| c.to_string()).collect();
                self.playwright
                    .type_keys(selector, &chars)
                    .await
                    .context("type_keys fallback also failed")?;
                Ok(())
            }
        }
    }

    /// Take a screenshot and store it in state.
    async fn take_screenshot(&mut self) -> Result<String> {
        let b64 = self
            .playwright
            .screenshot()
            .await
            .context("failed to take screenshot")?;
        self.state.last_screenshot_b64 = Some(b64.clone());
        Ok(b64)
    }

    /// Add a timestamped message to the action log.
    fn log(&mut self, msg: &str) {
        let entry = format!("[{}] {}", Utc::now().format("%H:%M:%S"), msg);
        tracing::info!(item = %self.state.item_name, "{}", entry);
        self.state.action_log.push(entry);
    }

    // ---------------------------------------------------------------------- //
    // Selector resolution — profile first, then vision fallback               //
    // ---------------------------------------------------------------------- //

    async fn get_login_username_selector(&mut self) -> Result<String> {
        if let Some(profile) = match_profile(&self.profiles, &self.login_url) {
            if let Some(sel) = &profile.login_username_selector {
                return Ok(sel.clone());
            }
        }
        self.resolve_selector_via_vision("login to the site", "find the username input field")
            .await
    }

    async fn get_login_password_selector(&mut self) -> Result<String> {
        if let Some(profile) = match_profile(&self.profiles, &self.login_url) {
            if let Some(sel) = &profile.login_password_selector {
                return Ok(sel.clone());
            }
        }
        self.resolve_selector_via_vision("login to the site", "find the password input field")
            .await
    }

    async fn get_login_submit_selector(&mut self) -> Result<String> {
        if let Some(profile) = match_profile(&self.profiles, &self.login_url) {
            if let Some(sel) = &profile.login_submit_selector {
                return Ok(sel.clone());
            }
        }
        self.resolve_selector_via_vision("login to the site", "find the login submit button")
            .await
    }

    async fn get_password_current_selector(&mut self) -> Result<String> {
        if let Some(profile) = match_profile(&self.profiles, &self.login_url) {
            if let Some(sel) = &profile.password_current_selector {
                return Ok(sel.clone());
            }
        }
        self.resolve_selector_via_vision(
            "change the account password",
            "find the current password input field",
        )
        .await
    }

    async fn get_password_new_selector(&mut self) -> Result<String> {
        if let Some(profile) = match_profile(&self.profiles, &self.login_url) {
            if let Some(sel) = &profile.password_new_selector {
                return Ok(sel.clone());
            }
        }
        self.resolve_selector_via_vision(
            "change the account password",
            "find the new password input field",
        )
        .await
    }

    async fn get_password_confirm_selector(&mut self) -> Result<String> {
        if let Some(profile) = match_profile(&self.profiles, &self.login_url) {
            if let Some(sel) = &profile.password_confirm_selector {
                return Ok(sel.clone());
            }
        }
        self.resolve_selector_via_vision(
            "change the account password",
            "find the confirm password input field",
        )
        .await
    }

    async fn get_password_submit_selector(&mut self) -> Result<String> {
        if let Some(profile) = match_profile(&self.profiles, &self.login_url) {
            if let Some(sel) = &profile.password_submit_selector {
                return Ok(sel.clone());
            }
        }
        self.resolve_selector_via_vision(
            "change the account password",
            "find the save/submit button",
        )
        .await
    }

    /// Use vision to identify a CSS selector for an element.
    async fn resolve_selector_via_vision(
        &mut self,
        task: &str,
        step: &str,
    ) -> Result<String> {
        let screenshot = self.take_screenshot().await?;
        let action = self.vision.analyze(&screenshot, task, step).await?;

        match action {
            VisionAction::Fill { selector, .. } => Ok(selector),
            VisionAction::Click { selector, .. } => Ok(selector),
            other => bail!("vision could not identify element for '{}': {:?}", step, other),
        }
    }
}
