//! Rotation strategy implementations for each supported service.

use anyhow::Context as _;
use serde::Serialize;

// -------------------------------------------------------------------------- //
// Result type                                                                  //
// -------------------------------------------------------------------------- //

/// Outcome of a single rotation attempt.
#[derive(Debug, Serialize)]
pub struct RotationResult {
    pub service: String,
    pub status: String,
    pub message: String,
}

use zeroize::Zeroizing;

/// Abstracts the channel used to mint a fresh bearer token for a backing
/// service. Production impl is `SshDockerMintExecutor`; tests substitute a
/// fake.
#[async_trait::async_trait]
pub trait MintExecutor: Send + Sync {
    /// Mint a new bearer token using `username`/`password` as the dashboard
    /// auth credentials. Implementations MUST NOT log `password` or include
    /// it in returned errors.
    async fn mint(
        &self,
        username: &str,
        password: &str,
    ) -> anyhow::Result<Zeroizing<String>>;
}

// -------------------------------------------------------------------------- //
// Strategies                                                                   //
// -------------------------------------------------------------------------- //

/// Sonarr rotation is not API-based — it requires direct config file access.
pub async fn rotate_sonarr() -> RotationResult {
    RotationResult {
        service: "sonarr".to_string(),
        status: "unsupported".to_string(),
        message: "Sonarr API key rotation requires config file access and is not supported via the API strategy.".to_string(),
    }
}

/// Radarr rotation is not API-based — it requires direct config file access.
pub async fn rotate_radarr() -> RotationResult {
    RotationResult {
        service: "radarr".to_string(),
        status: "unsupported".to_string(),
        message: "Radarr API key rotation requires config file access and is not supported via the API strategy.".to_string(),
    }
}

/// Bootstrap a UniFi OS API key from local admin credentials.
///
/// Authenticates to the UniFi OS REST API using username+password, generates
/// an API key, logs out, and returns the key. No retries on auth failure —
/// each retry extends the account lockout window.
///
/// # Arguments
/// * `uri` — UniFi OS base URL, e.g. `https://unifi.splendidus.live`
/// * `username` — local admin username (NOT an SSO account)
/// * `password` — local admin password
/// * `verify_ssl` — set false to skip TLS verification (self-signed certs)
pub async fn bootstrap_unifi_api_key(
    uri: &str,
    username: &str,
    password: &str,
    verify_ssl: bool,
) -> anyhow::Result<zeroize::Zeroizing<String>> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(!verify_ssl)
        .cookie_store(true)
        .build()
        .context("build reqwest client for UniFi bootstrap")?;

    // Step 1: Authenticate — obtain session cookie.
    // X-Csrf-Token must be present (any non-empty value); UniFi OS rejects
    // the request with 403 if the header is absent entirely.
    let login_resp = client
        .post(format!("{}/api/auth/login", uri))
        .header("X-Csrf-Token", "bootstrap")
        .json(&serde_json::json!({
            "username": username,
            "password": password
        }))
        .send()
        .await
        .context("UniFi login request failed")?;

    if !login_resp.status().is_success() {
        let status = login_resp.status();
        anyhow::bail!(
            "bootstrap: UniFi login failed ({}) — check local admin credentials in auth_item",
            status
        );
    }

    // Step 2: Generate API key. Logout runs regardless of outcome.
    let key_result: anyhow::Result<zeroize::Zeroizing<String>> = async {
        let key_resp = client
            .post(format!("{}/api/users/self/api-key", uri))
            .json(&serde_json::json!({}))
            .send()
            .await
            .context("UniFi API key generation request failed")?;

        if !key_resp.status().is_success() {
            let status = key_resp.status();
            anyhow::bail!("bootstrap: UniFi API key generation failed ({})", status);
        }

        let body: serde_json::Value = key_resp
            .json()
            .await
            .context("parse UniFi API key response")?;

        let api_key = body["data"]["apiKey"]
            .as_str()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "bootstrap: 'apiKey' not found in UniFi response: {}",
                    body
                )
            })?
            .to_string();

        Ok(zeroize::Zeroizing::new(api_key))
    }
    .await;

    // Step 3: Logout — always, even if step 2 failed.
    let _ = client
        .delete(format!("{}/api/auth/logout", uri))
        .send()
        .await;

    key_result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bootstrap_unifi_api_key_exists() {
        // Compile-time check: verify the function exists with the correct
        // parameter types and return type. The if-false guard means the future
        // is never polled and no network call is made.
        if false {
            let _ = bootstrap_unifi_api_key("uri", "user", "pass", false);
        }
    }

    use std::sync::Arc;
    use zeroize::Zeroizing;

    struct FakeMintExecutor {
        result: Result<String, String>,
        last_call: tokio::sync::Mutex<Option<(String, String)>>,
    }

    #[async_trait::async_trait]
    impl MintExecutor for FakeMintExecutor {
        async fn mint(
            &self,
            username: &str,
            password: &str,
        ) -> anyhow::Result<Zeroizing<String>> {
            *self.last_call.lock().await = Some((username.to_string(), password.to_string()));
            match &self.result {
                Ok(tok) => Ok(Zeroizing::new(tok.clone())),
                Err(msg) => Err(anyhow::anyhow!("{}", msg)),
            }
        }
    }

    #[tokio::test]
    async fn fake_mint_executor_returns_configured_token() {
        let fake = FakeMintExecutor {
            result: Ok("tok_abc".to_string()),
            last_call: tokio::sync::Mutex::new(None),
        };
        let exec: Arc<dyn MintExecutor> = Arc::new(fake);
        let out = exec.mint("user1", "pw1").await.unwrap();
        assert_eq!(&*out, "tok_abc");
    }
}
