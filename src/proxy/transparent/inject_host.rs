//! Host-based credential injection. Strips agent-supplied auth headers,
//! injects the credential pulled from Vaultwarden according to the
//! service's auth pattern.
//!
//! Production credential resolution: mirrors what
//! `crate::proxy::apply_auth_and_send` does for the `/proxy` path —
//! `VaultManager::decrypt_password` for bearer/header/query_param and
//! `decrypt_field` for basic. Test-utils builds substitute a stub via
//! `VaultManager::test_item_password` so integration tests don't need a
//! live Vaultwarden.

use anyhow::{bail, Context, Result};
use base64::Engine;
use std::sync::Arc;

use crate::proxy::registry::{AuthPattern, ServiceEntry};
use crate::proxy::transparent::mitm::HttpRequest;
use crate::proxy::AppState;
use crate::vault::VaultManager;

const FORBIDDEN_HEADERS: &[&str] = &[
    "authorization",
    "x-api-key",
    "x-plex-token",
    "cookie",
    "proxy-authorization",
];

/// Inject vault credentials into the agent's request based on
/// `service.auth`. Strips any pre-existing auth headers first.
pub async fn inject(
    mut req: HttpRequest,
    service: &Arc<ServiceEntry>,
    vault: Arc<VaultManager>,
    vault_folder: &str,
    state: Arc<AppState>,
) -> Result<HttpRequest> {
    strip_forbidden_headers(&mut req.headers);

    match &service.auth {
        AuthPattern::Bearer { vault_item } => {
            let token = resolve_password(&vault, vault_folder, vault_item)
                .with_context(|| format!("resolve vault item '{vault_item}'"))?;
            req.headers
                .push(("Authorization".into(), format!("Bearer {token}")));
        }
        AuthPattern::Header {
            vault_item,
            header_name,
        } => {
            let value = resolve_password(&vault, vault_folder, vault_item)
                .with_context(|| format!("resolve vault item '{vault_item}'"))?;
            req.headers.push((header_name.clone(), value));
        }
        AuthPattern::Basic {
            vault_item,
            key_field,
            secret_field,
        } => {
            // Test-stub fast path: the test_passwords map is single-dim
            // (folder, item)->password. Basic-auth E2E tests seed the
            // pre-encoded `"user:pass"` pair as the password value, so
            // base64 it directly when the stub hits. Production goes
            // through the real two-field decrypt below.
            let encoded = if let Ok(pair) = vault.test_item_password(vault_folder, vault_item) {
                base64::engine::general_purpose::STANDARD.encode(pair)
            } else {
                let key = vault
                    .decrypt_field(vault_item, key_field)
                    .with_context(|| format!("resolve {vault_item}.{key_field}"))?;
                let secret = vault
                    .decrypt_field(vault_item, secret_field)
                    .with_context(|| format!("resolve {vault_item}.{secret_field}"))?;
                let key_s = std::str::from_utf8(&key)
                    .map_err(|e| anyhow::anyhow!("key field is not valid UTF-8: {e}"))?
                    .to_string();
                let secret_s = std::str::from_utf8(&secret)
                    .map_err(|e| anyhow::anyhow!("secret field is not valid UTF-8: {e}"))?
                    .to_string();
                drop(key);
                drop(secret);
                base64::engine::general_purpose::STANDARD.encode(format!("{key_s}:{secret_s}"))
            };
            req.headers
                .push(("Authorization".into(), format!("Basic {encoded}")));
        }
        AuthPattern::QueryParam {
            vault_item,
            param_name,
        } => {
            let value = resolve_password(&vault, vault_folder, vault_item)
                .with_context(|| format!("resolve vault item '{vault_item}'"))?;
            let sep = if req.path.contains('?') { '&' } else { '?' };
            req.path.push(sep);
            req.path.push_str(param_name);
            req.path.push('=');
            req.path.push_str(&urlencoding::encode(&value));
        }
        AuthPattern::OAuthClientCredentials {
            vault_item,
            token_url,
            client_id_field,
            client_secret_field,
            scope,
        } => {
            let token = crate::proxy::get_or_refresh_oauth_token(
                &state,
                vault_item,
                token_url,
                client_id_field,
                client_secret_field,
                scope,
                false,
            )
            .await
            .with_context(|| format!("oauth token for vault item '{vault_item}'"))?;
            req.headers
                .push(("Authorization".into(), format!("Bearer {token}")));
        }
        AuthPattern::OAuthRefresh {
            vault_item,
            token_url,
            client_id_field,
            client_secret_field,
            refresh_token_field,
            scope,
            writeback,
        } => {
            let token = crate::proxy::get_or_refresh_oauth_refresh_token(
                &state,
                vault_item,
                token_url,
                client_id_field,
                client_secret_field,
                refresh_token_field,
                scope,
                *writeback,
                false,
            )
            .await
            .with_context(|| format!("oauth refresh for vault item '{vault_item}'"))?;
            req.headers
                .push(("Authorization".into(), format!("Bearer {token}")));
        }
        other => {
            bail!(
                "transparent host_inject does not support auth pattern {:?}; service '{}'",
                other,
                service.name
            );
        }
    }
    Ok(req)
}

/// Resolve an item's password field. Production path uses
/// `VaultManager::decrypt_password`; under the test-utils build, the
/// seeded `test_passwords` map wins when an entry exists (so E2E tests
/// don't need a live Vaultwarden + decryption setup).
fn resolve_password(vault: &VaultManager, folder: &str, item: &str) -> Result<String> {
    if let Ok(test_value) = vault.test_item_password(folder, item) {
        return Ok(test_value);
    }
    let buf = vault.decrypt_password(item)?;
    let s = std::str::from_utf8(&buf)
        .map_err(|e| anyhow::anyhow!("credential is not valid UTF-8: {e}"))?
        .to_string();
    drop(buf);
    Ok(s)
}

fn strip_forbidden_headers(headers: &mut Vec<(String, String)>) {
    headers.retain(|(k, _)| !FORBIDDEN_HEADERS.iter().any(|f| k.eq_ignore_ascii_case(f)));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forbidden_headers_stripped() {
        let mut h = vec![
            ("Authorization".into(), "Bearer attacker".into()),
            ("X-Api-Key".into(), "leak".into()),
            ("Accept".into(), "*/*".into()),
            ("cookie".into(), "session=stale".into()),
        ];
        strip_forbidden_headers(&mut h);
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].0, "Accept");
    }
}
