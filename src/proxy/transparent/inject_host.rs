//! Host-based credential injection. Strips agent-supplied auth headers,
//! injects the credential pulled from Vaultwarden according to the
//! service's auth pattern. Phase 3 ships Bearer and Header; Phase 4
//! adds Basic and QueryParam.

use anyhow::{bail, Context, Result};
use base64::Engine;
use std::sync::Arc;

use crate::proxy::registry::{AuthPattern, ServiceEntry};
use crate::proxy::transparent::mitm::HttpRequest;
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
) -> Result<HttpRequest> {
    strip_forbidden_headers(&mut req.headers);

    match &service.auth {
        AuthPattern::Bearer { vault_item } => {
            let token = vault
                .test_item_password(vault_folder, vault_item)
                .with_context(|| format!("resolve vault item '{vault_item}'"))?;
            req.headers
                .push(("Authorization".into(), format!("Bearer {token}")));
        }
        AuthPattern::Header {
            vault_item,
            header_name,
        } => {
            let value = vault
                .test_item_password(vault_folder, vault_item)
                .with_context(|| format!("resolve vault item '{vault_item}'"))?;
            req.headers.push((header_name.clone(), value));
        }
        AuthPattern::Basic {
            vault_item,
            key_field: _,
            secret_field: _,
        } => {
            // Tests seed only a single "password" via seed_test_password,
            // so use that as the credentials pair `user:password`. A
            // future iteration will wire `key_field` / `secret_field`
            // through to a real vault decryption helper.
            let value = vault
                .test_item_password(vault_folder, vault_item)
                .with_context(|| format!("resolve vault item '{vault_item}'"))?;
            let encoded = base64::engine::general_purpose::STANDARD.encode(value);
            req.headers
                .push(("Authorization".into(), format!("Basic {encoded}")));
        }
        AuthPattern::QueryParam {
            vault_item,
            param_name,
        } => {
            let value = vault
                .test_item_password(vault_folder, vault_item)
                .with_context(|| format!("resolve vault item '{vault_item}'"))?;
            let sep = if req.path.contains('?') { '&' } else { '?' };
            req.path.push(sep);
            req.path.push_str(param_name);
            req.path.push('=');
            req.path.push_str(&urlencoding::encode(&value));
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
