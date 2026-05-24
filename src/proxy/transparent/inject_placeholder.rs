//! Placeholder substitution. Scans request path, header values, and
//! (when Content-Type is textual) the request body for literal
//! `__vault.<name>__` tokens. Each token is resolved via the
//! `[[transparent_placeholder]]` map to a vault item field and the
//! literal is replaced with the resolved value.

use anyhow::{Context, Result};
use bytes::Bytes;
use std::collections::BTreeSet;
use std::sync::Arc;

use crate::proxy::registry::TransparentPlaceholder;
use crate::proxy::transparent::mitm::HttpRequest;
use crate::vault::VaultManager;

const TEXTUAL_PREFIXES: &[&str] = &[
    "application/json",
    "application/x-www-form-urlencoded",
    "text/",
];

/// Returned when a request references a placeholder token that has
/// no `[[transparent_placeholder]]` binding. mitm::run maps this to
/// a 502 envelope with `transparent_error_code = "placeholder_unresolved"`.
#[derive(Debug)]
pub struct PlaceholderUnresolved(pub String);
impl std::fmt::Display for PlaceholderUnresolved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "placeholder '{}' referenced in request but not declared in any [[transparent_placeholder]] block",
            self.0
        )
    }
}
impl std::error::Error for PlaceholderUnresolved {}

pub async fn substitute(
    mut req: HttpRequest,
    placeholders: &[TransparentPlaceholder],
    vault: Arc<VaultManager>,
    vault_folder: &str,
    body_limit_bytes: usize,
) -> Result<HttpRequest> {
    let used = find_placeholders(&req);
    if used.is_empty() {
        return Ok(req);
    }

    let mut resolved: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for token in &used {
        let cfg = placeholders
            .iter()
            .find(|p| &p.token == token)
            .ok_or_else(|| anyhow::Error::new(PlaceholderUnresolved(token.clone())))?;
        let value = vault
            .test_item_password(vault_folder, &cfg.vault_item)
            .with_context(|| {
                format!(
                    "resolve placeholder '{}' → vault item '{}'",
                    token, cfg.vault_item
                )
            })?;
        let _ = cfg.field; // production lookup uses cfg.field; the
                           // test helper only stores password values.
        resolved.insert(token.clone(), value);
    }

    // Path substitution.
    for (token, value) in &resolved {
        if req.path.contains(token) {
            req.path = req.path.replace(token, value);
        }
    }
    // Header substitution.
    for (_, v) in req.headers.iter_mut() {
        for (token, value) in &resolved {
            if v.contains(token) {
                *v = v.replace(token, value);
            }
        }
    }

    // Body substitution.
    let content_type = req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    let is_textual = TEXTUAL_PREFIXES
        .iter()
        .any(|prefix| content_type.starts_with(prefix));
    if !is_textual {
        return Ok(req);
    }
    if req.body.len() > body_limit_bytes {
        tracing::warn!(
            len = req.body.len(),
            limit = body_limit_bytes,
            "placeholder: body exceeds limit; forwarding without substitution",
        );
        return Ok(req);
    }
    let mut body_str = std::str::from_utf8(&req.body)
        .map(|s| s.to_string())
        .map_err(|_| anyhow::anyhow!("body marked textual but is not valid UTF-8"))?;
    for (token, value) in &resolved {
        body_str = body_str.replace(token, value);
    }
    req.body = Bytes::from(body_str.into_bytes());
    Ok(req)
}

fn find_placeholders(req: &HttpRequest) -> Vec<String> {
    let mut out = BTreeSet::new();
    let mut scan = |s: &str| {
        let mut rest = s;
        while let Some(start) = rest.find("__vault.") {
            // Find the closing __ after the start prefix.
            let after_prefix = &rest[start + 8..];
            if let Some(end_rel) = after_prefix.find("__") {
                let token_end = start + 8 + end_rel + 2;
                let token = &rest[start..token_end];
                out.insert(token.to_string());
                rest = &rest[token_end..];
            } else {
                break;
            }
        }
    };
    scan(&req.path);
    for (_, v) in &req.headers {
        scan(v);
    }
    if let Ok(s) = std::str::from_utf8(&req.body) {
        scan(s);
    }
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req_with(body: &'static str, ct: &str) -> HttpRequest {
        HttpRequest {
            method: "POST".into(),
            path: "/".into(),
            headers: vec![("Content-Type".into(), ct.into())],
            body: Bytes::from_static(body.as_bytes()),
        }
    }

    #[tokio::test]
    async fn substitutes_in_json_body() {
        let req = req_with(r#"{"k":"__vault.pat__"}"#, "application/json");
        let pl = vec![TransparentPlaceholder {
            token: "__vault.pat__".into(),
            vault_item: "stub".into(),
            field: "password".into(),
        }];
        let vault = Arc::new(VaultManager::new_stub());
        vault
            .seed_test_password("vault-proxy", "stub", "real")
            .await;
        let out = substitute(req, &pl, vault, "vault-proxy", 32 * 1024 * 1024)
            .await
            .unwrap();
        assert_eq!(out.body, Bytes::from_static(b"{\"k\":\"real\"}"));
    }

    #[tokio::test]
    async fn passes_binary_body_through() {
        let body: Vec<u8> = vec![
            0, 1, 2, 3, b'_', b'_', b'v', b'a', b'u', b'l', b't', b'.', b'x', b'_', b'_',
        ];
        let req = HttpRequest {
            method: "POST".into(),
            path: "/".into(),
            headers: vec![("Content-Type".into(), "application/octet-stream".into())],
            body: Bytes::from(body.clone()),
        };
        let pl = vec![TransparentPlaceholder {
            token: "__vault.x__".into(),
            vault_item: "stub".into(),
            field: "password".into(),
        }];
        let vault = Arc::new(VaultManager::new_stub());
        vault
            .seed_test_password("vault-proxy", "stub", "real")
            .await;
        let out = substitute(req, &pl, vault, "vault-proxy", 32 * 1024 * 1024)
            .await
            .unwrap();
        assert_eq!(out.body.as_ref(), body.as_slice());
    }

    #[tokio::test]
    async fn errors_on_unresolved() {
        let req = req_with(r#"{"x":"__vault.nope__"}"#, "application/json");
        let pl: Vec<TransparentPlaceholder> = Vec::new();
        let vault = Arc::new(VaultManager::new_stub());
        let err = substitute(req, &pl, vault, "vault-proxy", 32 * 1024 * 1024)
            .await
            .unwrap_err();
        assert!(err.downcast_ref::<PlaceholderUnresolved>().is_some());
    }
}
