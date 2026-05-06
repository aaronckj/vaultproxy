// src/credential_audit/marker.rs
use crate::vault::VaultManager;
use anyhow::{Context, Result};
use std::sync::Arc;

const MARKER_HEADER: &str = "# claude-credential-audit";

/// Suffix appended to `vault_folder` to form the review-delete folder name.
///
/// When `vault_folder = "staging"` the destination folder is
/// `"staging-review-delete"`.  When `vault_folder` is `None` (unconfigured)
/// the legacy global name `"_review-delete"` is used so existing deployments
/// that have not set `vault_folder` continue to work without a data-migration.
///
/// # Isolation rationale (iter-58)
///
/// Vaultwarden has no nested folders — all folders are root-level in a flat
/// list.  A global `"_review-delete"` folder is shared across every deployment
/// that uses the same Vaultwarden instance.  An operator running two vault-proxy
/// deployments (`vault_folder = "staging"` and `vault_folder = "prod"`) would
/// have both deployments dumping flagged items into the same folder, making it
/// impossible to distinguish which deployment flagged an item without reading the
/// marker note.  Prefixing the folder with the `vault_folder` name gives each
/// deployment its own isolated quarantine bucket at zero cost.
const REVIEW_DELETE_SUFFIX: &str = "-review-delete";

/// Build the review-delete folder name for the given vault_folder scope.
///
/// Returns `"<vault_folder>-review-delete"` when `vault_folder` is set, or
/// the legacy `"_review-delete"` when it is `None` (unconfigured deployment).
fn review_delete_folder(vault_folder: Option<&str>) -> String {
    match vault_folder {
        Some(vf) => format!("{}{}", vf, REVIEW_DELETE_SUFFIX),
        None => "_review-delete".to_string(),
    }
}

pub struct Marker {
    vault: Arc<VaultManager>,
    /// The vault_folder scope for this deployment.  Used to construct the
    /// per-deployment review-delete folder name (see `review_delete_folder()`).
    vault_folder: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MarkRequest<'a> {
    pub item_id: &'a str,
    pub reason: &'a str,
    pub detail: &'a str,
    pub pass: i32,
    pub run_id: &'a str,
}

/// Pure builder. Returns `Some(new_notes)` if the cipher should be updated,
/// or `None` if the cipher already carries our marker block (idempotent).
pub fn build_marker_note(
    existing: Option<&str>,
    req: &MarkRequest<'_>,
    timestamp_iso: &str,
) -> Option<String> {
    if let Some(s) = existing {
        if s.contains(MARKER_HEADER) {
            return None;
        }
    }
    let block = format!(
        "{header}\nmarked: {ts}\nreason: {reason}\ndetail: {detail}\npass: {pass}\nrun_id: {run_id}\n",
        header = MARKER_HEADER,
        ts = timestamp_iso,
        reason = req.reason,
        detail = req.detail,
        pass = req.pass,
        run_id = req.run_id,
    );
    Some(match existing {
        Some(s) if !s.is_empty() => format!("{}\n\n{}", s.trim_end(), block),
        _ => block,
    })
}

impl Marker {
    /// Create a `Marker` scoped to the given `vault_folder`.
    ///
    /// - `vault_folder = Some("staging")` → flagged items are moved to
    ///   `"staging-review-delete"`.
    /// - `vault_folder = None` → falls back to the legacy `"_review-delete"`
    ///   folder so existing single-deployment setups are unaffected.
    pub fn new(vault: Arc<VaultManager>, vault_folder: Option<String>) -> Self {
        Self {
            vault,
            vault_folder,
        }
    }

    pub async fn ensure_folder(&self) -> Result<String> {
        let folder_name = review_delete_folder(self.vault_folder.as_deref());
        self.vault
            .ensure_folder_by_name(&folder_name)
            .await
            .with_context(|| format!("ensure {} folder", folder_name))
    }

    pub async fn mark(&self, req: &MarkRequest<'_>) -> Result<()> {
        let folder_id = self.ensure_folder().await?;
        let folder_name = review_delete_folder(self.vault_folder.as_deref());
        self.vault
            .move_cipher_to_folder_id(req.item_id, &folder_id)
            .await
            .with_context(|| format!("move cipher to {}", folder_name))?;

        // Read existing notes (if any), append our marker block when not
        // already present. Idempotent — re-running mark on the same item
        // doesn't grow the notes field.
        let existing = self
            .vault
            .decrypt_notes_by_id(req.item_id)
            .context("decrypt existing notes during mark")?;
        let existing_str = existing
            .as_ref()
            .map(|b| std::str::from_utf8(b.as_bytes()).unwrap_or(""));
        let now = chrono::Utc::now().to_rfc3339();
        if let Some(new_notes) = build_marker_note(existing_str, req, &now) {
            self.vault
                .update_notes_by_id(req.item_id, &new_notes)
                .await
                .context("write marker note to cipher")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folder_name_with_vault_folder_prefix() {
        assert_eq!(
            review_delete_folder(Some("staging")),
            "staging-review-delete"
        );
        assert_eq!(review_delete_folder(Some("prod")), "prod-review-delete");
    }

    #[test]
    fn folder_name_none_uses_legacy_name() {
        assert_eq!(review_delete_folder(None), "_review-delete");
    }

    #[test]
    fn build_marker_note_fresh_appends_block() {
        let req = MarkRequest {
            item_id: "abc",
            reason: "dead",
            detail: "401 from /v1/me at openai.com",
            pass: 1,
            run_id: "11111111-1111-1111-1111-111111111111",
        };
        let out = build_marker_note(None, &req, "2026-04-30T12:00:00Z");
        let s = out.expect("expected Some(new_notes)");
        assert!(s.starts_with("# claude-credential-audit\n"));
        assert!(s.contains("marked: 2026-04-30T12:00:00Z"));
        assert!(s.contains("reason: dead"));
        assert!(s.contains("detail: 401 from /v1/me at openai.com"));
        assert!(s.contains("pass: 1"));
        assert!(s.contains("run_id: 11111111-1111-1111-1111-111111111111"));
    }

    #[test]
    fn build_marker_note_existing_user_notes_appends_below() {
        let req = MarkRequest {
            item_id: "abc",
            reason: "duplicate",
            detail: "duplicate of \"primary login\"",
            pass: 1,
            run_id: "rrr",
        };
        let out = build_marker_note(Some("user kept this around"), &req, "T");
        let s = out.expect("expected Some(new_notes)");
        assert!(s.starts_with("user kept this around\n\n# claude-credential-audit\n"));
    }

    #[test]
    fn build_marker_note_idempotent_when_marker_already_present() {
        let already =
            "# claude-credential-audit\nmarked: T\nreason: dead\ndetail: x\npass: 1\nrun_id: r\n";
        let req = MarkRequest {
            item_id: "abc",
            reason: "dead",
            detail: "x",
            pass: 1,
            run_id: "r",
        };
        let out = build_marker_note(Some(already), &req, "T");
        assert!(out.is_none());
    }
}
