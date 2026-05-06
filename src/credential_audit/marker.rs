// src/credential_audit/marker.rs
use crate::vault::VaultManager;
use anyhow::{Context, Result};
use std::sync::Arc;

const REVIEW_DELETE_FOLDER: &str = "_review-delete";
const MARKER_HEADER: &str = "# claude-credential-audit";

pub struct Marker {
    vault: Arc<VaultManager>,
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
    pub fn new(vault: Arc<VaultManager>) -> Self {
        Self { vault }
    }

    pub async fn ensure_folder(&self) -> Result<String> {
        self.vault
            .ensure_folder_by_name(REVIEW_DELETE_FOLDER)
            .await
            .context("ensure _review-delete folder")
    }

    pub async fn mark(&self, req: &MarkRequest<'_>) -> Result<()> {
        let folder_id = self.ensure_folder().await?;
        self.vault
            .move_cipher_to_folder_id(req.item_id, &folder_id)
            .await
            .context("move cipher to _review-delete")?;

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
    fn folder_name_constant() {
        assert_eq!(REVIEW_DELETE_FOLDER, "_review-delete");
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
