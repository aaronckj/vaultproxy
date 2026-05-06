use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemMapping {
    pub vw_id: String,
    pub last_cloud_rev: Option<String>,
    pub last_vw_rev: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderMapping {
    pub collection_id: String,
    pub org_id: String,
    pub vw_folder_id: String,
    pub name: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SyncMap {
    pub items: HashMap<String, ItemMapping>, // cloud_cipher_id → mapping
    pub folders: HashMap<String, FolderMapping>, // collection_id → folder mapping
}

/// Keep the last N rotated backups around. A map that drops to zero entries
/// is a common symptom of the broken-sync failure mode this guard exists for,
/// so we keep more snapshots than we strictly need. Tradeoff: ~10 files × a
/// few hundred KB each is negligible disk vs. the cost of mass-duplicating
/// 900+ ciphers on the next sync if the live file disappears.
const SYNC_MAP_BACKUP_RETENTION: usize = 10;

impl SyncMap {
    /// Load from a JSON file. Returns a default (empty) SyncMap if the file
    /// does not exist. If the file exists but parses as empty / has lost
    /// entries, falls back to the newest `.bak.*` snapshot that deserialises
    /// cleanly — this guards against the "next sync duplicates everything"
    /// failure we saw when the live map got truncated.
    pub fn load(path: &str) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                match serde_json::from_str::<SyncMap>(&contents) {
                    Ok(map) if !map.items.is_empty() => Ok(map),
                    // Empty or parse error — prefer a backup if one exists.
                    Ok(empty_map) => {
                        if let Some(backup) = Self::restore_newest_backup(path)? {
                            tracing::warn!(
                                "sync-map at {path} parsed but had 0 items; restored from newest backup"
                            );
                            Ok(backup)
                        } else {
                            Ok(empty_map)
                        }
                    }
                    Err(e) => {
                        if let Some(backup) = Self::restore_newest_backup(path)? {
                            tracing::warn!(
                                "sync-map at {path} unparseable ({e}); restored from newest backup"
                            );
                            Ok(backup)
                        } else {
                            Err(anyhow::Error::from(e))
                                .with_context(|| format!("Failed to parse sync map at {path}"))
                        }
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Live file missing — restore from newest backup if present.
                if let Some(backup) = Self::restore_newest_backup(path)? {
                    tracing::warn!("sync-map at {path} missing; restored from newest backup");
                    Ok(backup)
                } else {
                    Ok(SyncMap::default())
                }
            }
            Err(e) => Err(e).with_context(|| format!("Failed to read sync map at {path}")),
        }
    }

    /// Persist the map to a JSON file with restricted permissions (0600).
    /// Uses safe_write_config to reject symlinks. Before the write, the
    /// existing file (if any) is rotated to a timestamped `.bak.*` snapshot
    /// — older snapshots past the retention window are pruned.
    pub fn save(&self, path: &str) -> Result<()> {
        let contents =
            serde_json::to_string_pretty(self).context("Failed to serialize sync map")?;

        // Rotate the existing live file to a timestamped backup. Errors here
        // are logged but non-fatal: we'd rather lose a backup than lose the
        // ability to persist the current map.
        if let Err(e) = Self::rotate_backup(path) {
            tracing::warn!("sync-map backup rotation failed (continuing): {e}");
        }

        crate::secure::safe_write_config(path, contents.as_bytes())
            .with_context(|| format!("Failed to write sync map to {path}"))
    }

    /// Copy the live file to `<path>.bak.<timestamp>` and prune old snapshots
    /// beyond SYNC_MAP_BACKUP_RETENTION. No-op when the live file doesn't
    /// exist yet (first-run case).
    fn rotate_backup(path: &str) -> Result<()> {
        if !std::path::Path::new(path).exists() {
            return Ok(());
        }
        // Timestamp with millisecond precision so rapid back-to-back saves
        // (e.g., the post-move sync burst) don't collide.
        let ts = chrono::Utc::now().format("%Y%m%dT%H%M%S%3fZ");
        let backup_path = format!("{path}.bak.{ts}");
        std::fs::copy(path, &backup_path)
            .with_context(|| format!("copy {path} → {backup_path}"))?;
        Self::prune_backups(path)?;
        Ok(())
    }

    /// Keep only the newest SYNC_MAP_BACKUP_RETENTION backups — older ones
    /// are deleted.
    fn prune_backups(path: &str) -> Result<()> {
        let mut backups = Self::list_backups(path)?;
        // list_backups returns newest-first; retain the head, delete the tail.
        if backups.len() > SYNC_MAP_BACKUP_RETENTION {
            for old in backups.drain(SYNC_MAP_BACKUP_RETENTION..) {
                if let Err(e) = std::fs::remove_file(&old) {
                    tracing::warn!(
                        "failed to prune old sync-map backup {}: {}",
                        old.display(),
                        e
                    );
                }
            }
        }
        Ok(())
    }

    /// Return backup paths sorted newest-first by filename (timestamp suffix
    /// is lexicographically sortable by design).
    fn list_backups(path: &str) -> Result<Vec<std::path::PathBuf>> {
        let live = std::path::Path::new(path);
        let dir = live.parent().unwrap_or_else(|| std::path::Path::new("."));
        let prefix = format!(
            "{}.bak.",
            live.file_name().and_then(|s| s.to_str()).unwrap_or("")
        );

        let mut entries: Vec<std::path::PathBuf> = match std::fs::read_dir(dir) {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| n.starts_with(&prefix))
                        .unwrap_or(false)
                })
                .collect(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(anyhow::Error::from(e).context("list backup dir")),
        };
        entries.sort_by(|a, b| b.cmp(a)); // descending — newest first
        Ok(entries)
    }

    /// Try each backup newest-first; return the first one that parses into a
    /// non-empty map. None if no usable backup exists.
    fn restore_newest_backup(path: &str) -> Result<Option<Self>> {
        for bp in Self::list_backups(path)? {
            let Ok(contents) = std::fs::read_to_string(&bp) else {
                continue;
            };
            let Ok(map) = serde_json::from_str::<SyncMap>(&contents) else {
                continue;
            };
            if !map.items.is_empty() {
                return Ok(Some(map));
            }
        }
        Ok(None)
    }

    /// Look up the VaultWarden ID for a given cloud cipher ID.
    pub fn get_vw_id(&self, cloud_id: &str) -> Option<&str> {
        self.items.get(cloud_id).map(|m| m.vw_id.as_str())
    }

    /// Reverse lookup: find the cloud cipher ID for a given VaultWarden ID.
    #[allow(dead_code)] // needed for future reverse sync
    pub fn get_cloud_id(&self, vw_id: &str) -> Option<&str> {
        self.items
            .iter()
            .find(|(_, mapping)| mapping.vw_id == vw_id)
            .map(|(cloud_id, _)| cloud_id.as_str())
    }

    /// Record or update a cloud↔VW item mapping.
    pub fn set_item(
        &mut self,
        cloud_id: impl Into<String>,
        vw_id: impl Into<String>,
        cloud_rev: Option<impl Into<String>>,
        vw_rev: Option<impl Into<String>>,
    ) {
        self.items.insert(
            cloud_id.into(),
            ItemMapping {
                vw_id: vw_id.into(),
                last_cloud_rev: cloud_rev.map(|r| r.into()),
                last_vw_rev: vw_rev.map(|r| r.into()),
            },
        );
    }

    /// Remove an item mapping by cloud cipher ID.
    pub fn remove_item(&mut self, cloud_id: &str) {
        self.items.remove(cloud_id);
    }

    /// Record or update a collection↔VW folder mapping.
    pub fn set_folder(
        &mut self,
        collection_id: impl Into<String>,
        org_id: impl Into<String>,
        vw_folder_id: impl Into<String>,
        name: impl Into<String>,
    ) {
        let collection_id = collection_id.into();
        self.folders.insert(
            collection_id.clone(),
            FolderMapping {
                collection_id,
                org_id: org_id.into(),
                vw_folder_id: vw_folder_id.into(),
                name: name.into(),
            },
        );
    }

    /// Look up the VaultWarden folder ID for a given collection ID.
    pub fn get_folder_id(&self, collection_id: &str) -> Option<&str> {
        self.folders
            .get(collection_id)
            .map(|m| m.vw_folder_id.as_str())
    }
}
