use anyhow::Result;
use rusqlite::Connection;
use std::path::Path;

pub fn open_db(path: impl AsRef<Path>) -> Result<Connection> {
    let conn = Connection::open(path)?;
    conn.execute_batch("PRAGMA journal_mode=WAL;")?;
    Ok(conn)
}

const MIGRATIONS: &[(i32, &str)] = &[
    (
        1,
        r#"
    CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        applied_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS audit_runs (
        run_id TEXT PRIMARY KEY,
        status TEXT NOT NULL,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        pass1_complete INTEGER NOT NULL DEFAULT 0,
        applied_at TEXT
    );

    CREATE TABLE IF NOT EXISTS audit_run_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id TEXT NOT NULL,
        item_id TEXT NOT NULL,
        category TEXT NOT NULL,
        status TEXT NOT NULL,
        reason TEXT NOT NULL DEFAULT '',
        evidence_json TEXT NOT NULL DEFAULT '{}',
        dedup_cluster_id TEXT,
        marked_for_delete INTEGER NOT NULL DEFAULT 0,
        pass INTEGER NOT NULL DEFAULT 1,
        FOREIGN KEY(run_id) REFERENCES audit_runs(run_id)
    );

    CREATE INDEX IF NOT EXISTS idx_run_items_run ON audit_run_items(run_id);
    CREATE INDEX IF NOT EXISTS idx_run_items_marked ON audit_run_items(run_id, marked_for_delete);
    "#,
    ),
    (
        2,
        r#"
    ALTER TABLE audit_run_items ADD COLUMN pass2_verdict TEXT;
    ALTER TABLE audit_run_items ADD COLUMN pass2_evidence_json TEXT;
    ALTER TABLE audit_run_items ADD COLUMN pass2_attempted_at TEXT;

    CREATE TABLE IF NOT EXISTS audit_host_blacklist (
        run_id TEXT NOT NULL,
        host TEXT NOT NULL,
        reason TEXT,
        first_seen_at TEXT,
        PRIMARY KEY (run_id, host)
    );
    "#,
    ),
    (
        3,
        // iter-9: add fail_reason column to audit_runs so fail_run() can
        // record why a scan aborted (e.g. "engine_unreachable",
        // "engine_error: connection refused"). Previously the _reason
        // argument was discarded, leaving operators with no diagnostic
        // information about aborted runs.
        r#"
    ALTER TABLE audit_runs ADD COLUMN fail_reason TEXT;
    "#,
    ),
];

/// Mark any audit_runs left in `running` (or paused) state as `aborted` with
/// reason `orphaned_orchestrator_restart`. Called once at boot before the
/// orchestrator starts accepting new scans, so the "another audit run is in
/// progress" check never trips on a previous-process leftover.
///
/// Returns the number of rows updated.
pub fn cleanup_orphaned_runs(conn: &Connection) -> Result<usize> {
    let now = chrono::Utc::now().to_rfc3339();
    let n = conn.execute(
        "UPDATE audit_runs
            SET status = 'aborted_orphaned_restart', finished_at = ?1
          WHERE status IN ('running','paused_proxy_down','paused_engine_crash')",
        rusqlite::params![&now],
    )?;
    Ok(n)
}

pub fn run_migrations(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT (datetime('now'))
        );",
    )?;
    let mut applied: std::collections::HashSet<i32> = std::collections::HashSet::new();
    {
        let mut stmt = conn.prepare("SELECT version FROM schema_migrations")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            applied.insert(row.get(0)?);
        }
    }
    for (version, sql) in MIGRATIONS {
        if applied.contains(version) {
            continue;
        }
        conn.execute_batch(sql)?;
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES (?1)",
            [version],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrate_creates_tables() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('audit_runs','audit_run_items','schema_migrations')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn cleanup_orphaned_runs_marks_running_rows_aborted() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();

        // Seed: one running, one paused, one already finished.
        conn.execute(
            "INSERT INTO audit_runs(run_id, status, started_at) VALUES
                ('orphan-1', 'running',           '2026-04-30T00:00:00Z'),
                ('orphan-2', 'paused_engine_crash','2026-04-30T00:00:00Z'),
                ('done-1',   'completed',         '2026-04-30T00:00:00Z')",
            [],
        )
        .unwrap();

        let updated = cleanup_orphaned_runs(&conn).unwrap();
        assert_eq!(updated, 2, "two stale rows should have been swept");

        let still_active: i64 = conn
            .query_row(
                "SELECT count(*) FROM audit_runs
                  WHERE status IN ('running','paused_proxy_down','paused_engine_crash')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(still_active, 0);

        let aborted: i64 = conn
            .query_row(
                "SELECT count(*) FROM audit_runs WHERE status = 'aborted_orphaned_restart'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(aborted, 2);

        // Idempotent: a second call with no orphans is a no-op.
        let second = cleanup_orphaned_runs(&conn).unwrap();
        assert_eq!(second, 0);
    }

    #[test]
    fn migrate_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();
        run_migrations(&conn).unwrap();
        let count: i64 = conn
            .query_row("SELECT count(*) FROM schema_migrations", [], |row| row.get(0))
            .unwrap();
        assert!(count >= 1);
    }

    /// iter-9: migration 3 adds `fail_reason` to audit_runs.
    #[test]
    fn migration_3_adds_fail_reason_column() {
        let conn = Connection::open_in_memory().unwrap();
        run_migrations(&conn).unwrap();
        // Write a fail_reason — would panic with "table has no column named
        // fail_reason" if migration 3 didn't run.
        conn.execute(
            "INSERT INTO audit_runs(run_id, status, started_at, fail_reason)
             VALUES ('r1', 'aborted_engine_error', '2026-05-05T00:00:00Z', 'engine_unreachable')",
            [],
        )
        .expect("fail_reason column must exist after migration 3");
        let reason: Option<String> = conn
            .query_row(
                "SELECT fail_reason FROM audit_runs WHERE run_id = 'r1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(reason.as_deref(), Some("engine_unreachable"));
    }
}
