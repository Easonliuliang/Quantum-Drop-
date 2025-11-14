use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{named_params, params, Connection};
use serde::Serialize;
use tauri::Manager;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntry {
    pub id: String,
    pub timestamp: i64,
    pub event_type: String,
    pub identity_id: Option<String>,
    pub device_id: Option<String>,
    pub task_id: Option<String>,
    pub details: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct AuditLogger {
    db_path: PathBuf,
}

impl AuditLogger {
    pub fn new(app: &tauri::AppHandle) -> Result<Self> {
        let mut base = app
            .path()
            .app_data_dir()
            .context("failed to resolve app data dir for audit logger")?;
        base.push("storage");
        std::fs::create_dir_all(&base).context("failed to prepare audit storage dir")?;
        let db_path = base.join("audit.sqlite3");
        let logger = Self { db_path };
        logger.migrate()?;
        Ok(logger)
    }

    fn open(&self) -> Result<Connection> {
        Connection::open(&self.db_path).context("failed to open audit sqlite")
    }

    fn migrate(&self) -> Result<()> {
        let conn = self.open()?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS audit_log (
                id TEXT PRIMARY KEY,
                timestamp INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                identity_id TEXT,
                device_id TEXT,
                task_id TEXT,
                details TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_audit_identity ON audit_log(identity_id);
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC);
        "#,
        )
        .context("failed to migrate audit log table")?;
        Ok(())
    }

    pub fn log_event(
        &self,
        event_type: &str,
        identity_id: Option<&str>,
        device_id: Option<&str>,
        task_id: Option<&str>,
        details: serde_json::Value,
    ) {
        if let Err(err) = self.insert_entry(event_type, identity_id, device_id, task_id, details) {
            eprintln!("audit log failed: {err:?}");
        }
    }

    fn insert_entry(
        &self,
        event_type: &str,
        identity_id: Option<&str>,
        device_id: Option<&str>,
        task_id: Option<&str>,
        details: serde_json::Value,
    ) -> Result<()> {
        let conn = self.open()?;
        conn.execute(
            r#"
            INSERT INTO audit_log (id, timestamp, event_type, identity_id, device_id, task_id, details)
            VALUES (:id, :timestamp, :event_type, :identity_id, :device_id, :task_id, :details)
        "#,
            named_params! {
                ":id": uuid::Uuid::new_v4().to_string(),
                ":timestamp": Utc::now().timestamp_millis(),
                ":event_type": event_type,
                ":identity_id": identity_id,
                ":device_id": device_id,
                ":task_id": task_id,
                ":details": details.to_string(),
            },
        )
        .context("failed to insert audit log entry")?;
        Ok(())
    }

    pub fn query(&self, identity_id: &str, limit: Option<usize>) -> Result<Vec<AuditEntry>> {
        let conn = self.open()?;
        let mut stmt = conn
            .prepare(
                r#"
                SELECT id, timestamp, event_type, identity_id, device_id, task_id, details
                FROM audit_log
                WHERE identity_id = ?1 OR identity_id IS NULL
                ORDER BY timestamp DESC
                LIMIT ?2
            "#,
            )
            .context("failed to prepare audit log query")?;
        let limit_val = limit.unwrap_or(100) as i64;
        let rows = stmt
            .query_map(params![identity_id, limit_val], |row| {
                let details: String = row.get(6)?;
                Ok(AuditEntry {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    event_type: row.get(2)?,
                    identity_id: row.get(3)?,
                    device_id: row.get(4)?,
                    task_id: row.get(5)?,
                    details: serde_json::from_str(&details).unwrap_or(serde_json::json!({})),
                })
            })
            .context("failed to map audit rows")?;
        let mut entries = Vec::new();
        for row in rows {
            entries.push(row?);
        }
        Ok(entries)
    }
}

pub fn log_simple_event(
    app: &tauri::AppHandle,
    event_type: &str,
    identity_id: Option<&str>,
    device_id: Option<&str>,
    task_id: Option<&str>,
    details: serde_json::Value,
) {
    if let Some(logger) = app.try_state::<AuditLogger>() {
        logger.log_event(event_type, identity_id, device_id, task_id, details);
    }
}
