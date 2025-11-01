pub mod identity;

use std::{fs, path::PathBuf};

#[cfg(test)]
use std::path::Path;

use anyhow::{Context, Result};
use chrono::{TimeZone, Utc};
use rusqlite::{named_params, params, Connection, OptionalExtension, Row};
use tauri::Manager;

use crate::commands::types::{TransferDirection, TransferStatus, TransferSummary};

pub use identity::{DeviceRecord, EntitlementRecord, IdentityRecord, IdentityStore};

#[derive(Clone, Debug)]
pub struct TransferStore {
    db_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct TransferRecord {
    pub id: String,
    pub code: Option<String>,
    pub direction: TransferDirection,
    pub status: TransferStatus,
    pub bytes_total: Option<u64>,
    pub bytes_sent: Option<u64>,
    pub route: Option<String>,
    pub pot_path: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl TransferStore {
    pub fn initialise(app_handle: &tauri::AppHandle) -> Result<Self> {
        let mut base = app_handle
            .path()
            .app_data_dir()
            .context("failed to resolve app data dir")?;
        base.push("storage");
        fs::create_dir_all(&base).context("failed to create storage directory")?;

        let db_path = base.join("transfers.sqlite3");
        let store = Self {
            db_path: db_path.clone(),
        };
        store.migrate()?;
        Ok(store)
    }

    #[cfg(test)]
    pub fn with_path(path: impl AsRef<Path>) -> Result<Self> {
        let db_path = path.as_ref().to_path_buf();
        let store = Self { db_path };
        store.migrate()?;
        Ok(store)
    }

    pub fn insert_or_update(&self, record: &TransferRecord) -> Result<()> {
        let conn = self.open()?;
        let bytes_total = record.bytes_total.map(|value| value as i64);
        let bytes_sent = record.bytes_sent.map(|value| value as i64);
        conn.execute(
            r#"
            INSERT INTO transfers (
                id, code, direction, status, bytes_total, bytes_sent, route, pot_path, created_at, updated_at
            ) VALUES (
                :id, :code, :direction, :status, :bytes_total, :bytes_sent, :route, :pot_path, :created_at, :updated_at
            )
            ON CONFLICT(id) DO UPDATE SET
                code = excluded.code,
                direction = excluded.direction,
                status = excluded.status,
                bytes_total = excluded.bytes_total,
                bytes_sent = excluded.bytes_sent,
                route = excluded.route,
                pot_path = excluded.pot_path,
                updated_at = excluded.updated_at
        "#,
            named_params! {
                ":id": &record.id,
                ":code": record.code.as_deref(),
                ":direction": direction_to_str(&record.direction),
                ":status": status_to_str(&record.status),
                ":bytes_total": bytes_total,
                ":bytes_sent": bytes_sent,
                ":route": record.route.as_deref(),
                ":pot_path": record.pot_path.as_deref(),
                ":created_at": record.created_at,
                ":updated_at": record.updated_at,
            },
        )
        .context("failed to insert transfer record")?;
        Ok(())
    }

    pub fn list_transfers(
        &self,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> Result<Vec<TransferRecord>> {
        let conn = self.open()?;
        let mut stmt = conn
            .prepare(
                r#"
                SELECT id, code, direction, status, bytes_total, bytes_sent, route, pot_path, created_at, updated_at
                FROM transfers
                ORDER BY updated_at DESC
                LIMIT ?1 OFFSET ?2
            "#,
            )
            .context("failed to prepare list query")?;
        let limit_val = limit.map(|value| value as i64).unwrap_or(-1);
        let offset_val = offset.unwrap_or(0) as i64;
        let rows = stmt
            .query_map(params![limit_val, offset_val], Self::map_row)
            .context("failed to iterate transfer rows")?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    #[allow(dead_code)]
    pub fn get(&self, id: &str) -> Result<Option<TransferRecord>> {
        let conn = self.open()?;
        let mut stmt = conn
            .prepare(
                r#"
            SELECT id, code, direction, status, bytes_total, bytes_sent, route, pot_path, created_at, updated_at
            FROM transfers
            WHERE id = ?1
        "#,
            )
            .context("failed to prepare get query")?;

        let record = stmt
            .query_row(params![id], Self::map_row)
            .optional()
            .context("failed to fetch transfer")?;
        Ok(record)
    }

    pub fn to_summary(record: &TransferRecord) -> TransferSummary {
        let created = Utc
            .timestamp_millis_opt(record.created_at)
            .single()
            .unwrap_or_else(|| Utc::now());
        let updated = Utc
            .timestamp_millis_opt(record.updated_at)
            .single()
            .unwrap_or_else(|| Utc::now());

        TransferSummary {
            task_id: record.id.clone(),
            code: record.code.clone(),
            direction: record.direction.clone(),
            status: record.status.clone(),
            created_at: created,
            updated_at: updated,
            route: record
                .route
                .as_deref()
                .and_then(crate::commands::types::TransferRoute::from_label),
            files: Vec::new(),
            pot_path: record.pot_path.clone(),
        }
    }

    fn migrate(&self) -> Result<()> {
        if let Some(parent) = self.db_path.parent() {
            fs::create_dir_all(parent).context("failed to prepare db directory")?;
        }
        let conn = self.open()?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS transfers (
                id TEXT PRIMARY KEY,
                code TEXT,
                direction TEXT NOT NULL,
                status TEXT NOT NULL,
                bytes_total INTEGER,
                bytes_sent INTEGER,
                route TEXT,
                pot_path TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_transfers_updated_at ON transfers(updated_at);
        "#,
        )
        .context("failed to run migrations")?;
        Ok(())
    }

    fn open(&self) -> Result<Connection> {
        Connection::open(&self.db_path).context("failed to open sqlite connection")
    }

    fn map_row(row: &Row<'_>) -> rusqlite::Result<TransferRecord> {
        let direction_str: String = row.get("direction")?;
        let status_str: String = row.get("status")?;
        Ok(TransferRecord {
            id: row.get("id")?,
            code: row.get::<_, Option<String>>("code")?,
            direction: direction_from_str(&direction_str).unwrap_or(TransferDirection::Send),
            status: status_from_str(&status_str).unwrap_or(TransferStatus::Failed),
            bytes_total: row
                .get::<_, Option<i64>>("bytes_total")?
                .and_then(|value| (value >= 0).then_some(value as u64)),
            bytes_sent: row
                .get::<_, Option<i64>>("bytes_sent")?
                .and_then(|value| (value >= 0).then_some(value as u64)),
            route: row.get("route")?,
            pot_path: row.get("pot_path")?,
            created_at: row.get("created_at")?,
            updated_at: row.get("updated_at")?,
        })
    }
}

fn direction_to_str(direction: &TransferDirection) -> &str {
    match direction {
        TransferDirection::Send => "send",
        TransferDirection::Receive => "receive",
    }
}

fn status_to_str(status: &TransferStatus) -> &str {
    match status {
        TransferStatus::Pending => "pending",
        TransferStatus::InProgress => "inprogress",
        TransferStatus::Completed => "completed",
        TransferStatus::Cancelled => "cancelled",
        TransferStatus::Failed => "failed",
    }
}

fn direction_from_str(value: &str) -> Option<TransferDirection> {
    match value {
        "send" => Some(TransferDirection::Send),
        "receive" => Some(TransferDirection::Receive),
        _ => None,
    }
}

fn status_from_str(value: &str) -> Option<TransferStatus> {
    match value {
        "pending" => Some(TransferStatus::Pending),
        "inprogress" => Some(TransferStatus::InProgress),
        "completed" => Some(TransferStatus::Completed),
        "cancelled" => Some(TransferStatus::Cancelled),
        "failed" => Some(TransferStatus::Failed),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::types::TransferRoute;
    use tempfile::TempDir;

    #[test]
    fn creates_and_lists_records() {
        let tmp = TempDir::new().unwrap();
        let store = TransferStore::with_path(tmp.path().join("db.sqlite")).unwrap();

        let record = TransferRecord {
            id: "task_123".into(),
            code: Some("CODE123".into()),
            direction: TransferDirection::Send,
            status: TransferStatus::Completed,
            bytes_total: Some(20),
            bytes_sent: Some(10),
            route: Some("lan".into()),
            pot_path: Some("/tmp/task_123.pot.json".into()),
            created_at: 1_700_000_000_000,
            updated_at: 1_700_000_000_100,
        };
        store.insert_or_update(&record).unwrap();

        let listed = store.list_transfers(Some(10), Some(0)).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, record.id);
        assert_eq!(listed[0].status, TransferStatus::Completed);

        let fetched = store.get(&record.id).unwrap();
        assert!(fetched.is_some());
        let fetched = fetched.unwrap();
        assert_eq!(fetched.route.as_deref(), Some("lan"));
        assert_eq!(fetched.bytes_sent, Some(10));

        let summary = TransferStore::to_summary(&listed[0]);
        assert_eq!(summary.route, Some(TransferRoute::Lan));
    }
}
