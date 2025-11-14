use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use rusqlite::{named_params, Connection, OptionalExtension, Row};
use serde::{Deserialize, Serialize};
use tauri::Manager;

const ED25519_PUBLIC_KEY_BYTES: usize = 32;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityRecord {
    pub identity_id: String,
    pub public_key: String,
    pub label: Option<String>,
    pub created_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRecord {
    pub device_id: String,
    pub identity_id: String,
    pub public_key: String,
    pub name: Option<String>,
    pub status: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_seen_at: i64,
    pub capabilities: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntitlementRecord {
    pub identity_id: String,
    pub plan: String,
    pub expires_at: Option<i64>,
    pub features: Vec<String>,
    pub updated_at: i64,
    pub license_key: Option<String>,
    pub license_signature: Option<String>,
    pub license_limits: Option<String>,
    pub issued_at: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct IdentityStore {
    db_path: PathBuf,
}

impl IdentityStore {
    pub fn initialise(app: &tauri::AppHandle) -> Result<Self> {
        let mut base = app
            .path()
            .app_data_dir()
            .context("failed to resolve app data dir for identity store")?;
        base.push("storage");
        std::fs::create_dir_all(&base).context("failed to prepare storage directory")?;

        let db_path = base.join("identities.sqlite3");
        let store = Self {
            db_path: db_path.clone(),
        };
        store.migrate()?;
        Ok(store)
    }

    #[cfg_attr(not(any(test, doctest)), allow(dead_code))]
    pub fn with_path(path: impl AsRef<Path>) -> Result<Self> {
        let store = Self {
            db_path: path.as_ref().to_path_buf(),
        };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<()> {
        if let Some(parent) = self.db_path.parent() {
            std::fs::create_dir_all(parent)
                .context("failed to prepare directory for identity database")?;
        }
        let conn = self.open()?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS identities (
                id TEXT PRIMARY KEY,
                public_key TEXT NOT NULL,
                label TEXT,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                identity_id TEXT NOT NULL,
                public_key TEXT NOT NULL,
                name TEXT,
                status TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                last_seen_at INTEGER NOT NULL,
                capabilities TEXT,
                FOREIGN KEY(identity_id) REFERENCES identities(id)
            );
            CREATE TABLE IF NOT EXISTS entitlements (
                identity_id TEXT PRIMARY KEY,
                plan TEXT NOT NULL,
                expires_at INTEGER,
                features TEXT,
                updated_at INTEGER NOT NULL,
                license_key TEXT,
                signature TEXT,
                limits TEXT,
                issued_at INTEGER,
                FOREIGN KEY(identity_id) REFERENCES identities(id)
            );
        "#,
        )
        .context("failed to run identity migrations")?;
        Self::ensure_entitlement_columns(&conn)?;
        Ok(())
    }

    fn open(&self) -> Result<rusqlite::Connection> {
        rusqlite::Connection::open(&self.db_path)
            .context("failed to open identity sqlite connection")
    }

    pub fn register_identity(
        &self,
        identity_id: &str,
        public_key: &str,
        label: Option<&str>,
    ) -> Result<IdentityRecord> {
        if identity_id.trim().is_empty() {
            return Err(anyhow!("identity_id cannot be empty"));
        }
        let now = Utc::now().timestamp_millis();
        let conn = self.open()?;
        validate_hex_payload(public_key, ED25519_PUBLIC_KEY_BYTES, "identity public key")?;

        conn.execute(
            r#"
            INSERT INTO identities (id, public_key, label, created_at)
            VALUES (:id, :public_key, :label, :created_at)
            ON CONFLICT(id) DO UPDATE SET
                public_key = excluded.public_key,
                label = COALESCE(excluded.label, identities.label)
        "#,
            named_params! {
                ":id": identity_id,
                ":public_key": public_key,
                ":label": label,
                ":created_at": now,
            },
        )
        .context("failed to register identity")?;
        let record = self
            .get_identity(identity_id)?
            .ok_or_else(|| anyhow!("identity lookup failed after insert"))?;
        Ok(record)
    }

    pub fn register_device(
        &self,
        identity_id: &str,
        device_id: &str,
        public_key: &str,
        name: Option<&str>,
        status: &str,
    ) -> Result<DeviceRecord> {
        if device_id.trim().is_empty() {
            return Err(anyhow!("device_id cannot be empty"));
        }
        let now = Utc::now().timestamp_millis();
        let conn = self.open()?;
        validate_hex_payload(public_key, ED25519_PUBLIC_KEY_BYTES, "device public key")?;
        conn.execute(
            r#"
            INSERT INTO devices (id, identity_id, public_key, name, status, created_at, updated_at, last_seen_at, capabilities)
            VALUES (:id, :identity_id, :public_key, :name, :status, :created_at, :updated_at, :last_seen_at, :capabilities)
            ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                status = excluded.status,
                public_key = excluded.public_key,
                updated_at = excluded.updated_at,
                last_seen_at = excluded.last_seen_at,
                capabilities = excluded.capabilities
        "#,
            named_params! {
                ":id": device_id,
                ":identity_id": identity_id,
                ":public_key": public_key,
                ":name": name,
                ":status": status,
                ":created_at": now,
                ":updated_at": now,
                ":last_seen_at": now,
                ":capabilities": serde_json::to_string(&Vec::<String>::new()).unwrap_or_default(),
            },
        )
        .context("failed to register device")?;
        Ok(DeviceRecord {
            device_id: device_id.to_string(),
            identity_id: identity_id.to_string(),
            public_key: public_key.to_string(),
            name: name.map(|value| value.to_string()),
            status: status.to_string(),
            created_at: now,
            updated_at: now,
            last_seen_at: now,
            capabilities: Vec::new(),
        })
    }

    pub fn list_devices(&self, identity_id: &str) -> Result<Vec<DeviceRecord>> {
        let conn = self.open()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT id, identity_id, public_key, name, status, created_at, updated_at, last_seen_at, capabilities
            FROM devices
            WHERE identity_id = ?1
            ORDER BY created_at ASC
        "#,
        )?;
        let rows = stmt.query_map([identity_id], |row| Self::map_device(row))?;
        let mut devices = Vec::new();
        for entry in rows {
            devices.push(entry?);
        }
        Ok(devices)
    }

    pub fn get_device(&self, identity_id: &str, device_id: &str) -> Result<Option<DeviceRecord>> {
        let conn = self.open()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT id, identity_id, public_key, name, status, created_at, updated_at, last_seen_at, capabilities
            FROM devices
            WHERE identity_id = ?1 AND id = ?2
        "#,
        )?;
        let record = stmt
            .query_row([identity_id, device_id], |row| Self::map_device(row))
            .optional()?;
        Ok(record)
    }

    pub fn touch_device(
        &self,
        identity_id: &str,
        device_id: &str,
        name: Option<&str>,
        status: Option<&str>,
        capabilities: Option<&[String]>,
    ) -> Result<DeviceRecord> {
        let mut existing = self
            .get_device(identity_id, device_id)?
            .ok_or_else(|| anyhow!("device not registered"))?;
        let now = Utc::now().timestamp_millis();

        if let Some(new_name) = name {
            existing.name = Some(new_name.trim().to_string());
        }
        if let Some(new_status) = status {
            existing.status = new_status.trim().to_string();
        }
        if let Some(new_capabilities) = capabilities {
            existing.capabilities = new_capabilities.to_vec();
        }

        let conn = self.open()?;
        conn.execute(
            r#"
            UPDATE devices
            SET name = :name,
                status = :status,
                updated_at = :updated_at,
                last_seen_at = :last_seen_at,
                capabilities = :capabilities
            WHERE identity_id = :identity_id AND id = :device_id
        "#,
            named_params! {
                ":name": existing.name.as_deref(),
                ":status": &existing.status,
                ":updated_at": now,
                ":last_seen_at": now,
                ":capabilities": serde_json::to_string(&existing.capabilities).unwrap_or_default(),
                ":identity_id": identity_id,
                ":device_id": device_id,
            },
        )
        .context("failed to update device attributes")?;

        existing.updated_at = now;
        existing.last_seen_at = now;
        Ok(existing)
    }

    pub fn get_entitlement(&self, identity_id: &str) -> Result<Option<EntitlementRecord>> {
        let conn = self.open()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT identity_id, plan, expires_at, features, updated_at,
                   license_key, signature, limits, issued_at
            FROM entitlements
            WHERE identity_id = ?1
        "#,
        )?;
        let record = stmt
            .query_row([identity_id], |row| Self::map_entitlement(row))
            .optional()?;
        Ok(record)
    }

    pub fn set_entitlement(
        &self,
        identity_id: &str,
        plan: &str,
        expires_at: Option<i64>,
        features: &[String],
    ) -> Result<EntitlementRecord> {
        if identity_id.trim().is_empty() {
            return Err(anyhow!("identity_id cannot be empty"));
        }
        let now = Utc::now().timestamp_millis();
        let features_json = serde_json::to_string(features).context("failed to encode features")?;
        let conn = self.open()?;
        conn.execute(
            r#"
            INSERT INTO entitlements (identity_id, plan, expires_at, features, updated_at)
            VALUES (:identity_id, :plan, :expires_at, :features, :updated_at)
            ON CONFLICT(identity_id) DO UPDATE SET
                plan = excluded.plan,
                expires_at = excluded.expires_at,
                features = excluded.features,
                updated_at = excluded.updated_at
        "#,
            named_params! {
                ":identity_id": identity_id,
                ":plan": plan,
                ":expires_at": expires_at,
                ":features": features_json,
                ":updated_at": now,
            },
        )
        .context("failed to persist entitlement")?;
        Ok(EntitlementRecord {
            identity_id: identity_id.to_string(),
            plan: plan.to_string(),
            expires_at,
            features: features.to_vec(),
            updated_at: now,
            license_key: None,
            license_signature: None,
            license_limits: None,
            issued_at: None,
        })
    }

    fn map_device(row: &Row) -> rusqlite::Result<DeviceRecord> {
        Ok(DeviceRecord {
            device_id: row.get(0)?,
            identity_id: row.get(1)?,
            public_key: row.get(2)?,
            name: row.get(3)?,
            status: row.get(4)?,
            created_at: row.get(5)?,
            updated_at: row.get(6)?,
            last_seen_at: row.get(7)?,
            capabilities: row
                .get::<_, Option<String>>(8)?
                .and_then(|payload| serde_json::from_str(&payload).ok())
                .unwrap_or_default(),
        })
    }

    fn map_entitlement(row: &Row) -> rusqlite::Result<EntitlementRecord> {
        let features: Option<String> = row.get(3)?;
        let parsed = features
            .as_deref()
            .map(|payload| serde_json::from_str(payload).unwrap_or_else(|_| Vec::new()))
            .unwrap_or_default();
        Ok(EntitlementRecord {
            identity_id: row.get(0)?,
            plan: row.get(1)?,
            expires_at: row.get(2)?,
            features: parsed,
            updated_at: row.get(4)?,
            license_key: row.get(5)?,
            license_signature: row.get(6)?,
            license_limits: row.get(7)?,
            issued_at: row.get(8)?,
        })
    }

    pub fn get_identity(&self, identity_id: &str) -> Result<Option<IdentityRecord>> {
        let conn = self.open()?;
        let mut stmt = conn.prepare(
            r#"
            SELECT id, public_key, label, created_at
            FROM identities
            WHERE id = ?1
        "#,
        )?;
        let record = stmt
            .query_row([identity_id], |row| Self::map_identity(row))
            .optional()?;
        Ok(record)
    }

    fn map_identity(row: &Row) -> rusqlite::Result<IdentityRecord> {
        Ok(IdentityRecord {
            identity_id: row.get(0)?,
            public_key: row.get(1)?,
            label: row.get(2)?,
            created_at: row.get(3)?,
        })
    }

    pub fn count_devices(&self, identity_id: &str) -> Result<usize> {
        let conn = self.open()?;
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM devices WHERE identity_id = ?1",
                [identity_id],
                |row| row.get(0),
            )
            .context("failed to count devices")?;
        Ok(count as usize)
    }

    pub(crate) fn raw_connection(&self) -> Result<Connection> {
        self.open()
    }

    pub fn db_path(&self) -> PathBuf {
        self.db_path.clone()
    }

    fn ensure_entitlement_columns(conn: &Connection) -> Result<()> {
        for (name, ty) in [
            ("license_key", "TEXT"),
            ("signature", "TEXT"),
            ("limits", "TEXT"),
            ("issued_at", "INTEGER"),
        ] {
            let statement = format!("ALTER TABLE entitlements ADD COLUMN {name} {ty}");
            if let Err(err) = conn.execute(&statement, []) {
                let msg = err.to_string();
                if !msg.contains("duplicate column name") {
                    return Err(err)
                        .context(format!("failed to add column '{name}' to entitlements"));
                }
            }
        }
        Ok(())
    }
}

fn validate_hex_payload(input: &str, expected_len: usize, field: &str) -> Result<Vec<u8>> {
    let trimmed = input.trim();
    let decoded = hex::decode(trimmed).map_err(|_| anyhow!("{field} must be hex-encoded"))?;
    if decoded.len() != expected_len {
        return Err(anyhow!(
            "{field} must be {expected_len} bytes, got {}",
            decoded.len()
        ));
    }
    Ok(decoded)
}
