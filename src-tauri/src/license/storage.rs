use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::{DateTime, Datelike, NaiveDateTime, Utc};
use rusqlite::{named_params, OptionalExtension};

use crate::{
    license::types::{License, LicenseLimits, LicenseTier},
    store::{identity::EntitlementRecord, IdentityStore},
};

#[derive(Debug, Clone)]
pub struct LicenseUsage {
    pub identity_id: String,
    pub p2p_used: u32,
    pub last_reset_month: String,
}

#[derive(Debug, Clone)]
pub struct LicenseStore {
    identity_store: IdentityStore,
    db_path: PathBuf,
}

impl LicenseStore {
    pub fn new(identity_store: &IdentityStore) -> Result<Self> {
        let store = Self {
            identity_store: identity_store.clone(),
            db_path: identity_store.db_path(),
        };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<()> {
        let conn = self.identity_store.raw_connection()?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS license_usage (
                identity_id TEXT PRIMARY KEY,
                p2p_used INTEGER NOT NULL DEFAULT 0,
                last_reset_month TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY(identity_id) REFERENCES identities(id)
            );
        "#,
        )
        .context("failed to run license_usage migration")?;
        Ok(())
    }

    pub fn fetch_entitlement(&self, identity_id: &str) -> Result<Option<EntitlementRecord>> {
        self.identity_store
            .get_entitlement(identity_id)
            .context("failed to load entitlement")
    }

    pub fn upsert_license(&self, license: &License) -> Result<()> {
        let conn = self.identity_store.raw_connection()?;
        let limits_json =
            serde_json::to_string(&license.limits).context("failed to encode license limits")?;
        conn.execute(
            r#"
            INSERT INTO entitlements (
                identity_id, plan, expires_at, features, updated_at,
                license_key, signature, limits, issued_at
            )
            VALUES (
                :identity_id, :plan, :expires_at, :features, :updated_at,
                :license_key, :signature, :limits, :issued_at
            )
            ON CONFLICT(identity_id) DO UPDATE SET
                plan = excluded.plan,
                expires_at = excluded.expires_at,
                features = excluded.features,
                updated_at = excluded.updated_at,
                license_key = excluded.license_key,
                signature = excluded.signature,
                limits = excluded.limits,
                issued_at = excluded.issued_at
        "#,
            named_params! {
                ":identity_id": license.identity_id,
                ":plan": license.tier.label(),
                ":expires_at": license.expires_at.map(|value| value.timestamp_millis()),
                ":features": serde_json::to_string(&Vec::<String>::new()).unwrap_or_default(),
                ":updated_at": Utc::now().timestamp_millis(),
                ":license_key": license.key.as_deref(),
                ":signature": license.signature.as_deref(),
                ":limits": limits_json,
                ":issued_at": Some(license.issued_at.timestamp_millis()),
            },
        )
        .context("failed to persist license metadata")?;
        Ok(())
    }

    pub fn get_usage(&self, identity_id: &str) -> Result<LicenseUsage> {
        let conn = self.identity_store.raw_connection()?;
        let month = current_month();
        let mut stmt = conn.prepare(
            r#"
            SELECT identity_id, p2p_used, last_reset_month
            FROM license_usage
            WHERE identity_id = ?1
        "#,
        )?;
        let mut usage = stmt
            .query_row([identity_id], |row| {
                Ok(LicenseUsage {
                    identity_id: row.get(0)?,
                    p2p_used: row.get::<_, i64>(1)? as u32,
                    last_reset_month: row.get(2)?,
                })
            })
            .optional()?;

        match usage {
            Some(ref mut record) => {
                if record.last_reset_month != month {
                    record.p2p_used = 0;
                    record.last_reset_month = month.clone();
                    self.update_usage(record)?;
                }
            }
            None => {
                let record = LicenseUsage {
                    identity_id: identity_id.to_string(),
                    p2p_used: 0,
                    last_reset_month: month.clone(),
                };
                self.insert_usage(&record)?;
                usage = Some(record);
            }
        }
        usage.ok_or_else(|| anyhow::anyhow!("license usage initialisation failed"))
    }

    pub fn increment_p2p_usage(&self, usage: &LicenseUsage) -> Result<()> {
        let mut updated = usage.clone();
        updated.p2p_used += 1;
        self.update_usage(&updated)?;
        Ok(())
    }

    pub fn reset_usage(&self, identity_id: &str) -> Result<()> {
        let record = LicenseUsage {
            identity_id: identity_id.to_string(),
            p2p_used: 0,
            last_reset_month: current_month(),
        };
        self.update_usage(&record)?;
        Ok(())
    }

    pub fn count_devices(&self, identity_id: &str) -> Result<usize> {
        self.identity_store
            .count_devices(identity_id)
            .context("failed to count devices")
    }

    pub fn load_license_from_entitlement(
        &self,
        record: Option<EntitlementRecord>,
        identity_id: &str,
    ) -> License {
        if let Some(record) = record {
            let tier = LicenseTier::from_str(&record.plan);
            let limits = record
                .license_limits
                .as_ref()
                .and_then(|payload| serde_json::from_str::<LicenseLimits>(payload).ok())
                .unwrap_or_else(|| default_limits_for_tier(&tier));
            let issued_at = record
                .issued_at
                .unwrap_or_else(|| Utc::now().timestamp_millis());
            License {
                key: record.license_key,
                tier,
                identity_id: identity_id.to_string(),
                issued_at: DateTime::<Utc>::from_utc(
                    NaiveDateTime::from_timestamp_millis(issued_at)
                        .unwrap_or_else(|| NaiveDateTime::from_timestamp_millis(0).unwrap()),
                    Utc,
                ),
                expires_at: record
                    .expires_at
                    .and_then(|value| NaiveDateTime::from_timestamp_millis(value))
                    .map(|dt| DateTime::<Utc>::from_utc(dt, Utc)),
                limits,
                signature: record.license_signature,
            }
        } else {
            License::free(identity_id.to_string())
        }
    }

    fn insert_usage(&self, usage: &LicenseUsage) -> Result<()> {
        let conn = self.identity_store.raw_connection()?;
        conn.execute(
            r#"
            INSERT INTO license_usage (identity_id, p2p_used, last_reset_month, updated_at)
            VALUES (:identity_id, :p2p_used, :last_reset_month, :updated_at)
        "#,
            named_params! {
                ":identity_id": usage.identity_id,
                ":p2p_used": usage.p2p_used as i64,
                ":last_reset_month": usage.last_reset_month,
                ":updated_at": Utc::now().timestamp_millis(),
            },
        )
        .context("failed to insert license usage")?;
        Ok(())
    }

    fn update_usage(&self, usage: &LicenseUsage) -> Result<()> {
        let conn = self.identity_store.raw_connection()?;
        conn.execute(
            r#"
            INSERT INTO license_usage (identity_id, p2p_used, last_reset_month, updated_at)
            VALUES (:identity_id, :p2p_used, :last_reset_month, :updated_at)
            ON CONFLICT(identity_id) DO UPDATE SET
                p2p_used = excluded.p2p_used,
                last_reset_month = excluded.last_reset_month,
                updated_at = excluded.updated_at
        "#,
            named_params! {
                ":identity_id": usage.identity_id,
                ":p2p_used": usage.p2p_used as i64,
                ":last_reset_month": usage.last_reset_month,
                ":updated_at": Utc::now().timestamp_millis(),
            },
        )
        .context("failed to update license usage")?;
        Ok(())
    }
}

fn current_month() -> String {
    let now = Utc::now();
    format!("{:04}-{:02}", now.year(), now.month())
}

fn default_limits_for_tier(tier: &LicenseTier) -> LicenseLimits {
    match tier {
        LicenseTier::Free => LicenseLimits::free_defaults(),
        LicenseTier::Pro => LicenseLimits::pro_defaults(),
        LicenseTier::Enterprise => LicenseLimits::enterprise_defaults(),
    }
}
