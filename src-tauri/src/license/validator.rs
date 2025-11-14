use anyhow::{Context, Result};
use chrono::{DateTime, TimeZone, Utc};
use ed25519_dalek::{ed25519::signature::Verifier, Signature, VerifyingKey};
use serde::Deserialize;

use crate::{
    license::{
        storage::{LicenseStore, LicenseUsage},
        types::{License, LicenseError, LicenseLimits, LicenseStatus, LicenseTier},
    },
    store::IdentityStore,
};

#[derive(Debug, Clone)]
pub struct LicenseManager {
    store: LicenseStore,
    verify_key: Option<VerifyingKey>,
    allow_unverified: bool,
}

impl LicenseManager {
    pub fn new(identity_store: &IdentityStore) -> Result<Self> {
        let store = LicenseStore::new(identity_store)?;
        let verify_key = std::env::var("QD_LICENSE_PUBKEY")
            .ok()
            .and_then(|hex| hex::decode(hex).ok())
            .and_then(|bytes| {
                if bytes.len() == 32 {
                    let mut array = [0u8; 32];
                    array.copy_from_slice(&bytes);
                    VerifyingKey::from_bytes(&array).ok()
                } else {
                    None
                }
            });
        let allow_unverified = std::env::var("QD_LICENSE_ALLOW_UNSIGNED")
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE"))
            .unwrap_or(cfg!(debug_assertions));
        Ok(Self {
            store,
            verify_key,
            allow_unverified,
        })
    }

    pub fn active_license(&self, identity_id: &str) -> Result<License> {
        let record = self.store.fetch_entitlement(identity_id)?;
        Ok(self
            .store
            .load_license_from_entitlement(record, identity_id))
    }

    pub fn enforce_device_limit(&self, license: &License) -> Result<(), LicenseError> {
        if let Some(limit) = license.limits.max_devices {
            let count = self
                .store
                .count_devices(&license.identity_id)
                .map_err(|err| LicenseError::new("LICENSE_DB_ERROR", err.to_string()))?;
            if count >= limit {
                return Err(LicenseError::new(
                    "DEVICE_LIMIT_EXCEEDED",
                    format!("当前版本最多支持 {limit} 台设备，请升级以解锁更多"),
                ));
            }
        }
        Ok(())
    }

    pub fn enforce_file_size(
        &self,
        license: &License,
        size_bytes: u64,
    ) -> Result<(), LicenseError> {
        if let Some(limit_mb) = license.limits.max_file_size_mb {
            let limit_bytes = limit_mb * 1_048_576;
            if size_bytes > limit_bytes {
                return Err(LicenseError::new(
                    "FILE_SIZE_EXCEEDED",
                    format!(
                        "文件大小超出限制（当前 {:.2} GB，免费版上限 {} GB）",
                        size_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
                        limit_mb as f64 / 1024.0
                    ),
                ));
            }
        }
        Ok(())
    }

    pub fn ensure_p2p_quota(&self, license: &License) -> Result<LicenseUsage, LicenseError> {
        if license.limits.p2p_monthly_quota.is_none() {
            return self
                .store
                .get_usage(&license.identity_id)
                .map_err(|err| LicenseError::new("LICENSE_DB_ERROR", err.to_string()));
        }
        let usage = self
            .store
            .get_usage(&license.identity_id)
            .map_err(|err| LicenseError::new("LICENSE_DB_ERROR", err.to_string()))?;
        if let Some(quota) = license.limits.p2p_monthly_quota {
            if usage.p2p_used >= quota {
                return Err(LicenseError::new(
                    "P2P_QUOTA_EXCEEDED",
                    format!("本月跨网传输次数已用完（免费版每月 {quota} 次），请升级到 Pro 版"),
                ));
            }
        }
        Ok(usage)
    }

    pub fn record_p2p_usage(&self, usage: &LicenseUsage) -> Result<()> {
        self.store
            .increment_p2p_usage(usage)
            .context("failed to record p2p usage")
    }

    pub fn reset_usage(&self, identity_id: &str) -> Result<()> {
        self.store
            .reset_usage(identity_id)
            .context("failed to reset license usage")
    }

    pub fn activate_license(&self, identity_id: &str, blob: &str) -> Result<License, LicenseError> {
        let payload = parse_license_blob(blob)?;
        if let Some(expected) = payload.identity_id.as_deref() {
            if expected.trim() != identity_id.trim() {
                return Err(LicenseError::new(
                    "LICENSE_ID_MISMATCH",
                    "许可证与当前身份不匹配",
                ));
            }
        }
        let tier = payload.tier.clone().unwrap_or(LicenseTier::Pro);
        let limits = payload
            .limits
            .clone()
            .unwrap_or_else(|| default_limits_for_tier(&tier));

        if let Some(public_key) = self.verify_key.as_ref() {
            let signature = payload.signature.as_ref().ok_or_else(|| {
                LicenseError::new("LICENSE_SIGNATURE_MISSING", "许可证缺少签名，无法验证来源")
            })?;
            verify_license_signature(public_key, signature, &payload)?;
        } else if !self.allow_unverified {
            return Err(LicenseError::new(
                "LICENSE_VERIFICATION_REQUIRED",
                "许可证验证未配置，请设置 QD_LICENSE_PUBKEY",
            ));
        }

        let license = License {
            key: Some(payload.key.clone()),
            tier,
            identity_id: identity_id.to_string(),
            issued_at: timestamp_to_datetime(payload.issued_at),
            expires_at: payload.expires_at.map(|ts| timestamp_to_datetime(ts)),
            limits,
            signature: payload.signature.clone(),
        };

        self.store
            .upsert_license(&license)
            .map_err(|err| LicenseError::new("LICENSE_DB_ERROR", err.to_string()))?;
        self.reset_usage(identity_id)
            .map_err(|err| LicenseError::new("LICENSE_DB_ERROR", err.to_string()))?;
        Ok(license)
    }

    pub fn status(&self, identity_id: &str) -> Result<LicenseStatus> {
        let license = self.active_license(identity_id)?;
        let usage = self
            .store
            .get_usage(identity_id)
            .context("failed to load license usage")?;
        let expires_at = license.expires_at.map(|dt| dt.timestamp_millis());
        Ok(LicenseStatus {
            identity_id: identity_id.to_string(),
            tier: license.tier.label().to_string(),
            license_key: license.key.clone(),
            issued_at: license.issued_at.timestamp_millis(),
            expires_at,
            limits: license.limits.clone(),
            p2p_used: usage.p2p_used,
            p2p_quota: license.limits.p2p_monthly_quota,
        })
    }
}

fn verify_license_signature(
    verify_key: &VerifyingKey,
    signature_hex: &str,
    payload: &RawLicensePayload,
) -> Result<(), LicenseError> {
    let bytes = hex::decode(signature_hex).map_err(|_| {
        LicenseError::new(
            "LICENSE_SIGNATURE_INVALID",
            "许可证签名不是合法的十六进制字符串",
        )
    })?;
    if bytes.len() != 64 {
        return Err(LicenseError::new(
            "LICENSE_SIGNATURE_INVALID",
            "许可证签名字节长度不正确",
        ));
    }
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&bytes);
    let signature = Signature::from_bytes(&sig_bytes);
    let message = payload.signing_payload();
    verify_key
        .verify(message.as_bytes(), &signature)
        .map_err(|_| LicenseError::new("LICENSE_SIGNATURE_INVALID", "许可证签名验证失败"))?;
    Ok(())
}

fn timestamp_to_datetime(ts: i64) -> DateTime<Utc> {
    Utc.timestamp_millis_opt(ts)
        .single()
        .unwrap_or_else(Utc::now)
}

fn default_limits_for_tier(tier: &LicenseTier) -> LicenseLimits {
    match tier {
        LicenseTier::Free => LicenseLimits::free_defaults(),
        LicenseTier::Pro => LicenseLimits::pro_defaults(),
        LicenseTier::Enterprise => LicenseLimits::enterprise_defaults(),
    }
}

fn parse_license_blob(blob: &str) -> Result<RawLicensePayload, LicenseError> {
    serde_json::from_str::<RawLicensePayload>(blob).map_err(|err| {
        LicenseError::new("LICENSE_PARSE_ERROR", format!("许可证内容解析失败: {err}"))
    })
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawLicensePayload {
    pub key: String,
    pub tier: Option<LicenseTier>,
    pub identity_id: Option<String>,
    pub issued_at: i64,
    pub expires_at: Option<i64>,
    pub limits: Option<LicenseLimits>,
    pub signature: Option<String>,
}

impl RawLicensePayload {
    fn signing_payload(&self) -> String {
        let limits = self
            .limits
            .as_ref()
            .and_then(|value| serde_json::to_string(value).ok())
            .unwrap_or_else(|| "null".into());
        format!(
            "quantumdrop.license.v1|{key}|{tier}|{identity}|{issued}|{expires}|{limits}",
            key = self.key,
            tier = self
                .tier
                .as_ref()
                .map(|tier| tier.label())
                .unwrap_or("free"),
            identity = self.identity_id.as_deref().unwrap_or("*"),
            issued = self.issued_at,
            expires = self
                .expires_at
                .map(|value| value.to_string())
                .unwrap_or_else(|| "0".into()),
            limits = limits
        )
    }
}

impl From<LicenseError> for anyhow::Error {
    fn from(value: LicenseError) -> Self {
        anyhow::anyhow!("{}: {}", value.code, value.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::IdentityStore;
    use rand::{rngs::OsRng, RngCore};
    use serde_json::json;
    use std::sync::{Mutex, OnceLock};
    use tempfile::tempdir;

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock")
    }

    #[test]
    fn activate_license_rejects_identity_mismatch() {
        let _env = env_guard();
        let temp = tempdir().expect("temp dir");
        let store = IdentityStore::with_path(temp.path().join("identities.sqlite")).expect("store");
        store
            .register_identity("id-valid", &random_hex(32), Some("Valid"))
            .expect("register identity");
        let _allow_guard = EnvOverride::set("QD_LICENSE_ALLOW_UNSIGNED", "1".into());
        let _key_guard = EnvOverride::set("QD_LICENSE_PUBKEY", "".into());
        let manager = LicenseManager::new(&store).expect("manager");
        let payload = json!({
            "key": "QD-PRO-TEST-0001",
            "tier": LicenseTier::Pro,
            "identityId": "other-id",
            "issuedAt": 1_700_000_000_000i64,
            "expiresAt": 1_800_000_000_000i64,
            "limits": LicenseLimits::pro_defaults(),
        });
        let blob = serde_json::to_string(&payload).expect("blob");
        let err = manager
            .activate_license("id-valid", &blob)
            .expect_err("should reject mismatched identity");
        assert_eq!(err.code, "LICENSE_ID_MISMATCH");
    }

    #[test]
    fn activate_license_requires_signature_when_verification_enabled() {
        let _env = env_guard();
        let temp = tempdir().expect("temp dir");
        let store = IdentityStore::with_path(temp.path().join("identities.sqlite")).expect("store");
        store
            .register_identity("id-verify", &random_hex(32), Some("Verify"))
            .expect("register identity");
        let mut rng = OsRng;
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
        let _pubkey_guard = EnvOverride::set(
            "QD_LICENSE_PUBKEY",
            hex::encode(signing_key.verifying_key().to_bytes()),
        );
        let _allow_guard = EnvOverride::set("QD_LICENSE_ALLOW_UNSIGNED", "0".into());
        let manager = LicenseManager::new(&store).expect("manager");
        let payload = json!({
            "key": "QD-PRO-TEST-0002",
            "tier": LicenseTier::Pro,
            "identityId": "id-verify",
            "issuedAt": 1_700_000_000_000i64,
            "expiresAt": 1_800_000_000_000i64,
            "limits": LicenseLimits::pro_defaults(),
        });
        let blob = serde_json::to_string(&payload).expect("blob");
        let err = manager
            .activate_license("id-verify", &blob)
            .expect_err("missing signature should be rejected");
        assert_eq!(err.code, "LICENSE_SIGNATURE_MISSING");
    }

    fn random_hex(bytes: usize) -> String {
        let mut rng = rand::thread_rng();
        let mut buf = vec![0u8; bytes];
        rng.fill_bytes(&mut buf);
        hex::encode(buf)
    }

    struct EnvOverride {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvOverride {
        fn set(key: &'static str, value: String) -> Self {
            let previous = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for EnvOverride {
        fn drop(&mut self) {
            if let Some(prev) = &self.previous {
                std::env::set_var(self.key, prev);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    #[test]
    fn activate_license_allows_unsigned_when_enabled() {
        let _env = env_guard();
        let temp = tempfile::tempdir().expect("temp dir");
        let store = IdentityStore::with_path(temp.path().join("identities.sqlite")).expect("store");
        store
            .register_identity("id-unsigned", &random_hex(32), Some("Unsigned"))
            .expect("identity");
        let _allow_guard = EnvOverride::set("QD_LICENSE_ALLOW_UNSIGNED", "1".into());
        std::env::remove_var("QD_LICENSE_PUBKEY");
        let manager = LicenseManager::new(&store).expect("manager");
        let payload = json!({
            "key": "QD-PRO-UNSIGNED",
            "tier": LicenseTier::Pro,
            "identityId": "id-unsigned",
            "issuedAt": 1_700_000_000_000i64,
            "expiresAt": 1_800_000_000_000i64,
            "limits": LicenseLimits::pro_defaults()
        });
        let blob = serde_json::to_string(&payload).expect("blob");
        let license = manager
            .activate_license("id-unsigned", &blob)
            .expect("activation");
        assert_eq!(license.identity_id, "id-unsigned");
    }

    #[test]
    fn enforce_device_limit_blocks_when_count_reached() {
        let _env = env_guard();
        let temp = tempfile::tempdir().expect("temp dir");
        let store = IdentityStore::with_path(temp.path().join("identities.sqlite")).expect("store");
        store
            .register_identity("id-devices", &random_hex(32), Some("Devices"))
            .expect("identity");
        store
            .register_device(
                "id-devices",
                "device-a",
                &random_hex(32),
                Some("primary"),
                "active",
            )
            .expect("device");
        let manager = LicenseManager::new(&store).expect("manager");
        let mut limits = LicenseLimits::pro_defaults();
        limits.max_devices = Some(1);
        let license = License {
            key: Some("QD-PRO-DEV".into()),
            tier: LicenseTier::Pro,
            identity_id: "id-devices".into(),
            issued_at: Utc::now(),
            expires_at: None,
            limits,
            signature: None,
        };
        let err = manager
            .enforce_device_limit(&license)
            .expect_err("limit exceeded");
        assert_eq!(err.code, "DEVICE_LIMIT_EXCEEDED");
    }

    #[test]
    fn enforce_file_size_rejects_large_payload() {
        let _env = env_guard();
        let temp = tempfile::tempdir().expect("temp dir");
        let store = IdentityStore::with_path(temp.path().join("identities.sqlite")).expect("store");
        store
            .register_identity("id-files", &random_hex(32), Some("Files"))
            .expect("identity");
        let manager = LicenseManager::new(&store).expect("manager");
        let mut limits = LicenseLimits::pro_defaults();
        limits.max_file_size_mb = Some(512);
        let license = License {
            key: Some("QD-PRO-FILES".into()),
            tier: LicenseTier::Pro,
            identity_id: "id-files".into(),
            issued_at: Utc::now(),
            expires_at: None,
            limits,
            signature: None,
        };
        let err = manager
            .enforce_file_size(&license, 600 * 1024 * 1024)
            .expect_err("file too large");
        assert_eq!(err.code, "FILE_SIZE_EXCEEDED");
    }

    #[test]
    fn ensure_p2p_quota_errors_after_usage() {
        let _env = env_guard();
        let temp = tempfile::tempdir().expect("temp dir");
        let store = IdentityStore::with_path(temp.path().join("identities.sqlite")).expect("store");
        store
            .register_identity("id-quota", &random_hex(32), Some("Quota"))
            .expect("identity");
        let manager = LicenseManager::new(&store).expect("manager");
        let mut limits = LicenseLimits::pro_defaults();
        limits.p2p_monthly_quota = Some(2);
        let license = License {
            key: Some("QD-PRO-P2P".into()),
            tier: LicenseTier::Pro,
            identity_id: "id-quota".into(),
            issued_at: Utc::now(),
            expires_at: None,
            limits,
            signature: None,
        };
        let usage = manager.ensure_p2p_quota(&license).expect("initial quota");
        manager.record_p2p_usage(&usage).expect("record first");
        let usage = manager.ensure_p2p_quota(&license).expect("second quota");
        manager.record_p2p_usage(&usage).expect("record second");
        let err = manager
            .ensure_p2p_quota(&license)
            .expect_err("quota exceeded");
        assert_eq!(err.code, "P2P_QUOTA_EXCEEDED");
    }
}
