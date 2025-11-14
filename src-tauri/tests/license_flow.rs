use anyhow::Result;
use chrono::Utc;
use courier_agent::{
    license::{LicenseLimits, LicenseManager, LicenseTier},
    store::IdentityStore,
};
use ed25519_dalek::{Signer, SigningKey};
use rand::{rngs::OsRng, RngCore};
use serde_json::json;
use tempfile::tempdir;

const SIGNING_PREFIX: &str = "quantumdrop.license.v1";

#[test]
fn license_activation_flow_enforces_limits() -> Result<()> {
    let temp = tempdir()?;
    let db_path = temp.path().join("identities.sqlite3");
    let identity_store = IdentityStore::with_path(&db_path)?;
    let identity_id = "id_e2e_license_flow";
    let identity_key = random_hex(32);
    identity_store.register_identity(identity_id, &identity_key, Some("E2E Tester"))?;
    identity_store.register_device(
        identity_id,
        "device-primary",
        &random_hex(32),
        Some("Primary"),
        "active",
    )?;

    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let _pubkey_guard = EnvOverride::set(
        "QD_LICENSE_PUBKEY",
        hex::encode(signing_key.verifying_key().to_bytes()),
    );
    let _allow_guard = EnvOverride::set("QD_LICENSE_ALLOW_UNSIGNED", "0".into());

    let manager = LicenseManager::new(&identity_store)?;

    let limits = LicenseLimits {
        p2p_monthly_quota: Some(2),
        max_file_size_mb: Some(512),
        max_devices: Some(1),
        resume_enabled: true,
        history_days: Some(30),
    };

    let license_blob =
        issue_license_blob(&signing_key, identity_id, LicenseTier::Pro, &limits, 30)?;

    let license = manager.activate_license(identity_id, &license_blob)?;
    assert_eq!(license.identity_id, identity_id);
    assert_eq!(license.limits.max_devices, Some(1));

    let device_err = manager
        .enforce_device_limit(&license)
        .expect_err("device enforcement should fail");
    assert_eq!(device_err.code, "DEVICE_LIMIT_EXCEEDED");

    let file_err = manager
        .enforce_file_size(&license, 600 * 1024 * 1024)
        .expect_err("file size enforcement should fail");
    assert_eq!(file_err.code, "FILE_SIZE_EXCEEDED");

    let usage = manager.ensure_p2p_quota(&license)?;
    manager.record_p2p_usage(&usage)?;
    let usage = manager.ensure_p2p_quota(&license)?;
    manager.record_p2p_usage(&usage)?;
    let quota_err = manager
        .ensure_p2p_quota(&license)
        .expect_err("p2p quota enforcement should fail");
    assert_eq!(quota_err.code, "P2P_QUOTA_EXCEEDED");

    Ok(())
}

fn issue_license_blob(
    signing_key: &SigningKey,
    identity_id: &str,
    tier: LicenseTier,
    limits: &LicenseLimits,
    valid_days: i64,
) -> Result<String> {
    assert!(valid_days > 0, "valid_days must be positive");
    let issued_at = Utc::now().timestamp_millis();
    let expires_at = issued_at + valid_days * 86_400_000;
    let key = format!(
        "QD-{}-{}",
        tier.label().to_ascii_uppercase(),
        uuid::Uuid::new_v4()
            .to_string()
            .replace('-', "")
            .chars()
            .take(12)
            .collect::<String>()
            .to_ascii_uppercase()
    );
    let payload = signing_payload(
        &key,
        &tier,
        identity_id,
        issued_at,
        Some(expires_at),
        limits,
    )?;
    let signature = signing_key.sign(payload.as_bytes());
    let json_payload = json!({
        "key": key,
        "tier": tier,
        "identityId": identity_id,
        "issuedAt": issued_at,
        "expiresAt": expires_at,
        "limits": limits,
        "signature": hex::encode(signature.to_bytes()),
    });
    Ok(serde_json::to_string(&json_payload)?)
}

fn signing_payload(
    key: &str,
    tier: &LicenseTier,
    identity_id: &str,
    issued_at: i64,
    expires_at: Option<i64>,
    limits: &LicenseLimits,
) -> Result<String> {
    let limits_json = serde_json::to_string(limits)?;
    let expires = expires_at
        .map(|value| value.to_string())
        .unwrap_or_else(|| "0".to_string());
    Ok(format!(
        "{prefix}|{key}|{tier}|{identity}|{issued}|{expires}|{limits}",
        prefix = SIGNING_PREFIX,
        key = key,
        tier = tier.label(),
        identity = identity_id,
        issued = issued_at,
        expires = expires,
        limits = limits_json
    ))
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
