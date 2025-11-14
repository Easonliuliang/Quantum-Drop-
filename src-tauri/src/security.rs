use std::fs;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

fn default_enforce_signature() -> bool {
    cfg!(not(debug_assertions))
}

fn default_disconnect_on_fail() -> bool {
    true
}

fn default_audit_log() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityConfig {
    #[serde(default = "default_enforce_signature")]
    pub enforce_signature_verification: bool,
    #[serde(default = "default_disconnect_on_fail")]
    pub disconnect_on_verification_fail: bool,
    #[serde(default = "default_audit_log")]
    pub enable_audit_log: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enforce_signature_verification: default_enforce_signature(),
            disconnect_on_verification_fail: default_disconnect_on_fail(),
            enable_audit_log: default_audit_log(),
        }
    }
}

impl SecurityConfig {
    pub fn load(app: &AppHandle) -> Self {
        let mut config = Self::default();
        if let Ok(Some(file_cfg)) = Self::load_from_file(app) {
            config = file_cfg;
        }
        config.apply_env();
        config
    }

    fn load_from_file(app: &AppHandle) -> anyhow::Result<Option<Self>> {
        let mut path = app
            .path()
            .app_data_dir()
            .context("failed to resolve app data dir for security config")?;
        path.push("config");
        path.push("app.yaml");
        if !path.exists() {
            return Ok(None);
        }
        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed to read security config {}", path.display()))?;
        let value: serde_yaml::Value = serde_yaml::from_str(&content)
            .with_context(|| format!("invalid yaml in {}", path.display()))?;
        if let Some(security) = value.get("security") {
            let parsed: SecurityConfig = serde_yaml::from_value(security.clone())
                .context("invalid security configuration block")?;
            Ok(Some(parsed))
        } else {
            Ok(None)
        }
    }

    fn apply_env(&mut self) {
        if let Ok(value) = std::env::var("QD_ENFORCE_SIGNATURE") {
            if let Ok(parsed) = value.parse::<bool>() {
                self.enforce_signature_verification = parsed;
            }
        }
        if let Ok(value) = std::env::var("QD_DISCONNECT_ON_FAIL") {
            if let Ok(parsed) = value.parse::<bool>() {
                self.disconnect_on_verification_fail = parsed;
            }
        }
        if let Ok(value) = std::env::var("QD_ENABLE_AUDIT_LOG") {
            if let Ok(parsed) = value.parse::<bool>() {
                self.enable_audit_log = parsed;
            }
        }
    }
}
