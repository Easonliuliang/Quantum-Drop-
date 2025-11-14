use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LicenseTier {
    Free,
    Pro,
    Enterprise,
}

impl LicenseTier {
    pub fn from_str(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "pro" => LicenseTier::Pro,
            "enterprise" | "team" | "business" => LicenseTier::Enterprise,
            _ => LicenseTier::Free,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            LicenseTier::Free => "free",
            LicenseTier::Pro => "pro",
            LicenseTier::Enterprise => "enterprise",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LicenseLimits {
    pub p2p_monthly_quota: Option<u32>,
    pub max_file_size_mb: Option<u64>,
    pub max_devices: Option<usize>,
    pub resume_enabled: bool,
    pub history_days: Option<u32>,
}

impl LicenseLimits {
    pub fn free_defaults() -> Self {
        Self {
            p2p_monthly_quota: Some(10),
            max_file_size_mb: Some(2048), // 2GB
            max_devices: Some(3),
            resume_enabled: false,
            history_days: Some(7),
        }
    }

    pub fn pro_defaults() -> Self {
        Self {
            p2p_monthly_quota: None,
            max_file_size_mb: None,
            max_devices: None,
            resume_enabled: true,
            history_days: None,
        }
    }

    pub fn enterprise_defaults() -> Self {
        Self {
            p2p_monthly_quota: None,
            max_file_size_mb: None,
            max_devices: None,
            resume_enabled: true,
            history_days: None,
        }
    }
}

impl Default for LicenseLimits {
    fn default() -> Self {
        Self::free_defaults()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct License {
    pub key: Option<String>,
    pub tier: LicenseTier,
    pub identity_id: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub limits: LicenseLimits,
    pub signature: Option<String>,
}

impl License {
    pub fn free(identity_id: impl Into<String>) -> Self {
        Self {
            key: None,
            tier: LicenseTier::Free,
            identity_id: identity_id.into(),
            issued_at: Utc::now(),
            expires_at: None,
            limits: LicenseLimits::free_defaults(),
            signature: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LicenseStatus {
    pub identity_id: String,
    pub tier: String,
    pub license_key: Option<String>,
    pub issued_at: i64,
    pub expires_at: Option<i64>,
    pub limits: LicenseLimits,
    pub p2p_used: u32,
    pub p2p_quota: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct LicenseError {
    pub code: &'static str,
    pub message: String,
}

impl LicenseError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}
