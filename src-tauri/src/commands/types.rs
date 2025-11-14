use std::{fmt, io};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    audit::AuditEntry,
    config::default_lan_streams,
    license::{LicenseError, LicenseLimits, LicenseStatus},
    metrics::RouteMetricsSnapshot,
    store::TransferStatsRecord,
};
fn default_true() -> bool {
    true
}

fn default_intensity() -> u8 {
    2
}

fn default_speed() -> f32 {
    1.0
}

fn default_quality() -> String {
    "medium".to_string()
}

fn default_fps() -> u16 {
    60
}

#[derive(Debug, Clone, Serialize)]
pub struct GenerateCodeResponse {
    pub task_id: String,
    pub code: String,
    pub qr_data_url: Option<String>,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TaskResponse {
    pub task_id: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SenderInfoDto {
    pub code: String,
    pub device_name: String,
    pub host: String,
    pub port: u16,
    pub public_key: String,
    pub cert_fingerprint: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteMetricsDto {
    pub route: String,
    pub attempts: u64,
    pub successes: u64,
    pub failures: u64,
    pub success_rate: Option<f32>,
    pub avg_latency_ms: Option<f32>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferStatsDto {
    pub total_transfers: u64,
    pub total_bytes: u64,
    pub success_count: u64,
    pub failure_count: u64,
    pub success_rate: f32,
    pub lan_percent: f32,
    pub p2p_percent: f32,
    pub relay_percent: f32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditLogDto {
    pub id: String,
    pub timestamp: i64,
    pub event_type: String,
    pub identity_id: Option<String>,
    pub device_id: Option<String>,
    pub task_id: Option<String>,
    pub details: Value,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LicenseStatusDto {
    pub identity_id: String,
    pub tier: String,
    pub license_key: Option<String>,
    pub issued_at: i64,
    pub expires_at: Option<i64>,
    pub limits: LicenseLimitsDto,
    pub p2p_used: u32,
    pub p2p_quota: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LicenseLimitsDto {
    pub p2p_monthly_quota: Option<u32>,
    pub max_file_size_mb: Option<u64>,
    pub max_devices: Option<usize>,
    pub resume_enabled: bool,
    pub history_days: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportPotResponse {
    pub pot_path: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyPotResponse {
    pub valid: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct P2pSmokeTestResponse {
    pub route: String,
    pub bytes_echoed: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransferSummary {
    pub task_id: String,
    pub code: Option<String>,
    pub direction: TransferDirection,
    pub status: TransferStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub route: Option<TransferRoute>,
    pub files: Vec<TransferFileSummary>,
    pub pot_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransferFileSummary {
    pub name: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TransferDirection {
    Send,
    Receive,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TransferStatus {
    Pending,
    InProgress,
    Completed,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TransferPhase {
    Preparing,
    Pairing,
    Connecting,
    Transferring,
    Finalizing,
    Done,
    Error,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TransferRoute {
    Lan,
    P2p,
    Relay,
    Cache,
}

impl TransferRoute {
    pub fn from_label(label: &str) -> Option<Self> {
        match label.to_ascii_lowercase().as_str() {
            "lan" => Some(TransferRoute::Lan),
            "p2p" => Some(TransferRoute::P2p),
            "relay" => Some(TransferRoute::Relay),
            "cache" => Some(TransferRoute::Cache),
            _ => None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            TransferRoute::Lan => "lan",
            TransferRoute::P2p => "p2p",
            TransferRoute::Relay => "relay",
            TransferRoute::Cache => "cache",
        }
    }
}

impl From<RouteMetricsSnapshot> for RouteMetricsDto {
    fn from(value: RouteMetricsSnapshot) -> Self {
        Self {
            route: value.route,
            attempts: value.attempts,
            successes: value.successes,
            failures: value.failures,
            success_rate: value.success_rate,
            avg_latency_ms: value.avg_latency_ms,
            last_error: value.last_error,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResumeProgressDto {
    pub chunk_size: u64,
    pub total_chunks: u64,
    pub received_chunks: Vec<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransferProgressEvent {
    pub task_id: String,
    pub phase: TransferPhase,
    pub progress: Option<f32>,
    pub bytes_sent: Option<u64>,
    pub bytes_total: Option<u64>,
    pub speed_bps: Option<u64>,
    pub route: Option<TransferRoute>,
    pub route_attempts: Option<Vec<String>>,
    pub message: Option<String>,
    pub resume: Option<ResumeProgressDto>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransferLifecycleEvent {
    pub task_id: String,
    pub direction: TransferDirection,
    pub code: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityRegistrationPayload {
    pub identity_id: String,
    pub public_key: String,
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityResponse {
    pub identity_id: String,
    pub public_key: String,
    pub label: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRegistrationPayload {
    pub identity_id: String,
    pub device_id: String,
    pub public_key: String,
    pub name: Option<String>,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceResponse {
    pub device_id: String,
    pub identity_id: String,
    pub public_key: String,
    pub name: Option<String>,
    pub status: String,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicesQueryPayload {
    pub identity_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityRefPayload {
    pub identity_id: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicesResponse {
    pub items: Vec<DeviceResponse>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntitlementUpdatePayload {
    pub identity_id: String,
    pub plan: String,
    pub expires_at: Option<i64>,
    #[serde(default)]
    pub features: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LicenseActivatePayload {
    pub identity_id: String,
    pub license_blob: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntitlementDto {
    pub identity_id: String,
    pub plan: String,
    pub expires_at: Option<i64>,
    pub features: Vec<String>,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsPayload {
    pub preferred_routes: Vec<String>,
    pub code_expire_sec: i64,
    pub relay_enabled: bool,
    pub chunk_policy: ChunkPolicyPayload,
    #[serde(default = "default_true")]
    pub quantum_mode: bool,
    #[serde(default = "default_true")]
    pub minimal_quantum_ui: bool,
    #[serde(default = "default_intensity")]
    pub quantum_intensity: u8,
    #[serde(default = "default_speed")]
    pub quantum_speed: f32,
    #[serde(default = "default_true", rename = "animationsEnabled")]
    pub animations_enabled: bool,
    #[serde(default = "default_true", rename = "audioEnabled")]
    pub audio_enabled: bool,
    #[serde(default = "default_true", rename = "enable3DQuantum")]
    pub enable3d_quantum: bool,
    #[serde(default = "default_quality", rename = "quantum3DQuality")]
    pub quantum3d_quality: String,
    #[serde(default = "default_fps", rename = "quantum3DFps")]
    pub quantum3d_fps: u16,
    #[serde(default = "default_true", rename = "wormholeMode")]
    pub wormhole_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChunkPolicyPayload {
    pub adaptive: bool,
    pub min_bytes: u64,
    pub max_bytes: u64,
    #[serde(default = "default_lan_streams")]
    pub lan_streams: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    EUnknown,
    EInvalidInput,
    ENotFound,
    ECodeExpired,
    ERouteUnreach,
    EDiskFull,
    EVerifyFail,
    EPermDenied,
    ELicense,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandError {
    pub code: ErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatedPayload<T> {
    pub identity_id: String,
    pub device_id: String,
    pub signature: String,
    #[serde(bound(deserialize = "T: Deserialize<'de>"))]
    pub payload: T,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedPathsPayload {
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedReceivePayload {
    pub code: String,
    pub save_dir: String,
    pub host: String,
    pub port: u16,
    pub sender_public_key: String,
    pub sender_cert_fingerprint: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectByCodePayload {
    pub code: String,
    pub save_dir: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebRtcSenderPayload {
    pub code: String,
    pub file_paths: Vec<String>,
    pub device_public_key: String,
    pub device_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebRtcReceiverPayload {
    pub code: String,
    pub save_dir: String,
    pub device_public_key: String,
    pub device_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeartbeatPayload {
    pub status: Option<String>,
    pub capabilities: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceUpdatePayload {
    pub name: Option<String>,
    pub status: Option<String>,
    pub capabilities: Option<Vec<String>>,
}

impl CommandError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::EInvalidInput, message)
    }

    pub fn not_found() -> Self {
        Self::new(ErrorCode::ENotFound, "resource not found")
    }

    pub fn code_expired() -> Self {
        Self::new(ErrorCode::ECodeExpired, "session code expired")
    }

    pub fn route_unreachable(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::ERouteUnreach, message)
    }

    pub fn disk_full(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::EDiskFull, message)
    }

    pub fn verify_failed(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::EVerifyFail, message)
    }

    pub fn permission_denied(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::EPermDenied, message)
    }

    pub fn unknown(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::EUnknown, message)
    }

    pub fn license_violation(error: LicenseError) -> Self {
        Self::new(
            ErrorCode::ELicense,
            format!("{}: {}", error.code, error.message),
        )
    }

    pub fn from_io(err: &io::Error, context: impl Into<String>) -> Self {
        let context_str = context.into();
        match err.kind() {
            io::ErrorKind::PermissionDenied => {
                Self::permission_denied(format!("{context_str}: {err}"))
            }
            io::ErrorKind::NotFound => {
                Self::new(ErrorCode::ENotFound, format!("{context_str}: {err}"))
            }
            io::ErrorKind::StorageFull | io::ErrorKind::WriteZero => {
                Self::disk_full(format!("{context_str}: {err}"))
            }
            _ => Self::unknown(format!("{context_str}: {err}")),
        }
    }
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl<E> From<E> for CommandError
where
    E: Into<anyhow::Error>,
{
    fn from(value: E) -> Self {
        let err = value.into();
        CommandError::unknown(err.to_string())
    }
}

impl From<LicenseStatus> for LicenseStatusDto {
    fn from(value: LicenseStatus) -> Self {
        Self {
            identity_id: value.identity_id,
            tier: value.tier,
            license_key: value.license_key,
            issued_at: value.issued_at,
            expires_at: value.expires_at,
            limits: value.limits.into(),
            p2p_used: value.p2p_used,
            p2p_quota: value.p2p_quota,
        }
    }
}

impl From<TransferStatsRecord> for TransferStatsDto {
    fn from(value: TransferStatsRecord) -> Self {
        let total = value.total_transfers.max(1);
        let percent = |count: u64| (count as f32 / total as f32) * 100.0;
        let success_rate = if value.total_transfers == 0 {
            0.0
        } else {
            value.success_count as f32 / value.total_transfers as f32
        };
        Self {
            total_transfers: value.total_transfers,
            total_bytes: value.total_bytes,
            success_count: value.success_count,
            failure_count: value.failure_count,
            success_rate,
            lan_percent: percent(value.lan_count),
            p2p_percent: percent(value.p2p_count),
            relay_percent: percent(value.relay_count),
        }
    }
}

impl From<AuditEntry> for AuditLogDto {
    fn from(value: AuditEntry) -> Self {
        Self {
            id: value.id,
            timestamp: value.timestamp,
            event_type: value.event_type,
            identity_id: value.identity_id,
            device_id: value.device_id,
            task_id: value.task_id,
            details: value.details,
        }
    }
}

impl From<LicenseLimits> for LicenseLimitsDto {
    fn from(value: LicenseLimits) -> Self {
        Self {
            p2p_monthly_quota: value.p2p_monthly_quota,
            max_file_size_mb: value.max_file_size_mb,
            max_devices: value.max_devices,
            resume_enabled: value.resume_enabled,
            history_days: value.history_days,
        }
    }
}

impl From<crate::transport::RouteKind> for TransferRoute {
    fn from(value: crate::transport::RouteKind) -> Self {
        match value {
            crate::transport::RouteKind::Lan => TransferRoute::Lan,
            crate::transport::RouteKind::P2p => TransferRoute::P2p,
            crate::transport::RouteKind::Relay => TransferRoute::Relay,
            crate::transport::RouteKind::MockLocal => TransferRoute::Cache,
        }
    }
}
