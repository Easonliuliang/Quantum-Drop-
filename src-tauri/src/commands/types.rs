use std::{fmt, io};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize)]
pub struct GenerateCodeResponse {
    pub task_id: String,
    pub code: String,
    pub qr_data_url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TaskResponse {
    pub task_id: String,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsPayload {
    pub preferred_routes: Vec<String>,
    pub code_expire_sec: i64,
    pub relay_enabled: bool,
    pub chunk_policy: ChunkPolicyPayload,
    #[serde(default = "default_true")]
    pub quantum_mode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChunkPolicyPayload {
    pub adaptive: bool,
    pub min_bytes: u64,
    pub max_bytes: u64,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandError {
    pub code: ErrorCode,
    pub message: String,
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
