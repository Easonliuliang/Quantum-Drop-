use std::fmt;

use chrono::{DateTime, Utc};
use serde::Serialize;

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
pub struct ExportPotResponse {
    pub pot_path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyPotResponse {
    pub valid: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransferSummary {
    pub task_id: String,
    pub code: Option<String>,
    pub direction: TransferDirection,
    pub status: TransferStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub files: Vec<TransferFileSummary>,
    pub pot_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransferFileSummary {
    pub name: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TransferDirection {
    Send,
    Receive,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TransferStatus {
    Pending,
    InProgress,
    Completed,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
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

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TransferRoute {
    Lan,
    P2p,
    Relay,
    Cache,
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
}

#[derive(Debug, Clone, Serialize)]
pub struct TransferLifecycleEvent {
    pub task_id: String,
    pub direction: TransferDirection,
    pub code: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug)]
pub enum CommandError {
    NotFound,
    InvalidInput(String),
    Internal(anyhow::Error),
}

impl CommandError {
    pub fn invalid(msg: impl Into<String>) -> Self {
        CommandError::InvalidInput(msg.into())
    }
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CommandError::NotFound => write!(f, "resource not found"),
            CommandError::InvalidInput(msg) => write!(f, "{msg}"),
            CommandError::Internal(err) => write!(f, "{err}"),
        }
    }
}

impl<E> From<E> for CommandError
where
    E: Into<anyhow::Error>,
{
    fn from(value: E) -> Self {
        CommandError::Internal(value.into())
    }
}
