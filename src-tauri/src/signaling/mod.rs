//! Signaling façade for the minimum viable wormhole.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Clone)]
pub struct SessionTicket {
    pub ticket_id: String,
    pub code: String,
    pub created_at: DateTime<Utc>,
    pub expire_at: DateTime<Utc>,
}

impl SessionTicket {
    pub fn new(code: String, ttl_seconds: i64) -> Self {
        let created_at = Utc::now();
        let expire_at = created_at + chrono::Duration::seconds(ttl_seconds);
        Self {
            ticket_id: Uuid::new_v4().to_string(),
            code,
            created_at,
            expire_at,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionDescriptionType {
    Offer,
    Answer,
    Pranswer,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionDescription {
    #[serde(rename = "type")]
    pub kind: SessionDescriptionType,
    pub sdp: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceCandidate {
    pub candidate: String,
    #[serde(rename = "sdpMLineIndex", default)]
    pub sdp_mline_index: Option<u32>,
    #[serde(rename = "sdpMid", default)]
    pub sdp_mid: Option<String>,
}

#[cfg(feature = "signaling-server")]
mod server;

#[cfg(feature = "signaling-server")]
pub use server::router as signaling_router;
