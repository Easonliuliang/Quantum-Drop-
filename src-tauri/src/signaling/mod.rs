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

/// Aggregate WebRTC session state exchanged via the signaling channel.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionDesc {
    pub session_id: String,
    #[serde(default)]
    pub offer: Option<SessionDescription>,
    #[serde(default)]
    pub answer: Option<SessionDescription>,
    #[serde(default)]
    pub candidates: Vec<IceCandidate>,
    #[serde(default)]
    pub signer_device_id: Option<String>,
    #[serde(default)]
    pub signer_device_name: Option<String>,
    #[serde(default)]
    pub signer_public_key: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
}

#[allow(dead_code)]
impl SessionDesc {
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            offer: None,
            answer: None,
            candidates: Vec::new(),
            signer_device_id: None,
            signer_device_name: None,
            signer_public_key: None,
            signature: None,
        }
    }

    /// Merge partial updates, replacing offer/answer and appending candidates.
    pub fn merge(&mut self, update: SessionDesc) {
        if update.offer.is_some() {
            self.offer = update.offer;
        }
        if update.answer.is_some() {
            self.answer = update.answer;
        }
        if !update.candidates.is_empty() {
            self.candidates.extend(update.candidates);
        }
    }
}

#[cfg(feature = "signaling-server")]
mod server;

#[cfg(feature = "signaling-server")]
pub use server::router as signaling_router;
