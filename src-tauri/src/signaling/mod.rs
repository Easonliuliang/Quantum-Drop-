//! Signaling façade for the minimum viable wormhole.

use chrono::{DateTime, Utc};
use serde::Serialize;
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
