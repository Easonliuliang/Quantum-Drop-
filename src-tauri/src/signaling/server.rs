use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::response::IntoResponse;
#[cfg(feature = "transport-relay")]
use axum::Json;
use axum::{routing::get, Router};
use futures::stream::SplitSink;
use futures::{SinkExt, StreamExt};
use hex::FromHex;
use serde::Deserialize;
use serde_json::{self, json};
use tokio::sync::{mpsc, RwLock};
use uuid::Uuid;

use ed25519_dalek::{ed25519::signature::Verifier, Signature as EdSignature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::security::SecurityConfig;

use super::SessionDesc;

pub type SharedState = Arc<SignalingState>;

#[derive(Debug, Clone)]
pub struct SignalingState {
    pub registry: SessionRegistry,
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Default)]
pub struct SessionRegistry {
    inner: Arc<RwLock<HashMap<String, SessionEntry>>>,
}

#[derive(Debug, Clone)]
pub struct SessionEntry {
    state: SessionDesc,
    peers: HashMap<Uuid, PeerHandle>,
}

#[derive(Clone, Debug)]
pub struct PeerHandle {
    tx: mpsc::UnboundedSender<SessionDesc>,
    device_id: String,
    device_name: Option<String>,
    public_key: Option<Vec<u8>>,
    fingerprint: Option<String>,
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn register(
        &self,
        session_id: &str,
        peer_id: Uuid,
        peer: PeerHandle,
    ) -> Option<SessionDesc> {
        let mut guard = self.inner.write().await;
        let entry = guard
            .entry(session_id.to_string())
            .or_insert_with(|| SessionEntry {
                state: SessionDesc::new(session_id.to_string()),
                peers: HashMap::new(),
            });
        entry.peers.insert(peer_id, peer);
        if entry.state.offer.is_some()
            || entry.state.answer.is_some()
            || !entry.state.candidates.is_empty()
        {
            Some(entry.state.clone())
        } else {
            None
        }
    }

    pub async fn merge_and_broadcast(
        &self,
        session_id: &str,
        from_peer: Uuid,
        mut update: SessionDesc,
        security: &SecurityConfig,
    ) -> Result<(), SignalingError> {
        let mut targets: Vec<mpsc::UnboundedSender<SessionDesc>> = Vec::new();
        let snapshot = {
            let mut guard = self.inner.write().await;
            let entry = guard
                .entry(session_id.to_string())
                .or_insert_with(|| SessionEntry {
                    state: SessionDesc::new(session_id.to_string()),
                    peers: HashMap::new(),
                });
            let peer = entry
                .peers
                .get(&from_peer)
                .ok_or(SignalingError::UnknownPeer)?;
            let verification_result = verify_signature(&update, peer);
            let signature_valid = verification_result.is_ok();
            if !signature_valid {
                if security.enable_audit_log {
                    log::warn!(
                        "signaling signature verification failed (session={}, device={})",
                        session_id,
                        peer.device_id
                    );
                }
                if security.enforce_signature_verification {
                    return Err(SignalingError::Signature(
                        verification_result
                            .err()
                            .unwrap_or_else(|| "invalid signature".into()),
                    ));
                }
                update.signature = None;
            }
            let mut signature_payload = update.signature.clone();
            if !signature_valid {
                signature_payload = None;
            }
            update.signer_device_id = Some(peer.device_id.clone());
            update.signer_device_name = peer.device_name.clone();
            update.signer_public_key = peer.public_key.as_ref().map(|pk| hex::encode(pk));
            update.signature = signature_payload.clone();

            let mut sanitized = update.clone();
            sanitized.signer_device_id = None;
            sanitized.signer_device_name = None;
            sanitized.signer_public_key = None;
            sanitized.signature = None;

            entry.state.merge(sanitized);
            let mut snapshot = entry.state.clone();
            snapshot.signer_device_id = update.signer_device_id.clone();
            snapshot.signer_device_name = update.signer_device_name.clone();
            snapshot.signer_public_key = update.signer_public_key.clone();
            snapshot.signature = signature_payload;

            for (peer_id, handle) in entry.peers.iter() {
                if *peer_id != from_peer {
                    targets.push(handle.tx.clone());
                }
            }
            snapshot
        };

        for sender in targets {
            let _ = sender.send(snapshot.clone());
        }
        Ok(())
    }

    pub async fn remove(&self, session_id: &str, peer_id: Uuid) {
        let mut guard = self.inner.write().await;
        if let Some(entry) = guard.get_mut(session_id) {
            entry.peers.remove(&peer_id);
            if entry.peers.is_empty() {
                guard.remove(session_id);
            }
        }
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct SessionQuery {
    #[serde(rename = "sessionId")]
    session_id: String,
    #[serde(rename = "deviceId")]
    device_id: Option<String>,
    #[serde(rename = "deviceName")]
    device_name: Option<String>,
    #[serde(rename = "publicKey")]
    public_key: Option<String>,
}

#[derive(Debug)]
pub enum SignalingError {
    UnknownPeer,
    Signature(String),
}

impl SignalingError {
    pub fn code(&self) -> &'static str {
        match self {
            SignalingError::UnknownPeer => "E_SESSION_UNKNOWN",
            SignalingError::Signature(_) => "E_SIGNATURE_INVALID",
        }
    }

    pub fn message(&self) -> String {
        match self {
            SignalingError::UnknownPeer => "peer not registered for session".into(),
            SignalingError::Signature(reason) => reason.clone(),
        }
    }
}

pub fn router(config: SecurityConfig) -> Router {
    let state = SignalingState {
        registry: SessionRegistry::new(),
        security: config,
    };
    let router = Router::new()
        .route("/ws", get(upgrade))
        .with_state(Arc::new(state));

    #[cfg(feature = "transport-relay")]
    let router = router.route("/relay", get(relay_registry));

    router
}

async fn upgrade(
    ws: WebSocketUpgrade,
    State(state): State<SharedState>,
    Query(query): Query<SessionQuery>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| async move {
        handle_socket(socket, state, query).await;
    })
}

async fn handle_socket(socket: WebSocket, state: SharedState, query: SessionQuery) {
    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<SessionDesc>();
    let peer_id = Uuid::new_v4();
    let (device_id, device_name, public_key, fingerprint) = parse_peer_metadata(&query, peer_id);
    let peer_handle = PeerHandle {
        tx: tx.clone(),
        device_id: device_id.clone(),
        device_name: device_name.clone(),
        public_key: public_key.clone(),
        fingerprint,
    };

    if let Some(snapshot) = state
        .registry
        .register(&query.session_id, peer_id, peer_handle)
        .await
    {
        if send_snapshot(&mut sender, &snapshot).await.is_err() {
            state.registry.remove(&query.session_id, peer_id).await;
            return;
        }
    }

    loop {
        tokio::select! {
            biased;
            Some(update) = rx.recv() => {
                if send_snapshot(&mut sender, &update).await.is_err() {
                    break;
                }
            }
            maybe_msg = receiver.next() => {
                match maybe_msg {
                    Some(Ok(Message::Text(text))) => {
                        match serde_json::from_str::<SessionDesc>(&text) {
                            Ok(mut update) => {
                                update.session_id = query.session_id.clone();
                                match state
                                    .registry
                                    .merge_and_broadcast(
                                        &query.session_id,
                                        peer_id,
                                        update,
                                        &state.security,
                                    )
                                    .await
                                {
                                    Ok(()) => {}
                                    Err(err) => {
                                        let payload = serde_json::json!({
                                            "error": err.code(),
                                            "reason": err.message()
                                        })
                                        .to_string();
                                        let _ = sender.send(Message::Text(payload)).await;
                                        if state.security.disconnect_on_verification_fail {
                                            break;
                                        }
                                    }
                                }
                            }
                            Err(err) => {
                                let _ = sender.send(Message::Text(format!("error: {err}"))).await;
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) => break,
                    Some(Ok(Message::Ping(payload))) => {
                        if sender.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Binary(_))) => {}
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Err(_)) => break,
                    None => break,
                }
            }
        }
    }

    state.registry.remove(&query.session_id, peer_id).await;
}

async fn send_snapshot(
    sender: &mut SplitSink<WebSocket, Message>,
    snapshot: &SessionDesc,
) -> Result<(), axum::Error> {
    let text = serde_json::to_string(snapshot).unwrap_or_default();
    sender.send(Message::Text(text)).await
}

#[cfg(feature = "transport-relay")]
#[derive(Debug, serde::Serialize)]
struct RelayRegistryResponse {
    host: String,
    port: u16,
}

#[cfg(feature = "transport-relay")]
async fn relay_registry() -> Json<RelayRegistryResponse> {
    Json(RelayRegistryResponse {
        host: "127.0.0.1".into(),
        port: 0,
    })
}

const SIGNATURE_DOMAIN: &str = "quantumdrop.signaling.v1";

fn parse_peer_metadata(
    query: &SessionQuery,
    peer_id: Uuid,
) -> (String, Option<String>, Option<Vec<u8>>, Option<String>) {
    let device_id = query
        .device_id
        .clone()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("peer-{peer_id}"));
    let device_name = query.device_name.clone();
    let public_key = query
        .public_key
        .as_ref()
        .and_then(|hex| Vec::from_hex(hex).ok());
    let fingerprint = public_key
        .as_ref()
        .map(|pk| fingerprint_from_public_key(pk));
    (device_id, device_name, public_key, fingerprint)
}

fn fingerprint_from_public_key(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest[..16.min(digest.len())]
        .iter()
        .map(|byte| format!("{:02X}", byte))
        .collect::<Vec<_>>()
        .join(":")
}

fn build_sign_message(desc: &SessionDesc, device_id: &str) -> String {
    let offer = desc
        .offer
        .as_ref()
        .map(|value| value.sdp.as_str())
        .unwrap_or("");
    let answer = desc
        .answer
        .as_ref()
        .map(|value| value.sdp.as_str())
        .unwrap_or("");
    let ice = serde_json::to_string(&desc.candidates).unwrap_or_default();
    format!(
        "{domain}\nsession:{session}\ndevice:{device}\noffer:{offer}\nanswer:{answer}\nice:{ice}",
        domain = SIGNATURE_DOMAIN,
        session = desc.session_id,
        device = device_id,
        offer = offer,
        answer = answer,
        ice = ice
    )
}

fn verify_signature(update: &SessionDesc, peer: &PeerHandle) -> Result<(), String> {
    let public_key = peer
        .public_key
        .as_ref()
        .ok_or_else(|| "peer public key not provided".to_string())?;
    if public_key.len() != 32 {
        return Err("peer public key invalid length".into());
    }
    let signature_hex = update
        .signature
        .as_deref()
        .ok_or_else(|| "signature missing".to_string())?;
    let signature_bytes =
        Vec::from_hex(signature_hex).map_err(|_| "signature invalid hex".to_string())?;
    if signature_bytes.len() != 64 {
        return Err("signature invalid length".into());
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(public_key);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&signature_bytes);
    let verifying_key =
        VerifyingKey::from_bytes(&pk).map_err(|_| "peer public key invalid".to_string())?;
    let ed_sig = EdSignature::from_bytes(&sig);
    let message = build_sign_message(update, &peer.device_id);
    verifying_key
        .verify(message.as_bytes(), &ed_sig)
        .map_err(|_| "signature verification failed".to_string())
}


