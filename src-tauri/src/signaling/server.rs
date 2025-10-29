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
use serde::Deserialize;
use serde_json;
use tokio::sync::{mpsc, RwLock};
use uuid::Uuid;

use super::SessionDesc;

type SharedRegistry = Arc<SessionRegistry>;

#[derive(Debug, Clone, Default)]
struct SessionRegistry {
    inner: Arc<RwLock<HashMap<String, SessionEntry>>>,
}

#[derive(Debug, Clone)]
struct SessionEntry {
    state: SessionDesc,
    peers: HashMap<Uuid, mpsc::UnboundedSender<SessionDesc>>,
}

impl SessionRegistry {
    fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn register(
        &self,
        session_id: &str,
        peer_id: Uuid,
        tx: mpsc::UnboundedSender<SessionDesc>,
    ) -> Option<SessionDesc> {
        let mut guard = self.inner.write().await;
        let entry = guard
            .entry(session_id.to_string())
            .or_insert_with(|| SessionEntry {
                state: SessionDesc::new(session_id.to_string()),
                peers: HashMap::new(),
            });
        entry.peers.insert(peer_id, tx);
        if entry.state.offer.is_some()
            || entry.state.answer.is_some()
            || !entry.state.candidates.is_empty()
        {
            Some(entry.state.clone())
        } else {
            None
        }
    }

    async fn merge_and_broadcast(&self, session_id: &str, from_peer: Uuid, update: SessionDesc) {
        let mut targets: Vec<mpsc::UnboundedSender<SessionDesc>> = Vec::new();
        let snapshot = {
            let mut guard = self.inner.write().await;
            let entry = guard
                .entry(session_id.to_string())
                .or_insert_with(|| SessionEntry {
                    state: SessionDesc::new(session_id.to_string()),
                    peers: HashMap::new(),
                });
            entry.state.merge(update);
            for (peer_id, sender) in entry.peers.iter() {
                if *peer_id != from_peer {
                    targets.push(sender.clone());
                }
            }
            entry.state.clone()
        };

        for sender in targets {
            let _ = sender.send(snapshot.clone());
        }
    }

    async fn remove(&self, session_id: &str, peer_id: Uuid) {
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
struct SessionQuery {
    #[serde(rename = "sessionId")]
    session_id: String,
}

pub fn router() -> Router<SharedRegistry> {
    let router = Router::new()
        .route("/ws", get(upgrade))
        .with_state(Arc::new(SessionRegistry::new()));

    #[cfg(feature = "transport-relay")]
    let router = router.route("/relay", get(relay_registry));

    router
}

async fn upgrade(
    ws: WebSocketUpgrade,
    State(registry): State<SharedRegistry>,
    Query(query): Query<SessionQuery>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| async move {
        handle_socket(socket, registry, query.session_id).await;
    })
}

async fn handle_socket(socket: WebSocket, registry: SharedRegistry, session_id: String) {
    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<SessionDesc>();
    let peer_id = Uuid::new_v4();

    if let Some(snapshot) = registry.register(&session_id, peer_id, tx.clone()).await {
        if send_snapshot(&mut sender, &snapshot).await.is_err() {
            registry.remove(&session_id, peer_id).await;
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
                                update.session_id = session_id.clone();
                                registry.merge_and_broadcast(&session_id, peer_id, update).await;
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

    registry.remove(&session_id, peer_id).await;
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
