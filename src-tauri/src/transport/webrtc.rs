#![cfg(feature = "transport-webrtc")]

use std::{
    fs,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use async_trait::async_trait;
use bytes::Bytes;
use ed25519_dalek::{Signer, SigningKey};
use futures::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use log::{info, warn};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Emitter, Manager};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex, Notify};
use tokio::task::JoinHandle;
use tokio::time::{timeout, Duration};
use tokio_tungstenite::{
    connect_async, tungstenite::protocol::Message, MaybeTlsStream, WebSocketStream,
};
use url::Url;
use webrtc::{
    api::APIBuilder,
    data_channel::{
        data_channel_init::RTCDataChannelInit, data_channel_message::DataChannelMessage,
        RTCDataChannel,
    },
    ice_transport::ice_candidate::RTCIceCandidateInit,
    peer_connection::{
        configuration::RTCConfiguration, peer_connection_state::RTCPeerConnectionState,
        sdp::sdp_type::RTCSdpType, sdp::session_description::RTCSessionDescription,
        RTCPeerConnection,
    },
    Error as WebRtcError,
};

#[cfg(test)]
#[allow(unused_imports)]
use crate::security::SecurityConfig;
use crate::signaling::{
    IceCandidate as SignalIceCandidate, SessionDesc as SignalSessionDesc,
    SessionDescription as SignalSessionDescription,
    SessionDescriptionType as SignalDescriptionType,
};

use super::{
    adapter::{WebRtcHint, WebRtcRole},
    Frame, SessionDesc, TransportAdapter, TransportError, TransportStream,
};

type WsWrite = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;
type WsRead = SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;

const DATA_CHANNEL_LABEL: &str = "courier";
const SIGNALING_DOMAIN: &str = "quantumdrop.signaling.v1";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PeerDiscoveredEvent {
    session_id: String,
    device_id: String,
    device_name: Option<String>,
    fingerprint: Option<String>,
    verified: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct P2pConnectionFailedEvent {
    session_id: String,
    reason: String,
    suggestion: String,
}

#[derive(Clone)]
pub struct WebRtcAdapter {
    config: Arc<RTCConfiguration>,
    #[allow(dead_code)]
    signaling_url: Option<Arc<String>>,
    app_handle: Option<AppHandle>,
}

impl Default for WebRtcAdapter {
    fn default() -> Self {
        Self {
            config: Arc::new(RTCConfiguration::default()),
            signaling_url: None,
            app_handle: None,
        }
    }
}

impl WebRtcAdapter {
    #[allow(dead_code)]
    pub fn new(config: RTCConfiguration) -> Self {
        Self {
            config: Arc::new(config),
            signaling_url: None,
            app_handle: None,
        }
    }

    pub fn with_signaling(
        config: RTCConfiguration,
        signaling_url: String,
        app_handle: Option<AppHandle>,
    ) -> Self {
        Self {
            config: Arc::new(config),
            signaling_url: Some(Arc::new(signaling_url)),
            app_handle,
        }
    }

    async fn build_peer_connection(&self) -> Result<Arc<RTCPeerConnection>, WebRtcError> {
        let api = APIBuilder::new().build();
        let pc = api.new_peer_connection((*self.config).clone()).await?;
        Ok(Arc::new(pc))
    }
}

#[async_trait]
impl TransportAdapter for WebRtcAdapter {
    async fn connect(
        &self,
        session: &SessionDesc,
    ) -> Result<Box<dyn TransportStream>, TransportError> {
        if let (Some(hint), Some(url)) = (session.webrtc.as_ref(), self.signaling_url.as_ref()) {
            match self.connect_signaling(session, hint, url.as_str()).await {
                Ok(stream) => return Ok(stream),
                Err(err) => {
                    warn!(
                        "webrtc signaling failed for session {}: {err}; falling back to loopback",
                        session.session_id
                    );
                    // Emit P2P connection failure event to notify frontend
                    if let Some(app) = self.app_handle.as_ref() {
                        let payload = P2pConnectionFailedEvent {
                            session_id: session.session_id.clone(),
                            reason: err.to_string(),
                            suggestion: "网络环境复杂，P2P 打洞失败。建议：1) 切换到同一局域网 2) 检查防火墙设置 3) 稍后重试".into(),
                        };
                        if let Err(emit_err) = app.emit("p2p_connection_failed", payload) {
                            warn!("failed to emit p2p_connection_failed event: {emit_err}");
                        }
                    }
                }
            }
        }
        self.connect_loopback(session).await
    }
}

impl WebRtcAdapter {
    async fn connect_loopback(
        &self,
        session: &SessionDesc,
    ) -> Result<Box<dyn TransportStream>, TransportError> {
        let primary = self
            .build_peer_connection()
            .await
            .map_err(|err| TransportError::Setup(format!("webrtc pc create failed: {err}")))?;
        let loopback = self
            .build_peer_connection()
            .await
            .map_err(|err| TransportError::Setup(format!("webrtc loopback pc failed: {err}")))?;

        let label = session.session_id.clone();

        register_state_logger(&primary, format!("primary:{label}"));
        register_state_logger(&loopback, format!("loopback:{label}"));

        let (inbound_tx, inbound_rx) = mpsc::channel(32);
        let inbound_tx_clone = inbound_tx.clone();

        let channel = primary
            .create_data_channel(DATA_CHANNEL_LABEL, Some(RTCDataChannelInit::default()))
            .await
            .map_err(|err| TransportError::Setup(format!("data channel create failed: {err}")))?;

        let open_notify = Arc::new(Notify::new());
        let open_notify_clone = open_notify.clone();

        channel.on_open(Box::new(move || {
            let notifier = open_notify_clone.clone();
            Box::pin(async move {
                info!("webrtc data channel '{DATA_CHANNEL_LABEL}' opened");
                notifier.notify_waiters();
            })
        }));

        channel.on_message(Box::new(move |msg: DataChannelMessage| {
            let tx = inbound_tx_clone.clone();
            Box::pin(async move {
                let bytes = msg.data.to_vec();
                let frame = if msg.is_string {
                    match String::from_utf8(bytes.clone()) {
                        Ok(text) => Frame::Control(text),
                        Err(_) => Frame::Data(bytes),
                    }
                } else {
                    Frame::Data(bytes)
                };
                if tx.send(frame).await.is_err() {
                    warn!("webrtc inbound queue closed");
                }
            })
        }));

        loopback.on_data_channel(Box::new(|dc: Arc<RTCDataChannel>| {
            Box::pin(async move {
                dc.on_open(Box::new({
                    let channel = dc.clone();
                    move || {
                        let label = channel.label().to_string();
                        Box::pin(async move {
                            info!("webrtc loopback data channel '{label}' opened");
                        })
                    }
                }));

                let message_channel = dc.clone();
                dc.on_message(Box::new(move |msg: DataChannelMessage| {
                    let echo_chan = message_channel.clone();
                    Box::pin(async move {
                        let data = msg.data.clone();
                        let send_result = if msg.is_string {
                            match String::from_utf8(data.to_vec()) {
                                Ok(text) => echo_chan.send_text(&text).await,
                                Err(_) => echo_chan.send(&data).await,
                            }
                        } else {
                            echo_chan.send(&data).await
                        };
                        if let Err(err) = send_result {
                            warn!("loopback echo failed: {err}");
                        }
                    })
                }));
            })
        }));

        let tasks = wire_ice_exchange(&primary, &loopback);
        let ice_tasks = Arc::new(Mutex::new(tasks));

        perform_handshake(&primary, &loopback).await?;

        open_notify.notified().await;

        Ok(Box::new(LoopbackWebRtcStream {
            channel,
            inbound: Arc::new(Mutex::new(inbound_rx)),
            primary,
            loopback,
            ice_tasks,
        }))
    }

    async fn connect_signaling(
        &self,
        session: &SessionDesc,
        hint: &WebRtcHint,
        signaling_url: &str,
    ) -> Result<Box<dyn TransportStream>, TransportError> {
        let url = build_signaling_url(signaling_url, &session.session_id, hint)?;
        let (ws_stream, _) = connect_async(url)
            .await
            .map_err(|err| TransportError::Setup(format!("signaling connect failed: {err}")))?;
        let (ws_write, ws_read) = ws_stream.split();
        let signing_key = self.app_handle.as_ref().and_then(|app| {
            hint.identity_id
                .as_deref()
                .and_then(|identity| load_signing_key(app, identity))
        });
        let client = SignalingClient::new(session.session_id.clone(), ws_write, hint, signing_key);

        let role = hint.role.clone();
        let pc = self
            .build_peer_connection()
            .await
            .map_err(|err| TransportError::Setup(format!("webrtc pc create failed: {err}")))?;
        let (inbound_tx, inbound_rx) = mpsc::channel(32);
        let inbound = Arc::new(Mutex::new(inbound_rx));
        let channel_slot: Arc<Mutex<Option<Arc<RTCDataChannel>>>> = Arc::new(Mutex::new(None));
        let open_notify = Arc::new(Notify::new());

        register_ice_handler(&pc, client.clone());

        let offer_notify = Arc::new(Notify::new());
        let answer_notify = Arc::new(Notify::new());
        let offer_set = Arc::new(AtomicBool::new(false));
        let answer_set = Arc::new(AtomicBool::new(false));

        let offer_wait = if matches!(hint.role, WebRtcRole::Answerer) {
            Some(offer_notify.clone())
        } else {
            None
        };
        let answer_wait = if matches!(hint.role, WebRtcRole::Offerer) {
            Some(answer_notify.clone())
        } else {
            None
        };
        let reader_task = spawn_signaling_reader(
            ws_read,
            role.clone(),
            pc.clone(),
            client.clone(),
            offer_wait.clone(),
            answer_wait.clone(),
            offer_set.clone(),
            answer_set.clone(),
            self.app_handle.clone(),
        );

        match role {
            WebRtcRole::Offerer => {
                let channel = pc
                    .create_data_channel(DATA_CHANNEL_LABEL, Some(RTCDataChannelInit::default()))
                    .await
                    .map_err(|err| {
                        TransportError::Setup(format!("data channel create failed: {err}"))
                    })?;
                setup_data_channel(channel.clone(), inbound_tx.clone(), open_notify.clone());
                {
                    let mut slot = channel_slot.lock().await;
                    *slot = Some(channel.clone());
                }

                let offer = pc
                    .create_offer(None)
                    .await
                    .map_err(|err| TransportError::Setup(format!("offer create failed: {err}")))?;
                pc.set_local_description(offer.clone())
                    .await
                    .map_err(|err| {
                        TransportError::Setup(format!("set local offer failed: {err}"))
                    })?;
                client.send_offer(&offer).await?;

                if let Some(waiter) = answer_wait {
                    timeout(Duration::from_secs(20), waiter.notified())
                        .await
                        .map_err(|_| {
                            TransportError::Timeout("waiting for remote answer timed out".into())
                        })?;
                }
            }
            WebRtcRole::Answerer => {
                install_answer_handler(
                    &pc,
                    inbound_tx.clone(),
                    open_notify.clone(),
                    channel_slot.clone(),
                );
                if let Some(waiter) = offer_wait {
                    timeout(Duration::from_secs(20), waiter.notified())
                        .await
                        .map_err(|_| {
                            TransportError::Timeout("waiting for remote offer timed out".into())
                        })?;
                }
            }
        }

        timeout(Duration::from_secs(20), open_notify.notified())
            .await
            .map_err(|_| TransportError::Timeout("data channel open timed out".into()))?;

        let channel = {
            let mut guard = channel_slot.lock().await;
            guard.take().ok_or_else(|| {
                TransportError::Setup("data channel unavailable after signaling".into())
            })?
        };

        Ok(Box::new(SignaledWebRtcStream {
            channel,
            inbound,
            pc,
            reader_task,
            client,
        }))
    }
}

fn register_state_logger(peer: &Arc<RTCPeerConnection>, label: String) {
    let _ = peer.on_peer_connection_state_change(Box::new(move |state: RTCPeerConnectionState| {
        info!("webrtc[{label}] state -> {:?}", state);
        Box::pin(async {})
    }));
}

fn wire_ice_exchange(
    primary: &Arc<RTCPeerConnection>,
    loopback: &Arc<RTCPeerConnection>,
) -> Vec<JoinHandle<()>> {
    let (to_loopback_tx, mut to_loopback_rx) = mpsc::unbounded_channel::<RTCIceCandidateInit>();
    let (to_primary_tx, mut to_primary_rx) = mpsc::unbounded_channel::<RTCIceCandidateInit>();

    primary.on_ice_candidate(Box::new(move |candidate| {
        let tx = to_loopback_tx.clone();
        Box::pin(async move {
            if let Some(candidate) = candidate {
                match candidate.to_json() {
                    Ok(json) => {
                        if tx.send(json).is_err() {
                            warn!("failed to enqueue candidate for loopback");
                        }
                    }
                    Err(err) => warn!("candidate to_json failed: {err}"),
                }
            }
        })
    }));

    loopback.on_ice_candidate(Box::new(move |candidate| {
        let tx = to_primary_tx.clone();
        Box::pin(async move {
            if let Some(candidate) = candidate {
                match candidate.to_json() {
                    Ok(json) => {
                        if tx.send(json).is_err() {
                            warn!("failed to enqueue candidate for primary");
                        }
                    }
                    Err(err) => warn!("candidate to_json failed: {err}"),
                }
            }
        })
    }));

    let task_primary = {
        let loopback = loopback.clone();
        tokio::spawn(async move {
            while let Some(candidate) = to_loopback_rx.recv().await {
                if let Err(err) = loopback.add_ice_candidate(candidate).await {
                    warn!("apply candidate to loopback failed: {err}");
                }
            }
        })
    };

    let task_loopback = {
        let primary = primary.clone();
        tokio::spawn(async move {
            while let Some(candidate) = to_primary_rx.recv().await {
                if let Err(err) = primary.add_ice_candidate(candidate).await {
                    warn!("apply candidate to primary failed: {err}");
                }
            }
        })
    };

    vec![task_primary, task_loopback]
}

async fn perform_handshake(
    primary: &Arc<RTCPeerConnection>,
    loopback: &Arc<RTCPeerConnection>,
) -> Result<(), TransportError> {
    let offer = primary
        .create_offer(None)
        .await
        .map_err(|err| TransportError::Setup(format!("offer create failed: {err}")))?;
    primary
        .set_local_description(offer.clone())
        .await
        .map_err(|err| TransportError::Setup(format!("set local offer failed: {err}")))?;

    loopback
        .set_remote_description(offer)
        .await
        .map_err(|err| TransportError::Setup(format!("set loopback remote offer failed: {err}")))?;

    let answer = loopback
        .create_answer(None)
        .await
        .map_err(|err| TransportError::Setup(format!("answer create failed: {err}")))?;
    loopback
        .set_local_description(answer.clone())
        .await
        .map_err(|err| TransportError::Setup(format!("set loopback local answer failed: {err}")))?;

    primary
        .set_remote_description(answer)
        .await
        .map_err(|err| TransportError::Setup(format!("set remote answer failed: {err}")))?;

    let _ = primary.gathering_complete_promise().await;
    let _ = loopback.gathering_complete_promise().await;
    Ok(())
}

struct LoopbackWebRtcStream {
    channel: Arc<RTCDataChannel>,
    inbound: Arc<Mutex<mpsc::Receiver<Frame>>>,
    primary: Arc<RTCPeerConnection>,
    loopback: Arc<RTCPeerConnection>,
    ice_tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

#[async_trait]
impl TransportStream for LoopbackWebRtcStream {
    async fn send(&mut self, frame: Frame) -> Result<(), TransportError> {
        match frame {
            Frame::Control(text) => {
                self.channel
                    .send_text(&text)
                    .await
                    .map_err(|err| TransportError::Io(format!("webrtc send text failed: {err}")))?;
                Ok(())
            }
            Frame::Data(bytes) => {
                let data = Bytes::from(bytes);
                self.channel.send(&data).await.map_err(|err| {
                    TransportError::Io(format!("webrtc send binary failed: {err}"))
                })?;
                Ok(())
            }
        }
    }

    async fn recv(&mut self) -> Result<Frame, TransportError> {
        let mut rx = self.inbound.lock().await;
        rx.recv().await.ok_or(TransportError::Closed)
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        self.channel
            .close()
            .await
            .map_err(|err| TransportError::Io(format!("data channel close failed: {err}")))?;

        if let Err(err) = self.primary.close().await {
            warn!("primary peer close failed: {err}");
        }
        if let Err(err) = self.loopback.close().await {
            warn!("loopback peer close failed: {err}");
        }
        let mut tasks = self.ice_tasks.lock().await;
        while let Some(task) = tasks.pop() {
            task.abort();
        }
        Ok(())
    }
}

struct SignaledWebRtcStream {
    channel: Arc<RTCDataChannel>,
    inbound: Arc<Mutex<mpsc::Receiver<Frame>>>,
    pc: Arc<RTCPeerConnection>,
    reader_task: JoinHandle<()>,
    client: SignalingClient,
}

#[async_trait]
impl TransportStream for SignaledWebRtcStream {
    async fn send(&mut self, frame: Frame) -> Result<(), TransportError> {
        match frame {
            Frame::Control(text) => {
                self.channel
                    .send_text(&text)
                    .await
                    .map_err(|err| TransportError::Io(format!("webrtc send text failed: {err}")))?;
                Ok(())
            }
            Frame::Data(bytes) => {
                let data = Bytes::from(bytes);
                self.channel.send(&data).await.map_err(|err| {
                    TransportError::Io(format!("webrtc send binary failed: {err}"))
                })?;
                Ok(())
            }
        }
    }

    async fn recv(&mut self) -> Result<Frame, TransportError> {
        let mut rx = self.inbound.lock().await;
        rx.recv().await.ok_or(TransportError::Closed)
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        self.channel
            .close()
            .await
            .map_err(|err| TransportError::Io(format!("data channel close failed: {err}")))?;
        if let Err(err) = self.pc.close().await {
            warn!("webrtc peer close failed: {err}");
        }
        self.reader_task.abort();
        self.client.close().await;
        Ok(())
    }
}

#[derive(Clone)]
struct SignalingClient {
    session_id: Arc<String>,
    writer: Arc<Mutex<WsWrite>>,
    device_id: Option<String>,
    device_name: Option<String>,
    public_key: Option<String>,
    signing: Option<Arc<SigningKey>>,
}

impl SignalingClient {
    fn new(
        session_id: String,
        writer: WsWrite,
        hint: &WebRtcHint,
        signing_key: Option<SigningKey>,
    ) -> Self {
        Self {
            session_id: Arc::new(session_id),
            writer: Arc::new(Mutex::new(writer)),
            device_id: hint.device_id.clone(),
            device_name: hint.device_name.clone(),
            public_key: hint.signer_public_key.clone(),
            signing: signing_key.map(|key| Arc::new(key)),
        }
    }

    fn session_id(&self) -> &str {
        self.session_id.as_ref()
    }

    async fn send_offer(&self, desc: &RTCSessionDescription) -> Result<(), TransportError> {
        self.send_update(SignalSessionDesc {
            session_id: self.session_id.as_ref().clone(),
            offer: Some(to_signal_description(desc)?),
            answer: None,
            candidates: Vec::new(),
            signer_device_id: None,
            signer_device_name: None,
            signer_public_key: None,
            signature: None,
        })
        .await
    }

    async fn send_answer(&self, desc: &RTCSessionDescription) -> Result<(), TransportError> {
        self.send_update(SignalSessionDesc {
            session_id: self.session_id.as_ref().clone(),
            offer: None,
            answer: Some(to_signal_description(desc)?),
            candidates: Vec::new(),
            signer_device_id: None,
            signer_device_name: None,
            signer_public_key: None,
            signature: None,
        })
        .await
    }

    async fn send_candidate(&self, candidate: SignalIceCandidate) -> Result<(), TransportError> {
        self.send_update(SignalSessionDesc {
            session_id: self.session_id.as_ref().clone(),
            offer: None,
            answer: None,
            candidates: vec![candidate],
            signer_device_id: None,
            signer_device_name: None,
            signer_public_key: None,
            signature: None,
        })
        .await
    }

    async fn send_update(&self, mut update: SignalSessionDesc) -> Result<(), TransportError> {
        if let Some(device_id) = self.device_id.as_ref() {
            update.signer_device_id = Some(device_id.clone());
        }
        if let Some(device_name) = self.device_name.as_ref() {
            update.signer_device_name = Some(device_name.clone());
        }
        if let Some(public_key) = self.public_key.as_ref() {
            update.signer_public_key = Some(public_key.clone());
        }
        update.signature = self.sign_payload(&update);
        let text = serde_json::to_string(&update)
            .map_err(|err| TransportError::Setup(format!("signaling encode failed: {err}")))?;
        let mut writer = self.writer.lock().await;
        writer
            .send(Message::Text(text))
            .await
            .map_err(|err| TransportError::Setup(format!("signaling send failed: {err}")))
    }

    async fn send_raw(&self, message: Message) {
        let mut writer = self.writer.lock().await;
        let _ = writer.send(message).await;
    }

    async fn close(&self) {
        let mut writer = self.writer.lock().await;
        let _ = writer.send(Message::Close(None)).await;
    }

    fn sign_payload(&self, desc: &SignalSessionDesc) -> Option<String> {
        let signing = self.signing.as_deref()?;
        let device_id = self.device_id.as_ref()?;
        let payload = build_sign_payload(desc, device_id);
        let signature = signing.sign(payload.as_bytes());
        Some(hex::encode(signature.to_bytes()))
    }
}

fn build_signaling_url(
    base: &str,
    session_id: &str,
    hint: &WebRtcHint,
) -> Result<Url, TransportError> {
    let mut url = Url::parse(base)
        .map_err(|err| TransportError::Setup(format!("invalid signaling url '{base}': {err}")))?;
    {
        let mut pairs = url.query_pairs_mut();
        pairs.append_pair("sessionId", session_id);
        if let Some(device_id) = hint.device_id.as_ref() {
            pairs.append_pair("deviceId", device_id);
        }
        if let Some(name) = hint
            .device_name
            .as_ref()
            .filter(|value| !value.trim().is_empty())
        {
            pairs.append_pair("deviceName", name);
        }
        if let Some(public_key) = hint.signer_public_key.as_ref() {
            pairs.append_pair("publicKey", public_key);
        }
    }
    Ok(url)
}

fn load_signing_key(app: &AppHandle, identity_id: &str) -> Option<SigningKey> {
    let mut path = app.path().app_data_dir().ok()?;
    path.push("identity");
    path.push(format!("{identity_id}.priv"));
    let contents = fs::read_to_string(&path).ok()?;
    let trimmed = contents.trim();
    let decoded = hex::decode(trimmed).ok()?;
    if decoded.len() != 32 {
        warn!(
            "identity private key for '{}' has invalid length ({} bytes)",
            identity_id,
            decoded.len()
        );
        return None;
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&decoded);
    Some(SigningKey::from_bytes(&bytes))
}

fn setup_data_channel(
    channel: Arc<RTCDataChannel>,
    inbound_tx: mpsc::Sender<Frame>,
    open_notify: Arc<Notify>,
) {
    let notify = open_notify.clone();
    channel.on_open(Box::new(move || {
        let notify = notify.clone();
        Box::pin(async move {
            info!("webrtc data channel '{DATA_CHANNEL_LABEL}' opened");
            notify.notify_waiters();
        })
    }));

    let tx = inbound_tx.clone();
    channel.on_message(Box::new(move |msg: DataChannelMessage| {
        let tx = tx.clone();
        Box::pin(async move {
            let bytes = msg.data.to_vec();
            let frame = if msg.is_string {
                match String::from_utf8(bytes.clone()) {
                    Ok(text) => Frame::Control(text),
                    Err(_) => Frame::Data(bytes),
                }
            } else {
                Frame::Data(bytes)
            };
            if tx.send(frame).await.is_err() {
                warn!("webrtc inbound queue closed");
            }
        })
    }));
}

fn install_answer_handler(
    pc: &Arc<RTCPeerConnection>,
    inbound_tx: mpsc::Sender<Frame>,
    open_notify: Arc<Notify>,
    slot: Arc<Mutex<Option<Arc<RTCDataChannel>>>>,
) {
    pc.on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
        setup_data_channel(dc.clone(), inbound_tx.clone(), open_notify.clone());
        let slot = slot.clone();
        Box::pin(async move {
            let mut guard = slot.lock().await;
            *guard = Some(dc);
        })
    }));
}

fn register_ice_handler(pc: &Arc<RTCPeerConnection>, client: SignalingClient) {
    pc.on_ice_candidate(Box::new(move |candidate| {
        let client = client.clone();
        Box::pin(async move {
            if let Some(candidate) = candidate {
                match candidate.to_json() {
                    Ok(init) => {
                        if let Err(err) = client.send_candidate(to_signal_candidate(&init)).await {
                            warn!(
                                "failed to send ICE candidate for session {}: {}",
                                client.session_id(),
                                err
                            );
                        }
                    }
                    Err(err) => warn!("candidate to_json failed: {err}"),
                }
            }
        })
    }));
}

fn spawn_signaling_reader(
    mut ws_read: WsRead,
    role: WebRtcRole,
    pc: Arc<RTCPeerConnection>,
    client: SignalingClient,
    offer_ready: Option<Arc<Notify>>,
    answer_ready: Option<Arc<Notify>>,
    offer_set: Arc<AtomicBool>,
    answer_set: Arc<AtomicBool>,
    app_handle: Option<AppHandle>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(msg) = ws_read.next().await {
            match msg {
                Ok(Message::Text(text)) => match serde_json::from_str::<SignalSessionDesc>(&text) {
                    Ok(desc) => {
                        if let Err(err) = handle_signal_update(
                            &pc,
                            &client,
                            &desc,
                            role,
                            offer_ready.as_ref(),
                            answer_ready.as_ref(),
                            &offer_set,
                            &answer_set,
                        )
                        .await
                        {
                            warn!(
                                "signaling update failed for session {}: {}",
                                client.session_id(),
                                err
                            );
                        } else if let Some(app) = app_handle.as_ref() {
                            emit_peer_event(app, &desc);
                        }
                    }
                    Err(err) => warn!("invalid signaling payload: {err}"),
                },
                Ok(Message::Ping(payload)) => {
                    client.send_raw(Message::Pong(payload)).await;
                }
                Ok(Message::Close(_)) => break,
                Ok(Message::Pong(_)) => {}
                Ok(Message::Binary(_)) => {}
                Ok(Message::Frame(_)) => {}
                Err(err) => {
                    warn!("signaling stream error: {err}");
                    break;
                }
            }
        }
    })
}

async fn handle_signal_update(
    pc: &Arc<RTCPeerConnection>,
    client: &SignalingClient,
    update: &SignalSessionDesc,
    role: WebRtcRole,
    offer_ready: Option<&Arc<Notify>>,
    answer_ready: Option<&Arc<Notify>>,
    offer_set: &Arc<AtomicBool>,
    answer_set: &Arc<AtomicBool>,
) -> Result<(), TransportError> {
    if let Some(offer) = &update.offer {
        if matches!(role, WebRtcRole::Answerer) && !offer_set.swap(true, Ordering::SeqCst) {
            let rtc_offer = rtc_from_signal_description(offer)?;
            pc.set_remote_description(rtc_offer)
                .await
                .map_err(|err| TransportError::Setup(format!("set remote offer failed: {err}")))?;
            let answer = pc
                .create_answer(None)
                .await
                .map_err(|err| TransportError::Setup(format!("answer create failed: {err}")))?;
            pc.set_local_description(answer.clone())
                .await
                .map_err(|err| TransportError::Setup(format!("set local answer failed: {err}")))?;
            client.send_answer(&answer).await?;
            if let Some(notify) = offer_ready {
                notify.notify_waiters();
            }
        }
    }

    if let Some(answer) = &update.answer {
        if matches!(role, WebRtcRole::Offerer) && !answer_set.swap(true, Ordering::SeqCst) {
            let rtc_answer = rtc_from_signal_description(answer)?;
            pc.set_remote_description(rtc_answer)
                .await
                .map_err(|err| TransportError::Setup(format!("set remote answer failed: {err}")))?;
            if let Some(notify) = answer_ready {
                notify.notify_waiters();
            }
        }
    }

    for candidate in &update.candidates {
        let init = rtc_candidate_from_signal(candidate);
        if let Err(err) = pc.add_ice_candidate(init).await {
            warn!("failed to apply remote ICE candidate: {err}");
        }
    }

    Ok(())
}

fn to_signal_description(
    desc: &RTCSessionDescription,
) -> Result<SignalSessionDescription, TransportError> {
    let kind = match desc.sdp_type {
        RTCSdpType::Offer => SignalDescriptionType::Offer,
        RTCSdpType::Answer => SignalDescriptionType::Answer,
        RTCSdpType::Pranswer => SignalDescriptionType::Pranswer,
        other => {
            return Err(TransportError::Setup(format!(
                "unsupported SDP type {:?}",
                other
            )))
        }
    };
    Ok(SignalSessionDescription {
        kind,
        sdp: desc.sdp.clone(),
    })
}

fn rtc_from_signal_description(
    desc: &SignalSessionDescription,
) -> Result<RTCSessionDescription, TransportError> {
    let rtc = match desc.kind {
        SignalDescriptionType::Offer => RTCSessionDescription::offer(desc.sdp.clone()),
        SignalDescriptionType::Answer => RTCSessionDescription::answer(desc.sdp.clone()),
        SignalDescriptionType::Pranswer => RTCSessionDescription::pranswer(desc.sdp.clone()),
    };
    rtc.map_err(|err| TransportError::Setup(format!("invalid SDP: {err}")))
}

fn to_signal_candidate(init: &RTCIceCandidateInit) -> SignalIceCandidate {
    SignalIceCandidate {
        candidate: init.candidate.clone(),
        sdp_mline_index: init.sdp_mline_index.map(|value| value as u32),
        sdp_mid: init.sdp_mid.clone(),
    }
}

fn rtc_candidate_from_signal(candidate: &SignalIceCandidate) -> RTCIceCandidateInit {
    RTCIceCandidateInit {
        candidate: candidate.candidate.clone(),
        sdp_mid: candidate.sdp_mid.clone(),
        sdp_mline_index: candidate.sdp_mline_index.map(|value| value as u16),
        ..Default::default()
    }
}

fn build_sign_payload(desc: &SignalSessionDesc, device_id: &str) -> String {
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
        domain = SIGNALING_DOMAIN,
        session = desc.session_id,
        device = device_id,
        offer = offer,
        answer = answer,
        ice = ice
    )
}

fn emit_peer_event(app: &AppHandle, desc: &SignalSessionDesc) {
    if let Some(device_id) = desc.signer_device_id.as_ref() {
        let fingerprint = desc
            .signer_public_key
            .as_ref()
            .and_then(|hex| fingerprint_from_public_key_hex(hex));
        let payload = PeerDiscoveredEvent {
            session_id: desc.session_id.clone(),
            device_id: device_id.clone(),
            device_name: desc.signer_device_name.clone(),
            fingerprint,
            verified: desc.signature.is_some(),
        };
        if let Err(err) = app.emit("peer_discovered", payload) {
            warn!("failed to emit peer_discovered: {err}");
        }
    }
}

fn fingerprint_from_public_key_hex(hex_str: &str) -> Option<String> {
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.is_empty() {
        return None;
    }
    let digest = Sha256::digest(bytes);
    let formatted: Vec<String> = digest
        .iter()
        .take(16)
        .map(|byte| format!("{:02X}", byte))
        .collect();
    Some(formatted.join(":"))
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;
    #[allow(unused_imports)]
    use tokio::time::{timeout, Duration};

    #[cfg(feature = "signaling-server")]
    async fn spawn_signaling_server() -> tokio::task::JoinHandle<()> {
        use axum::Router;
        use tokio::net::TcpListener;

        let router: Router = crate::signaling::signaling_router(SecurityConfig::default());
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind signaling listener");
        let server = axum::serve(listener, router.into_make_service());
        tokio::spawn(async move {
            if let Err(err) = server.await {
                eprintln!("signaling server exited: {err}");
            }
        })
    }

    #[cfg(all(feature = "transport-webrtc", feature = "signaling-server"))]
    #[tokio::test]
    #[ignore]
    async fn data_channel_loopback_echoes_payload() {
        let server = spawn_signaling_server().await;

        let adapter = WebRtcAdapter::default();
        let session = SessionDesc::new("webrtc-loopback");
        let mut stream = adapter
            .connect(&session)
            .await
            .expect("connect webrtc loopback");

        let payload = Frame::Data(vec![7_u8; 64 * 1024]);
        stream.send(payload.clone()).await.expect("send payload");

        let echoed = timeout(Duration::from_secs(5), stream.recv())
            .await
            .expect("recv timeout")
            .expect("receive frame");

        match echoed {
            Frame::Data(bytes) => assert_eq!(bytes.len(), 64 * 1024),
            Frame::Control(text) => panic!("expected data frame, got control: {text}"),
        }

        stream.close().await.expect("close");
        server.abort();
    }
}
