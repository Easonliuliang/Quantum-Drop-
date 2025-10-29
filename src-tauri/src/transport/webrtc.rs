#![cfg(feature = "transport-webrtc")]

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use log::{info, warn};
use tokio::sync::{mpsc, Mutex, Notify};
use tokio::task::JoinHandle;
use webrtc::{
    api::APIBuilder,
    data_channel::{
        data_channel_init::RTCDataChannelInit, data_channel_message::DataChannelMessage,
        RTCDataChannel,
    },
    ice_transport::ice_candidate::RTCIceCandidateInit,
    peer_connection::{
        configuration::RTCConfiguration, peer_connection_state::RTCPeerConnectionState,
        RTCPeerConnection,
    },
    Error as WebRtcError,
};

use super::{Frame, SessionDesc, TransportAdapter, TransportError, TransportStream};

const DATA_CHANNEL_LABEL: &str = "courier";

#[derive(Clone)]
pub struct WebRtcAdapter {
    config: Arc<RTCConfiguration>,
}

impl Default for WebRtcAdapter {
    fn default() -> Self {
        Self {
            config: Arc::new(RTCConfiguration::default()),
        }
    }
}

impl WebRtcAdapter {
    pub fn new(config: RTCConfiguration) -> Self {
        Self {
            config: Arc::new(config),
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

        Ok(Box::new(WebRtcStream {
            channel,
            inbound: Arc::new(Mutex::new(inbound_rx)),
            primary,
            loopback,
            ice_tasks,
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

struct WebRtcStream {
    channel: Arc<RTCDataChannel>,
    inbound: Arc<Mutex<mpsc::Receiver<Frame>>>,
    primary: Arc<RTCPeerConnection>,
    loopback: Arc<RTCPeerConnection>,
    ice_tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

#[async_trait]
impl TransportStream for WebRtcStream {
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{timeout, Duration};

    #[cfg(feature = "signaling-server")]
    async fn spawn_signaling_server() -> tokio::task::JoinHandle<()> {
        use axum::Router;
        use tokio::net::TcpListener;

        let router: Router = crate::signaling::signaling_router();
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
