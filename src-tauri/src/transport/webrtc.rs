#![cfg(feature = "transport-webrtc")]

use std::sync::Arc;

use async_trait::async_trait;
use webrtc::{
    peer_connection::{
        configuration::RTCConfiguration, peer_connection_state::RTCPeerConnectionState,
        sdp::session_description::RTCSessionDescription, RTCPeerConnection,
    },
    Error as WebRtcError,
};

use super::{SessionDesc, TransportAdapter, TransportError, TransportStream};

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

    fn build_peer_connection(&self) -> Result<Arc<RTCPeerConnection>, WebRtcError> {
        let api = webrtc::api::APIBuilder::new().build();
        api.new_peer_connection((*self.config).clone())
            .map(Arc::new)
    }
}

#[async_trait]
impl TransportAdapter for WebRtcAdapter {
    async fn connect(
        &self,
        _session: &SessionDesc,
    ) -> Result<Box<dyn TransportStream>, TransportError> {
        match self.build_peer_connection() {
            Ok(peer) => {
                let state = peer.connection_state();
                Err(TransportError::Setup(format!(
                    "webrtc adapter stub; connection state {:?}",
                    state
                )))
            }
            Err(err) => Err(TransportError::Setup(format!(
                "webrtc adapter unavailable: {err}"
            ))),
        }
    }
}
