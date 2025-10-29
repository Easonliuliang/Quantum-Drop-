use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{mpsc, Mutex};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Control(String),
    Data(Vec<u8>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionDesc {
    pub session_id: String,
    #[cfg(feature = "transport-webrtc")]
    #[serde(default)]
    pub webrtc: Option<crate::signaling::SessionDesc>,
}

impl SessionDesc {
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            #[cfg(feature = "transport-webrtc")]
            webrtc: None,
        }
    }
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("transport stream closed")]
    Closed,
    #[error("transport setup error: {0}")]
    Setup(String),
    #[error("transport io error: {0}")]
    Io(String),
}

#[async_trait]
pub trait TransportAdapter: Send + Sync {
    async fn connect(
        &self,
        session: &SessionDesc,
    ) -> Result<Box<dyn TransportStream>, TransportError>;
}

#[async_trait]
pub trait TransportStream: Send + Sync {
    async fn send(&mut self, frame: Frame) -> Result<(), TransportError>;
    async fn recv(&mut self) -> Result<Frame, TransportError>;
    async fn close(&mut self) -> Result<(), TransportError>;
}

#[derive(Debug, Clone, Default)]
pub struct MockLocalAdapter;

pub struct MockLocalStream {
    sender: mpsc::Sender<Frame>,
    receiver: Arc<Mutex<mpsc::Receiver<Frame>>>,
}

impl MockLocalAdapter {
    pub fn new() -> Self {
        Self {}
    }

    fn build_stream() -> MockLocalStream {
        let (sender, receiver) = mpsc::channel(32);
        MockLocalStream {
            sender,
            receiver: Arc::new(Mutex::new(receiver)),
        }
    }
}

#[async_trait]
impl TransportAdapter for MockLocalAdapter {
    async fn connect(
        &self,
        session: &SessionDesc,
    ) -> Result<Box<dyn TransportStream>, TransportError> {
        let _ = &session.session_id;
        Ok(Box::new(Self::build_stream()))
    }
}

#[async_trait]
impl TransportStream for MockLocalStream {
    async fn send(&mut self, frame: Frame) -> Result<(), TransportError> {
        self.sender
            .send(frame)
            .await
            .map_err(|_| TransportError::Closed)
    }

    async fn recv(&mut self) -> Result<Frame, TransportError> {
        let mut receiver = self.receiver.lock().await;
        receiver.recv().await.ok_or(TransportError::Closed)
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Runtime;

    #[test]
    fn loopback_transfers_frames() {
        let rt = Runtime::new().expect("tokio runtime");
        rt.block_on(async {
            let adapter = MockLocalAdapter::new();
            let session = SessionDesc::new("test-session");
            let mut stream = adapter
                .connect(&session)
                .await
                .expect("connect mock adapter");

            let payload = Frame::Control("ping".into());
            stream.send(payload.clone()).await.expect("send");

            let received = stream.recv().await.expect("receive");
            assert_eq!(received, payload);

            stream.close().await.expect("close");
        });
    }
}
