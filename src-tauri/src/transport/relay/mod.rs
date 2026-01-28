#![cfg(feature = "transport-relay")]

use std::sync::Arc;

use async_trait::async_trait;
use log::info;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};

use crate::transport::{Frame, SessionDesc, TransportAdapter, TransportError, TransportStream};

const FRAME_HEADER_LEN: usize = 5;
const MAGIC_HEADER: u8 = 0x52; // 'R'

#[derive(Debug, Clone, Default)]
pub struct RelayAdapter;

impl RelayAdapter {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl TransportAdapter for RelayAdapter {
    async fn connect(
        &self,
        session: &SessionDesc,
    ) -> Result<Box<dyn TransportStream>, TransportError> {
        // 1. Determine Relay Server Address
        // Default to local dev server if no hint provided
        let relay_addr = if let Some(hint) = &session.relay {
            if hint.port != 0 {
                format!("{}:{}", hint.host, hint.port)
            } else {
                "127.0.0.1:8080".to_string()
            }
        } else {
            "127.0.0.1:8080".to_string()
        };

        info!("Connecting to Relay Server at {} for session {}", relay_addr, session.session_id);

        // 2. Connect to Server
        let mut stream = TcpStream::connect(&relay_addr)
            .await
            .map_err(|err| TransportError::Setup(format!("relay connect failed: {err}")))?;

        // 3. Handshake
        // Protocol: [Magic(1)][SessionID(32)][Role(1)]
        // Role: We don't strictly distinguish sender/receiver in the adapter interface yet, 
        // but we can use a placeholder or derive it if needed. 
        // For now, let's use 0x00 as a generic role since the server just pairs any two.
        let mut handshake = Vec::with_capacity(34);
        handshake.push(MAGIC_HEADER);
        
        // Ensure SessionID is exactly 32 bytes. If shorter, pad; if longer, truncate (or hash).
        // Assuming SessionID is a UUID string (36 chars) or similar. 
        // For simplicity, let's take the first 32 bytes or pad with spaces.
        let session_bytes = session.session_id.as_bytes();
        let mut id_buf = [0x20u8; 32]; // Space padding
        let len = std::cmp::min(session_bytes.len(), 32);
        id_buf[..len].copy_from_slice(&session_bytes[..len]);
        handshake.extend_from_slice(&id_buf);
        
        handshake.push(0x00); // Role (Generic)

        stream.write_all(&handshake).await.map_err(|err| {
            TransportError::Setup(format!("relay handshake failed: {err}"))
        })?;

        info!("Relay handshake sent for session {}", session.session_id);

        // 4. Wrap Stream
        // The server will bridge us when the other peer connects. 
        // We can now treat this TCP stream as a direct link to the peer.
        let stream = RelayStream::new(stream);
        Ok(Box::new(stream))
    }
}

struct RelayStream {
    reader: Arc<Mutex<tokio::net::tcp::OwnedReadHalf>>,
    writer: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
}

impl RelayStream {
    fn new(stream: TcpStream) -> Self {
        let (reader, writer) = stream.into_split();
        Self {
            reader: Arc::new(Mutex::new(reader)),
            writer: Arc::new(Mutex::new(writer)),
        }
    }
}

#[async_trait]
impl TransportStream for RelayStream {
    async fn send(&mut self, frame: Frame) -> Result<(), TransportError> {
        let mut writer = self.writer.lock().await;
        let payload = encode_frame(frame);
        writer
            .write_all(&payload)
            .await
            .map_err(|err| TransportError::Io(format!("relay write failed: {err}")))
    }

    async fn recv(&mut self) -> Result<Frame, TransportError> {
        let mut reader = self.reader.lock().await;
        decode_frame(&mut *reader).await
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        let mut writer = self.writer.lock().await;
        // Sending a close frame might be good practice, but TCP shutdown is sufficient for now
        writer
            .shutdown()
            .await
            .map_err(|err| TransportError::Io(format!("relay shutdown failed: {err}")))?;
        Ok(())
    }
}

fn encode_frame(frame: Frame) -> Vec<u8> {
    let mut payload = Vec::with_capacity(FRAME_HEADER_LEN);
    match frame {
        Frame::Control(text) => {
            payload.push(0u8);
            let bytes = text.into_bytes();
            payload.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            payload.extend_from_slice(&bytes);
        }
        Frame::Data(bytes) => {
            payload.push(1u8);
            payload.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            payload.extend_from_slice(&bytes);
        }
    }
    payload
}

async fn decode_frame(
    reader: &mut tokio::net::tcp::OwnedReadHalf,
) -> Result<Frame, TransportError> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    reader
        .read_exact(&mut header)
        .await
        .map_err(|err| map_read_error(err))?;

    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    let mut payload = vec![0u8; len];
    if len > 0 {
        reader
            .read_exact(&mut payload)
            .await
            .map_err(|err| map_read_error(err))?;
    }

    match header[0] {
        0 => {
            let text = String::from_utf8(payload.clone())
                .unwrap_or_else(|_| String::from_utf8_lossy(&payload).into_owned());
            Ok(Frame::Control(text))
        }
        1 => Ok(Frame::Data(payload)),
        other => Err(TransportError::Io(format!("unknown relay frame {other}"))),
    }
}

fn map_read_error(err: std::io::Error) -> TransportError {
    if err.kind() == std::io::ErrorKind::UnexpectedEof {
        TransportError::Closed
    } else {
        TransportError::Io(format!("relay read failed: {err}"))
    }
}

