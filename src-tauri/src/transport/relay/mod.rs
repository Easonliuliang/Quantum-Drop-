#![cfg(feature = "transport-relay")]

use std::sync::Arc;

use async_trait::async_trait;
use log::{info, warn};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex,
    try_join,
};

use crate::transport::{Frame, SessionDesc, TransportAdapter, TransportError, TransportStream};

const FRAME_HEADER_LEN: usize = 5;

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
        if let Some(hint) = &session.relay {
            if hint.port != 0 {
                warn!(
                    "relay hint {}:{} ignored by loopback adapter",
                    hint.host, hint.port
                );
            }
        }

        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .map_err(|err| TransportError::Setup(format!("relay bind failed: {err}")))?;
        let listen_addr = listener
            .local_addr()
            .map_err(|err| TransportError::Setup(format!("relay addr lookup failed: {err}")))?;

        let accept_future = async move {
            listener
                .accept()
                .await
                .map_err(|err| TransportError::Setup(format!("relay accept failed: {err}")))
        };
        let connect_future = async move {
            TcpStream::connect(listen_addr)
                .await
                .map_err(|err| TransportError::Setup(format!("relay connect failed: {err}")))
        };
        let ((server_stream, peer_addr), client_stream) = try_join!(accept_future, connect_future)?;
        info!(
            "relay loopback established for session {} via {}",
            session.session_id, peer_addr
        );

        let stream = RelayLoopbackStream::new(client_stream, server_stream).await?;
        Ok(Box::new(stream))
    }
}

struct RelayLoopbackStream {
    reader: Arc<Mutex<tokio::net::tcp::OwnedReadHalf>>,
    writer: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
}

impl RelayLoopbackStream {
    async fn new(
        client_stream: TcpStream,
        server_stream: TcpStream,
    ) -> Result<Self, TransportError> {
        let (client_reader, client_writer) = client_stream.into_split();
        let (server_reader, server_writer) = server_stream.into_split();

        tokio::spawn(async move {
            if let Err(err) = relay_echo(server_reader, server_writer).await {
                warn!("relay echo loop exited: {err}");
            }
        });

        Ok(Self {
            reader: Arc::new(Mutex::new(client_reader)),
            writer: Arc::new(Mutex::new(client_writer)),
        })
    }
}

#[async_trait]
impl TransportStream for RelayLoopbackStream {
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
        writer
            .shutdown()
            .await
            .map_err(|err| TransportError::Io(format!("relay shutdown failed: {err}")))?;
        Ok(())
    }
}

async fn relay_echo(
    mut inbound: tokio::net::tcp::OwnedReadHalf,
    mut outbound: tokio::net::tcp::OwnedWriteHalf,
) -> Result<(), TransportError> {
    loop {
        let mut header = [0u8; FRAME_HEADER_LEN];
        if inbound.read_exact(&mut header).await.is_err() {
            break;
        }
        let frame_type = header[0];
        let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
        let mut payload = vec![0u8; len];
        inbound
            .read_exact(&mut payload)
            .await
            .map_err(|err| TransportError::Io(format!("relay echo read failed: {err}")))?;

        outbound
            .write_all(&header)
            .await
            .map_err(|err| TransportError::Io(format!("relay echo header write failed: {err}")))?;
        if !payload.is_empty() {
            outbound.write_all(&payload).await.map_err(|err| {
                TransportError::Io(format!("relay echo payload write failed: {err}"))
            })?;
        }

        // End-of-stream marker for control frames carrying "close".
        if frame_type == 0 && payload == b"close" {
            break;
        }
    }
    outbound.shutdown().await.ok();
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Runtime;

    #[test]
    fn relay_loopback_transfers_frames() {
        let rt = Runtime::new().expect("runtime");
        rt.block_on(async {
            let adapter = RelayAdapter::new();
            let session = SessionDesc::new("relay-loopback");
            let mut stream = adapter.connect(&session).await.expect("connect relay");

            let payload = Frame::Control("relay-ping".into());
            stream.send(payload.clone()).await.expect("send control");
            let echoed = stream.recv().await.expect("recv control");
            assert_eq!(echoed, payload);

            let data = Frame::Data(vec![7, 8, 9]);
            stream.send(data.clone()).await.expect("send data");
            let echoed = stream.recv().await.expect("recv data");
            assert_eq!(echoed, data);

            stream.close().await.expect("close");
        });
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "manual relay smoke test to avoid CI hangs"]
    async fn relay_manual_smoke() {
        let adapter = RelayAdapter::new();
        let session = SessionDesc::new("relay-manual");
        let mut stream = adapter.connect(&session).await.expect("connect relay");

        stream
            .send(Frame::Data(vec![1, 2, 3, 4]))
            .await
            .expect("send data");

        let echo = stream.recv().await.expect("recv data");
        match echo {
            Frame::Data(bytes) => assert_eq!(bytes, vec![1, 2, 3, 4]),
            other => panic!("unexpected frame: {:?}", other),
        }
    }
}
