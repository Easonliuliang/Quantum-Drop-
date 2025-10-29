#![cfg(feature = "transport-quic")]

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use quinn::{
    ClientConfig, Connection, Endpoint, RecvStream, SendStream, ServerConfig, TransportConfig,
};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::RootCertStore;
use tokio::{task::JoinHandle, try_join};

use super::adapter::TransportError;
use super::{Frame, SessionDesc, TransportAdapter, TransportStream};

const FRAME_HEADER_LEN: usize = 5;

#[derive(Clone)]
pub struct QuicAdapter {
    cert_der: Arc<Vec<u8>>,
    key_der: Arc<Vec<u8>>,
    server_name: Arc<String>,
}

impl QuicAdapter {
    pub fn new() -> Result<Self, TransportError> {
        let CertifiedKey { cert, key_pair } = generate_simple_self_signed(vec!["localhost".into()])
            .map_err(|err| TransportError::Setup(format!("failed to generate dev cert: {err}")))?;
        let cert_der = cert.der().as_ref().to_vec();
        let key_der = key_pair.serialize_der();
        Ok(Self {
            cert_der: Arc::new(cert_der),
            key_der: Arc::new(key_der),
            server_name: Arc::new("localhost".to_string()),
        })
    }

    fn build_server_config(&self) -> Result<ServerConfig, TransportError> {
        let cert = CertificateDer::from(self.cert_der.as_ref().clone());
        let key = PrivatePkcs8KeyDer::from(self.key_der.as_ref().clone());
        let mut server_config = ServerConfig::with_single_cert(vec![cert], key.into())
            .map_err(|err| TransportError::Setup(format!("server config build failed: {err}")))?;

        let mut transport = TransportConfig::default();
        transport.keep_alive_interval(Some(Duration::from_secs(5)));
        server_config.transport_config(Arc::new(transport));
        Ok(server_config)
    }

    fn build_client_config(&self) -> Result<ClientConfig, TransportError> {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(self.cert_der.as_ref().clone()))
            .map_err(|err| TransportError::Setup(format!("add root cert failed: {err}")))?;

        let mut client_config = ClientConfig::with_root_certificates(Arc::new(roots))
            .map_err(|err| TransportError::Setup(format!("client config init failed: {err}")))?;

        let mut transport = TransportConfig::default();
        transport.keep_alive_interval(Some(Duration::from_secs(5)));
        client_config.transport_config(Arc::new(transport));

        Ok(client_config)
    }
}

#[async_trait]
impl TransportAdapter for QuicAdapter {
    async fn connect(
        &self,
        _session: &SessionDesc,
    ) -> Result<Box<dyn TransportStream>, TransportError> {
        let server_config = self.build_server_config()?;
        let server_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));

        let server_endpoint = Endpoint::server(server_config, server_addr).map_err(|err| {
            TransportError::Setup(format!("failed to spawn server endpoint: {err}"))
        })?;
        let server_addr = server_endpoint
            .local_addr()
            .map_err(|err| TransportError::Setup(format!("failed to read server addr: {err}")))?;

        let mut client_endpoint = Endpoint::client(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .map_err(|err| {
                TransportError::Setup(format!("failed to spawn client endpoint: {err}"))
            })?;
        client_endpoint.set_default_client_config(self.build_client_config()?);

        let connecting = client_endpoint
            .connect(server_addr, &self.server_name)
            .map_err(|err| TransportError::Setup(format!("connect initiation failed: {err}")))?;

        let client_task = async {
            connecting
                .await
                .map_err(|err| TransportError::Setup(format!("client connect failed: {err}")))
        };

        let server_task = {
            let server = server_endpoint.clone();
            async move {
                server
                    .accept()
                    .await
                    .ok_or(TransportError::Closed)?
                    .await
                    .map_err(|err| TransportError::Setup(format!("server accept failed: {err}")))
            }
        };

        let (client_connection, server_connection) = try_join!(client_task, server_task)?;

        let stream = QuicLoopbackStream::new(
            client_endpoint.clone(),
            server_endpoint.clone(),
            client_connection.clone(),
            server_connection.clone(),
        )
        .await?;

        Ok(Box::new(stream))
    }
}

struct QuicLoopbackStream {
    send: SendStream,
    recv: RecvStream,
    _client_endpoint: Endpoint,
    _server_endpoint: Endpoint,
    client_connection: Connection,
    server_connection: Connection,
    echo_task: JoinHandle<()>,
}

impl QuicLoopbackStream {
    async fn new(
        client_endpoint: Endpoint,
        server_endpoint: Endpoint,
        client_connection: Connection,
        server_connection: Connection,
    ) -> Result<Self, TransportError> {
        let (send, recv) = client_connection
            .open_bi()
            .await
            .map_err(|err| TransportError::Setup(format!("open bidi stream failed: {err}")))?;

        let (server_send, server_recv) = server_connection
            .accept_bi()
            .await
            .map_err(|err| TransportError::Setup(format!("server stream failed: {err}")))?;

        let echo_task = tokio::spawn(async move {
            let _ = echo_loop(server_recv, server_send).await;
        });

        Ok(Self {
            send,
            recv,
            _client_endpoint: client_endpoint,
            _server_endpoint: server_endpoint,
            client_connection,
            server_connection,
            echo_task,
        })
    }
}

#[async_trait]
impl TransportStream for QuicLoopbackStream {
    async fn send(&mut self, frame: Frame) -> Result<(), TransportError> {
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

        self.send
            .write_all(&payload)
            .await
            .map_err(|err| TransportError::Io(format!("quic write failed: {err}")))?;
        Ok(())
    }

    async fn recv(&mut self) -> Result<Frame, TransportError> {
        let mut header = [0u8; FRAME_HEADER_LEN];
        self.recv
            .read_exact(&mut header)
            .await
            .map_err(|err| TransportError::Io(format!("quic read header failed: {err}")))?;
        let frame_type = header[0];
        let len_bytes: [u8; 4] = header[1..5]
            .try_into()
            .map_err(|_| TransportError::Io("invalid frame length header".into()))?;
        let len = u32::from_be_bytes(len_bytes) as usize;

        let mut buf = vec![0u8; len];
        self.recv
            .read_exact(&mut buf)
            .await
            .map_err(|err| TransportError::Io(format!("quic read body failed: {err}")))?;

        match frame_type {
            0 => {
                let text = String::from_utf8(buf).map_err(|err| {
                    TransportError::Io(format!("frame utf8 decode failed: {err}"))
                })?;
                Ok(Frame::Control(text))
            }
            1 => Ok(Frame::Data(buf)),
            _ => Err(TransportError::Io(format!(
                "unknown frame type: {frame_type}"
            ))),
        }
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        if !self.echo_task.is_finished() {
            self.echo_task.abort();
        }
        if let Err(err) = self.send.finish() {
            return Err(TransportError::Io(format!("finish failed: {err}")));
        }
        self.client_connection.close(0u32.into(), b"done");
        self.server_connection.close(0u32.into(), b"done");
        Ok(())
    }
}

async fn echo_loop(mut recv: RecvStream, mut send: SendStream) -> Result<(), TransportError> {
    while let Some(chunk) = recv
        .read_chunk(usize::MAX, true)
        .await
        .map_err(|err| TransportError::Io(format!("server read failed: {err}")))?
    {
        send.write_all(chunk.bytes.as_ref())
            .await
            .map_err(|err| TransportError::Io(format!("server echo write failed: {err}")))?;
    }
    let _ = send.finish();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::runtime::Runtime;

    #[test]
    fn quic_loopback_roundtrip() {
        let rt = Runtime::new().expect("runtime");
        rt.block_on(async {
            let adapter = QuicAdapter::new().expect("quic adapter");
            let session = SessionDesc {
                session_id: "loopback-test".into(),
            };
            let mut stream = adapter.connect(&session).await.expect("connect quic");

            let payload = Frame::Data(vec![42; 512]);
            stream.send(payload.clone()).await.expect("send");
            let received = stream.recv().await.expect("recv");
            assert_eq!(received, payload);
            stream.close().await.expect("close");
        });
    }
}
