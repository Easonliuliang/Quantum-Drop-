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
use sha2::{Digest, Sha256};
use tokio::{sync::mpsc, task::JoinHandle, try_join};

use super::adapter::TransportError;
use super::{Frame, SessionDesc, TransportAdapter, TransportStream};

const FRAME_HEADER_LEN: usize = 5;
const DEFAULT_LAN_STREAMS: usize = 3;
const MAX_LAN_STREAMS: usize = 4;
const INBOUND_CHANNEL_SIZE: usize = 64;

fn encode_frame(frame: &Frame) -> Vec<u8> {
    match frame {
        Frame::Control(text) => {
            let bytes = text.as_bytes();
            let mut payload = Vec::with_capacity(FRAME_HEADER_LEN + bytes.len());
            payload.push(0u8);
            payload.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            payload.extend_from_slice(bytes);
            payload
        }
        Frame::Data(bytes) => {
            let mut payload = Vec::with_capacity(FRAME_HEADER_LEN + bytes.len());
            payload.push(1u8);
            payload.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            payload.extend_from_slice(bytes);
            payload
        }
    }
}

async fn write_frame(stream: &mut SendStream, frame: &Frame) -> Result<(), TransportError> {
    let payload = encode_frame(frame);
    stream
        .write_all(&payload)
        .await
        .map_err(|err| TransportError::Io(format!("quic write failed: {err}")))
}

async fn read_frame(stream: &mut RecvStream) -> Result<Frame, TransportError> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|err| TransportError::Io(format!("quic read header failed: {err}")))?;
    let len_bytes: [u8; 4] = header[1..5]
        .try_into()
        .map_err(|_| TransportError::Io("invalid frame length header".into()))?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|err| TransportError::Io(format!("quic read body failed: {err}")))?;
    match header[0] {
        0 => {
            let text = String::from_utf8(buf)
                .map_err(|err| TransportError::Io(format!("frame utf8 decode failed: {err}")))?;
            Ok(Frame::Control(text))
        }
        1 => Ok(Frame::Data(buf)),
        other => Err(TransportError::Io(format!("unknown frame type: {other}"))),
    }
}

#[derive(Clone)]
struct QuicCredentials {
    cert_der: Arc<Vec<u8>>,
    key_der: Arc<Vec<u8>>,
    server_name: Arc<String>,
}

impl QuicCredentials {
    fn new(server_name: impl Into<String>) -> Result<Self, TransportError> {
        let domain = server_name.into();
        let CertifiedKey { cert, key_pair } = generate_simple_self_signed(vec![domain.clone()])
            .map_err(|err| TransportError::Setup(format!("failed to generate dev cert: {err}")))?;
        let cert_der = cert.der().as_ref().to_vec();
        let key_der = key_pair.serialize_der();
        Ok(Self {
            cert_der: Arc::new(cert_der),
            key_der: Arc::new(key_der),
            server_name: Arc::new(domain),
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

    fn fingerprint_hex(&self) -> String {
        let digest = Sha256::digest(self.cert_der.as_ref());
        hex::encode(digest)
    }
}

#[derive(Clone)]
pub struct QuicAdapter {
    creds: Arc<QuicCredentials>,
}

impl QuicAdapter {
    pub fn new() -> Result<Self, TransportError> {
        Ok(Self {
            creds: Arc::new(QuicCredentials::new("localhost")?),
        })
    }

    fn build_server_config(&self) -> Result<ServerConfig, TransportError> {
        self.creds.build_server_config()
    }

    fn build_client_config(&self) -> Result<ClientConfig, TransportError> {
        self.creds.build_client_config()
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
            .connect(server_addr, self.creds.server_name.as_str())
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
        write_frame(&mut self.send, &frame).await
    }

    async fn recv(&mut self) -> Result<Frame, TransportError> {
        read_frame(&mut self.recv).await
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

#[derive(Clone)]
pub struct LanQuic {
    creds: Arc<QuicCredentials>,
    stream_count: usize,
}

impl LanQuic {
    pub fn new() -> Result<Self, TransportError> {
        Self::with_streams(DEFAULT_LAN_STREAMS)
    }

    pub fn with_streams(stream_count: usize) -> Result<Self, TransportError> {
        let count = stream_count.clamp(1, MAX_LAN_STREAMS);
        Ok(Self {
            creds: Arc::new(QuicCredentials::new("quantumdrop.local")?),
            stream_count: count,
        })
    }

    pub fn certificate_fingerprint(&self) -> String {
        self.creds.fingerprint_hex()
    }

    pub async fn bind(&self, addr: SocketAddr) -> Result<LanQuicListener, TransportError> {
        let endpoint = Endpoint::server(self.creds.build_server_config()?, addr)
            .map_err(|err| TransportError::Setup(format!("failed to bind lan listener: {err}")))?;
        Ok(LanQuicListener {
            endpoint,
            stream_count: self.stream_count,
        })
    }

    pub async fn connect(&self, remote: SocketAddr) -> Result<LanQuicStream, TransportError> {
        let mut endpoint =
            Endpoint::client(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))).map_err(|err| {
                TransportError::Setup(format!("failed to create client endpoint: {err}"))
            })?;
        endpoint.set_default_client_config(self.creds.build_client_config()?);
        let connecting = endpoint
            .connect(remote, self.creds.server_name.as_str())
            .map_err(|err| TransportError::Setup(format!("connect initiation failed: {err}")))?;
        let connection = connecting
            .await
            .map_err(|err| TransportError::Setup(format!("client connect failed: {err}")))?;
        let stream_count = self.stream_count.max(1);
        let mut streams = Vec::with_capacity(stream_count);
        for _ in 0..stream_count {
            let (send, recv) = connection
                .open_bi()
                .await
                .map_err(|err| TransportError::Setup(format!("open bidi stream failed: {err}")))?;
            streams.push((send, recv));
        }
        Ok(LanQuicStream::new(streams, endpoint, connection))
    }
}

pub struct LanQuicListener {
    endpoint: Endpoint,
    stream_count: usize,
}

impl LanQuicListener {
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.endpoint
            .local_addr()
            .map_err(|err| TransportError::Setup(format!("failed to read listener addr: {err}")))
    }

    pub async fn accept(&self) -> Result<LanQuicStream, TransportError> {
        let connection = self
            .endpoint
            .accept()
            .await
            .ok_or(TransportError::Closed)?
            .await
            .map_err(|err| TransportError::Setup(format!("server accept failed: {err}")))?;
        let stream_count = self.stream_count.max(1);
        let mut streams = Vec::with_capacity(stream_count);
        for _ in 0..stream_count {
            let (send, recv) = connection
                .accept_bi()
                .await
                .map_err(|err| TransportError::Setup(format!("server stream failed: {err}")))?;
            streams.push((send, recv));
        }
        Ok(LanQuicStream::new(
            streams,
            self.endpoint.clone(),
            connection,
        ))
    }
}

pub struct LanQuicStream {
    senders: Vec<SendStream>,
    next_sender: usize,
    inbound_rx: mpsc::Receiver<Result<Frame, TransportError>>,
    inbound_tasks: Vec<JoinHandle<()>>,
    _endpoint: Endpoint,
    connection: Connection,
}

impl LanQuicStream {
    fn new(
        streams: Vec<(SendStream, RecvStream)>,
        endpoint: Endpoint,
        connection: Connection,
    ) -> Self {
        let (tx, rx) = mpsc::channel(INBOUND_CHANNEL_SIZE);
        let mut senders = Vec::with_capacity(streams.len());
        let mut tasks = Vec::with_capacity(streams.len());
        for (send, mut recv) in streams {
            senders.push(send);
            let tx_clone = tx.clone();
            let handle = tokio::spawn(async move {
                loop {
                    match read_frame(&mut recv).await {
                        Ok(frame) => {
                            if tx_clone.send(Ok(frame)).await.is_err() {
                                break;
                            }
                        }
                        Err(err) => {
                            let _ = tx_clone.send(Err(err)).await;
                            break;
                        }
                    }
                }
            });
            tasks.push(handle);
        }
        drop(tx);
        Self {
            senders,
            next_sender: 0,
            inbound_rx: rx,
            inbound_tasks: tasks,
            _endpoint: endpoint,
            connection,
        }
    }
}

#[async_trait]
impl TransportStream for LanQuicStream {
    async fn send(&mut self, frame: Frame) -> Result<(), TransportError> {
        if self.senders.is_empty() {
            return Err(TransportError::Closed);
        }
        let idx = self.next_sender;
        self.next_sender = (self.next_sender + 1) % self.senders.len();
        write_frame(&mut self.senders[idx], &frame).await
    }

    async fn recv(&mut self) -> Result<Frame, TransportError> {
        match self.inbound_rx.recv().await {
            Some(Ok(frame)) => Ok(frame),
            Some(Err(err)) => Err(err),
            None => Err(TransportError::Closed),
        }
    }

    async fn close(&mut self) -> Result<(), TransportError> {
        self.inbound_rx.close();
        for sender in &mut self.senders {
            let _ = sender.finish();
        }
        for handle in self.inbound_tasks.drain(..) {
            handle.abort();
        }
        self.connection.close(0u32.into(), b"lan closed");
        Ok(())
    }
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
            let session = SessionDesc::new("loopback-test");
            let mut stream = adapter.connect(&session).await.expect("connect quic");

            let payload = Frame::Data(vec![42; 512]);
            stream.send(payload.clone()).await.expect("send");
            let received = stream.recv().await.expect("recv");
            assert_eq!(received, payload);
            stream.close().await.expect("close");
        });
    }

    #[tokio::test]
    async fn lan_quic_multistream_roundtrip() {
        let quic = LanQuic::new().expect("lan quic");
        let listener = quic
            .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("bind lan listener");
        let addr = listener.local_addr().expect("listener addr");

        let frames: Vec<Frame> = (0..12).map(|i| Frame::Data(vec![i as u8; 512])).collect();
        let server_frames = frames.clone();

        let server_task = async move {
            let mut server = listener.accept().await.expect("accept stream");
            for expected in &server_frames {
                let received = tokio::time::timeout(Duration::from_secs(5), server.recv())
                    .await
                    .expect("server recv timeout")
                    .expect("server recv");
                assert_eq!(received, *expected);
            }
            Ok::<(), TransportError>(())
        };

        let client_task = async {
            let mut client = quic.connect(addr).await.expect("lan connect");
            for frame in &frames {
                client.send(frame.clone()).await.expect("client send");
            }
            Ok::<(), TransportError>(())
        };

        try_join!(server_task, client_task).expect("lan quic roundtrip");
    }
}
