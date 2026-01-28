use std::time::Duration;
use tokio::time::timeout;

use quantum_drop::transport::{Frame, LanQuic, TransportStream};

#[cfg(feature = "signaling-server")]
use std::net::SocketAddr;
#[cfg(feature = "signaling-server")]
use tokio::net::TcpListener;
#[cfg(feature = "signaling-server")]
use quantum_drop::transport::{SessionDesc, TransportAdapter};
#[cfg(feature = "signaling-server")]
use quantum_drop::transport::webrtc::WebRtcAdapter;
#[cfg(feature = "signaling-server")]
use quantum_drop::transport::adapter::{WebRtcHint, WebRtcRole};
#[cfg(feature = "signaling-server")]
use quantum_drop::security::SecurityConfig;
#[cfg(feature = "signaling-server")]
use quantum_drop::signaling::signaling_router as router;

#[tokio::test]
async fn test_quic_integration() {
    // 1. Setup Server (Listener)
    let server_quic = LanQuic::new().expect("Failed to create server QUIC");
    let listener = server_quic
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .expect("Failed to bind QUIC listener");
    let server_addr = listener.local_addr().expect("Failed to get server addr");

    println!("QUIC Server listening on {}", server_addr);

    let server_task = tokio::spawn(async move {
        let mut stream = listener.accept().await.expect("Server accept failed");
        let frame = stream.recv().await.expect("Server recv failed");
        if let Frame::Data(data) = frame {
            assert_eq!(data, b"Hello QUIC");
            stream
                .send(Frame::Data(b"Hello Back".to_vec()))
                .await
                .expect("Server send failed");
        } else {
            panic!("Unexpected frame type");
        }
    });

    // 2. Setup Client
    // We clone the server instance to share the same self-signed certificate/credentials,
    // ensuring the client trusts the server for this test.
    let client_quic = server_quic.clone();
    println!("Client connecting to {}", server_addr);
    
    let mut stream = timeout(Duration::from_secs(5), client_quic.connect(server_addr))
        .await
        .expect("Client connect timed out")
        .expect("Client connect failed");
    
    println!("Client connected!");

    // 3. Exchange Data
    stream
        .send(Frame::Data(b"Hello QUIC".to_vec()))
        .await
        .expect("Client send failed");
    
    let frame = stream.recv().await.expect("Client recv failed");
    if let Frame::Data(data) = frame {
        assert_eq!(data, b"Hello Back");
    } else {
        panic!("Unexpected frame type");
    }

    timeout(Duration::from_secs(5), server_task)
        .await
        .expect("Server task timed out")
        .expect("Server task failed");
}

#[tokio::test]
#[cfg(feature = "signaling-server")]
async fn test_webrtc_integration() {
    // 1. Start Signaling Server
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let signaling_addr = listener.local_addr().unwrap();
    let signaling_url = format!("ws://{}/ws", signaling_addr);
    
    println!("Signaling Server listening on {}", signaling_url);

    let app = router(SecurityConfig::default());
    
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // 2. Setup Alice (Offerer)
    let adapter_alice = WebRtcAdapter::with_signaling(
        Default::default(),
        signaling_url.clone(),
        None,
    );
    let mut session_alice = SessionDesc::new("webrtc-test-session");
    session_alice.webrtc = Some(WebRtcHint {
        role: WebRtcRole::Offerer,
        device_id: Some("alice-device".into()),
        identity_id: None,
        device_name: None,
        signer_public_key: None,
    });

    // 3. Setup Bob (Answerer)
    let adapter_bob = WebRtcAdapter::with_signaling(
        Default::default(),
        signaling_url.clone(),
        None,
    );
    let mut session_bob = SessionDesc::new("webrtc-test-session");
    session_bob.webrtc = Some(WebRtcHint {
        role: WebRtcRole::Answerer,
        device_id: Some("bob-device".into()),
        identity_id: None,
        device_name: None,
        signer_public_key: None,
    });

    // 4. Connect Both
    // We need to run them concurrently because they wait for each other
    let alice_task = tokio::spawn(async move {
        let mut stream = adapter_alice.connect(&session_alice).await.expect("Alice connect failed");
        stream.send(Frame::Data(b"Hello WebRTC".to_vec())).await.expect("Alice send failed");
        let frame = stream.recv().await.expect("Alice recv failed");
        if let Frame::Data(data) = frame {
            assert_eq!(data, b"Hello Back");
        }
    });

    let bob_task = tokio::spawn(async move {
        let mut stream = adapter_bob.connect(&session_bob).await.expect("Bob connect failed");
        let frame = stream.recv().await.expect("Bob recv failed");
        if let Frame::Data(data) = frame {
            assert_eq!(data, b"Hello WebRTC");
            stream.send(Frame::Data(b"Hello Back".to_vec())).await.expect("Bob send failed");
        }
    });

    // Wait for completion with timeout
    timeout(Duration::from_secs(10), async {
        let (res_a, res_b) = tokio::join!(alice_task, bob_task);
        res_a.unwrap();
        res_b.unwrap();
    })
    .await
    .expect("WebRTC test timed out");
}
