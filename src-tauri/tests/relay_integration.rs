use std::process::{Command, Child};
use std::time::Duration;
use tokio::time::sleep;
use courier_agent::transport::{RelayAdapter, SessionDesc, TransportAdapter, Frame, RelayHint};

struct ServerGuard(Child);

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

#[tokio::test]
async fn test_relay_integration() {
    // 1. Build the relay server binary first to ensure it's fresh
    let status = Command::new("cargo")
        .args(&["build", "--bin", "relay_server"])
        .status()
        .expect("Failed to build relay_server");
    assert!(status.success(), "Failed to compile relay_server");

    // 2. Start Relay Server
    // We assume the binary is in target/debug/relay_server
    let server_bin = "./target/debug/relay_server";
    let child = Command::new(server_bin)
        .spawn()
        .expect("Failed to start relay_server");
    let _guard = ServerGuard(child);

    // Give it a moment to start listening
    sleep(Duration::from_secs(1)).await;

    // 3. Setup Clients
    let adapter_a = RelayAdapter::new();
    let adapter_b = RelayAdapter::new();

    let session_id = "integration-test-session-uuid-001"; // 32 chars roughly
    
    // Configure session with local relay hint
    let mut session = SessionDesc::new(session_id);
    session.relay = Some(RelayHint {
        host: "127.0.0.1".to_string(),
        port: 8080,
    });

    // 4. Connect Alice (Sender)
    // We spawn this because connect() might block waiting for handshake or peer? 
    // Actually our connect() implementation sends handshake and returns. 
    // But the *bridging* happens when both connect. 
    // The stream returned by connect() is ready to use immediately after handshake?
    // Let's look at the implementation: connect() sends handshake and returns RelayStream.
    // The RelayStream.recv() will block until data comes.
    
    let mut stream_a = adapter_a.connect(&session).await.expect("Alice connect failed");
    let mut stream_b = adapter_b.connect(&session).await.expect("Bob connect failed");

    // 5. Exchange Data
    // Alice sends to Bob
    let msg = "Hello from Alice via Relay";
    stream_a.send(Frame::Data(msg.as_bytes().to_vec())).await.expect("Alice send failed");

    // Bob receives
    let frame = stream_b.recv().await.expect("Bob recv failed");
    match frame {
        Frame::Data(data) => {
            assert_eq!(data, msg.as_bytes());
            println!("Bob received: {}", String::from_utf8_lossy(&data));
        }
        _ => panic!("Bob received unexpected frame"),
    }

    // Bob sends to Alice
    let msg_reply = "Hello from Bob";
    stream_b.send(Frame::Data(msg_reply.as_bytes().to_vec())).await.expect("Bob send failed");

    // Alice receives
    let frame = stream_a.recv().await.expect("Alice recv failed");
    match frame {
        Frame::Data(data) => {
            assert_eq!(data, msg_reply.as_bytes());
            println!("Alice received: {}", String::from_utf8_lossy(&data));
        }
        _ => panic!("Alice received unexpected frame"),
    }

    // 6. Cleanup
    stream_a.close().await.ok();
    stream_b.close().await.ok();
}
