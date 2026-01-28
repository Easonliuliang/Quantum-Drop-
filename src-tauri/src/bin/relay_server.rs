use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

const MAGIC_HEADER: u8 = 0x52; // 'R'
const SESSION_ID_LEN: usize = 32;

#[derive(Debug)]
struct Peer {
    stream: TcpStream,
    addr: SocketAddr,
}

type SessionMap = Arc<Mutex<HashMap<String, Peer>>>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Basic logging setup (simple print for now, can be upgraded to env_logger)
    println!("Starting Relay Server on 0.0.0.0:8080...");

    let listener = TcpListener::bind("0.0.0.0:8080").await?;
    let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));

    loop {
        let (stream, addr) = listener.accept().await?;
        let sessions = sessions.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, addr, sessions).await {
                eprintln!("Connection error from {}: {}", addr, e);
            }
        });
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    addr: SocketAddr,
    sessions: SessionMap,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Handshake
    // Protocol: [Magic(1)][SessionID(32)][Role(1)]
    let mut buf = [0u8; 1 + SESSION_ID_LEN + 1];
    stream.read_exact(&mut buf).await?;

    if buf[0] != MAGIC_HEADER {
        return Err("Invalid magic header".into());
    }

    let session_id = String::from_utf8_lossy(&buf[1..1 + SESSION_ID_LEN]).to_string();
    let role = buf[1 + SESSION_ID_LEN]; // 0: Sender, 1: Receiver (Role is informational for now)

    println!(
        "New connection: {} | Session: {} | Role: {}",
        addr, session_id, role
    );

    // 2. Pairing Logic
    let mut map = sessions.lock().await;

    if let Some(waiting_peer) = map.remove(&session_id) {
        // Match found! Bridge the connections.
        println!("Session {} paired! Bridging {} <-> {}", session_id, waiting_peer.addr, addr);
        drop(map); // Unlock early

        bridge_streams(waiting_peer.stream, stream).await?;
    } else {
        // No peer waiting, store this connection and wait.
        println!("Session {} waiting for peer...", session_id);
        map.insert(session_id, Peer { stream, addr });
    }

    Ok(())
}

async fn bridge_streams(mut stream_a: TcpStream, mut stream_b: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let (mut ri, mut wi) = stream_a.split();
    let (mut ro, mut wo) = stream_b.split();

    let client_to_server = async {
        tokio::io::copy(&mut ri, &mut wo).await
    };

    let server_to_client = async {
        tokio::io::copy(&mut ro, &mut wi).await
    };

    tokio::try_join!(client_to_server, server_to_client)?;

    Ok(())
}
