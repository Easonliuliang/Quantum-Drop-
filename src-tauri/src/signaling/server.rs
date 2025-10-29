use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::IntoResponse;
use axum::{routing::get, Router};
use futures::stream::StreamExt;

pub fn router() -> Router {
    Router::new().route("/ws", get(upgrade))
}

async fn upgrade(ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(handle_socket)
}

async fn handle_socket(mut socket: WebSocket) {
    while let Some(Ok(msg)) = socket.next().await {
        match msg {
            Message::Text(text) => {
                let _ = socket.send(Message::Text(text)).await;
            }
            Message::Binary(bin) => {
                let _ = socket.send(Message::Binary(bin)).await;
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
    let _ = socket.close().await;
}
