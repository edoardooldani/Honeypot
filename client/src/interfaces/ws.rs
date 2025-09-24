use tokio_tungstenite::{tungstenite::protocol::Message, MaybeTlsStream};
use futures_util::{pin_mut, future, StreamExt};
use tracing::{error, info, warn};
use std::sync::Arc;
use common::tls::generate_client_session_id;
use tokio::sync::Mutex;


pub async fn handle_websocket(
    ws_stream: tokio_tungstenite::WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
) -> (futures_channel::mpsc::UnboundedSender<Message>, Arc<Mutex<u32>>) {

    let maybe_tls_stream = ws_stream.get_ref();
    let session_id = Arc::new(Mutex::new(0));
    if let MaybeTlsStream::Rustls(tls_stream) = maybe_tls_stream {
        let tls_session = tls_stream.get_ref().1;
    
        {
            let mut id = session_id.lock().await;
            *id = generate_client_session_id(tls_session);
        }
    } 

    let (stdin_tx, stdin_rx) = futures_channel::mpsc::unbounded();
    let stdin_tx_pong = stdin_tx.clone();
    
    info!("🖥️ WebSocket connection established, session ID: {}", *session_id.lock().await);

    let (write, read) = ws_stream.split();

    tokio::spawn(async move {
        let stdin_to_ws = stdin_rx.map(Ok).forward(write);

        let ws_to_stdout = read.for_each(move |message| {
            let stdin_tx_pong = stdin_tx_pong.clone();
            async move {
                match message {
                    Ok(Message::Binary(_)) => info!("📥 Received Binary Data"),
                    Ok(Message::Ping(data)) => {
                        info!("📡 Received PING, sending PONG...");
                        let _ = stdin_tx_pong.unbounded_send(Message::Pong(data));
                    }
                    Ok(Message::Close(_)) => warn!("❌ WebSocket connection closed by the peer"),
                    Ok(other) => error!("⚠️ Unsupported Message Type: {:?}", other),
                    Err(e) => error!("❌ Error in message: {}", e),
                }
            }
        });

        pin_mut!(stdin_to_ws, ws_to_stdout);
        let _ = future::select(stdin_to_ws, ws_to_stdout).await;
        info!("🔚 WebSocket task terminated");
    });
    
    return (stdin_tx, session_id);
}
