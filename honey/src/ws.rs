use tokio_tungstenite::{tungstenite::protocol::Message, MaybeTlsStream};
use futures_util::{pin_mut, future, StreamExt};
use tracing::{error, info};
use std::sync::{Arc, Mutex};
use common::tls::generate_client_session_id;
use crate::network::receiver::scan_datalink;
use crate::virtual_net::graph::NetworkGraph;


pub async fn handle_websocket(ws_stream: tokio_tungstenite::WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>){
    let maybe_tls_stream = ws_stream.get_ref();
    let session_id = Arc::new(Mutex::new(0));
    if let MaybeTlsStream::Rustls(tls_stream) = maybe_tls_stream {
        let tls_session = tls_stream.get_ref().1;
    
        {
            let mut id = session_id.lock().unwrap();
            *id = generate_client_session_id(tls_session);
        }
    } 

    let (stdin_tx, stdin_rx) = futures_channel::mpsc::unbounded();
    let stdin_tx_pong = stdin_tx.clone();
    let stdin_tx_graph = stdin_tx.clone();

    let graph = Arc::new(Mutex::new(NetworkGraph::new()));
    let graph_clone = Arc::clone(&graph);

    tokio::spawn(scan_datalink(stdin_tx_graph, Arc::clone(&session_id), graph_clone));


    let (mut write, read) = ws_stream.split();
    let stdin_to_ws = stdin_rx.map(Ok).forward(&mut write);

    let ws_to_stdout = read.for_each(|message| async {
        match message {
            Ok(msg) => match msg {
                Message::Binary(_bin) => info!("📥 Received Binary Data"),
                Message::Ping(ping_data) => {
                    info!("📡 Received PING, sending PONG...");
                    let _ = stdin_tx_pong.unbounded_send(Message::Pong(ping_data));
                }
                _ => error!("⚠️ Unsupported Message Type: {:?}", msg),
            },
            Err(e) => error!("❌ Error in message: {}", e),
        }
    });
    pin_mut!(stdin_to_ws, ws_to_stdout);
    future::select(stdin_to_ws, ws_to_stdout).await;
    
}
