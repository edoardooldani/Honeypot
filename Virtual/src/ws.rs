use tokio_tungstenite::{tungstenite::protocol::Message, MaybeTlsStream};
use futures_util::{pin_mut, future, StreamExt};
use std::sync::{Arc, Mutex};
use common::tls::generate_client_session_id;
use crate::network_scanner::scan_local_network;


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
    let stdin_tx_network = stdin_tx.clone();

    tokio::spawn(scan_local_network(stdin_tx_network, Arc::clone(&session_id)));

    let (mut write, read) = ws_stream.split();
    let stdin_to_ws = stdin_rx.map(Ok).forward(&mut write);

    let ws_to_stdout = read.for_each(|message| async {
        match message {
            Ok(msg) => match msg {
                Message::Binary(_bin) => println!("📥 Received Binary Data"),
                Message::Ping(ping_data) => {
                    println!("📡 Received PING, sending PONG...");
                    let _ = stdin_tx_pong.unbounded_send(Message::Pong(ping_data));
                }
                _ => eprintln!("⚠️ Unsupported Message Type"),
            },
            Err(e) => eprintln!("❌ Error in message: {}", e),
        }
    });
    pin_mut!(stdin_to_ws, ws_to_stdout);
    future::select(stdin_to_ws, ws_to_stdout).await;
    
}
