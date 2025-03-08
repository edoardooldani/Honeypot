
use std::sync::Arc;

use axum::{
    extract::{ws::{Message, WebSocket, WebSocketUpgrade}, State, Extension},
    response::IntoResponse,
};
use futures_util::SinkExt;
use bincode;
use common::types::Packet;

use crate::app_state::WssAppState;


pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(wss_state): State<Arc<WssAppState>>,
    Extension(device_name): Extension<String>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_websocket(socket, Arc::clone(&wss_state), device_name))
}


async fn handle_websocket(mut socket: WebSocket, wss_state: Arc<WssAppState>, device_name: String) {

    while let Some(result) = socket.recv().await {
        match result {
            Ok(Message::Text(_text)) => {
                return;
            }

            Ok(Message::Binary(bin)) =>{                
                match bincode::deserialize::<Packet>(&bin) {
                    Ok(mut packet) => {
                        if let Some(_header) = &packet.header.checksum {
                            if !packet.verify_checksum() {
                                eprintln!("Checksum verification error!: {:?}", packet.header.id);
                            }

                            let mut connections = wss_state.connections.lock().await;
                            if let Some(session_id) = connections.get_mut(&device_name) {
                                if packet.header.id == *session_id + 1 {
                                    *session_id += 1;
                                    //println!("📩 Messaggio valido da {} (session_id={})\n", device_name, packet.header.id);
                                } else {
                                    println!("CLOSE SOCKET header.id: {:?}, session_id: {:?}", packet.header.id, *session_id+1); 

                                    let _ = socket.close().await;
                                    break;
                                }
                            }

                            //println!("Packet: {:?}\n", packet);
                        }
                        
                    },
                    Err(e) => eprintln!("Deserialization error: {}", e),
                }
                
            }
            Ok(Message::Close(_)) => {
                {
                    let mut connections = wss_state.connections.lock().await;
                    connections.remove(&device_name);
                    println!("❌ Connessione chiusa: {}", device_name);
                }
            }
            _ => {}
        }
    }
}
