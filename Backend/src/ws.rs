
use std::sync::Arc;

use axum::{
    extract::{ws::{Message, WebSocket, WebSocketUpgrade}, State, Extension},
    response::IntoResponse,
};
use chrono::Utc;
use futures_util::SinkExt;
use bincode;
use common::types::Packet;
use tracing::{info, warn, error};

use crate::app_state::WssAppState;


pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(wss_state): State<Arc<WssAppState>>,
    Extension(device_name): Extension<String>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_websocket(socket, Arc::clone(&wss_state), device_name))
}


async fn handle_websocket(mut socket: WebSocket, wss_state: Arc<WssAppState>, device_name: String) {

    info!("✅ New WebSocket connection from: `{}`", device_name);

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
                                close_socket_with_error(&mut socket, &device_name, "Invalid checksum!").await;
                                break;
                            }
                        } else {
                            close_socket_with_error(&mut socket, &device_name, "Missing checksum!").await;
                            break;
                        }

                        let mut connections = wss_state.connections.lock().await;
                        if let Some(session_id) = connections.get_mut(&device_name) {
                            *session_id += 1;
                            if packet.header.id != *session_id{
                                close_socket_with_error(&mut socket, &device_name, "Invalid session id!").await;
                                break;
                            }
                        }
                        
                        let current_timestamp = Utc::now().timestamp();
                        if (current_timestamp - packet.header.timestamp).abs() > 180 {  // 3 minutes
                            close_socket_with_error(&mut socket, &device_name, "Invalid timestamp!").await;
                            break;
                        }
                        // TO DO when devices will have mac registrered
                        /* 
                        if !is_device_registered(&device_name).await {
                            close_socket_with_error(&mut socket, &device_name, "Device non registrato").await;
                            break;
                        } else if !is_device_active(&device_name).await {
                            close_socket_with_error(&mut socket, &device_name, "Device inattivo").await;
                            break;
                        }
                        */
                    },
                    Err(e) => {
                        close_socket_with_error(&mut socket, &device_name, &format!("Deserialization error: {}", e)).await;
                        break;
                    }
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


async fn close_socket_with_error(socket: &mut WebSocket, device_name: &str, reason: &str) {
    error!("🛑 [{}] {}", device_name, reason);
    let _ = socket.close().await;
    warn!("❌ Connessione chiusa: {}", device_name);
}