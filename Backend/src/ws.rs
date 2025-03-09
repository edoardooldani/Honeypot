
use std::sync::Arc;

use axum::{
    body::Bytes, extract::{ws::{Message, WebSocket, WebSocketUpgrade}, Extension, State}, response::IntoResponse
};
use chrono::Utc;
use futures_util::SinkExt;
use bincode;
use common::types::{Packet, DeviceType, PriorityLevel};
use tracing::{info, warn, error};
use tokio::time::{self, Duration};

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

    // Ping per controllare connessioni inattive
    let mut interval = time::interval(Duration::from_secs(15));

    'ws_loop: while let Some(result) = tokio::select! {
        msg = socket.recv() => msg,
        _ = interval.tick() => {
            if let Err(e) = socket.send(Message::Ping(Bytes::new())).await {
                let error_msg = format!("🚨 Ping failure: {}. Closing connection for `{}`", e, device_name);
                close_socket_with_error(&mut socket, &device_name, error_msg.as_str()).await;
                break 'ws_loop;
            }
            continue 'ws_loop;
        }
    } {
        match result {
            Ok(Message::Binary(bin)) => {
                if let Err(err_msg) = process_packet(&wss_state, &device_name, &bin).await {
                    close_socket_with_error(&mut socket, &device_name, &err_msg).await;
                    break;
                }
            } 
            Ok(Message::Pong(_)) => {
                info!("✅ Pong received from `{}`", device_name);
            }
            Ok(Message::Close(_)) | Err(_) => {
                break;
            }
            _ => {
                close_socket_with_error(&mut socket, &device_name, "Invalid message!").await;
                break;
            }
        }
    }

    let mut connections = wss_state.connections.lock().await;
    connections.remove(&device_name);
    warn!("❌ Connessione chiusa: `{}`", device_name);
}


async fn process_packet(wss_state: &Arc<WssAppState>, device_name: &str, bin: &[u8]) -> Result<(), String> {
    let mut packet: Packet = bincode::deserialize(bin).map_err(|e| format!("Deserialization error: {}", e))?;

    if !packet.verify_checksum() {
        return Err(format!("Invalid checksum (ID: {})", packet.header.id));
    }

    let mut connections = wss_state.connections.lock().await;
    if let Some(session_id) = connections.get_mut(device_name) {
        if packet.header.id != *session_id + 1 {
            return Err(format!("Invalid session ID: expected {}, got {}", *session_id + 1, packet.header.id));
        }
        *session_id += 1;
    } else {
        return Err("Session not found".to_string());
    }

    let current_timestamp = Utc::now().timestamp();
    if (current_timestamp - packet.header.timestamp as i64).abs() > 180 {
        return Err(format!("Invalid timestamp: {}", packet.header.timestamp));
    }

    if DeviceType::from_u8(packet.header.data_type).is_none() {
        return Err(format!("Invalid device type: {}", packet.header.data_type));
    }

    if PriorityLevel::from_u8(packet.header.priority).is_none() {
        return Err(format!("Invalid priority level: {}", packet.header.priority));
    }

    info!("📩 Valid message from `{}`: ID={} type={:?}", device_name, packet.header.id, packet.header.data_type);
    
    Ok(())
}


async fn close_socket_with_error(socket: &mut WebSocket, device_name: &str, reason: &str) {
    error!("🛑 [{}] {}", device_name, reason);
    let _ = socket.close().await;
    warn!("❌ Connessione chiusa: `{}`", device_name);
}

/* 
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

                        if DeviceType::from_u8(packet.header.data_type).is_none() {
                            close_socket_with_error(
                                &mut socket,
                                &device_name,
                                &format!("Invalid device type: {}", packet.header.data_type),
                            ).await;
                            break;
                        }

                        if PriorityLevel::from_u8(packet.header.priority).is_none() {
                            close_socket_with_error(
                                &mut socket,
                                &device_name,
                                &format!("Invalid priority: {}", packet.header.priority),
                            ).await;
                            break;
                        }                        // TO DO when devices will have mac registrered
                        /* 
                        if !is_device_registered(&device_name).await {
                            close_socket_with_error(&mut socket, &device_name, "Device non registrato").await;
                            break;
                        } else if !is_device_active(&device_name).await {
                            close_socket_with_error(&mut socket, &device_name, "Device inattivo").await;
                            break;
                        }
                        */
                        println!("Device: {:?}, Message ID: {:?}, MAC: {:?}", device_name, packet.header.id, packet.header.mac_address);
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
                    info!("❌ Connessione chiusa: {}", device_name);
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
    */