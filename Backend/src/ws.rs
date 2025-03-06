
use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::IntoResponse,
};

use bincode;
use common::types::{Packet, Payload, ProcessPayload};


pub async fn ws_handler(ws: WebSocketUpgrade,
) -> impl IntoResponse {
    ws.on_upgrade(handle_websocket)
}


async fn handle_websocket(mut socket: WebSocket) {

    while let Some(result) = socket.recv().await {
        match result {
            Ok(Message::Text(text)) => {
                if socket
                    .send(Message::Text(format!("echo: {}", text).into()))
                    .await
                    .is_err()
                {
                    // Se il client ha chiuso la connessione o c'è un errore, esci dal ciclo
                    break;
                }
            }
            Ok(Message::Binary(bin)) =>{
                
                match bincode::deserialize::<Packet>(&bin) {
                    Ok(mut packet) => {
                        if let Some(header) = &packet.header.checksum {
                            if !packet.verify_checksum() {
                                eprintln!("Checksum verification error!: {:?}", packet.header.id);
                            }

                            println!("Packet: {:?}", packet);
                        }
                        
                    },
                    Err(e) => eprintln!("Deserialization error: {}", e),
                }
                
            }
            Ok(Message::Close(_)) => break,
            _ => {}
        }
    }
}
