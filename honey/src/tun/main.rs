use tokio_tungstenite::tungstenite::Message;
use tracing::info;
use std::sync::Arc;
use tokio_tun::{TunBuilder, Tun};
use tokio::sync::Mutex;

use crate::virtual_net::{graph::NetworkGraph, virtual_node::handle_tun_msg};

pub async fn create_main_tun(
    tx: futures_channel::mpsc::UnboundedSender<Message>, 
    session_id: Arc<Mutex<u32>>, 
    graph: Arc<Mutex<NetworkGraph>>
) {

    let tun_name = "main_tun";

    let tun = Arc::new(
        Tun::open(tun_name).expect("Failed to open existing TUN interface")
    );
    info!("Main TUN interface opened");

    let tun_reader: Arc<Tun> = Arc::clone(&tun);
    let mut buf = [0u8; 1024];

    loop {
        match tun_reader.recv(&mut buf).await {
            Ok(n) => {
                if n > 0 {
                    match handle_tun_msg(graph.clone(), buf, n).await {
                        Ok(msg) => {
                            if !msg.is_empty() {
                                // Optional: send packet if needed
                            }
                        }
                        Err(e) => {        
                            eprintln!("Error while processing packet: {}", e);
                        }
                    }
                }
            }
            Err(e) => {        
                eprintln!("Error receiving data from TUN interface: {}", e);
            }
        }
    }
}