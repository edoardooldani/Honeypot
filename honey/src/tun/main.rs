use tokio_tungstenite::tungstenite::Message;
use tracing::info;
use std::sync::{Arc, Mutex};

use tokio_tun::{TunBuilder, Tun};

use crate::{network::sender::find_ip_by_mac, virtual_net::{graph::NetworkGraph, virtual_node::handle_tun_msg}};

pub async fn create_main_tun(
    tx: futures_channel::mpsc::UnboundedSender<Message>, 
    session_id: Arc<Mutex<u32>>, 
    graph: Arc<Mutex<NetworkGraph>>
) {

    let tun_name = "main_tun";
    let ipv4_address = "10.0.0.1";
    let netmask = "255.255.255.0";

    let tun = Arc::new(
        TunBuilder::new()
            .name(tun_name)
            .address(ipv4_address)
            .netmask(netmask)
            .up()
            .build()
            .pop()
            .await
            .unwrap(),
    );

    let tun_reader: Arc<Tun> = Arc::clone(&tun);
    let mut buf = [0u8; 1024];

    loop {
        match tun_reader.recv(&mut buf).await {
            Ok(n) => {
                if n > 0 {
                    println!("Buf received: {:?}", buf);
                }
            }
            Err(e) => {        
                eprintln!("Errore: {}", e);
            }
        }
    }
}
