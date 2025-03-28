use pnet::util::MacAddr;
use tokio_tungstenite::tungstenite::Message;
use tracing::info;
use std::{net::Ipv4Addr, str::FromStr, sync::{Arc, Mutex}};
#[cfg(target_os = "linux")]
use tokio_tun::{TunBuilder, Tun};
use tokio::io;

use crate::virtual_net::{graph::NetworkGraph, virtual_node::handle_tun_msg};

pub async fn create_main_tun(
    tx: futures_channel::mpsc::UnboundedSender<Message>, 
    session_id: Arc<Mutex<u32>>, 
    graph: Arc<Mutex<NetworkGraph>>
) {

    let tun_name = "main_tun";
    let ipv4_address: Ipv4Addr = "192.168.1.251".parse().map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid IP: {}", e))
    }).expect("Error parsing IP");    

    let netmask = "255.255.255.0".parse::<Ipv4Addr>().expect("Error parsing netmask");

    let tun = Arc::new(
        TunBuilder::new()
            .name(tun_name)
            .address(ipv4_address)
            .netmask(netmask)
            .up()
            .build()
            .unwrap()
            .pop()
            .unwrap()
    );
    info!("Main TUN inteface UP");
    
    let tun_reader: Arc<Tun> = Arc::clone(&tun);
    let mut buf = [0u8; 1024];

    loop {
        match tun_reader.recv(&mut buf).await {
            Ok(n) => {
                if n > 0 {
                    match handle_tun_msg(graph.clone(), buf, n).await {
                        Ok(msg) => {
                            
                            if !msg.is_empty(){
                                /* 
                                println!("Message to send: {:?}", msg);

                                if let Err(e) = tun_writer.send(msg.as_slice()).await {
                                    eprintln!("Error while sending packet: {:?}", e);
                                } else {
                                    println!("Packet sent successfully!");
                                }
                                */
                            }
                            
                        }Err(e) => {        
                            eprintln!("Errore: {}", e);
                        }
                    }
                }
            }
            Err(e) => {        
                eprintln!("Errore: {}", e);
            }
        }
    }
}
