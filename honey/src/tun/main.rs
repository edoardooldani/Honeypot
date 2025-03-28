use pnet::packet::ethernet::EthernetPacket;
use tokio_tungstenite::tungstenite::Message;
use tracing::info;
use std::sync::Arc;
use std::fs::File;
use tokio_tun::{TunBuilder, Tun};
use tokio::sync::Mutex;
use std::io::{self, Read, Write};
use std::os::unix::io::AsRawFd;



use crate::virtual_net::{graph::NetworkGraph, virtual_node::handle_tun_msg};

pub async fn create_main_tun(
    tx: futures_channel::mpsc::UnboundedSender<Message>, 
    session_id: Arc<Mutex<u32>>, 
    graph: Arc<Mutex<NetworkGraph>>
) {
    let mut tun_file = open_existing_tun("main_tun").unwrap();
    let mut buf = vec![0u8; 1500]; // Buffer per i pacchetti ricevuti

    loop {
        let n = tun_file.read(&mut buf).unwrap();
        let ethernet_packet = EthernetPacket::new(&buf).unwrap();
        println!("eth: {:?}", ethernet_packet);
    }


}


fn open_existing_tun(tun_name: &str) -> io::Result<File> {
    let tun_path = format!("/dev/net/tun");
    let tun_file = File::open(tun_path)?;

    // Configura la TUN per leggere e scrivere pacchetti
    tun_file.set_len(0)?;
    Ok(tun_file)
}



    /* 
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
    */