use pnet::datalink;
use pnet::ipnetwork::IpNetwork;
use pnet::packet::ethernet::EthernetPacket;
use tokio_tungstenite::tungstenite::Message;
use tracing::info;
use std::net::IpAddr;
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
    open_existing_tun("main_tun");
    


}

fn open_existing_tun(tun_name: &str) {
    let interfaces = datalink::interfaces();

    // Stampa informazioni su ogni interfaccia
    for interface in interfaces {
        println!("Interfaccia: {}", interface.name);
        
        // Mostra se l'interfaccia è attiva o meno
        println!("  Attiva: {}", interface.is_up());
        
        // Mostra gli indirizzi IP associati all'interfaccia
        for ip in interface.ips {
            match ip {
                IpNetwork::V4(v4) => println!("  IPv4: {}", v4),
                IpNetwork::V6(v6) => println!("  IPv6: {}", v6),
            }
        }

        // Mostra l'indirizzo MAC (se disponibile)
        if let Some(mac) = interface.mac {
            println!("  MAC: {}", mac);
        }

        println!(); // Linea vuota per separare le interfacce
    }
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