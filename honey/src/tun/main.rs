use pnet::datalink;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::Packet;
use tokio::time::sleep;
use tokio_tungstenite::tungstenite::Message;
use tracing::info;
use std::sync::Arc;
use std::time::Duration;
use tokio_tun::{TunBuilder, Tun};
use tokio::sync::Mutex;



use crate::virtual_net::{graph::NetworkGraph, virtual_node::handle_tun_msg};

pub async fn create_main_tun(
    tx: futures_channel::mpsc::UnboundedSender<Message>, 
    session_id: Arc<Mutex<u32>>, 
    graph: Arc<Mutex<NetworkGraph>>
) {
    let interfaces = datalink::interfaces();
    
    let main_tun = interfaces.into_iter()
        .find(|iface| iface.name == "main_tun")
        .expect("Interfaccia main_tun non trovata");
        
    let (_tx, mut rx) = match datalink::channel(&main_tun, Default::default()) {
        Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Tipo di canale non supportato"),
        Err(e) => panic!("Errore nell'aprire il canale: {}", e),
    };
    
    info!("In ascolto su main_tun...");
    
    // Leggi i pacchetti che arrivano sull'interfaccia TUN
    loop {
        match rx.next() {
            Ok(packet) => {
                // Decodifica il pacchetto Ethernet
                if let Some(ethernet_packet) = EthernetPacket::new(packet) {
                    match ethernet_packet.get_ethertype() {
                        EtherTypes::Ipv4 => {
                            // Se il pacchetto è di tipo IPv4
                            if let Some(ipv4_packet) = pnet::packet::ipv4::Ipv4Packet::new(ethernet_packet.payload()) {
                                let src_ip = ipv4_packet.get_source();
                                let dst_ip = ipv4_packet.get_destination();
                                
                                // Stampa le informazioni del pacchetto
                                println!("Pacchetto IPv4 ricevuto:");
                                println!("  Fonte IP: {}", src_ip);
                                println!("  Destinazione IP: {}", dst_ip);
                            }
                        }
                        EtherTypes::Ipv6 => {
                            println!("Pacchetto IPv6 ricevuto");
                        }
                        _ => {
                            println!("Pacchetto di tipo sconosciuto");
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Errore nella lettura del pacchetto: {}", e);
            }
        }
        
        sleep(Duration::from_millis(100)).await;
    }    


}
