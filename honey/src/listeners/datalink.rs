use pnet::datalink::{self, Channel};
use pnet::packet::ethernet::EthernetPacket;
use tokio_tungstenite::tungstenite::protocol::Message;
use std::sync::{Arc, Mutex};
use crate::listeners::network::get_primary_interface;
use crate::virtual_net::arp_tracker::{detect_arp_scanner, ArpTracker};
use crate::virtual_net::{graph::{NetworkGraph, NodeType}, node::handle_virtual_packet};


pub async fn scan_datalink(
    _tx: futures_channel::mpsc::UnboundedSender<Message>, 
    _session_id: Arc<Mutex<u32>>, 
    graph: Arc<Mutex<NetworkGraph>>) {

    let interface = get_primary_interface().expect("Nessuna interfaccia valida trovata");

    let (_tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(_, rx)) => ((), rx),
        Ok(_) => panic!("Tipo di canale non supportato"),
        Err(e) => panic!("Errore nell'apertura del canale: {}", e),
    };

    let arp_tracker = Arc::new(Mutex::new(ArpTracker::new()));

    println!("📡 In ascolto del traffico di rete...");
    let local_mac = get_local_mac();

    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(ethernet_packet) = EthernetPacket::new(packet) {

                    let src_mac = ethernet_packet.get_source().to_string();
                    let dest_mac = ethernet_packet.get_destination().to_string();
                    let bytes = packet.len() as u64;
            
                    let protocol = ethernet_packet.get_ethertype().to_string();
            
                    let src_type = classify_mac_address(&src_mac);
                    let dest_type = classify_mac_address(&dest_mac);
            
                    let mut graph = graph.lock().unwrap();
            
                    graph.add_node(src_mac.clone(), None, src_type);
                    graph.add_node(dest_mac.clone(), None, dest_type);
                    
                    graph.add_connection(&src_mac, &dest_mac, &protocol, bytes);

                    if let Some(dest_node) = graph.nodes.get(&dest_mac) {
                        let node = &graph.graph[*dest_node];

                        if node.node_type == NodeType::Virtual || dest_mac == "ff:ff:ff:ff:ff:ff" {
                            let router = graph.find_router();
                            handle_virtual_packet(&dest_mac, &src_mac, bytes, &protocol, router);
                            
                        }
                    }
                    
                    detect_arp_scanner(ethernet_packet, Arc::clone(&arp_tracker), &mut graph, local_mac.clone());
                    
                }
            }
            Err(e) => eprintln!("❌ Errore nella lettura del pacchetto: {}", e),
        }
    }
}


fn classify_mac_address(mac: &str) -> NodeType {
    if mac == "ff:ff:ff:ff:ff:ff" {
        return NodeType::Broadcast;
    }
    if mac.starts_with("01:00:5e") || mac.starts_with("33:33") {
        return NodeType::Multicast;
    }

    NodeType::Real
}

pub fn get_local_mac() -> Option<String> {
    let interfaces = datalink::interfaces();

    interfaces
        .into_iter()
        .filter(|iface| !iface.is_loopback() && !iface.ips.is_empty())
        .find(|iface| iface.mac.is_some())
        .map(|iface| format!("{}", iface.mac.unwrap()))
}