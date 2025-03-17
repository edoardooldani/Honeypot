use pnet::datalink::{self, Channel};
use pnet::packet::ethernet::EthernetPacket;
use tokio_tungstenite::tungstenite::protocol::Message;
use std::sync::{Arc, Mutex};
use crate::listeners::sender::get_primary_interface;
use crate::virtual_net::arp_tracker::{detect_arp_scanner, ArpTracker};
use crate::virtual_net::virtual_node::{handle_virtual_packet, handle_virtual_responses};
use crate::virtual_net::graph::{NetworkGraph, NodeType};


pub async fn scan_datalink(
    tx: futures_channel::mpsc::UnboundedSender<Message>, 
    session_id: Arc<Mutex<u32>>, 
    graph: Arc<Mutex<NetworkGraph>>) {

    let interface = get_primary_interface().expect("Nessuna interfaccia valida trovata");

    let (mut tx_datalink, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx_datalink, rx)) => (tx_datalink, rx),
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
                        let virtual_node = &graph.graph[*dest_node];

                        if dest_mac == "ff:ff:ff:ff:ff:ff" {
                            if let Some(router_mac) = graph.find_router().map(|router| router.mac_address.clone()) {

                                if src_mac != router_mac {
                                    handle_virtual_responses(&graph, &mut *tx_datalink, &ethernet_packet, &src_mac);
                                }
                            }                             
                        } 
                        else if virtual_node.node_type == NodeType::Virtual{
                            handle_virtual_packet(
                                &ethernet_packet, 
                    &virtual_node.mac_address, 
                    &virtual_node.ip_address.clone().expect("Ip virtual node must be known"), 
                    &src_mac, &mut *tx_datalink
                            );
                        }
                        
                    }
                    
                    detect_arp_scanner(
                        tx.clone(), 
                        session_id.clone(),
                        &ethernet_packet, 
                        Arc::clone(&arp_tracker), 
                        &mut graph, 
                        local_mac.clone());
                    
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

