use pnet::datalink::{self, Channel, DataLinkSender};
use pnet::packet::arp::{ArpOperations, ArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::Packet;
use pnet::util::MacAddr;
use tokio_tungstenite::tungstenite::protocol::Message;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use crate::listeners::sender::get_primary_interface;
use crate::virtual_net::arp_tracker::{detect_arp_attacks, ArpRepliesTracker, ArpRequestTracker};
use crate::virtual_net::virtual_node::handle_virtual_packet;
use crate::virtual_net::graph::{NetworkGraph, NodeType};

use super::sender::send_arp_reply;


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
    
    let arp_req_tracker = Arc::new(Mutex::new(ArpRequestTracker::new()));
    let arp_res_tracker = Arc::new(Mutex::new(ArpRepliesTracker::new()));


    println!("📡 In ascolto del traffico di rete...");
    let local_mac = get_local_mac();

    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(ethernet_packet) = EthernetPacket::new(packet) {

                    
                    let src_mac = ethernet_packet.get_source().to_string();
                    let dest_mac = ethernet_packet.get_destination().to_string();
                    let bytes = packet.len() as u64;
            
                    let protocol = ethernet_packet.get_ethertype();

                    let mut src_ip: Option<String> = None;
                    let mut dest_ip: Option<String> = None;


                    if let Some((sc_ip, dst_ip)) = get_src_dest_ip(&ethernet_packet) {
                        src_ip = Some(sc_ip.to_string());
                        dest_ip= Some(dst_ip.to_string());
                    }

                    let src_type = classify_mac_address(&src_mac);
                    let dest_type = classify_mac_address(&dest_mac);
            
                    let mut graph = graph.lock().unwrap();
                    
                    graph.add_node(src_mac.clone(), src_ip, src_type);
                    graph.add_node(dest_mac.clone(), dest_ip, dest_type);
                    
                    graph.add_connection(&src_mac, &dest_mac, &protocol.to_string(), bytes);

                    if dest_mac == "ff:ff:ff:ff:ff:ff" {
                        handle_broadcast(&ethernet_packet, &mut *graph, &mut *tx_datalink);
                    }

                    // Handle virtual receiver
                    if let Some(dest_node) = graph.nodes.get(&dest_mac) {
                        let graph_node = &graph.graph[*dest_node];
 
                        if graph_node.node_type == NodeType::Virtual{
                            handle_virtual_packet(
                                &ethernet_packet, 
                    &graph_node.mac_address, 
                    &graph_node.ip_address.clone().expect("Virtual node IP is always known!"), 
                    &src_mac, &mut *tx_datalink
                            );
                        }
                        
                    }
                    
                
                    if ethernet_packet.get_ethertype() == EtherTypes::Arp {
                        detect_arp_attacks(
                            tx.clone(), 
                            session_id.clone(),
                            &ethernet_packet, 
                            Arc::clone(&arp_req_tracker), 
                            Arc::clone(&arp_res_tracker),
                            &mut graph, 
                            local_mac.clone()
                        );
                    }
                }
            }
            Err(e) => eprintln!("❌ Errore nella lettura del pacchetto: {}", e),
        }
    }
}


fn handle_broadcast(
    ethernet_packet: &EthernetPacket,
    graph: &mut NetworkGraph,
    tx_datalink: &mut dyn DataLinkSender,
) {

    if ethernet_packet.get_ethertype() == EtherTypes::Arp {
        if let Some(arp_packet) = ArpPacket::new(ethernet_packet.payload()) {
            if arp_packet.get_operation() == ArpOperations::Request {
                let requested_ip = arp_packet.get_target_proto_addr();
                let sender_mac = ethernet_packet.get_source(); 

                // Don't answer to router
                if !graph.is_router(sender_mac) {  
                    if let Some(virtual_node) = graph.find_virtual_node_by_ip(requested_ip) {
                        let virtual_mac = MacAddr::from_str(&virtual_node.mac_address).expect("MAC non valido");

                        // Don't answer to itself
                        if sender_mac.to_string() != get_local_mac(){

                            send_arp_reply(
                                tx_datalink,
                                virtual_mac,
                                requested_ip,
                                arp_packet.get_sender_hw_addr(),
                                arp_packet.get_sender_proto_addr(),
                            );
                        }
                    }
                }else{
                    println!("Will not answer to router");
                }
            }
        }
    }
}


fn get_src_dest_ip(packet: &EthernetPacket) -> Option<(IpAddr, IpAddr)> {
    match packet.get_ethertype() {
        EtherTypes::Arp => {
            if let Some(arp_packet) = ArpPacket::new(packet.payload()) {
                let src_ip = IpAddr::V4(arp_packet.get_sender_proto_addr());
                let dst_ip = IpAddr::V4(arp_packet.get_target_proto_addr());
                return Some((src_ip, dst_ip));
            }
        }
        EtherTypes::Ipv4 => {
            if let Some(ipv4_packet) = Ipv4Packet::new(packet.payload()) {
                let src_ip = IpAddr::V4(ipv4_packet.get_source());
                let dst_ip = IpAddr::V4(ipv4_packet.get_destination());
                return Some((src_ip, dst_ip));
            }
        }
        EtherTypes::Ipv6 => {
            if let Some(ipv6_packet) = Ipv6Packet::new(packet.payload()) {
                let src_ip = IpAddr::V6(ipv6_packet.get_source());
                let dst_ip = IpAddr::V6(ipv6_packet.get_destination());
                return Some((src_ip, dst_ip));
            }
        }
        _ => {}
    }
    None
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

pub fn get_local_mac() -> String {
    let interfaces = datalink::interfaces();

    let preferred_interfaces = ["eth", "wlan", "en"]; // Ethernet, Wi-Fi, etc.

    let mac = interfaces
        .into_iter()
        .filter(|iface| {
            !iface.is_loopback()
                && !iface.ips.is_empty()
                && preferred_interfaces.iter().any(|p| iface.name.starts_with(p))
        })
        .find_map(|iface| iface.mac.map(|mac| mac.to_string()));

    mac.unwrap_or_else(|| "00:00:00:00:00:00".to_string())
}

