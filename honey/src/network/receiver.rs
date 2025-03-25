use pnet::datalink::{self, Channel, Config, DataLinkSender};
use pnet::packet::arp::{ArpOperations, ArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::echo_request::EchoRequestPacket;
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use pnet::util::MacAddr;
use rustls::pki_types::IpAddr;
use tokio_tungstenite::tungstenite::protocol::Message;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use crate::network::sender::send_icmp_reply;
use crate::utilities::network::{classify_mac_address, get_local_mac, get_primary_interface, get_src_dest_ip};
use crate::trackers::arp_tracker::{detect_arp_attacks, AlertTracker, ArpRepliesTracker, ArpRequestTracker};
use crate::trackers::tcp_tracker::{detect_tcp_syn_attack, TcpSynDetector};
use crate::virtual_net::virtual_node::{handle_broadcast, handle_virtual_packet};
use crate::virtual_net::graph::{NetworkGraph, NodeType};


pub async fn scan_datalink(
    tx: futures_channel::mpsc::UnboundedSender<Message>, 
    session_id: Arc<Mutex<u32>>, 
    graph: Arc<Mutex<NetworkGraph>>) {

    let interface = get_primary_interface().expect("Nessuna interfaccia valida trovata");

    let mut config = Config::default();
    config.promiscuous = true;
    
    let (mut tx_datalink, mut rx) = match datalink::channel(&interface, config) {
        Ok(Channel::Ethernet(tx_datalink, rx)) => (tx_datalink, rx),
        Ok(_) => panic!("Tipo di canale non supportato"),
        Err(e) => panic!("Errore nell'apertura del canale: {}", e),
    };
    
    let alert_tracker: Arc<Mutex<HashMap<String, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
    
    let arp_req_tracker = Arc::new(Mutex::new(ArpRequestTracker::new()));
    let arp_res_tracker = Arc::new(Mutex::new(ArpRepliesTracker::new()));
    let tcp_syn_tracker = Arc::new(Mutex::new(TcpSynDetector::new()));


    println!("📡 In ascolto del traffico di rete...");
    let local_mac = get_local_mac();

    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(ethernet_packet) = EthernetPacket::new(packet) {
                    let src_mac = ethernet_packet.get_source().to_string();
                    
                    if src_mac == local_mac {
                        continue;
                    }

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

                    if let Some(dest_ip) = dest_ip.clone() {
                        
                        if !graph.nodes.contains_key(&src_mac) {
                            graph.add_node(src_mac.clone(), src_ip.clone(), src_type);
                        }
                    
                        if dest_mac != "ff:ff:ff:ff:ff:ff" && !graph.nodes.contains_key(&dest_mac) {
                            graph.add_node(dest_mac.clone(), Some(dest_ip.clone()), dest_type);
                        }
                    
                        if graph.nodes.contains_key(&src_mac) && graph.nodes.contains_key(&dest_mac) {
                            graph.add_connection(&src_mac, &dest_mac, &protocol.to_string(), bytes);
                        }
                    }

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
                    &src_mac, 
                                &mut *tx_datalink
                            );
                        }
                        
                    }
                    
                    detect_attacks(
                        tx.clone(), 
                        session_id.clone(), 
                        &ethernet_packet, 
                        &mut graph, 
                        local_mac.clone(), 
                        alert_tracker.clone(),
                        Arc::clone(&arp_req_tracker), 
                        Arc::clone(&arp_res_tracker), 
                        tcp_syn_tracker.clone()
                    );

                }
            }
            Err(e) => eprintln!("❌ Errore nella lettura del pacchetto: {}", e),
        }
    }
}


fn detect_attacks(
    tx: futures_channel::mpsc::UnboundedSender<Message>,
    session_id: Arc<Mutex<u32>>,
    ethernet_packet: &EthernetPacket,
    graph: &mut NetworkGraph,
    local_mac: String,
    alert_tracker: AlertTracker,
    arp_req_tracker: Arc<Mutex<ArpRequestTracker>>,
    arp_res_tracker: Arc<Mutex<ArpRepliesTracker>>,
    tcp_syn_tracker: Arc<Mutex<TcpSynDetector>>,
) {
    if ethernet_packet.get_ethertype() == EtherTypes::Arp {
        detect_arp_attacks(
            tx.clone(), 
            session_id.clone(),
            ethernet_packet, 
            arp_req_tracker, 
            arp_res_tracker,
            alert_tracker,
            graph, 
            local_mac.clone()
        );
    }
    if ethernet_packet.get_ethertype() == EtherTypes::Ipv4 {
        println!("Ether packet: {:?}", ethernet_packet);

        if let Some(ipv4_packet) = Ipv4Packet::new(ethernet_packet.payload()) {
            let next_protocol = ipv4_packet.get_next_level_protocol();
            match next_protocol {
                IpNextHeaderProtocols::Icmp => {
                    println!("ICMP ");
                    if let Some(icmp_packet) = IcmpPacket::new(ipv4_packet.payload()) {
                        if icmp_packet.get_icmp_type() == IcmpTypes::EchoRequest {
                            if let Some(echo_request) = EchoRequestPacket::new(icmp_packet.packet()) {
                                //send_icmp_reply(tx, ethernet_packet, &ipv4_packet, virtual_mac, virtual_ip, sender_mac, &echo_request);
                                println!("echo req: {:?}", echo_request);
                            }
                        }
                    }
                }

                IpNextHeaderProtocols::Tcp => {
                    detect_tcp_syn_attack(
                        tx.clone(),
                        session_id.clone(),
                        ipv4_packet,
                        ethernet_packet.get_source().to_string(),
                        local_mac,
                        tcp_syn_tracker
                    );    
                }
                _ => {
                    
                }
            }
            
        }
    }
}

