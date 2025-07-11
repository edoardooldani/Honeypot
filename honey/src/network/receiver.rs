use pnet::datalink::{self, Channel, Config, DataLinkSender};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::Packet;
use pnet::util::MacAddr;
use tokio_tungstenite::tungstenite::protocol::Message;
use tract_onnx::prelude::SimplePlan;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use tokio::sync::Mutex;
use std::sync::Arc;
use std::time::Instant;
use crate::trackers::tracker::detect_attacks;
use crate::utilities::network::{get_local_mac, get_primary_interface};
use crate::trackers::arp_tracker::{ArpRepliesTracker, ArpRequestTracker};
use crate::trackers::tcp_tracker::TcpSynDetector;
use crate::honeypot::handler::handle_virtual_packet;
use crate::network::graph::{update_graph_from_packet, NetworkGraph};
use crate::AI::detection::detect_anomaly;
use tract_onnx::prelude::*;


pub async fn scan_datalink(
    tx: futures_channel::mpsc::UnboundedSender<Message>, 
    session_id: Arc<Mutex<u32>>, 
    graph: Arc<Mutex<NetworkGraph>>,
    ai_model: SimplePlan<TypedFact, Box<dyn TypedOp>, tract_onnx::prelude::Graph<TypedFact, Box<dyn TypedOp>>>
) {

    let interface = get_primary_interface().expect("Nessuna interfaccia valida trovata");

    let mut config = Config::default();
    config.promiscuous = true;
    
    let (tx_datalink, mut rx) = match datalink::channel(&interface, config) {
        Ok(Channel::Ethernet(tx, rx)) => (
            Arc::new(tokio::sync::Mutex::new(tx as Box<dyn DataLinkSender + Send>)),
            rx
        ),
        Ok(_) => panic!("Tipo di canale non supportato"),
        Err(e) => panic!("Errore nell'apertura del canale: {}", e),
    };
    
    let arp_req_alert_tracker: Arc<Mutex<HashMap<MacAddr, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
    let arp_res_alert_tracker: Arc<Mutex<HashMap<MacAddr, Instant>>> = Arc::new(Mutex::new(HashMap::new()));

    let arp_req_tracker = Arc::new(Mutex::new(ArpRequestTracker::new()));
    let arp_res_tracker = Arc::new(Mutex::new(ArpRepliesTracker::new()));
    let tcp_syn_tracker = Arc::new(Mutex::new(TcpSynDetector::new()));

    println!("📡 In ascolto del traffico di rete...");
    let local_mac = get_local_mac();

    loop {
        match rx.next() {
            Ok(packet) => {
                println!("📥 Ricevuto pacchetto: {} bytes", packet.len());
                if let Some(ethernet_packet) = EthernetPacket::new(packet) {
                    
                    
                    let src_mac = ethernet_packet.get_source();

                    if src_mac == local_mac {
                        continue;
                    }
                    
                    if let Some(ethernet_packet) = EthernetPacket::new(&packet.to_vec()) {
                        detect_anomaly(ai_model.clone(), ethernet_packet).await;
                    }
                    
                    let dest_ip: Ipv4Addr = update_graph_from_packet(graph.clone(), &ethernet_packet, packet.len()).await;

                    let (src_ip, dest_ip) = crate::utilities::network::get_src_dest_ip(&ethernet_packet)
                        .unwrap_or((Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 0)));
                    /* 
                    let graph_guard = graph.lock().await;

                    // Handle virtual node
                    if let Some(dest_node) = graph_guard.find_virtual_node_by_ip_or_mac(ethernet_packet.get_destination(), dest_ip) {
                        let tx_clone = tx_datalink.clone();
                        let ethertype = ethernet_packet.get_ethertype();
                        let payload = ethernet_packet.payload().to_vec();
                        let source = ethernet_packet.get_source();
                        let virtual_mac = dest_node.mac_address.clone();
                        let virtual_ip = dest_node.ipv4_address.clone();

                        tokio::spawn(async move {
                            handle_virtual_packet(
                                ethertype,
                                payload,
                                &source,
                                &virtual_mac, 
                                &virtual_ip, 
                                tx_clone
                            ).await;  
                        });
                                
                    }
                    */
                    let mut graph_lock = graph.lock().await;

                    detect_attacks(
                        tx.clone(), 
                        session_id.clone(), 
                        &ethernet_packet, 
                        &mut graph_lock, 
                        local_mac.clone(), 
                        arp_req_alert_tracker.clone(),
                        arp_res_alert_tracker.clone(),
                        Arc::clone(&arp_req_tracker), 
                        Arc::clone(&arp_res_tracker), 
                        tcp_syn_tracker.clone(),
                    ).await;
                    
                }

            },
            Err(e) => {
                eprintln!("❌ Errore nella lettura del pacchetto: {}", e);
                continue;
            }
        };
    }
}

