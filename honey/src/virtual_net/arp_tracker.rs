use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Instant, Duration};

use common::packet::{build_packet, calculate_header};
use common::types::{ArpAlertPayload, DataType, PayloadType};
use pnet::packet::{arp::{ArpOperations, ArpPacket}, Packet};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use tokio_tungstenite::tungstenite::Message;
use tracing::warn;

use super::graph::{NetworkGraph, NodeType};

pub struct ArpTracker {
    requests: HashMap<String, HashSet<String>>, // MAC -> IP richiesti
    timestamps: HashMap<String, Instant>,       // MAC -> Ultimo timestamp
}

impl ArpTracker {
    pub fn new() -> Self {
        ArpTracker {
            requests: HashMap::new(),
            timestamps: HashMap::new(),
        }
    }

    pub fn track_arp(&mut self, src_mac: &str, dest_ip: &str) -> bool {
        let now = Instant::now();
        let threshold = Duration::from_secs(5);

        let entry = self.requests.entry(src_mac.to_string()).or_insert_with(HashSet::new);
        entry.insert(dest_ip.to_string());

        let last_time = self.timestamps.entry(src_mac.to_string()).or_insert(now);
        let elapsed = now.duration_since(*last_time);

        if elapsed < threshold && entry.len() > 10 {
            return true;
        }

        self.timestamps.insert(src_mac.to_string(), now);
        false
    }
}



pub fn detect_arp_scanner(
    tx: futures_channel::mpsc::UnboundedSender<Message>, 
    session_id: Arc<Mutex<u32>>,
    ethernet_packet: &EthernetPacket, 
    arp_tracker: Arc<Mutex<ArpTracker>>, 
    graph: &mut NetworkGraph, 
    self_mac: Option<String>){
        
    if ethernet_packet.get_ethertype() == EtherTypes::Arp {
        if let Some(arp_packet) = ArpPacket::new(ethernet_packet.payload()) {
            if arp_packet.get_operation() == ArpOperations::Request {
                let src_mac = format!("{}", arp_packet.get_sender_hw_addr());
                let dest_ip = format!("{}", arp_packet.get_target_proto_addr());

                let mut tracker = arp_tracker.lock().unwrap();
                if tracker.track_arp(&src_mac, &dest_ip) {
                    if let Some(node) = graph.nodes.get(&src_mac) {
                        let node = &graph.graph[*node];
                        if node.node_type != NodeType::Router {
                            if let Some(local_mac) = self_mac {
                                if node.mac_address != local_mac {
                                    warn!("⚠️ Attenzione: potenziale scansione Nmap da {}\n", src_mac);

                                    let arp_alert_payload = PayloadType::ArpAlert(ArpAlertPayload { 
                                        mac_address: mac_string_to_bytes(&node.mac_address), 
                                        ip_address: node.ip_address.clone().unwrap_or_else(|| "Unknown".to_string()) 
                                    });
                                                                                                                
                                    let mac_bytes = mac_string_to_bytes(&local_mac);
                                    send_arp_alert(tx, arp_alert_payload, session_id, DataType::ArpAlert.to_u8(), mac_bytes);
                                }else{                                    
                                    println!("{:?}", node);
                                }
                                
                            }
                        }
                    }
                }
            }
        }
    }
}


fn send_arp_alert(
    tx: futures_channel::mpsc::UnboundedSender<Message>,
    payload: PayloadType,
    session_id: Arc<Mutex<u32>>,
    data_type: u8,
    mac_address: [u8; 6],
) {
    let msg = {
        let mut id = session_id.lock().unwrap();
        *id += 1;

        let header = calculate_header(*id, data_type, 0, mac_address);
        let packet = build_packet(header, payload);
        let serialized = bincode::serialize(&packet).expect("Errore nella serializzazione");

        Message::Binary(serialized.into())
    };

    if let Err(e) = tx.unbounded_send(msg) {
        eprintln!("Errore nell'invio del messaggio WebSocket: {:?}", e);
    }
}



fn mac_string_to_bytes(mac: &str) -> [u8; 6] {
    let bytes: Vec<u8> = mac
        .split(':')
        .filter_map(|s| u8::from_str_radix(s, 16).ok())
        .collect();
    if bytes.len() == 6 {
        [bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]]
    } else {
        [0, 0, 0, 0, 0, 0]
    }
}