use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Instant, Duration};

use pnet::packet::{arp::{ArpOperations, ArpPacket}, Packet};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
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



pub fn detect_arp_scanner(ethernet_packet: EthernetPacket, arp_tracker: Arc<Mutex<ArpTracker>>, graph: &mut NetworkGraph, self_mac: Option<String>){
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
                                }
                                
                            }
                        }
                    }
                }
            }
        }
    }
}