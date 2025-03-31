use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use tokio::sync::Mutex;
use std::sync::Arc;
use std::time::{Instant, Duration};

use common::packet::{build_packet, calculate_header};
use common::types::{ArpAlertPayload, ArpAttackType, DataType, PayloadType};
use pnet::packet::{arp::{ArpOperations, ArpPacket}, Packet};
use pnet::packet::ethernet::EthernetPacket;
use pnet::util::MacAddr;
use tokio_tungstenite::tungstenite::Message;
use tracing::warn;

use crate::utilities::network::mac_to_bytes;
use crate::virtual_net::graph::{NetworkGraph, NodeType};


pub type ArpReqAlertTracker = Arc<Mutex<HashMap<MacAddr, Instant>>>;
pub type ArpResAlertTracker = Arc<Mutex<HashMap<MacAddr, Instant>>>;
pub type ArpAlertTracker = Arc<Mutex<HashMap<MacAddr, Instant>>>;


pub struct ArpRequestTracker {
    requests: HashMap<MacAddr, HashSet<String>>,  // MAC -> IP richiesti
    timestamps: HashMap<MacAddr, Instant>,       // MAC -> Ultimo timestamp
}


impl ArpRequestTracker {
    pub fn new() -> Self {
        ArpRequestTracker {
            requests: HashMap::new(),
            timestamps: HashMap::new(),
        }
    }

    pub fn track_arp(&mut self, src_mac: &MacAddr, dest_ip: &Ipv4Addr) -> bool {
        let now = Instant::now();
        let threshold = Duration::from_secs(5);

        let entry = self.requests.entry(*src_mac).or_insert_with(HashSet::new);
        entry.insert(dest_ip.to_string());

        let last_time = self.timestamps.entry(*src_mac).or_insert(now);
        let elapsed = now.duration_since(*last_time);

        if elapsed < threshold && entry.len() > 10 {
            return true;
        }

        self.timestamps.insert(src_mac.clone(), now);
        false
    }
}


pub async fn detect_arp_attacks<'a>(
    tx: futures_channel::mpsc::UnboundedSender<Message>, 
    session_id: Arc<Mutex<u32>>,
    ethernet_packet: &'a EthernetPacket<'a>,  // Aggiungi il lifetime 'a qui
    arp_req_tracker: Arc<Mutex<ArpRequestTracker>>, 
    arp_res_tracker: Arc<Mutex<ArpRepliesTracker>>, 
    last_req_alert_tracker: ArpReqAlertTracker,
    last_res_alert_tracker: ArpResAlertTracker,
    graph: &mut NetworkGraph, 
    self_mac: MacAddr){
    
    
    if let Some(arp_packet) = ArpPacket::new(ethernet_packet.payload()) {

        let src_mac = arp_packet.get_sender_hw_addr();
        let dest_ip = arp_packet.get_target_proto_addr();

        if arp_packet.get_operation() == ArpOperations::Request {

            let mut tracker = arp_req_tracker.lock().await;
            if tracker.track_arp(&src_mac, &dest_ip) {
                if let Some(node) = graph.nodes.get(&src_mac) {
                    let node = &graph.graph[*node];
                    if node.node_type != NodeType::Router {

                        if node.mac_address != self_mac {
                            let mut alerts = last_req_alert_tracker.lock().await;
                            let now = Instant::now();
                            let key = node.mac_address.clone();
                            let timeout = Duration::from_secs(300); // 5 minuti
                        
                            if alerts.get(&key).map_or(true, |&last| now.duration_since(last) > timeout) {
                                warn!("⚠️ Attenzione: potenziale scansione Nmap da {}\n", src_mac);
                        
                                let arp_alert_payload = PayloadType::ArpAlert(ArpAlertPayload { 
                                    mac_addresses: vec![mac_to_bytes(&node.mac_address)], 
                                    ip_address: node.ipv4_address.to_string(),
                                    arp_attack_type: ArpAttackType::ArpScanning.to_u8()
                                });
                        
                                let mac_bytes = mac_to_bytes(&self_mac);
                                send_arp_alert(tx.clone(), arp_alert_payload, session_id.clone(), DataType::ArpAlert.to_u8(), mac_bytes).await;
                        
                                alerts.insert(key, now);
                            }
                        }
                            
                        
                    }
                }
            }
        }
        else if arp_packet.get_operation() == ArpOperations::Reply {
            let sender_ip = arp_packet.get_sender_proto_addr();

            let mut monitor = arp_res_tracker.lock().await;
            monitor.record_arp_poisoning(tx.clone(), session_id.clone(), sender_ip, src_mac.clone(), self_mac.clone()).await;
            monitor.record_arp_flooding(tx, session_id, src_mac, sender_ip, self_mac, last_res_alert_tracker).await;
        }

    }
    
}



#[derive(Debug)]
pub struct ArpRepliesTracker {
    ip_mac_map:  HashMap<Ipv4Addr, HashSet<Box<[u8; 6]>>>,  // IP -> Set di MAC address
    arp_reply_count: HashMap<MacAddr, u64>,  // MAC Address -> Numero di risposte ARP inviate
}

impl ArpRepliesTracker {
    pub fn new() -> Self {
        Self {
            ip_mac_map: HashMap::new(),
            arp_reply_count: HashMap::new(),
        }
    }

    pub async fn record_arp_poisoning(&mut self,
        tx: futures_channel::mpsc::UnboundedSender<Message>, 
        session_id: Arc<Mutex<u32>>,
        ip: Ipv4Addr, 
        mac: MacAddr, 
        self_mac: MacAddr) {

        let mac_set = self.ip_mac_map.entry(ip).or_insert_with(HashSet::new);

        let mac_bytes: Box<[u8; 6]> = Box::new(mac_to_bytes(&mac));
        mac_set.insert(mac_bytes);

        if mac != self_mac && mac_set.len() > 1 {
            
            warn!("⚠️ Possible ARP poisoning: IP {:?} associated to more than one mac: {:?}", ip, mac_set);

            let arp_alert_payload = PayloadType::ArpAlert(ArpAlertPayload { 
                mac_addresses: mac_set.clone().into_iter().map(|b| *b).collect(), 
                ip_address: ip.to_string(),
                arp_attack_type: ArpAttackType::ArpScanning.to_u8()
            });
                                                                                        
            let mac_bytes = mac_to_bytes(&self_mac);
            send_arp_alert(tx, arp_alert_payload, session_id, DataType::ArpAlert.to_u8(), mac_bytes).await;
        
        }
    }

    /// Registra quante ARP Replies ha inviato un MAC address
    pub async fn record_arp_flooding(&mut self, 
        tx: futures_channel::mpsc::UnboundedSender<Message>, 
        session_id: Arc<Mutex<u32>>,
        mac: MacAddr, 
        ip: Ipv4Addr,
        self_mac: MacAddr,
        last_res_alert_tracker: ArpResAlertTracker
    ) {

        let count = self.arp_reply_count.entry(mac.clone()).or_insert(0);
        *count += 1;
        
        if mac != self_mac && *count > 50 {
            let mut alerts = last_res_alert_tracker.lock().await;
            let now = Instant::now();
            let timeout = Duration::from_secs(300); // 5 minuti
        
            if alerts.get(&mac).map_or(true, |&last| now.duration_since(last) > timeout) {
                            
                warn!("🚨 Possible ARP flooding: Mac {} sent {} ARP Replies!", mac, count);

                let arp_alert_payload = PayloadType::ArpAlert(ArpAlertPayload { 
                    mac_addresses: vec![mac_to_bytes(&mac)], 
                    ip_address: ip.to_string(),
                    arp_attack_type: ArpAttackType::ArpFlooding.to_u8()
                });
                                                                                            
                let mac_bytes = mac_to_bytes(&self_mac);
                send_arp_alert(tx, arp_alert_payload, session_id, DataType::ArpAlert.to_u8(), mac_bytes).await;
                alerts.insert(mac, now);

            }
        }
    }
}


async fn send_arp_alert(
    tx: futures_channel::mpsc::UnboundedSender<Message>,
    payload: PayloadType,
    session_id: Arc<Mutex<u32>>,
    data_type: u8,
    mac_address: [u8; 6],
) {
    let msg = {
        let mut id = session_id.lock().await;
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

