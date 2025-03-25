use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::packet::{build_packet, calculate_header};
use common::types::{DataType, PayloadType, TcpAlertPayload, TcpAttackType};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use tokio_tungstenite::tungstenite::Message;
use tracing::warn;

use crate::utilities::network::mac_string_to_bytes;

#[derive(Debug)]
pub struct TcpSynDetector {
    attempts: HashMap<String, Vec<Instant>>,
}

impl TcpSynDetector {
    pub fn new() -> Self {
        Self {
            attempts: HashMap::new(),
        }
    }

    /// Register syn and check if it is an alert
    pub fn register_syn(&mut self, src_ip: String) -> bool {
        let now = Instant::now();
        let entry = self.attempts.entry(src_ip.clone()).or_insert(Vec::new());
        entry.push(now);

        entry.retain(|&time| now.duration_since(time) < Duration::from_secs(10));

        // 15 syn in 10 seconds
        if entry.len() > 15 {
            return true;
        }

        false
    }
}


pub fn detect_tcp_syn_attack(
    tx: futures_channel::mpsc::UnboundedSender<Message>, 
    session_id: Arc<Mutex<u32>>,
    ipv4_packet: Ipv4Packet,
    src_mac: String,
    self_mac: String,
    tcp_syn_tracker: Arc<Mutex<TcpSynDetector>>
){
    if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {

        if tcp_packet.get_flags() == 0x02 {
            let src_ip = ipv4_packet.get_source().to_string();
            
            let dest_port = tcp_packet.get_destination();

            let mut guard = tcp_syn_tracker.lock().unwrap();
            if guard.register_syn(src_ip.clone()) {
                warn!("🔥 Possible TCP Syn attack from Mac: {} and IP: {}!", src_mac, src_ip);

                let tcp_alert_payload = PayloadType::TcpAlert(TcpAlertPayload { 
                    mac_address: mac_string_to_bytes(&src_mac), 
                    ip_address: src_ip,
                    dest_port,
                    tcp_attack_type: TcpAttackType::TcpSyn.to_u8()
                });
                                                                                            
                let mac_bytes = mac_string_to_bytes(&self_mac);
                send_tcp_alert(tx, tcp_alert_payload, session_id, DataType::TcpAlert.to_u8(), mac_bytes);

            }
        }
    }
    
}

fn send_tcp_alert(
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