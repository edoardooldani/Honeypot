use tract_onnx::prelude::*;
use pnet::packet::ethernet::EthernetPacket;
use std::collections::HashMap;
use std::sync::Mutex as StdMutex;
use lazy_static::lazy_static;
use std::time::{Duration, Instant};
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;

use crate::trackers::flow::{FlowKey, FlowPacket, FlowStats, FlowTracker, PacketDirection};

lazy_static! {
    static ref FLOW_TRACKER: StdMutex<FlowTracker> = StdMutex::new(FlowTracker {
        flows: HashMap::new(),
        timeout: Duration::from_secs(10),
        max_packets: 30,
    });
}

pub async fn detect_anomaly<'a>(
    model: SimplePlan<TypedFact, Box<dyn TypedOp>, tract_onnx::prelude::Graph<TypedFact, Box<dyn TypedOp>>>, 
    ethernet_packet: EthernetPacket<'a>
) -> bool {

    let eth_payload = ethernet_packet.payload();
    println!("📦 Ricevuto pacchetto Ethernet: {} bytes", eth_payload.len());
    
    if let Some(ipv4_packet) = pnet::packet::ipv4::Ipv4Packet::new(eth_payload) {
        let src_ip = ipv4_packet.get_source().to_string();
        let dst_ip = ipv4_packet.get_destination().to_string();
        let protocol = ipv4_packet.get_next_level_protocol();

        let (src_port, dst_port, flags) = if protocol == pnet::packet::ip::IpNextHeaderProtocols::Tcp {
            if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                (
                    tcp_packet.get_source(),
                    tcp_packet.get_destination(),
                    Some(tcp_packet.get_flags())
                )
            } else {
                return false;
            }
        } else {
            return false; // Ignora i non-TCP per ora
        };

        let key = FlowKey {
            src_ip: src_ip.clone(),
            dst_ip: dst_ip.clone(),
            src_port,
            dst_port,
            protocol: "TCP".to_string(),
        };

        // Direzione: assume che la sorgente iniziale sia forward
        let direction = PacketDirection::Forward;

        let packet = FlowPacket {
            timestamp: Instant::now(),
            length: ethernet_packet.packet().len(),
            direction,
            flags,
        };

        let mut tracker = FLOW_TRACKER.lock().unwrap();
        let maybe_complete = tracker.update_flow(key, packet);

        if let Some(completed_flow) = maybe_complete {
            // QUI: chiama inferenza con completed_flow
            println!("📤 Esegui inferenza: {} packets", completed_flow.packets.len());
            return true;
        }
    }

    false
}