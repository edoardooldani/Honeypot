use tract_onnx::prelude::*;
use pnet::packet::{ethernet::EthernetPacket, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, udp::UdpPacket};
use std::collections::HashMap;
use std::sync::Mutex as StdMutex;
use lazy_static::lazy_static;
use std::time::{Duration, Instant};
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;

use crate::{trackers::flow::{FlowKey, FlowTracker}, ai::features::PacketFeatures};

lazy_static! {
    static ref FLOW_TRACKER: StdMutex<FlowTracker> = StdMutex::new(FlowTracker {
        flows: HashMap::new(),
    });
}

pub async fn detect_anomaly<'a>(
    model: SimplePlan<TypedFact, Box<dyn TypedOp>, tract_onnx::prelude::Graph<TypedFact, Box<dyn TypedOp>>>, 
    ethernet_packet: EthernetPacket<'a>
) -> bool {

    let packet_features = get_packet_flow(&ethernet_packet).await;

    if packet_features.is_none() {
        return false; // No tcp/udp found, no anomaly to detect
    }

    println!("Packet Features: {:?}", packet_features);
    false
}

async fn get_packet_flow<'a>(ethernet_packet: &EthernetPacket<'a>) -> Option<PacketFeatures> {
    if let Some(ip_packet) = Ipv4Packet::new(ethernet_packet.payload()) {
        let src_ip = ip_packet.get_source().to_string();
        let dst_ip = ip_packet.get_destination().to_string();
        let protocol = ip_packet.get_next_level_protocol();

        if protocol == IpNextHeaderProtocols::Tcp {
            if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {
                let src_port = tcp_packet.get_source();
                let dst_port = tcp_packet.get_destination();

                let key = FlowKey {
                    ip_src: src_ip,
                    ip_dst: dst_ip,
                    port_src: src_port,
                    port_dst: dst_port,
                    protocol: 6,
                };

                return Some(FLOW_TRACKER.lock().unwrap().get_flow_or_insert(key).clone());
            }
        }
        else if protocol == IpNextHeaderProtocols::Udp {
            if let Some(udp_packet) = UdpPacket::new(ip_packet.payload()) {
                let src_port = udp_packet.get_source();
                let dst_port = udp_packet.get_destination();

                let key = FlowKey {
                    ip_src: src_ip,
                    ip_dst: dst_ip,
                    port_src: src_port,
                    port_dst: dst_port,
                    protocol: 17,
                };
                
                return Some(FLOW_TRACKER.lock().unwrap().get_flow_or_insert(key).clone());
            }
        }
    }
    
    None
}