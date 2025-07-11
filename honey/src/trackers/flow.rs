use std::collections::HashMap;
use crate::ai::features::PacketFeatures;
use lazy_static::lazy_static;
use pnet::packet::{ethernet::EthernetPacket, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, udp::UdpPacket};
use std::sync::Mutex;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketDirection {
    Forward,
    Backward,
}

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct FlowKey {
    pub ip_src: String,
    pub ip_dst: String,
    pub port_src: u16,
    pub port_dst: u16,
    pub protocol: u8,
}

pub struct FlowTracker {
    pub flows: HashMap<FlowKey, PacketFeatures>,
}

impl FlowTracker {
    pub fn get_flow_or_insert(&mut self, key: FlowKey) -> &PacketFeatures {
        self.flows.entry(key.clone()).or_insert_with(PacketFeatures::default)
    }
}

lazy_static! {
    static ref FLOW_TRACKER: Mutex<FlowTracker> = Mutex::new(FlowTracker {
        flows: HashMap::new(),
    });
}

pub async fn get_packet_flow<'a>(ethernet_packet: &EthernetPacket<'a>) -> Option<PacketFeatures> {
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