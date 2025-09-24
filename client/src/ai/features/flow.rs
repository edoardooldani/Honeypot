use std::collections::hash_map::Entry;
use std::collections::HashMap;
use common::packet_features::{PacketDirection, PacketFeatures};
use lazy_static::lazy_static;
use pnet::packet::{ethernet::EthernetPacket, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, udp::UdpPacket};
use std::net::Ipv4Addr;
use std::sync::Mutex;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;


#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct FlowKey {
    pub ip_src: String,
    pub ip_dst: String,
    //pub port_src: u16,
    //pub port_dst: u16,
    pub protocol: u8,
}

pub struct FlowTracker {
    pub flows: HashMap<FlowKey, PacketFeatures>,
}

impl FlowTracker {
    pub fn flow_update<'a>(&mut self, key: FlowKey, ethernet_packet: &EthernetPacket<'a>) -> &PacketFeatures {
        let features = match self.flows.entry(key.clone()) {
            Entry::Occupied(entry) => {
                let features = entry.into_mut();
                features
            }
            Entry::Vacant(entry) => {
                let new_features = PacketFeatures::default();
                //new_features.src_port = key.port_src;
                //new_features.dst_port = key.port_dst;
                entry.insert(new_features)
            }
        };

        // TO DO: Handle Ipv6
        if let Some(ip_packet) = Ipv4Packet::new(ethernet_packet.payload()) {
            let packet_src_ip = ip_packet.get_source().to_string();

            match is_forward(&packet_src_ip, &key.ip_src) {
                PacketDirection::Forward=> features.update_directional(&ip_packet, PacketDirection::Forward),
                PacketDirection::Backward => features.update_directional(&ip_packet, PacketDirection::Backward),
            }
        }

        features    
    }
}

lazy_static! {
    static ref FLOW_TRACKER: Mutex<FlowTracker> = Mutex::new(FlowTracker {
        flows: HashMap::new(),
    });
}

fn is_forward(packet_src: &str, flow_src: &str) -> PacketDirection {
    if packet_src == flow_src {
        PacketDirection::Forward
    } else {
        PacketDirection::Backward
    }
}

pub async fn update_and_get_flow<'a>(ethernet_packet: &EthernetPacket<'a>) -> Option<PacketFeatures> {
    if let Some(ip_packet) = Ipv4Packet::new(ethernet_packet.payload()) {
        let src_ip = ip_packet.get_source().to_string();
        let dst_ip = ip_packet.get_destination().to_string();
        let protocol = ip_packet.get_next_level_protocol();

        if protocol == IpNextHeaderProtocols::Tcp {
            if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {
                let src_port = tcp_packet.get_source();
                let dst_port = tcp_packet.get_destination();

                // Ignoring mDNS packets
                if src_port == 5353 && dst_port == 5353 {
                    return None;
                }

                let key = FlowKey {
                    ip_src: src_ip,
                    ip_dst: dst_ip,
                    protocol: 6,
                };
                
                let mut features = FLOW_TRACKER.lock().unwrap().flow_update(key, &ethernet_packet).clone();
                features.protocol = 6;
                return Some(features);
            }
        }
        else if protocol == IpNextHeaderProtocols::Udp {
            if let Some(_udp_packet) = UdpPacket::new(ip_packet.payload()) {

                // Ignore mDNS packets for Apple devices
                if dst_ip == Ipv4Addr::new(224, 0, 0, 251).to_string() {
                    return None; 
                }

                let key = FlowKey {
                    ip_src: src_ip,
                    ip_dst: dst_ip,
                    protocol: 17,
                };
                
                let mut features = FLOW_TRACKER.lock().unwrap().flow_update(key, &ethernet_packet).clone();
                features.protocol = 17;
                return Some(features);
            }
        }
    }
    
    None
}