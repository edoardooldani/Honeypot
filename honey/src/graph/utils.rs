use std::{net::Ipv4Addr, str::FromStr};

use pnet::{datalink::NetworkInterface, packet::{arp::ArpPacket, ethernet::{EtherTypes, EthernetPacket}, ipv4::Ipv4Packet, Packet}, util::MacAddr};
use pnet::datalink;
use rand::Rng;
use crate::graph::types::NetworkGraph;

pub fn get_src_and_dest_ip(packet: &EthernetPacket) -> Option<(Ipv4Addr, Ipv4Addr)> {
    match packet.get_ethertype() {
        EtherTypes::Arp => {
            let arp_packet = ArpPacket::new(packet.payload())?;
            return Some((arp_packet.get_sender_proto_addr(), arp_packet.get_target_proto_addr()))
        }
        EtherTypes::Ipv4 => {
            let ipv4_packet = Ipv4Packet::new(packet.payload())?;
            return Some((ipv4_packet.get_source(), ipv4_packet.get_destination()))
        }
        _ => {}
    }
    None
}

pub fn get_src_and_dest_transport(packet: &EthernetPacket) -> (u16, u16, u8) {
    match packet.get_ethertype() {
        EtherTypes::Ipv4 => {
            if let Some(ipv4_packet) = Ipv4Packet::new(packet.payload()) {
                let next_protocol = ipv4_packet.get_next_level_protocol();
                match next_protocol {
                    pnet::packet::ip::IpNextHeaderProtocols::Tcp => {
                        if let Some(transport_packet) = pnet::packet::tcp::TcpPacket::new(ipv4_packet.payload()) {
                            let src_port = transport_packet.get_source();
                            let dst_port = transport_packet.get_destination();
                            return (src_port, dst_port, 6);
                        }
                    }
                    pnet::packet::ip::IpNextHeaderProtocols::Udp => {
                        if let Some(_transport_packet) = pnet::packet::udp::UdpPacket::new(ipv4_packet.payload()) {
                            return (0, 0, 17);
                        }
                    }
                    pnet::packet::ip::IpNextHeaderProtocols::Icmp => {
                        return (0, 0, 0);
                    }
                    _ => {}
                }
                
            }
        }
        _ => {}
    }
    return (0, 0, 0);
}



pub fn get_primary_interface() -> Option<NetworkInterface> {
    let interfaces = datalink::interfaces();
    
    interfaces
        .into_iter()
        .filter(|iface| !iface.is_loopback() && !iface.ips.is_empty())
        .find(|iface| iface.mac.is_some())
}


pub fn generate_virtual_ip(graph: &NetworkGraph) -> Ipv4Addr {
    let mut rng = rand::rng();
    let mut last_octet = rng.random_range(100..115);

    let base_ip = [192, 168, 1];

    loop {
        let new_ip = Ipv4Addr::new(base_ip[0], base_ip[1], base_ip[2], last_octet);

        if !graph.nodes.values().any(|node| node.ipv4_address == Some(new_ip)) {
            return new_ip;
        }

        last_octet += 1;
        if last_octet > 253 {
            panic!("No IP address available!");
        }
    }
}

pub fn generate_virtual_ipv6() -> String {
    let mut rng = rand::rng();
    let last_segment = rng.random_range(100..130);
    let base_ip = "fe80::1000:".to_string(); // Link-local address base
    
    format!("{}{:x}", base_ip, last_segment) // Concatenate to create a valid IPv6 address
}



pub fn generate_virtual_mac() -> MacAddr {
    let mac_prefixes = vec![
        "00:1A:2B", // Cisco
        "34:56:78", // Samsung
        "70:C9:32", // Apple
        "D8:21:DA", // TP-Link
        "60:1D:9D", // Dell
        "C4:3C:B0", // Asus
    ];

    let mut rng = rand::rng();
    let prefix = mac_prefixes[rng.random_range(0..mac_prefixes.len())];
    
    let suffix = [
        rng.random_range(0..=255),
        rng.random_range(0..=255),
        rng.random_range(0..=255),
    ];

    let mac_string = format!("{}:{:02X}:{:02X}:{:02X}", prefix, suffix[0], suffix[1], suffix[2]);

    MacAddr::from_str(&mac_string).expect("Failed to parse MAC address")
}