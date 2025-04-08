use std::{net::Ipv4Addr, str::FromStr};

use pnet::{datalink::NetworkInterface, packet::{arp::ArpPacket, ethernet::{EtherTypes, EthernetPacket}, ipv4::Ipv4Packet, Packet}, util::MacAddr};
use pnet::datalink;
use rand::Rng;
use crate::network::graph::{NetworkGraph, NodeType};

pub fn get_src_dest_ip(packet: &EthernetPacket) -> Option<(Ipv4Addr, Ipv4Addr)> {
    match packet.get_ethertype() {
        EtherTypes::Arp => {
            if let Some(arp_packet) = ArpPacket::new(packet.payload()) {
                let src_ip = arp_packet.get_sender_proto_addr();
                let dst_ip = arp_packet.get_target_proto_addr();
                return Some((src_ip, dst_ip)); 
            }
        }
        EtherTypes::Ipv4 => {
            if let Some(ipv4_packet) = Ipv4Packet::new(packet.payload()) {
                let src_ip = ipv4_packet.get_source();
                let dst_ip = ipv4_packet.get_destination();
                return Some((src_ip, dst_ip));
            }
        }
        _ => {}
    }
    None
}



pub fn classify_mac_address(mac: MacAddr) -> NodeType {
    // Controllo per indirizzo MAC Broadcast (tutti i byte sono 0xFF)
    if mac.octets().iter().all(|&byte| byte == 0xFF) {
        return NodeType::Broadcast;
    }

    // Controllo per indirizzo MAC Multicast (prefix 01:00:5e o 33:33)
    let octets = mac.octets();
    if octets.starts_with(&[0x01, 0x00, 0x5e]) || octets.starts_with(&[0x33, 0x33]) {
        return NodeType::Multicast;
    }

    // Se non è né broadcast né multicast, è un indirizzo MAC "Reale"
    NodeType::Real
}

pub fn get_local_mac() -> MacAddr {
    let interfaces = datalink::interfaces();

    let preferred_interfaces = ["eth", "en"]; // Ethernet, Wi-Fi, etc.

    let mac = interfaces
        .into_iter()
        .filter(|iface| {
            !iface.is_loopback()
                && !iface.ips.is_empty()
                && preferred_interfaces.iter().any(|p| iface.name.starts_with(p))
        })
        .find_map(|iface| iface.mac.map(|mac| mac.to_string()));

    MacAddr::from_str(&mac.expect("Couldn't get local mac address")).expect("Couldn't cast mac into MacAddr")
}


pub fn get_primary_interface() -> Option<NetworkInterface> {
    let interfaces = datalink::interfaces();

    interfaces
        .into_iter()
        .filter(|iface| !iface.is_loopback() && !iface.ips.is_empty())
        .find(|iface| iface.mac.is_some())
}


pub fn mac_to_bytes(mac: &MacAddr) -> [u8; 6] {
    let mac_bytes = mac.octets(); // Ottieni i byte direttamente tramite octets()
    [mac_bytes[0], mac_bytes[1], mac_bytes[2], mac_bytes[3], mac_bytes[4], mac_bytes[5]]
}

pub async fn generate_virtual_ip(graph: &mut NetworkGraph) -> Ipv4Addr {
    let mut rng = rand::rng();
    let mut last_octet = rng.random_range(100..115);

    let base_ip = [192, 168, 1];

    loop {
        let new_ip = Ipv4Addr::new(base_ip[0], base_ip[1], base_ip[2], last_octet);

        if !graph.graph.node_weights().any(|node| node.ipv4_address == new_ip) {
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