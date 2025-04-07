use std::{net::Ipv4Addr, str::FromStr};

use pnet::{datalink::NetworkInterface, packet::{arp::ArpPacket, ethernet::{EtherTypes, EthernetPacket}, ipv4::Ipv4Packet, Packet}, util::MacAddr};
use pnet::datalink;
use crate::network::graph::NodeType;

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
