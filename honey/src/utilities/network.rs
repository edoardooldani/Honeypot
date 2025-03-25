use std::net::IpAddr;

use pnet::{datalink::NetworkInterface, packet::{arp::ArpPacket, ethernet::{EtherTypes, EthernetPacket}, ipv4::Ipv4Packet, ipv6::Ipv6Packet, Packet}};
use pnet::datalink;
use crate::virtual_net::graph::NodeType;


pub fn get_src_dest_ip(packet: &EthernetPacket) -> Option<(IpAddr, IpAddr)> {
    match packet.get_ethertype() {
        EtherTypes::Arp => {
            if let Some(arp_packet) = ArpPacket::new(packet.payload()) {
                let src_ip = IpAddr::V4(arp_packet.get_sender_proto_addr());
                let dst_ip = IpAddr::V4(arp_packet.get_target_proto_addr());
                return Some((src_ip, dst_ip));
            }
        }
        EtherTypes::Ipv4 => {
            if let Some(ipv4_packet) = Ipv4Packet::new(packet.payload()) {
                let src_ip = IpAddr::V4(ipv4_packet.get_source());
                let dst_ip = IpAddr::V4(ipv4_packet.get_destination());
                return Some((src_ip, dst_ip));
            }
        }
        EtherTypes::Ipv6 => {
            if let Some(ipv6_packet) = Ipv6Packet::new(packet.payload()) {
                let src_ip = IpAddr::V6(ipv6_packet.get_source());
                let dst_ip = IpAddr::V6(ipv6_packet.get_destination());
                return Some((src_ip, dst_ip));
            }
        }
        _ => {}
    }
    None
}

pub fn classify_mac_address(mac: &str) -> NodeType {
    if mac == "ff:ff:ff:ff:ff:ff" {
        return NodeType::Broadcast;
    }
    if mac.starts_with("01:00:5e") || mac.starts_with("33:33") {
        return NodeType::Multicast;
    }

    NodeType::Real
}

pub fn get_local_mac() -> String {
    let interfaces = datalink::interfaces();

    let preferred_interfaces = ["eth", "wlan", "en"]; // Ethernet, Wi-Fi, etc.

    let mac = interfaces
        .into_iter()
        .filter(|iface| {
            !iface.is_loopback()
                && !iface.ips.is_empty()
                && preferred_interfaces.iter().any(|p| iface.name.starts_with(p))
        })
        .find_map(|iface| iface.mac.map(|mac| mac.to_string()));

    mac.unwrap_or_else(|| "00:00:00:00:00:00".to_string())
}


pub fn get_primary_interface() -> Option<NetworkInterface> {
    let interfaces = datalink::interfaces();

    interfaces
        .into_iter()
        .filter(|iface| !iface.is_loopback() && !iface.ips.is_empty())
        .find(|iface| iface.mac.is_some())
}


pub fn mac_string_to_bytes(mac: &str) -> [u8; 6] {
    let bytes: Vec<u8> = mac
        .split(':')
        .filter_map(|s| u8::from_str_radix(s, 16).ok())
        .collect();
    if bytes.len() == 6 {
        [bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]]
    } else {
        [0, 0, 0, 0, 0, 0]
    }
}