use std::{net::Ipv4Addr, str::FromStr, sync::{Arc, Mutex}, thread, time::Duration};

use pnet::{datalink::{Channel, NetworkInterface}, packet::{arp::{ArpOperations, ArpPacket}, ethernet::{EtherTypes, EthernetPacket}, ipv4::Ipv4Packet, Packet}, util::MacAddr};
use pnet::datalink;
use crate::{network::sender::send_arp_request, virtual_net::graph::NodeType};

pub fn get_src_dest_ip(packet: &EthernetPacket) -> Option<(Ipv4Addr, Ipv4Addr)> {
    match packet.get_ethertype() {
        EtherTypes::Arp => {
            if let Some(arp_packet) = ArpPacket::new(packet.payload()) {
                let src_ip = arp_packet.get_sender_proto_addr(); // This is Ipv4Addr
                let dst_ip = arp_packet.get_target_proto_addr(); // This is Ipv4Addr
                return Some((src_ip, dst_ip)); // Return Ipv4Addr
            }
        }
        EtherTypes::Ipv4 => {
            if let Some(ipv4_packet) = Ipv4Packet::new(packet.payload()) {
                let src_ip = ipv4_packet.get_source(); // This is Ipv4Addr
                let dst_ip = ipv4_packet.get_destination(); // This is Ipv4Addr
                return Some((src_ip, dst_ip)); // Return Ipv4Addr
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

    let preferred_interfaces = ["eth", "wlan", "en"]; // Ethernet, Wi-Fi, etc.

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


pub async fn find_ip_by_mac(target_mac: &MacAddr) -> Ipv4Addr {
    let interface = get_primary_interface().expect("Nessuna interfaccia valida trovata");

    let my_ip = match interface.ips.iter().find(|ip| ip.is_ipv4()) {
        Some(ip) => match ip.ip() {
            std::net::IpAddr::V4(ipv4) => ipv4,
            _ => return Ipv4Addr::new(0, 0, 0, 0),
        },
        None => return Ipv4Addr::new(0, 0, 0, 0),
    };

    let my_mac = interface.mac.unwrap();
    let subnet = (my_ip.octets()[0], my_ip.octets()[1], my_ip.octets()[2]);

    let (tx_datalink, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Ipv4Addr::new(0, 0, 0, 0),
        Err(_) => return Ipv4Addr::new(0, 0, 0, 0),
    };

    let tx_arc = Arc::new(Mutex::new(tx_datalink));

    // Spawning async tasks using tokio::spawn
    for i in 1..=254 {
        let target_ip = Ipv4Addr::new(subnet.0, subnet.1, subnet.2, i);
        let tx_clone = Arc::clone(&tx_arc);
        let my_mac_clone = my_mac.clone();

        tokio::spawn(async move {
            let mut tx_lock = tx_clone.lock().unwrap();
            send_arp_request(&mut **tx_lock, my_mac_clone, my_ip, target_ip);
        });
    }

    let timeout = Duration::from_secs(2);
    let start_time = std::time::Instant::now();

    while start_time.elapsed() < timeout {
        match rx.next() {
            Ok(packet) => {
                if let Some(ethernet_packet) = EthernetPacket::new(packet) {
                    if ethernet_packet.get_ethertype() == EtherTypes::Arp {
                        if let Some(arp_packet) = ArpPacket::new(ethernet_packet.payload()) {
                            if arp_packet.get_operation() == ArpOperations::Reply {
                                let sender_mac = arp_packet.get_sender_hw_addr();
                                let sender_ip = arp_packet.get_sender_proto_addr();

                                if sender_mac == *target_mac {
                                    return sender_ip;
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => break,
        }
    }

    Ipv4Addr::new(0, 0, 0, 0)
}
