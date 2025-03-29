use pnet::datalink::{self, Channel, DataLinkSender};
use pnet::packet::arp::{ArpOperations, MutableArpPacket};
use pnet::packet::ethernet::{MutableEthernetPacket, EtherTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::process::Command;
use std::str::FromStr;
use std::{io, str};
use std::sync::Mutex;
use lazy_static::lazy_static;


use crate::utilities::network::get_primary_interface;



pub fn send_arp_request(tx: &mut dyn datalink::DataLinkSender, my_mac: pnet::util::MacAddr, my_ip: Ipv4Addr, target_ip: Ipv4Addr) {
    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    ethernet_packet.set_destination(pnet::util::MacAddr::broadcast());
    ethernet_packet.set_source(my_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
    arp_packet.set_hardware_type(pnet::packet::arp::ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(my_mac);
    arp_packet.set_sender_proto_addr(my_ip);
    arp_packet.set_target_hw_addr(pnet::util::MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);

    ethernet_packet.set_payload(&arp_buffer);

    tx.send_to(ethernet_packet.packet(), None).unwrap().unwrap();
}

lazy_static! {
    static ref SENT_ARP_REPLIES: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
}

pub fn build_arp_reply(my_mac: pnet::util::MacAddr, my_ip: Ipv4Addr, target_mac: pnet::util::MacAddr, target_ip: Ipv4Addr) -> Result<Vec<u8>, io::Error>{
    
    let key = format!("{}->{}", my_ip, target_ip);

    let mut sent_replies = SENT_ARP_REPLIES.lock().unwrap();
    if sent_replies.contains(&key) {
        println!("⚠️ ARP Reply già inviata per {}", key);
        return Err(io::Error::new(io::ErrorKind::Other, "ARP reply already sent"));
    }
    sent_replies.insert(key);

    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    ethernet_packet.set_destination(target_mac);
    ethernet_packet.set_source(my_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
    arp_packet.set_hardware_type(pnet::packet::arp::ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Reply);
    arp_packet.set_sender_hw_addr(my_mac);
    arp_packet.set_sender_proto_addr(my_ip);
    arp_packet.set_target_hw_addr(target_mac);
    arp_packet.set_target_proto_addr(target_ip);
    
    println!("📤 Inviando ARP Reply ARP: {:?}", arp_packet);

    ethernet_packet.set_payload(&arp_buffer);

    println!("📤 Inviando ARP Reply Ethernet: {:?}", ethernet_packet);

    Ok(ethernet_packet.packet().to_vec())

}


pub fn send_tcp_syn_ack(
    tx: &mut dyn DataLinkSender,
    virtual_mac: MacAddr,
    virtual_ip: Ipv4Addr,
    sender_mac: MacAddr,
    sender_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16
) {
    let mut ethernet_buffer = [0u8; 66]; // Ethernet (14) + IPv4 (20) + TCP (32)
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    ethernet_packet.set_destination(sender_mac);
    ethernet_packet.set_source(virtual_mac);
    ethernet_packet.set_ethertype(EtherTypes::Ipv4);

    let mut ipv4_buffer = [0u8; 20];
    let mut ipv4_packet = MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(5);
    ipv4_packet.set_total_length(40);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ipv4_packet.set_source(virtual_ip);
    ipv4_packet.set_destination(sender_ip);
    ipv4_packet.set_ttl(64);

    let mut tcp_buffer = [0u8; 32];
    let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer).unwrap();
    tcp_packet.set_source(dst_port); // 🔹 Rispondiamo dallo stesso servizio
    tcp_packet.set_destination(src_port);
    tcp_packet.set_sequence(0); // 🔹 Genera un numero random se vuoi
    tcp_packet.set_acknowledgement(1); // 🔹 Risponde con ACK=1
    tcp_packet.set_flags(TcpFlags::SYN | TcpFlags::ACK);
    tcp_packet.set_window(8192);
    tcp_packet.set_data_offset(5);

    ethernet_packet.set_payload(ipv4_packet.packet());
    ipv4_packet.set_payload(tcp_packet.packet());

    tx.send_to(ethernet_packet.packet(), None).unwrap().unwrap();
}



pub async fn send_ipv4_packet(ipv4_packet: Vec<u8>, src_mac: MacAddr, dst_mac: MacAddr) -> Result<(), String> {
    let interface = get_primary_interface().expect("Primary interface not found");

    let channel = datalink::channel(&interface, Default::default())
    .map_err(|e| format!("Error creating network channel: {}", e))?;

    let (mut tx, _rx) = match channel {
        Channel::Ethernet(tx, _rx) => (tx, _rx), // If Ethernet channel
        _ => return Err("Invalid channel type".to_string()), // Handle other types if necessary
    };

    let mut packet_buffer = vec![0u8; 42 + ipv4_packet.len()]; // Header Ethernet (42 bytes) + IPv4 payload
    let mut ether_packet = MutableEthernetPacket::new(&mut packet_buffer).unwrap();

    ether_packet.set_destination(dst_mac);
    ether_packet.set_source(src_mac);
    ether_packet.set_ethertype(pnet::packet::ethernet::EtherTypes::Ipv4);

    ether_packet.set_payload(&ipv4_packet);

    println!("Sending Ethernet frame: {:?}", ether_packet.packet());

    match tx.send_to(ether_packet.packet(), None) {
        Some(Ok(_)) => {
            println!("Packet sent successfully");
        },
        Some(Err(e)) => {
            eprintln!("Failed to send packet: {}", e);
        },
        None => {
            eprintln!("Error: Channel is None");
        }
    }
    Ok(())
}



pub async fn get_mac_address(ip: String) -> Option<MacAddr> {
    // Eseguiamo il comando 'arp' per ottenere la mappatura IP -> MAC
    let output = Command::new("arp")
        .arg("-n") // Aggiungiamo l'opzione per evitare di risolvere i nomi host (evita problemi su Linux)
        .arg(ip)
        .output();

    match output {
        Ok(output) => {
            if !output.stdout.is_empty() {
                let result = str::from_utf8(&output.stdout)
                    .unwrap_or("")
                    .to_string();

                // Cerchiamo di estrarre l'indirizzo MAC dal risultato
                let mac_str = result.split_whitespace()
                    .nth(3);  // L'indirizzo MAC dovrebbe trovarsi al quarto posto
                
                if let Some(mac) = mac_str {
                    // Convertiamo la stringa MAC in un MacAddr
                    MacAddr::from_str(mac).ok()
                } else {
                    None
                }
            } else {
                None
            }
        },
        Err(_) => None,  // In caso di errore nell'esecuzione del comando
    }
}