use pnet::datalink::{self, DataLinkSender};
use pnet::packet::arp::{ArpOperations, MutableArpPacket};
use pnet::packet::ethernet::{MutableEthernetPacket, EtherTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{checksum, MutableIpv4Packet};
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use tokio::sync::Mutex;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::process::Command;
use std::str::FromStr;
use std::str;
use std::sync::Arc;
use lazy_static::lazy_static;

const ETHERNET_LEN: usize = 66;
const IPV4_LEN: usize = 52;
const TCP_LEN: usize = 32;


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

pub async fn send_arp_reply(
    my_mac: MacAddr,
     my_ip: Ipv4Addr, 
     target_mac: MacAddr, 
     target_ip: Ipv4Addr, 
     tx: Arc<Mutex<Box<dyn DataLinkSender + Send>>>
) {
    
    let key = format!("{}->{}", my_ip, target_ip);

    let mut sent_replies = SENT_ARP_REPLIES.lock().await;
    if sent_replies.contains(&key) {
        return;
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

    ethernet_packet.set_payload(&arp_buffer);

    let mut tx_sender = tx.lock().await;
    let _ = tx_sender.send_to(&ethernet_packet.packet().to_vec(), None).expect("Failed sending ARP reply");

}


pub async fn send_tcp_stream(
    tx: Arc<Mutex<Box<dyn DataLinkSender + Send>>>,
    virtual_mac: MacAddr,
    virtual_ip: Ipv4Addr,
    destination_mac: MacAddr,
    destination_ip: Ipv4Addr,
    virtual_port: u16,
    destination_port: u16,
    seq: u32,
    response_flag: u8,
    payload: &[u8]
) {

    let next_seq: u32 = rand::random::<u32>();

        // 1. Costruisci il TCP header
    let mut tcp_buffer = vec![0u8; TCP_LEN];
    let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buffer).unwrap();
    tcp_packet.set_source(virtual_port);
    tcp_packet.set_destination(destination_port);
    tcp_packet.set_sequence(next_seq);
    tcp_packet.set_acknowledgement(seq+1);
    tcp_packet.set_flags(response_flag);
    tcp_packet.set_window(8192);
    tcp_packet.set_data_offset(5);

    // 2. Crea il buffer finale: header + payload
    let mut full_tcp_payload = Vec::with_capacity(TCP_LEN + payload.len());
    full_tcp_payload.extend_from_slice(tcp_packet.packet());
    full_tcp_payload.extend_from_slice(payload);

    // 3. Calcola checksum con header + payload
    let tcp_checksum = ipv4_checksum(
        &TcpPacket::new(&full_tcp_payload).unwrap(),
        &virtual_ip,
        &destination_ip,
    );
    let mut tcp_packet = MutableTcpPacket::new(&mut full_tcp_payload[..]).unwrap();
    tcp_packet.set_checksum(tcp_checksum);

    // 4. Costruisci IPv4 packet
    let mut ipv4_buffer = vec![0u8; IPV4_LEN + full_tcp_payload.len()];
    let mut ipv4_packet = MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(5);
    ipv4_packet.set_total_length((IPV4_LEN + full_tcp_payload.len()) as u16);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ipv4_packet.set_source(virtual_ip);
    ipv4_packet.set_destination(destination_ip);
    ipv4_packet.set_ttl(64);
    ipv4_packet.set_payload(&full_tcp_payload);
    ipv4_packet.set_checksum(checksum(&ipv4_packet.to_immutable()));

    // 5. Ethernet
    let mut ethernet_buffer = vec![0u8; ETHERNET_LEN + ipv4_packet.packet().len()];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    ethernet_packet.set_destination(destination_mac);
    ethernet_packet.set_source(virtual_mac);
    ethernet_packet.set_ethertype(EtherTypes::Ipv4);
    ethernet_packet.set_payload(ipv4_packet.packet());

    // 6. Send
    let mut tx_sender = tx.lock().await;
    tx_sender.send_to(ethernet_packet.packet(), None).unwrap().unwrap();
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