use etherparse::{IcmpEchoHeader, Icmpv6Slice, IpNumber, Ipv6FlowLabel, Ipv6Header};
use pnet::datalink::{self, Channel, DataLinkSender};
use pnet::packet::arp::{ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket, EtherTypes};
use pnet::packet::icmp::echo_reply::MutableEchoReplyPacket;
use pnet::packet::icmp::echo_request::EchoRequestPacket;
use pnet::packet::icmp::{checksum, IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::{Icmpv6, Icmpv6Code, Icmpv6Packet, Icmpv6Type, Icmpv6Types, MutableIcmpv6Packet, checksum as Icmpv6Checksum};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use tokio::io::AsyncWriteExt;
use tun::Tun;
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use std::thread;
use std::sync::{Arc, Mutex};
use lazy_static::lazy_static;


use crate::utilities::network::get_primary_interface;



pub fn find_ip_by_mac(target_mac: &str) -> String {
    let interface = get_primary_interface().expect("Nessuna interfaccia valida trovata");
    let my_ip = match interface.ips.iter().find(|ip| ip.is_ipv4()) {
        Some(ip) => match ip.ip() {
            std::net::IpAddr::V4(ipv4) => ipv4,
            _ => return "0.0.0.0".to_string(),
        },
        None => return "0.0.0.0".to_string(),
    };

    let my_mac = interface.mac.unwrap();
    let subnet = (my_ip.octets()[0], my_ip.octets()[1], my_ip.octets()[2]);

    let (tx_datalink, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return "0.0.0.0".to_string(),
        Err(_) => return "0.0.0.0".to_string(),
    };

    let tx_arc = Arc::new(Mutex::new(tx_datalink));
    
    for i in 1..=254 {
        let target_ip = Ipv4Addr::new(subnet.0, subnet.1, subnet.2, i);
        let tx_clone = Arc::clone(&tx_arc);
        let my_mac_clone = my_mac.clone();

        let _ = thread::spawn(move || {
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
                                let sender_mac = arp_packet.get_sender_hw_addr().to_string();
                                let sender_ip = arp_packet.get_sender_proto_addr().to_string();

                                if sender_mac == target_mac {
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

    "0.0.0.0".to_string()
}


fn send_arp_request(tx: &mut dyn datalink::DataLinkSender, my_mac: pnet::util::MacAddr, my_ip: Ipv4Addr, target_ip: Ipv4Addr) {
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

pub fn send_arp_reply(tx: &mut dyn DataLinkSender, my_mac: pnet::util::MacAddr, my_ip: Ipv4Addr, target_mac: pnet::util::MacAddr, target_ip: Ipv4Addr) {
    /* 
    let key = format!("{}->{}", my_ip, target_ip);

    // Evita di inviare più risposte per lo stesso IP
    let mut sent_replies = SENT_ARP_REPLIES.lock().unwrap();
    if sent_replies.contains(&key) {
        println!("⚠️ ARP Reply già inviata per {}", key);
        return;
    }
    sent_replies.insert(key);*/

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

    println!("📤 Inviando ARP Reply UNA SOLA VOLTA: {} → {}", my_ip, target_ip);
    tx.send_to(ethernet_packet.packet(), None).unwrap().unwrap();
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


pub fn send_icmp_reply(
    tx: &mut dyn DataLinkSender,
    ethernet_packet: &EthernetPacket,
    ipv4_packet: &pnet::packet::ipv4::Ipv4Packet,
    virtual_mac: MacAddr,
    virtual_ip: Ipv4Addr,
    echo_request: &EchoRequestPacket
) {

    let mut icmp_reply_buffer = vec![0u8; echo_request.packet().len()];
    let mut icmp_reply = MutableEchoReplyPacket::new(&mut icmp_reply_buffer).unwrap();

    icmp_reply.set_icmp_type(IcmpTypes::EchoReply);
    icmp_reply.set_identifier(echo_request.get_identifier());
    icmp_reply.set_sequence_number(echo_request.get_sequence_number());
    icmp_reply.set_payload(echo_request.payload());

    let icmp_packet = IcmpPacket::new(icmp_reply.packet()).unwrap();
    let checksum_value = checksum(&icmp_packet);
    icmp_reply.set_checksum(checksum_value);

    let mut ipv4_buffer = vec![0u8; 20 + icmp_reply.packet().len()];
    let mut ipv4_reply = MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();
    ipv4_reply.set_version(4);
    ipv4_reply.set_header_length(5);
    ipv4_reply.set_total_length((20 + icmp_reply.packet().len()) as u16);
    ipv4_reply.set_ttl(64);
    ipv4_reply.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Icmp);
    ipv4_reply.set_source(virtual_ip);
    ipv4_reply.set_destination(ipv4_packet.get_source());
    ipv4_reply.set_payload(icmp_reply.packet());

    // Buffer per il pacchetto Ethernet
    let mut ethernet_buffer = vec![0u8; 14 + ipv4_reply.packet().len()];
    let mut ethernet_reply = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    ethernet_reply.set_destination(ethernet_packet.get_source());
    ethernet_reply.set_source(virtual_mac);
    ethernet_reply.set_ethertype(EtherTypes::Ipv4);
    ethernet_reply.set_payload(ipv4_reply.packet());

    // Invia il pacchetto sulla rete
    tx.send_to(&ethernet_buffer, None);

}

pub fn send_icmpv6_reply(
    tun: Arc<Tun>,
    ipv6_packet: &Ipv6Header,
    icmpv6_request: &Icmpv6Slice,
) {
    let mut icmp_reply_buffer = vec![0u8; MutableIcmpv6Packet::minimum_packet_size()];
    let mut icmpv6_packet = MutableIcmpv6Packet::new(&mut icmp_reply_buffer).expect("Icmpv6 packet failed to create");
    icmpv6_packet.set_icmpv6_type(Icmpv6Types::EchoReply);
    icmpv6_packet.set_payload(icmpv6_request.payload());

    let pack = icmpv6_packet.to_immutable();
    let checksum_value = Icmpv6Checksum(&pack, &ipv6_packet.destination_addr(), &ipv6_packet.source_addr());
    icmpv6_packet.set_checksum(checksum_value);

    let icmpv6_reply = icmpv6_packet.to_immutable();
    //let icmpv6_reply = Icmpv6Packet::new(&icmpv6_packet).expect("Icmpv6 reply failed to create");
    

    // Crea il pacchetto IPv6 che conterrà la risposta ICMPv6
    let mut ipv6_reply_buffer = vec![0u8; Ipv6Header::LEN + icmpv6_reply.packet().len()];
    let mut ipv6_reply = MutableIpv6Packet::new(&mut ipv6_reply_buffer).unwrap();

    // Imposta i dettagli dell'header IPv6
    ipv6_reply.set_version(6);
    ipv6_reply.set_traffic_class(0); 
    ipv6_reply.set_flow_label(0);
    ipv6_reply.set_payload_length(icmpv6_packet.packet().len() as u16); 
    ipv6_reply.set_next_header(IpNextHeaderProtocols::Icmpv6); 
    ipv6_reply.set_hop_limit(64); 
    ipv6_reply.set_source(ipv6_packet.destination_addr()); // L'indirizzo di origine è l'indirizzo di destinazione della richiesta
    ipv6_reply.set_destination(ipv6_packet.source_addr()); // L'indirizzo di destinazione è l'indirizzo di origine della richiesta
    // Imposta il payload come il pacchetto ICMPv6
    ipv6_reply.set_payload(icmpv6_reply.packet());

    let ipv6_packet = ipv6_reply.consume_to_immutable();
    println!("ipv6 packet: {:?}", ipv6_packet);
    tun.send(    ipv6_packet.packet());
}