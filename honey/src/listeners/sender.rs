use pnet::datalink::{self, Channel, DataLinkSender, NetworkInterface};
use pnet::packet::arp::{ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket, EtherTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use std::net::Ipv4Addr;
use std::time::Duration;
use std::thread;
use std::sync::{Arc, Mutex};



pub fn find_ip_by_mac(target_mac: &str) -> Option<String> {
    let interface = get_primary_interface().expect("Nessuna interfaccia valida trovata");
    let my_ip = match interface.ips.iter().find(|ip| ip.is_ipv4()) {
        Some(ip) => match ip.ip() {
            std::net::IpAddr::V4(ipv4) => ipv4,
            _ => return None,
        },
        None => return None,
    };

    let my_mac = interface.mac.unwrap();
    let subnet = (my_ip.octets()[0], my_ip.octets()[1], my_ip.octets()[2]);

    let (tx_datalink, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return None,
        Err(_) => return None,
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
                                    return Some(sender_ip);
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => break,
        }
    }

    None
}

pub fn get_primary_interface() -> Option<NetworkInterface> {
    let interfaces = datalink::interfaces();

    interfaces
        .into_iter()
        .filter(|iface| !iface.is_loopback() && !iface.ips.is_empty())
        .find(|iface| iface.mac.is_some())
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


pub fn send_arp_reply(tx: &mut dyn DataLinkSender, my_mac: pnet::util::MacAddr, my_ip: Ipv4Addr, target_mac: pnet::util::MacAddr, target_ip: Ipv4Addr) {

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

    println!("📤 Inviando ARP Reply: {} → {}", my_ip, target_ip);
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