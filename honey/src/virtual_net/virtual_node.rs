use pnet::{datalink::DataLinkSender, packet::{arp::{ArpOperations, ArpPacket}, ethernet::{EtherTypes, EthernetPacket}, icmp::{echo_request::EchoRequestPacket, IcmpPacket, IcmpTypes}, ip::IpNextHeaderProtocols, tcp::{TcpFlags, TcpPacket}, Packet}, util::MacAddr};
use tracing::error;
use crate::network::sender::{send_arp_reply, send_icmp_reply, send_icmpv6_reply, send_tcp_syn_ack};
use std::{io::Write, net::{Ipv4Addr, Ipv6Addr}, str::FromStr, sync::Arc};
use etherparse::{Icmpv4Slice, Icmpv6Slice, IpNumber, Ipv4Header, Ipv6Header};

use super::graph::NetworkGraph;



pub fn handle_broadcast(
    ethernet_packet: &EthernetPacket,
    graph: &mut NetworkGraph,
    tx_datalink: &mut dyn DataLinkSender,
) {

    if ethernet_packet.get_ethertype() == EtherTypes::Arp {
        if let Some(arp_packet) = ArpPacket::new(ethernet_packet.payload()) {
            if arp_packet.get_operation() == ArpOperations::Request {
                let requested_ip = arp_packet.get_target_proto_addr();
                let sender_mac = ethernet_packet.get_source(); 

                // Don't answer to router
                if !graph.is_router(sender_mac) {  
                    if let Some(virtual_node) = graph.find_virtual_node_by_ip(requested_ip) {
                        let virtual_mac = MacAddr::from_str(&virtual_node.mac_address).expect("MAC non valido");
                        let virtual_ip_str = virtual_node.ipv4_address.clone();
                        
                        match virtual_ip_str.parse::<Ipv4Addr>() {
                            Ok(virtual_ip) => {
                                send_arp_reply(
                                    tx_datalink,
                                    virtual_mac,
                                    virtual_ip,
                                    arp_packet.get_sender_hw_addr(),
                                    arp_packet.get_sender_proto_addr(),
                                );
                            }
                            Err(e) => {
                                eprintln!("❌ Cannot convert '{}' in Ipv4Addr - {}", virtual_ip_str, e);
                            }
                        }  
                    }
                }
            }
        }
    }
}



pub fn handle_virtual_packet(
    ethernet_packet: &EthernetPacket,
    virtual_mac: &str,
    virtual_ip: &str,
    sender_mac: &str,
    tx: &mut dyn DataLinkSender
) {

    println!("Virtual node");
    let virtual_mac = MacAddr::from_str(virtual_mac).expect("MAC non valido");
    let virtual_ip = Ipv4Addr::from_str(virtual_ip).expect("IP non valido");
    let sender_mac = MacAddr::from_str(sender_mac).expect("MAC non valido");

    match ethernet_packet.get_ethertype() {
        EtherTypes::Arp => {
            if let Some(arp_packet) = ArpPacket::new(ethernet_packet.payload()) {
                if arp_packet.get_operation() == ArpOperations::Request
                    && arp_packet.get_target_proto_addr() == virtual_ip
                {
                    let sender_ip = arp_packet.get_sender_proto_addr();
                    send_arp_reply(tx, virtual_mac, virtual_ip, sender_mac, sender_ip);
                }
            }
        }

        EtherTypes::Ipv4 => {
            if let Some(ipv4_packet) = pnet::packet::ipv4::Ipv4Packet::new(ethernet_packet.payload()) {
                let next_protocol = ipv4_packet.get_next_level_protocol();
                match next_protocol {
                    IpNextHeaderProtocols::Tcp => {
                        if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                            if tcp_packet.get_flags() & TcpFlags::SYN != 0 {
                                let src_ip = ipv4_packet.get_source();
                                let src_port = tcp_packet.get_source();
                                let dst_port = tcp_packet.get_destination();
                                send_tcp_syn_ack(tx, virtual_mac, virtual_ip, sender_mac, src_ip, src_port, dst_port);
                            }
                        }
                    }
                    IpNextHeaderProtocols::Icmp => {
                        if let Some(icmp_packet) = IcmpPacket::new(ipv4_packet.payload()) {
                            if icmp_packet.get_icmp_type() == IcmpTypes::EchoRequest {
                                println!("Sending reply");
                                if let Some(echo_request) = EchoRequestPacket::new(icmp_packet.packet()) {
                                    send_icmp_reply(tx, ethernet_packet, &ipv4_packet, virtual_mac, virtual_ip, &echo_request);

                                }
                            }
                        }
                    }
                    _ => {
                        println!("Protocollo IP non supportato: {:?}", next_protocol);
                    }
                }
            }
        }

        _ => {
            error!("EtherType not supported: {:?}", ethernet_packet.get_ethertype());
        }
    }
}


/*
pub fn respond_to_icmp_echo(tun: &mut Device, packet: &SlicedPacket) {
    // Estrai l'IP e i dati ICMP
    let (src_ip, dst_ip, id, seq, icmp_payload) = match (&packet.ip_payload(), &packet.transport) {
        (Some(etherparse::InternetSlice::Ipv4(ipv4)), Some(etherparse::TransportSlice::Icmpv4(icmp))) => {
            let (src_ip, dst_ip) = (ipv4.source_addr(), ipv4.destination_addr());

            match icmp.icmp_type() {
                Icmpv4Type::EchoRequest(echo) => {
                    (src_ip, dst_ip, echo.id, echo.seq, icmp.payload())
                }
                _ => return, // Not an echo request
            }
        }
        _ => return,
    };

    // Costruisci l'intestazione ICMP Echo Reply
    let echo_reply = Icmpv4Type::EchoReply(IcmpEchoHeader { id, seq });
    let icmp_header = Icmpv4Header {
        icmp_type: echo_reply,
        checksum: 0,
    };

    let mut icmp_buf = Vec::new();
    icmp_header.write(&mut icmp_buf).unwrap();
    icmp_buf.extend_from_slice(icmp_payload);

    // Calcola checksum corretto
    let checksum = etherparse::checksum::Sum16BitWords::new()
        .add_slice(&icmp_buf)
        .ones_complement();
    icmp_buf[2] = (checksum >> 8) as u8;
    icmp_buf[3] = (checksum & 0xFF) as u8;

    // Costruisci header IPv4
    let ip_header = Ipv4Header::new(
        (20 + icmp_buf.len()) as u16,
        64,
        Icmp as u8,
        dst_ip.octets(),
        src_ip.octets(),
    );

    let mut reply_buf = Vec::new();
    ip_header.write(&mut reply_buf).unwrap();
    reply_buf.extend_from_slice(&icmp_buf);

    // Invia il pacchetto sulla TUN
    if let Err(e) = tun.write_all(&reply_buf) {
        eprintln!("❌ Errore invio Echo Reply: {:?}", e);
    } else {
        println!("📤 Echo Reply inviato a {}", src_ip);
    }
}
 */


 pub fn handle_tun_msg(tun: Arc<tokio_tun::Tun>, buf: [u8; 1024], n: usize, ipv4_address: Ipv4Addr, ipv6_address: Ipv6Addr) {
    if let Ok((ipv4, remaining_payload)) = Ipv4Header::from_slice(&buf[..n]) {
        println!("\n received ipv4");
        if ipv4.protocol == IpNumber::ICMP {
            if let Ok(icmp_packet) = Icmpv4Slice::from_slice(remaining_payload) {
                println!("\n\nicmp_packet: {:?}\n", icmp_packet);
            } else {
                eprintln!("❌ Errore nella decodifica del pacchetto ICMP.");
            }
        }
    }
    else if let Ok((ipv6, remaining_payload)) = Ipv6Header::from_slice(&buf[..n]) {
        if ipv6.next_header == IpNumber::IPV6_ICMP {
            if let Ok(icmpv6_packet) = Icmpv6Slice::from_slice(remaining_payload) {

                send_icmpv6_reply(
                    tun.clone(),
        &ipv6,
     &icmpv6_packet,
                    &ipv6_address
                );
            } else {
                eprintln!("❌ Errore nella decodifica del pacchetto ICMPv6.");
            }
        } else {
            println!("📡 source: {:?}, dest: {:?}", ipv6.source_addr(), ipv6.destination_addr());
        }
    }else {
        eprintln!("❌ Errore: pacchetto con versione IP non supportata.");
    }
    
}