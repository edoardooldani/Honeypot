use pnet::{datalink::DataLinkSender, packet::{arp::{ArpOperations, ArpPacket}, ethernet::{EtherTypes, EthernetPacket}, icmp::{echo_request::EchoRequestPacket, IcmpPacket, IcmpTypes}, ip::IpNextHeaderProtocols, tcp::{TcpFlags, TcpPacket}, Packet}, util::MacAddr};
use tracing::error;
use crate::network::sender::{send_arp_reply, send_icmp_reply, send_tcp_syn_ack, send_tun_icmp_reply, send_tun_icmpv6_reply};
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



 pub fn handle_tun_msg(tun: Arc<tokio_tun::Tun>, buf: [u8; 1024], n: usize, ipv4_address: Ipv4Addr, ipv6_address: Ipv6Addr) {
    if let Ok((ipv4, remaining_payload)) = Ipv4Header::from_slice(&buf[..n]) {
        println!("\nReceived IPv4 packet: {:?}", ipv4.protocol);

        if ipv4.protocol == IpNumber::ICMP {
            println!("ICMP");
            if let icmp_packet = EchoRequestPacket::new(remaining_payload).expect("Failed to extract icmpv4 packet"){
                println!("ICMP Packet: {:?}", icmp_packet);
                
                // Invia una risposta ICMP (Echo Reply)
                send_tun_icmp_reply(
                    tun.clone(),
                    &ipv4,
                    &icmp_packet,
                    &ipv4_address
                );
            } else {
                eprintln!("❌ Errore nella decodifica del pacchetto ICMP.");
            }
        } 
    }

    else if let Ok((ipv6, remaining_payload)) = Ipv6Header::from_slice(&buf[..n]) {
        if ipv6.next_header == IpNumber::IPV6_ICMP {
            if let Ok(icmpv6_packet) = Icmpv6Slice::from_slice(remaining_payload) {

                send_tun_icmpv6_reply(
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