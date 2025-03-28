use pnet::{datalink::DataLinkSender, packet::{arp::{ArpOperations, ArpPacket}, ethernet::{EtherTypes, EthernetPacket}, icmp::echo_request::EchoRequestPacket, ip::IpNextHeaderProtocols, tcp::{TcpFlags, TcpPacket}, Packet}, util::MacAddr};
use tracing::error;
use crate::network::sender::{send_arp_reply, send_tcp_syn_ack, build_tun_icmp_reply};
use std::{net::{Ipv4Addr, Ipv6Addr}, str::FromStr, sync::{Arc, Mutex}};
use etherparse::{IpNumber, Ipv4Header};

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



 pub async fn handle_tun_msg(
    graph: Arc<Mutex<NetworkGraph>>,
    buf: [u8; 1024], 
    n: usize
) -> Result<Vec<u8>, String>  {

    if let Ok((ipv4_header_received, remaining_payload)) = Ipv4Header::from_slice(&buf[..n]) {
        println!("Packet received: {:?}, source: {:?}, dest: {:?}", ipv4_header_received.protocol, ipv4_header_received.source, ipv4_header_received.destination);
        if ipv4_header_received.protocol == IpNumber::ICMP {
            println!("ICMP packet received");

            match EchoRequestPacket::new(remaining_payload).expect("Failed to extract icmpv4 packet") {

                icmp_packet=> {
                    println!("ICMP packet request");

                    let dest_addr = format!("{}.{}.{}.{}", ipv4_header_received.destination[0], ipv4_header_received.destination[1], ipv4_header_received.destination[2], ipv4_header_received.destination[3]);
                    let parsed_dest_ip = Ipv4Addr::from_str(&dest_addr).expect("Error parsing ip addr");

                    let graph_locked = graph.lock().unwrap();
                    let node = graph_locked.find_node_by_ip(parsed_dest_ip).expect("Node not found");
                                        
                    Ok(vec![])
                    /*
                    Ok(
                        build_tun_icmp_reply(
                        &ipv4,
                        &icmp_packet,
                        &ipv4_address,
                        virtual_mac,
                        MacAddr::from_str(&node.mac_address).expect("Error parsing mac address")
                        ).await?
                    )*/
                }
                _ => return Err("❌ Errore nella decodifica del pacchetto ICMP.".to_string()),
            }
        } else {
            return Ok(vec![]);
        }
    }else {
        return Ok(vec![]);
    } 
    /* 
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
    */
    
}