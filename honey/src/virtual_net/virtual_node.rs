use pnet::{datalink::DataLinkSender, packet::{arp::{ArpOperations, ArpPacket}, ethernet::{EtherTypes, EthernetPacket}, ip::IpNextHeaderProtocols, tcp::{TcpFlags, TcpPacket}, Packet}, util::MacAddr};
use crate::listeners::sender::{send_arp_reply, send_tcp_syn_ack};
use std::{net::Ipv4Addr, str::FromStr};


pub fn handle_virtual_packet(
    ethernet_packet: &EthernetPacket,
    virtual_mac: &str,
    virtual_ip: &str,
    sender_mac: &str,
    tx: &mut dyn DataLinkSender
) {


    let virtual_mac = MacAddr::from_str(virtual_mac).expect("MAC non valido");
    let virtual_ip = Ipv4Addr::from_str(virtual_ip).expect("IP non valido");
    let sender_mac = MacAddr::from_str(sender_mac).expect("MAC non valido");

    match ethernet_packet.get_ethertype() {

        EtherTypes::Arp => {
            if let Some(arp_packet) = ArpPacket::new(ethernet_packet.payload()) {
                if arp_packet.get_operation() == ArpOperations::Request && arp_packet.get_target_proto_addr() == virtual_ip {
                    let sender_ip = arp_packet.get_sender_proto_addr();
                    send_arp_reply(tx, virtual_mac, virtual_ip, sender_mac, sender_ip);
                }
            }
        }
        
        EtherTypes::Ipv4 => {
            if let Some(ipv4_packet) = pnet::packet::ipv4::Ipv4Packet::new(ethernet_packet.payload()) {
                if ipv4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                    if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                        if tcp_packet.get_flags() & TcpFlags::SYN != 0 {
                            let src_ip = ipv4_packet.get_source();
                            let src_port = tcp_packet.get_source();
                            let dst_port = tcp_packet.get_destination();
                            send_tcp_syn_ack(tx, virtual_mac, virtual_ip, sender_mac, src_ip, src_port, dst_port);
                        }
                    }
                }
            }
        }
        _ => {}
    }


}