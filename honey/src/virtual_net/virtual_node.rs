use pnet::{datalink::DataLinkSender, packet::{arp::{ArpOperations, ArpPacket}, ethernet::{EtherTypes, EthernetPacket}, ip::IpNextHeaderProtocols, tcp::{TcpFlags, TcpPacket}, Packet}, util::MacAddr};
use tracing::error;
use crate::network::sender::{send_arp_reply, send_tcp_syn_ack};
use std::net::Ipv4Addr;

use super::graph::NetworkGraph;



pub async fn handle_broadcast<'a>(
    ethernet_packet: &EthernetPacket<'a>,
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
                        let virtual_mac = virtual_node.mac_address;
                        let virtual_ip = virtual_node.ipv4_address.clone();

                        let _ = send_arp_reply(
                            virtual_mac,
                            virtual_ip,
                            arp_packet.get_sender_hw_addr(),
                            arp_packet.get_sender_proto_addr(),
                            tx_datalink
                        );
                        
                    }
                }
            }
        }
    }
}





pub fn handle_virtual_packet(
    ethernet_packet: &EthernetPacket,
    virtual_mac: &MacAddr,
    virtual_ip: &Ipv4Addr,
    sender_mac: &MacAddr,
    tx: &mut dyn DataLinkSender
) {

    match ethernet_packet.get_ethertype() {
        EtherTypes::Arp => {
            if let Some(arp_packet) = ArpPacket::new(ethernet_packet.payload()) {
                if arp_packet.get_operation() == ArpOperations::Request{

                    let _ = send_arp_reply(
                        *virtual_mac, 
                        *virtual_ip, 
                        arp_packet.get_sender_hw_addr(),
                        arp_packet.get_sender_proto_addr(),
                        &mut *tx
                    );

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
                                println!("Sending tcp ack");
                                let src_ip = ipv4_packet.get_source();
                                let src_port = tcp_packet.get_source();
                                let virtual_port = tcp_packet.get_destination();
                                send_tcp_syn_ack(&mut *tx, *virtual_mac, *virtual_ip, *sender_mac, src_ip, virtual_port, src_port);
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

