use pnet::{datalink::DataLinkSender, packet::{arp::{ArpOperations, ArpPacket}, ethernet::{EtherType, EtherTypes::{self, Arp}, EthernetPacket}, ip::IpNextHeaderProtocols, tcp::TcpPacket, Packet}, util::MacAddr};
use tokio::sync::Mutex;
use tracing::error;
use crate::network::sender::send_arp_reply;
use std::{net::Ipv4Addr, sync::Arc};

use super::{graph::NetworkGraph, tcp::handle_tcp_packet};



pub async fn handle_broadcast<'a>(
    ethernet_packet: &EthernetPacket<'a>,
    graph: &mut NetworkGraph,
    tx: Arc<Mutex<Box<dyn DataLinkSender + Send>>>,
) {

    if ethernet_packet.get_ethertype() == Arp {
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
                            tx.clone()
                        );
                        
                    }
                }
            }
        }
    }
}





pub async fn handle_virtual_packet<'a>(
    ethertype: EtherType,
    payload: Vec<u8>,
    source: &MacAddr,
    destination: &MacAddr,
    virtual_mac: &MacAddr,
    virtual_ip: &Ipv4Addr,
    tx: Arc<Mutex<Box<dyn DataLinkSender + Send>>>
) {

    match ethertype {
        EtherTypes::Arp => {
            if let Some(arp_packet) = ArpPacket::new(payload.as_slice()) {
                if arp_packet.get_operation() == ArpOperations::Request{

                    let _ = send_arp_reply(
                        *virtual_mac, 
                        *virtual_ip, 
                        arp_packet.get_sender_hw_addr(),
                        arp_packet.get_sender_proto_addr(),
                        tx.clone()
                    ).await;

                }
            }
        }

        EtherTypes::Ipv4 => {
            if let Some(ipv4_packet) = pnet::packet::ipv4::Ipv4Packet::new(payload.as_slice()) {
                let next_protocol = ipv4_packet.get_next_level_protocol();
                match next_protocol {
                    IpNextHeaderProtocols::Tcp => {
                        if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {

                            handle_tcp_packet(
                                tx.clone(), 
                                tcp_packet, 
                                *destination, 
                                ipv4_packet.get_destination(),
                                ipv4_packet.get_source(), 
                                *source,
                            ).await;
                            
                        }
                    }
                    _ => {
                        println!("Protocollo IP non supportato: {:?}", next_protocol);
                    }
                }
            }
        }

        _ => {
            error!("EtherType not supported: {:?}", ethertype);
        }
    }
}

