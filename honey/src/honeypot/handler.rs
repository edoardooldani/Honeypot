use pnet::{datalink::DataLinkSender, packet::{arp::{ArpOperations, ArpPacket}, ethernet::{EtherTypes, EthernetPacket}, ip::IpNextHeaderProtocols, tcp::{TcpFlags, TcpPacket}, Packet}};
use tokio::sync::Mutex;
use tracing::error;
//use crate::{network::sender::send_arp_reply, honeypot::proxy::ssh::handle_ssh_connection};
use crate::interfaces::sender::send_arp_reply;
use std::sync::Arc;

use super::tcp::handle_tcp_packet;


pub async fn handle_virtual_packet<'a>(
    ethernet_packet: EthernetPacket<'a>,
    tx: Arc<Mutex<Box<dyn DataLinkSender + Send>>>
) {

    match ethernet_packet.get_ethertype() {
        EtherTypes::Arp => {
            if let Some(arp_packet) = ArpPacket::new(ethernet_packet.payload()) {
                if arp_packet.get_operation() == ArpOperations::Request{

                    let _ = send_arp_reply(
                        ethernet_packet.get_destination(), 
                        arp_packet.get_target_proto_addr(), 
                        arp_packet.get_sender_hw_addr(),
                        arp_packet.get_sender_proto_addr(),
                        tx.clone()
                    ).await;

                }
            }
        }

        EtherTypes::Ipv4 => {
            if let Some(ipv4_packet) = pnet::packet::ipv4::Ipv4Packet::new(ethernet_packet.payload()) {
                let next_protocol = ipv4_packet.get_next_level_protocol();
                match next_protocol {
                    IpNextHeaderProtocols::Tcp => {

                        if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                            if tcp_packet.get_destination() == 22 && tcp_packet.get_flags() != TcpFlags::SYN {
                                /*handle_ssh_connection(
                                    tx.clone(), 
                                    *virtual_mac, 
                                    *virtual_ip, 
                                    *source, 
                                    ipv4_packet.get_source(), 
                                    tcp_packet
                                ).await;*/
                            }else {
                                handle_tcp_packet(
                                    tx.clone(), 
                                    tcp_packet, 
                                    ethernet_packet.get_destination(), 
                                    ipv4_packet.get_destination(),
                                    ipv4_packet.get_source(), 
                                    ethernet_packet.get_source(),
                                ).await;
                            }   
                        }
                    }
                    _ => {
                        error!("Protocollo IP non supportato: {:?}", next_protocol);
                    }
                }
            }
        }

        _ => {
            error!("EtherType not supported: {:?}", ethernet_packet.get_ethertype());
        }
    }
}

