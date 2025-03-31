use std::net::Ipv4Addr;

use pnet::{datalink::DataLinkSender, packet::{tcp::{TcpFlags, TcpPacket}, Packet}, util::MacAddr};
use tracing::error;

use crate::network::sender::send_tcp_syn_ack;

pub fn handle_ssh_connection(
    tx: &mut dyn DataLinkSender,
    tcp_received_packet: TcpPacket,
    virtual_mac: MacAddr,
    virtual_ip: Ipv4Addr,
    source_ip: Ipv4Addr,
    source_mac: MacAddr
){
    println!("TCP PAYLOAD: {:?}", tcp_received_packet.payload());
    
    /*if !tcp_received_packet.payload().starts_with(b"SSH-") {
        error!("🚩 Connection SSH in port: {}!", tcp_received_packet.get_destination());
        return;
    }*/
    let response_flags = TcpFlags::ACK | TcpFlags::PSH;
    let banner = b"SSH-2.0-OpenSSH_8.6\r\n";
    send_tcp_syn_ack(
        &mut *tx, 
        virtual_mac, 
        virtual_ip, 
        source_mac, 
        source_ip, 
        tcp_received_packet.get_destination(), 
        tcp_received_packet,
        response_flags,
        banner
        );

    return;
}