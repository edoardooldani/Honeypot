use std::{net::Ipv4Addr, sync::Arc};

use pnet::{datalink::DataLinkSender, packet::{tcp::{TcpFlags, TcpPacket}, Packet}, util::MacAddr};
use tokio::sync::Mutex;

use crate::{network::sender::send_tcp_stream, proxy::ssh::handle_ssh_connection};

pub async fn handle_tcp_packet<'a>(
    tx: Arc<Mutex<Box<dyn DataLinkSender + Send>>>,
    tcp_received_packet: TcpPacket<'a>,
    virtual_mac: MacAddr,
    virtual_ip: Ipv4Addr,
    source_ip: Ipv4Addr,
    source_mac: MacAddr
){
    match tcp_received_packet.get_flags(){
        flags if flags & TcpFlags::SYN != 0 => {
            let virtual_port = tcp_received_packet.get_destination();
            let response_flags: u8;

            if virtual_port == 22 || virtual_port == 80 {
                response_flags = TcpFlags::SYN | TcpFlags::ACK;
            }else {
                response_flags = TcpFlags::RST;
            }

            let empty_payload: &[u8] = &[];
            let next_seq: u32 = rand::random::<u32>();

            send_tcp_stream(
                tx.clone(), 
                virtual_mac, 
                virtual_ip, 
                source_mac, 
                source_ip, 
                virtual_port, 
                tcp_received_packet.get_source(),
                tcp_received_packet.get_sequence(),
                next_seq,
                response_flags,
                empty_payload
                ).await;
            
        }
        flags if flags & TcpFlags::ACK != 0 => {
            match tcp_received_packet.get_destination() {
                22 => {

                    handle_ssh_connection(
                        tx.clone(),
                        virtual_mac, 
                        virtual_ip, 
                        source_mac, 
                        source_ip, 
                        tcp_received_packet.get_source(), 
                        tcp_received_packet,
                    ).await;
                    
                
                }
                _ => {}
            }
        }
        _ => {}
    }
}
