use std::{net::{Ipv4Addr, TcpStream}, sync::Arc};

use pnet::{datalink::DataLinkSender, packet::tcp::{TcpFlags, TcpPacket}, util::MacAddr};
use rand::RngCore;
use tokio::sync::Mutex;

use crate::{network::sender::send_tcp_stream, virtual_net::application::handle_ssh_connection};

pub async fn handle_tcp_packet<'a>(
    tx: Arc<Mutex<Box<dyn DataLinkSender + Send>>>,
    tcp_received_packet: TcpPacket<'a>,
    virtual_mac: MacAddr,
    virtual_ip: Ipv4Addr,
    source_ip: Ipv4Addr,
    source_mac: MacAddr
){
    match tcp_received_packet.get_flags(){
        TcpFlags::SYN => {
            let virtual_port = tcp_received_packet.get_destination();
            let response_flags: u8;

            if virtual_port == 22 || virtual_port == 80 {
                response_flags = TcpFlags::SYN | TcpFlags::ACK;
            }else {
                response_flags = TcpFlags::RST;
            }

            let empty_payload: &[u8] = &[];
            let mut rng = rand::rng();
            let seq: u32 = rng.next_u32();

            send_tcp_stream(
                tx.clone(), 
                virtual_mac, 
                virtual_ip, 
                source_mac, 
                source_ip, 
                virtual_port, 
                tcp_received_packet.get_source(),
                tcp_received_packet.get_sequence(),
                seq,
                response_flags,
                empty_payload
                );
            
        }
        TcpFlags::ACK => {
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
