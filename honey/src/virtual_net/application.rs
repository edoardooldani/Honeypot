use std::{net::{Ipv4Addr, SocketAddr}, sync::Arc};

use pnet::{datalink::DataLinkSender, packet::tcp::{TcpFlags, TcpPacket}, util::MacAddr};
use rand::RngCore;
use tokio::{io::AsyncReadExt, net::TcpStream, sync::{mpsc, Mutex}};
use tracing::info;
use crate::{network::sender::send_tcp_stream, proxy::ssh::start_ssh_proxy};


pub async fn handle_ssh_connection(
    tx: Arc<Mutex<Box<dyn DataLinkSender + Send>>>,
    virtual_mac: MacAddr,
    virtual_ip: Ipv4Addr,
    destination_mac: MacAddr,
    destination_ip: Ipv4Addr,
    source_port: u16,
    tcp_received_packet: TcpPacket<'_>,
) {
    println!("Handling ssh");

    let sshd = TcpStream::connect("127.0.0.1:2022")
        .await
        .expect("❌ Connessione al server SSH fallita");

    // Estrai i campi necessari dal pacchetto
    let src_port = tcp_received_packet.get_source();
    let seq = tcp_received_packet.get_sequence();
    let ack = tcp_received_packet.get_acknowledgement();

    let tx_clone = Arc::clone(&tx);

    let (mut read_half, _) = tokio::io::split(sshd);
    let mut buf = [0u8; 1500];

    loop {
        match read_half.read(&mut buf).await {
            Ok(n) if n > 0 => {
                let payload = buf[..n].to_vec();

                let response_flags = TcpFlags::ACK;

                send_tcp_stream(
                    tx_clone.clone(),
                    virtual_mac,
                    virtual_ip,
                    destination_mac,
                    destination_ip,
                    22,
                    src_port,
                    seq,
                    response_flags,
                    &payload,
                ).await;
            }
            _ => break,
        }
    }
}