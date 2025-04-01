use std::{net::Ipv4Addr, sync::Arc};

use pnet::{datalink::DataLinkSender, packet::{tcp::{TcpFlags, TcpPacket}, Packet}, util::MacAddr};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream, sync:: Mutex};
use tracing::info;
use crate::network::sender::send_tcp_stream;


pub async fn handle_ssh_connection(
    tx: Arc<Mutex<Box<dyn DataLinkSender + Send>>>,
    virtual_mac: MacAddr,
    virtual_ip: Ipv4Addr,
    destination_mac: MacAddr,
    destination_ip: Ipv4Addr,
    source_port: u16,
    tcp_received_packet: TcpPacket<'_>,
) {

    let mut sshd = TcpStream::connect("127.0.0.1:2222")
        .await
        .expect("❌ Connessione al server SSH fallita");

    let src_port = tcp_received_packet.get_source();
    let seq = tcp_received_packet.get_sequence();
    let payload_from_client = tcp_received_packet.payload();

    let tx_clone = Arc::clone(&tx);

    if !payload_from_client.is_empty() {
        if let Err(e) = sshd.write_all(payload_from_client).await {
            eprintln!("❌ Errore nell’invio dati a sshd: {}", e);
            return;
        }
    }
    
    println!("\nBuffer received from client: {:?}", payload_from_client);

    let (mut read_half, _) = tokio::io::split(sshd);
    let mut buf = [0u8; 1500];

    loop {

        match read_half.read(&mut buf).await {
            Ok(n) if n > 0 => {
                let payload = buf[..n].to_vec();

                let response_flags = TcpFlags::ACK;
                println!("Buffer received from sshd: {:?}", payload);
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