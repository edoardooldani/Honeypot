use std::{collections::HashMap, net::Ipv4Addr, sync::Arc};

use pnet::{datalink::DataLinkSender, packet::{tcp::{TcpFlags, TcpPacket}, Packet}, util::MacAddr};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream, sync:: Mutex};
use tracing::info;
use crate::network::sender::send_tcp_stream;
use lazy_static::lazy_static;

lazy_static! {
    pub static ref SSH_SESSIONS: Arc<Mutex<HashMap<(Ipv4Addr, Ipv4Addr), Arc<Mutex<TcpStream>>>>> =
        Arc::new(Mutex::new(HashMap::new()));
}


pub async fn handle_ssh_connection(
    tx: Arc<Mutex<Box<dyn DataLinkSender + Send>>>,
    virtual_mac: MacAddr,
    virtual_ip: Ipv4Addr,
    destination_mac: MacAddr,
    destination_ip: Ipv4Addr,
    source_port: u16,
    tcp_received_packet: TcpPacket<'_>,
) {

    let src_port = tcp_received_packet.get_source();
    let seq = tcp_received_packet.get_sequence();
    let payload_from_client = tcp_received_packet.payload();
    let next_seq: u32 = tcp_received_packet.get_acknowledgement();


    let tx_clone = Arc::clone(&tx);

    let sshd_mutex = get_or_create_ssh_session(virtual_ip, destination_ip).await;
    let mut sshd = sshd_mutex.lock().await;

    if !payload_from_client.is_empty() {
        if let Err(e) = sshd.write_all(payload_from_client).await {
            eprintln!("❌ Errore nell’invio dati a sshd: {}", e);
            return;
        }
    }
    println!("\n\nPacket received from client: {:?}", tcp_received_packet.packet());
    let mut buf = [0u8; 1500];

    loop {

        match sshd.read(&mut buf).await {
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
                    next_seq,
                    response_flags,
                    &payload,
                ).await;
                
                break;
            }
            _ => break,
        }
    }
}



async fn get_or_create_ssh_session(virtual_ip: Ipv4Addr, destination_ip: Ipv4Addr) -> Arc<Mutex<TcpStream>>{
    let mut sessions = SSH_SESSIONS.lock().await;
    let key = (virtual_ip, destination_ip);

    let sshd: Arc<Mutex<TcpStream>> = match sessions.get(&key) {
        Some(stream) => Arc::clone(stream),
        None => {
            let stream = TcpStream::connect("127.0.0.1:2222")
                .await
                .expect("❌ Connessione al server SSH fallita");
            let arc_stream = Arc::new(Mutex::new(stream));
            sessions.insert(key, arc_stream.clone());
            arc_stream
        }
    };
    sshd
}