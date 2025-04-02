use std::{collections::HashMap, net::Ipv4Addr, sync::Arc};

use pnet::{datalink::DataLinkSender, packet::{tcp::{TcpFlags, TcpPacket}, Packet}, util::MacAddr};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream, sync:: Mutex};
use tracing::{info, error};
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
    tcp_received_packet: TcpPacket<'_>,
) {

    println!("Handling ssh...");

    let src_port = tcp_received_packet.get_source();
    let mut next_ack = tcp_received_packet.get_sequence();
    let payload_from_client = tcp_received_packet.payload();
    let next_seq: u32 = tcp_received_packet.get_acknowledgement();

    if payload_from_client.is_empty(){
        return;
    }

    let tx_clone = Arc::clone(&tx);

    if !payload_from_client.starts_with(b"SSH-") {
        return;
    }

    let sshd_mutex = get_or_create_ssh_session(virtual_ip, destination_ip).await;
    let mut sshd = sshd_mutex.lock().await;

    if let Err(e) = sshd.write_all(tcp_received_packet.packet()).await {
        error!("❌ Errore nell’invio dati a sshd: {}", e);
        let mut sessions = SSH_SESSIONS.lock().await;
        sessions.remove(&(virtual_ip, destination_ip));
        return;
    }
    
    info!("\n\nPacket received from client: {:?}", tcp_received_packet.packet());
    let mut buf = [0u8; 1500];

    //loop {

        match sshd.read(&mut buf).await {
            Ok(n) if n > 0 => {
                println!("Buff received from sshd: {:?}", buf);
                let payload = buf[..n].to_vec();
                next_ack += n as u32;
                let response_flags = TcpFlags::ACK;

                send_tcp_stream(
                    tx_clone.clone(),
                    virtual_mac,
                    virtual_ip,
                    destination_mac,
                    destination_ip,
                    22,
                    src_port,
                    next_seq,
                    next_ack,
                    response_flags,
                    &payload,
                ).await;

                //break;
            }
            _ => {}//break,

        }
    //}
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