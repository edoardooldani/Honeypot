use std::{collections::HashMap, net::Ipv4Addr, sync::Arc, time::Duration};

use pnet::{datalink::DataLinkSender, packet::{tcp::{TcpFlags, TcpPacket}, Packet}, util::MacAddr};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream, sync:: Mutex, time::timeout};
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

    if tcp_received_packet.payload().is_empty(){
        return;
    }

    info!("\n\nFlag received: {:?}\nPacket received from client: {:?}", tcp_received_packet.get_flags(), tcp_received_packet.packet());

    let src_port = tcp_received_packet.get_source();
    let payload_from_client = tcp_received_packet.payload();
    let mut next_ack: u32 = tcp_received_packet.get_sequence() + payload_from_client.len() as u32;
    let mut next_seq: u32 = tcp_received_packet.get_acknowledgement();

    let tx_clone = Arc::clone(&tx);

    let sshd_mutex = get_or_create_ssh_session(virtual_ip, destination_ip).await;
    let mut sshd = sshd_mutex.lock().await;

    if let Err(e) = sshd.write_all(payload_from_client).await {
        error!("❌ Errore nell’invio dati a sshd: {}", e);
        let mut sessions = SSH_SESSIONS.lock().await;
        sessions.remove(&(virtual_ip, destination_ip));
        return;
    }
    
    let mut buf = [0u8; 2048];

    //loop {
    match timeout(Duration::from_millis(200), sshd.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {

            let msg_type = buf[5];
            if msg_type == 31 {
                change_fingerprint(&mut buf, virtual_ip);
            }

            let full_payload = &buf[..n];
            let response_flags = TcpFlags::ACK | TcpFlags::PSH;
    
            let max_payload_size = 1460;
    
            for chunk in full_payload.chunks(max_payload_size) {
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
                    chunk,
                ).await;
    
                next_ack += chunk.len() as u32;
                next_seq += chunk.len() as u32;
            }
        }
        _ => {}
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


fn change_fingerprint(buf: &mut [u8], virtual_ip: Ipv4Addr) {
    let mask = virtual_ip.octets()[3];

    let k_s_len = u32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]]) as usize;
    let k_s_start = 10;
    let k_s_end = k_s_start + k_s_len;
    let k_s = &mut buf[k_s_start..k_s_end];

    println!("📌 Found K_S (host key) of length {} bytes", k_s_len);

    let key_type_len = u32::from_be_bytes([k_s[0], k_s[1], k_s[2], k_s[3]]) as usize;
    let key_type_end = 4 + key_type_len;
    let key_bytes_len = u32::from_be_bytes([
        k_s[key_type_end],
        k_s[key_type_end + 1],
        k_s[key_type_end + 2],
        k_s[key_type_end + 3],
    ]) as usize;
    let key_bytes_start = key_type_end + 4;
    let key_bytes_end = key_bytes_start + key_bytes_len;

    let key_bytes = &mut k_s[key_bytes_start..key_bytes_end];
    for b in key_bytes.iter_mut() {
        *b ^= mask;
    }
}