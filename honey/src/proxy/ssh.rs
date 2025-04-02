use std::{collections::HashMap, net::Ipv4Addr, sync::Arc, time::Duration};
use pnet::{datalink::DataLinkSender, packet::{tcp::{TcpFlags, TcpPacket}, Packet}, util::MacAddr};
use rand::{rngs::OsRng, TryRngCore};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream, sync:: Mutex, time::timeout};
use tracing::{info, error};
use crate::network::sender::send_tcp_stream;
use lazy_static::lazy_static;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey, KEYPAIR_LENGTH, SECRET_KEY_LENGTH};



lazy_static! {
    pub static ref SSH_SESSIONS: Arc<Mutex<HashMap<(Ipv4Addr, Ipv4Addr),Arc<Mutex<(TcpStream, SigningKey)>>
        >>> = Arc::new(Mutex::new(HashMap::new()));
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
    let mut sshd_locked = sshd_mutex.lock().await;
    let (ref mut sshd, ref signing_key) = *sshd_locked;

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
                change_fingerprint_and_sign(&mut buf, signing_key);
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



async fn get_or_create_ssh_session(virtual_ip: Ipv4Addr, destination_ip: Ipv4Addr) -> Arc<Mutex<(TcpStream, SigningKey)>>{
    let mut sessions = SSH_SESSIONS.lock().await;
    let key = (virtual_ip, destination_ip);

    let sshd: Arc<Mutex<(TcpStream, SigningKey)>> = match sessions.get(&key) {
        Some(stream) => Arc::clone(stream),
        None => {
            let stream = TcpStream::connect("127.0.0.1:2222")
                .await
                .expect("❌ Connessione al server SSH fallita");

            let signing_key = generate_signing_key();
            let keypair = SigningKey::from_keypair_bytes(&signing_key.to_keypair_bytes()).expect("Failed generating keypair");

            let arc_stream = Arc::new(Mutex::new((stream, keypair)));

            sessions.insert(key, arc_stream.clone());
            
            arc_stream
        }
    };
    sshd
}


fn generate_signing_key() -> SigningKey {
    let mut secret_bytes = [0u8; 32];
    OsRng.try_fill_bytes(&mut secret_bytes).expect("Failed filling secret key");

    println!("Secret key: {:?}", secret_bytes);

    SigningKey::from_bytes(&secret_bytes)
}


fn change_fingerprint_and_sign(buf: &mut [u8], signing_key: &SigningKey) {
    let pubkey_bytes = signing_key.verifying_key().to_bytes();
    let pubkey_len = pubkey_bytes.len() as u32;
    let key_type = b"ssh-ed25519";
    let key_type_len = key_type.len() as u32;

    let mut new_k_s = Vec::new();
    new_k_s.extend_from_slice(&key_type_len.to_be_bytes());
    new_k_s.extend_from_slice(key_type);
    new_k_s.extend_from_slice(&pubkey_len.to_be_bytes());
    new_k_s.extend_from_slice(&pubkey_bytes);

    let k_s_len = new_k_s.len() as u32;
    buf[6..10].copy_from_slice(&k_s_len.to_be_bytes());
    buf[10..10 + new_k_s.len()].copy_from_slice(&new_k_s);

    // 🔏 Costruisci un H fittizio solo per test (da sostituire con hash reale)
    let dummy_h = b"fake session hash";
    let signature = signing_key.sign(dummy_h);

    // 🧩 Costruisci la signature SSH format
    let mut signature_field = Vec::new();
    signature_field.extend_from_slice(&(key_type.len() as u32).to_be_bytes());
    signature_field.extend_from_slice(key_type);
    signature_field.extend_from_slice(&(signature.to_bytes().len() as u32).to_be_bytes());
    signature_field.extend_from_slice(&signature.to_bytes());

    // 📌 Trova fine Q_S e sostituisci la vecchia firma con la tua
    let sig_start = 10 + new_k_s.len() + 36; // ⚠️ questo 36 ≈ Q_S (deve essere calcolato dinamico!)
    let sig_end = sig_start + signature_field.len();
    buf[sig_start..sig_end].copy_from_slice(&signature_field);

    println!("🔐 Sostituita fingerprint e firma nel pacchetto tipo 31.");
}