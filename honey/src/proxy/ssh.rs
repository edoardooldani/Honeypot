use std::{collections::HashMap, net::Ipv4Addr, sync::Arc, time::Duration};
use pnet::{datalink::DataLinkSender, packet::{tcp::{TcpFlags, TcpPacket}, Packet}, util::MacAddr};
use rand::{rngs::OsRng, TryRngCore};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream, sync::Mutex, time::timeout};
use tracing::{info, error};
use crate::network::sender::send_tcp_stream;
use lazy_static::lazy_static;
use ed25519_dalek::{Signer, SigningKey};
use x25519_dalek::{StaticSecret, PublicKey as X25519PublicKey};

#[derive(Debug, Default)]
struct SSHSessionContext {
    v_c: Option<Vec<u8>>,        // Version string client
    v_s: Option<Vec<u8>>,        // Version string server
    i_c: Option<Vec<u8>>,        // KEXINIT client payload
    i_s: Option<Vec<u8>>,        // KEXINIT server payload
    k_s: Option<Vec<u8>>,        // Server host key
    q_c: Option<Vec<u8>>,        // Ephemeral client key
    q_s: Option<Vec<u8>>,        // Ephemeral server key
    k:   Option<Vec<u8>>,        // Shared secret
}

pub struct SSHSession {
    stream: TcpStream,
    signing_key: SigningKey,
    context: SSHSessionContext,
}

lazy_static! {
    pub static ref SSH_SESSIONS: Arc<Mutex<HashMap<(Ipv4Addr, Ipv4Addr),Arc<Mutex<SSHSession>>
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

    let ssh_session_mutex = get_or_create_ssh_session(virtual_ip, destination_ip).await;
    let mut ssh_session_locked = ssh_session_mutex.lock().await;
    
    let SSHSession { stream: sshd, signing_key, context } = &mut *ssh_session_locked;

    if let Err(e) = sshd.write_all(payload_from_client).await {
        error!("❌ Errore nell’invio dati a sshd: {}", e);
        let mut sessions = SSH_SESSIONS.lock().await;
        sessions.remove(&(virtual_ip, destination_ip));
        return;
    }
    
    check_client_context(tcp_received_packet.packet(), context);

    let mut buf = [0u8; 2048];

    //loop {
    match timeout(Duration::from_millis(200), sshd.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {

            check_server_context(&mut buf[..n], context, signing_key);
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



async fn get_or_create_ssh_session(
    virtual_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
) -> Arc<Mutex<SSHSession>> {
    let mut sessions = SSH_SESSIONS.lock().await;
    let key = (virtual_ip, destination_ip);

    match sessions.get(&key) {
        Some(session) => Arc::clone(session),
        None => {
            let stream = TcpStream::connect("127.0.0.1:2222")
                .await
                .expect("❌ Connessione al server SSH fallita");

            let signing_key = generate_signing_key();

            let session = SSHSession {
                stream,
                signing_key,
                context: SSHSessionContext::default(),
            };

            let arc_session = Arc::new(Mutex::new(session));
            sessions.insert(key, arc_session.clone());

            arc_session
        }
    }
}


fn check_client_context(received_packet: &[u8], context: &mut SSHSessionContext){
    if context.v_c.is_none() && received_packet.starts_with(b"SSH-") {
        if let Some(pos) = received_packet.iter().position(|&b| b == b'\n') {
            let line = &received_packet[..=pos];
            context.v_c = Some(line.to_vec());

            println!("🔍 Salvato V_C: {:?}", String::from_utf8_lossy(line));
            return;
        }
    }

    let msg_type = received_packet[5];
    match msg_type {
        20 => {
            if context.i_c.is_none() {
                context.i_c = Some(received_packet[5..received_packet.len()].to_vec());
                println!("🔍 Salvato i_C");
            }
        }
        30 => {
            if context.q_c.is_none(){
                context.q_c = Some(received_packet[6..received_packet.len()].to_vec());
                println!("🔍 Salvato q_C");
            }
        }
        _ => {}
    }
}

fn check_server_context(payload: &mut [u8], context: &mut SSHSessionContext, signing_key: &SigningKey) {

    if context.v_s.is_none() && payload.starts_with(b"SSH-") {
        if let Some(pos) = payload.iter().position(|&b| b == b'\n') {
            let line = &payload[..=pos];
            context.v_s = Some(line.to_vec());
            println!("🛰️ Salvato V_S: {:?}", String::from_utf8_lossy(line));
            return;
        }
    }

    if payload.len() < 6 {
        return;
    }

    let msg_type = payload[5];

    match msg_type {
        20 => {
            if context.i_s.is_none() {
                context.i_s = Some(payload[5..].to_vec());
                println!("📡 Salvato I_S (KEXINIT server)");
            }
        }
        31 => {

            change_fingerprint_and_sign(payload, signing_key);

            let mut idx = 6;
            if context.k_s.is_none() {
                if idx + 4 > payload.len() { return; }
                let k_s_len = u32::from_be_bytes(payload[idx..idx+4].try_into().unwrap()) as usize;
                idx += 4;

                if idx + k_s_len > payload.len() { return; }
                let k_s = payload[idx..idx + k_s_len].to_vec();
                context.k_s = Some(k_s);
                println!("🔑 Salvato K_S");
                idx += k_s_len;
            }

            // Q_S
            if context.q_s.is_none() {
                if idx + 4 > payload.len() { return; }
                let q_s_len = u32::from_be_bytes(payload[idx..idx+4].try_into().unwrap()) as usize;
                idx += 4;

                if idx + q_s_len > payload.len() { return; }
                let q_s = payload[idx..idx + q_s_len].to_vec();
                context.q_s = Some(q_s);
                println!("🧪 Salvato Q_S");
            }

            if context.k.is_none() {
                if let Some(q_c_bytes) = &context.q_c {
                    if let Some(shared) = derive_shared_secret(q_c_bytes, signing_key) {
                        context.k = Some(shared);
                        println!("🤝 Derivato shared secret K");
                    } else {
                        println!("⚠️ Derivazione shared secret fallita");
                    }
                }
            }
        }
        _ => {}
    }
}


fn derive_shared_secret(q_c_bytes: &[u8], signing_key: &SigningKey) -> Option<Vec<u8>> {
    if q_c_bytes.len() != 32 {
        return None;
    }

    let secret_bytes = signing_key.to_bytes();
    let scalar = StaticSecret::from(secret_bytes);
    let client_pub = X25519PublicKey::from(*<&[u8; 32]>::try_from(q_c_bytes).ok()?);

    let shared_secret = scalar.diffie_hellman(&client_pub);

    Some(shared_secret.as_bytes().to_vec())
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