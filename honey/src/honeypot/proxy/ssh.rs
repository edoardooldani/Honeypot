use std::{collections::HashMap, net::Ipv4Addr, sync::Arc, time::Duration};
use pnet::{datalink::DataLinkSender, packet::{tcp::{TcpFlags, TcpPacket}, Packet}, util::MacAddr};
use rand::{rngs::OsRng, TryRngCore};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream, sync::{mpsc, Mutex}, time::{sleep, timeout}};
use tracing::error;
use crate::network::sender::send_tcp_stream;
use lazy_static::lazy_static;
use ed25519_dalek::{Signer, SigningKey};
use x25519_dalek::{StaticSecret, PublicKey as X25519PublicKey};
use sha2::{Sha256, Digest};

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
    //stream: TcpStream,
    //signing_key: SigningKey,
    context: Arc<Mutex<SSHSessionContext>>,
    tx_sshd: Arc<Mutex<mpsc::Sender<Vec<u8>>>>, 
    rx_sshd: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>, 
}

lazy_static! {
    pub static ref SSH_SESSIONS: Arc<Mutex<HashMap<(Ipv4Addr, Ipv4Addr), Arc<Mutex<SSHSession>>>>> = Arc::new(Mutex::new(HashMap::new()));
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
        println!("Payload empty: {:?}", tcp_received_packet.packet());
        return;
    }

    let payload_from_client = tcp_received_packet.payload();

    let ssh_session_mutex = get_or_create_ssh_session(tx.clone(), virtual_ip, destination_ip, virtual_mac, destination_mac).await;
    let SSHSession { context , tx_sshd, rx_sshd} = &mut *ssh_session_mutex.lock().await;

    let tx_sshd_clone = Arc::clone(&tx_sshd);
    let rx_sshd_clone = Arc::clone(&rx_sshd);

    check_client_context(payload_from_client, context).await;

    tx_sshd_clone.lock().await.send(tcp_received_packet.packet().to_vec()).await.expect("Failed to send payload to SSHD");

    loop {
        sleep(Duration::from_millis(50)).await;
        match rx_sshd_clone.lock().await.recv().await {
            Some(response_packet) => {
                if response_packet == tcp_received_packet.packet().to_vec(){
                    continue;
                }

                let src_port = tcp_received_packet.get_source();
                let next_ack: u32 = tcp_received_packet.get_sequence() + payload_from_client.len() as u32;
                let next_seq: u32 = tcp_received_packet.get_acknowledgement();

                send_tcp_stream(
                    tx.clone(), 
                    virtual_mac, 
                    virtual_ip, 
                    destination_mac, 
                    destination_ip, 
                    22, 
                    src_port, 
                    next_seq, 
                    next_ack, 
                    TcpFlags::ACK | TcpFlags::PSH, 
                    &response_packet
                ).await;
                break;
            },
            None => {
                println!("Canale rx_sshd chiuso, terminando il loop.");
                break;
            }

        }
    }

}




async fn get_or_create_ssh_session(tx_datalink: Arc<Mutex<Box<dyn DataLinkSender + Send>>>, virtual_ip: Ipv4Addr, destination_ip: Ipv4Addr, virtual_mac: MacAddr, destination_mac: MacAddr) -> Arc<Mutex<SSHSession>> {
    let mut sessions = SSH_SESSIONS.lock().await;
    let key = (virtual_ip, destination_ip);

    match sessions.get(&key) {
        Some(session) => Arc::clone(session),
        None => {
            
            let (tx, rx) = mpsc::channel::<Vec<u8>>(2000);
            let tx_sshd = Arc::new(Mutex::new(tx));
            let rx_sshd = Arc::new(Mutex::new(rx));
            let context= Arc::new(Mutex::new(SSHSessionContext::default()));

            let session = SSHSession {
                context: context.clone(),
                tx_sshd: tx_sshd.clone(),
                rx_sshd: rx_sshd.clone()
            };

            let tx_sshd_clone = Arc::clone(&tx_sshd);
            let rx_sshd_clone = Arc::clone(&rx_sshd);
            let context_clone = Arc::clone(&context);

            println!("Creating new thread for new connection");
            tokio::spawn(async move {
                handle_sshd(tx_datalink, tx_sshd_clone, rx_sshd_clone, context_clone, virtual_ip, destination_ip, virtual_mac, destination_mac).await;
            });

            let arc_session = Arc::new(Mutex::new(session));
            sessions.insert(key, arc_session.clone());
            arc_session
        }
    }
}



async fn handle_sshd(
    tx: Arc<Mutex<Box<dyn DataLinkSender + Send>>>,
    tx_sshd: Arc<Mutex<mpsc::Sender<Vec<u8>>>>, 
    rx_sshd: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
    context: Arc<Mutex<SSHSessionContext>>,
    virtual_ip: Ipv4Addr,
    destination_ip: Ipv4Addr, 
    virtual_mac: MacAddr, 
    destination_mac: MacAddr,
){
    let mut stream = TcpStream::connect("127.0.0.1:2222").await.expect("❌ Connessione al server SSH fallita");
    let signing_key = generate_signing_key();

    loop {
        match rx_sshd.lock().await.recv().await {
            Some(packet_from_client) => {
                if let Some(tcp_packet) = TcpPacket::new(&packet_from_client) {
                    println!("Pacchetto che arriva: {:?}\n con size: {:?}", tcp_packet.payload(), tcp_packet.payload().len());
                    
                    if let Err(e) = stream.write_all(&tcp_packet.payload()).await {
                        error!("❌ Errore nell’invio dati a sshd: {}", e);
                        let mut sessions = SSH_SESSIONS.lock().await;
                        sessions.remove(&(virtual_ip, destination_ip));
                
                        let fin_flags = TcpFlags::ACK | TcpFlags::FIN;
                        send_tcp_stream(
                            tx.clone(),
                            virtual_mac,
                            virtual_ip,
                            destination_mac,
                            destination_ip,
                            22,
                            tcp_packet.get_source(),
                            tcp_packet.get_acknowledgement(),
                            tcp_packet.get_sequence() + tcp_packet.payload().len() as u32,
                            fin_flags,
                            &[],
                        ).await;
                        break;
                    }
                    
                    let mut sshd_response = [0u8; 2048];
                    loop{
                        sleep(Duration::from_millis(50)).await;

                        match timeout(Duration::from_millis(100), stream.read(&mut sshd_response)).await {
                            
                            Ok(Ok(n)) => {
                                if n == 0 {
                                    println!("Received zero bytes, retrying...");
                                    stream.write_all(&tcp_packet.payload()).await.expect("Failed sending again the message");
                                    
                                    continue;
                                } 

                                let mut sshd_vec: Vec<u8> = sshd_response[..n].to_vec();
                                check_server_context(&sshd_vec, context.clone(), &signing_key).await;
                        
                                println!("\n\nPacchetto TCP ricevuto dal client: {:?}\n\n Risposta che invio: {:?}\n\n", tcp_packet.packet(), sshd_vec);
                                tx_sshd.lock().await.send(sshd_vec).await.expect("Failed to send through sshd ");
                                break;
                            },
                            Ok(Err(e)) => {
                                println!("Error reading from SSHD stream: {}", e);
                                break;
                            },
                            _ => {},
                        }
                        
                    }
                }
            },
            None => {
                println!("Canale rx_sshd chiuso, terminando il loop.");
                break;
            }
        }

        sleep(Duration::from_millis(50)).await;
    }
}



async fn check_client_context(received_packet: &[u8], context: &mut Arc<Mutex<SSHSessionContext>>) {
    let mut context_locked = context.lock().await;

    if context_locked.v_c.is_none() && received_packet.starts_with(b"SSH-") {
        if let Some(pos) = received_packet.iter().position(|&b| b == b'\n') {
            let line = &received_packet[..=pos];
            context_locked.v_c = Some(line.to_vec());
            println!("🔍 Salvato V_C: {:?}", String::from_utf8_lossy(line));
            return;
        }
    }

    if received_packet.len() < 6 { return; }
    let msg_type = received_packet[5];
    match msg_type {
        20 => if context_locked.i_c.is_none() {
            context_locked.i_c = Some(received_packet[5..].to_vec());
            println!("🔍 Salvato i_C");
        },
        30 => if context_locked.q_c.is_none() {
            context_locked.q_c = Some(received_packet[6..].to_vec());
            println!("🔍 Salvato q_C");
        },
        _ => {}
    }
}

async fn check_server_context(payload: &Vec<u8>, context: Arc<Mutex<SSHSessionContext>>, signing_key: &SigningKey) -> Option<Vec<u8>> {
    let mut context_locked = context.lock().await;
    if context_locked.v_s.is_none() && payload.starts_with(b"SSH-") {
        if let Some(pos) = payload.iter().position(|&b| b == b'\n') {
            context_locked.v_s = Some(payload[..=pos].to_vec());
            println!("🛰️ Salvato V_S: {:?}", String::from_utf8_lossy(&payload[..=pos]));
            //return Some(payload.to_vec());
        }
    }

    if payload.len() < 6 { return None; }
    let msg_type = payload[5];

    match msg_type {
        20 => if context_locked.i_s.is_none() {
            context_locked.i_s = Some(payload[5..].to_vec());
            println!("📡 Salvato I_S (KEXINIT server)");
        },
        31 => {
            let mut idx = 6;
            let k_s_len = u32::from_be_bytes(payload[idx..idx+4].try_into().unwrap()) as usize;
            idx += 4;
            let k_s = payload[idx..idx + k_s_len].to_vec();
            context_locked.k_s = Some(k_s);
            idx += k_s_len;

            let q_s_len = u32::from_be_bytes(payload[idx..idx+4].try_into().unwrap()) as usize;
            idx += 4;
            let q_s = payload[idx..idx + q_s_len].to_vec();
            context_locked.q_s = Some(q_s.clone());
            //idx += q_s_len;

            if context_locked.k.is_none() {
                if let Some(q_c_bytes) = &context_locked.q_c {
                    if let Some(shared) = derive_shared_secret(q_c_bytes, signing_key) {
                        context_locked.k = Some(shared);
                        println!("🤝 Derivato shared secret K");
                    }
                }
            }

            //return Some(build_packet_31(context.clone(), signing_key).await);
        }
        _ => {}
    }

    None
}

fn derive_shared_secret(q_c_bytes: &[u8], signing_key: &SigningKey) -> Option<Vec<u8>> {
    if q_c_bytes.len() != 32 {
        return None;
    }
    let secret_bytes = signing_key.to_bytes();
    let scalar = StaticSecret::from(secret_bytes);
    let client_pub = X25519PublicKey::from(*<&[u8; 32]>::try_from(q_c_bytes).ok()?);
    Some(scalar.diffie_hellman(&client_pub).as_bytes().to_vec())
}

async fn calculate_session_hash(context: Arc<Mutex<SSHSessionContext>>) -> Option<Vec<u8>> {
    let mut hasher = Sha256::new();
    macro_rules! append_field {
        ($field:expr) => {
            if let Some(ref value) = $field {
                hasher.update((value.len() as u32).to_be_bytes());
                hasher.update(value);
            } else {
                return None;
            }
        };
    }

    let context_locked = context.lock().await;
    append_field!(context_locked.v_c);
    append_field!(context_locked.v_s);
    append_field!(context_locked.i_c);
    append_field!(context_locked.i_s);
    append_field!(context_locked.k_s);
    append_field!(context_locked.q_c);
    append_field!(context_locked.q_s);
    append_field!(context_locked.k);
    Some(hasher.finalize().to_vec())
}

async fn build_packet_31(context: Arc<Mutex<SSHSessionContext>>, signing_key: &SigningKey) -> Vec<u8> {
    let pubkey_bytes = signing_key.verifying_key().to_bytes();
    let key_type = b"ssh-ed25519";
    let mut k_s: Vec<u8> = vec![];
    k_s.extend(&(key_type.len() as u32).to_be_bytes());
    k_s.extend(key_type);
    k_s.extend(&(pubkey_bytes.len() as u32).to_be_bytes());
    k_s.extend(&pubkey_bytes);

    let signature = signing_key.sign(&calculate_session_hash(context.clone()).await.expect("Hash session calculation failed"));
    let mut signature_field: Vec<u8> = vec![];
    signature_field.extend(&(key_type.len() as u32).to_be_bytes());
    signature_field.extend(key_type);
    signature_field.extend(&(signature.to_bytes().len() as u32).to_be_bytes());
    signature_field.extend(&signature.to_bytes());

    let mut payload = vec![31];
    payload.extend(&(k_s.len() as u32).to_be_bytes());
    payload.extend(k_s);

    let context_locked = context.lock().await;
    let q_s = context_locked.q_s.as_ref().unwrap();
    payload.extend(&(q_s.len() as u32).to_be_bytes());
    payload.extend(q_s);
    payload.extend(&(signature_field.len() as u32).to_be_bytes());
    payload.extend(signature_field);

    let padding_len = 8 - ((payload.len() + 5) % 8);
    let mut final_packet = vec![];
    final_packet.extend(&((payload.len() + padding_len + 1) as u32).to_be_bytes());
    final_packet.push(padding_len as u8);
    final_packet.extend(payload);
    final_packet.extend(vec![0u8; padding_len]);
    final_packet
}


fn generate_signing_key() -> SigningKey {
    let mut secret_bytes = [0u8; 32];
    OsRng.try_fill_bytes(&mut secret_bytes).expect("Failed filling secret key");
    SigningKey::from_bytes(&secret_bytes)
}



fn build_ssh_packet(payload: &mut Vec<u8>) {
    let block_size = 8;
    let mut padding_len = block_size - ((payload.len() + 5) % block_size);
    if padding_len < 4 {
        padding_len += block_size;
    }

    let total_len = (payload.len() + padding_len + 1) as u32;

    let mut buf = Vec::new();
    buf.extend_from_slice(&total_len.to_be_bytes());
    buf.push(padding_len as u8);
    buf.extend_from_slice(payload);

    let padding: Vec<u8> = (0..padding_len).map(|_| rand::random::<u8>()).collect();
    buf.extend_from_slice(&padding);

    payload.clear();
    payload.extend_from_slice(&buf);
}