use std::{collections::HashMap, io::{Read, Write}, net::Ipv4Addr, path::Path, sync::Arc, time::Duration};
use pnet::{datalink::DataLinkSender, packet::{tcp::{TcpFlags, TcpPacket}, Packet}, util::MacAddr};
use ssh2::Session;
use tokio::{net::TcpStream, sync::{mpsc, Mutex}, time::sleep};
use crate::network::sender::send_tcp_stream;
use lazy_static::lazy_static;

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
        //println!("Payload empty: {:?}", tcp_received_packet.packet());
        return;
    }

    let payload_from_client = tcp_received_packet.payload();

    let ssh_session_mutex = get_or_create_ssh_session(tx.clone(), virtual_ip, destination_ip, virtual_mac, destination_mac).await;
    let SSHSession { context , tx_sshd, rx_sshd} = &mut *ssh_session_mutex.lock().await;

    let tx_sshd_clone = Arc::clone(&tx_sshd);
    let rx_sshd_clone = Arc::clone(&rx_sshd);

    tx_sshd_clone.lock().await.send(tcp_received_packet.packet().to_vec()).await.expect("Failed to send payload to SSHD");

    loop {
        sleep(Duration::from_millis(50)).await;
        match rx_sshd_clone.lock().await.recv().await {
            Some(response_packet) => {
                if response_packet == tcp_received_packet.packet().to_vec(){
                    continue;
                }
                println!("Received from sshd: {:?}", response_packet);
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
    let stream = TcpStream::connect("127.0.0.1:2222").await.expect("❌ Connessione al server SSH fallita");
    let mut session = Session::new().expect("Failed to create SSH session");
    session.set_tcp_stream(stream);
    session.handshake().expect("Failed to complete SSH handshake");

    let username = "edoardo"; 
    let private_key_path = "src/honeypot/proxy/keys/ssh"; 

    authenticate_with_public_key(&mut session, username, private_key_path).await;
    let mut buffer = [0u8; 1024];

    // Test: Invia un comando SSH di esempio (ad esempio, "ls" per listare i file)
    let command = "ls -l\n"; // Comando di test

    // Creazione di un canale per inviare il comando
    let mut channel = session.channel_session().expect("Failed to create SSH channel");

    // Scrivi il comando nel canale SSH
    channel.write_all(command.as_bytes()).expect("Failed to send command to SSH server");
    channel.flush().expect("Failed to flush data to SSH server");

    // Leggi la risposta dal server SSH
    let mut server_response = Vec::new();
    loop {
        let n = channel.read(&mut buffer).expect("Failed to read SSH server response");
        if n == 0 {
            break; // Fine della risposta
        }
        server_response.extend_from_slice(&buffer[..n]);
    }

    if server_response.is_empty() {
        println!("No response from SSH server.");
    } else {
        println!("Received response from SSH server: {:?}", server_response);

        // Invia la risposta al client
        let tx_locked = tx_sshd.lock().await;
        if let Err(e) = tx_locked.send(server_response).await {
            eprintln!("Failed to send server response to client: {}", e);
            return; // Esci in caso di errore
        }
    }
}    


async fn authenticate_with_public_key(session: &mut Session, username: &str, private_key_path: &str){
    let private_key = Path::new(private_key_path);
    
    session.userauth_pubkey_file(username, None, &private_key, None)
        .expect("Failed authenticating with private key");
    
    println!("Authentication with public key succeeded!");
}