use std::{collections::HashMap, io::Read, net::Ipv4Addr, path::Path, sync::Arc};
use pnet::{datalink::DataLinkSender, packet::{tcp::{TcpFlags, TcpPacket}, Packet}, util::MacAddr};
use rand::Rng;
use ssh2::Session;
use tokio::{net::TcpStream, sync::{mpsc, Mutex}};
use crate::network::sender::send_tcp_stream;
use lazy_static::lazy_static;



pub struct SSHSession {
    tx_sshd: Arc<Mutex<mpsc::Sender<String>>>, 
    rx_sshd: Arc<Mutex<mpsc::Receiver<String>>>, 
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
        return;
    }

    let payload_from_client = tcp_received_packet.payload();

    let ssh_session_mutex = get_or_create_ssh_session(virtual_ip, destination_ip).await;
    let SSHSession { tx_sshd, rx_sshd} = &mut *ssh_session_mutex.lock().await;

    let tx_sshd_clone = Arc::clone(&tx_sshd);
    let rx_sshd_clone = Arc::clone(&rx_sshd);

    let src_port = tcp_received_packet.get_source();
    let next_ack: u32 = tcp_received_packet.get_sequence() + payload_from_client.len() as u32;
    let next_seq: u32 = tcp_received_packet.get_acknowledgement();

    // Sending ACK
    /*send_tcp_stream(
        tx.clone(), 
        virtual_mac, 
        virtual_ip, 
        destination_mac, 
        destination_ip, 
        22,
        src_port, 
        next_seq, 
        next_ack, 
        TcpFlags::ACK, 
        &[]
    ).await;*/

    
    if payload_from_client.starts_with(b"SSH-"){
        let banner = b"SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2\r\n";

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
            banner
        ).await;

    }else if payload_from_client[5] == 0x14 {
        let key_inix = &create_kexinit_response();
        println!("Received packet: {:?}\nSending key inix: {:?}", tcp_received_packet.payload(), key_inix);

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
            key_inix
        ).await;
    } else {
        println!("Received other package, payload: {:?}", tcp_received_packet.payload());
    }

    /*

    tx_sshd_clone.lock().await.send(payload_str.clone()).await.expect("Failed to send payload to SSHD");

    loop {
        sleep(Duration::from_millis(50)).await;
        match rx_sshd_clone.lock().await.recv().await {
            Some(response_packet) => {
                if response_packet == payload_str{
                    continue;
                }

                println!("Received from sshd: {:?}", response_packet);
                

                let response_bytes = response_packet.as_bytes();

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
                    &response_bytes
                ).await;

            },
            None => {
                println!("Canale rx_sshd chiuso, terminando il loop.");
                break;
            }

        }
    }
 */
}


fn generate_random_cookie() -> Vec<u8> {
    let mut rng = rand::rng();
    let cookie: Vec<u8> = (0..16).map(|_| rng.random()).collect();
    cookie
}

fn create_kexinit_response() -> Vec<u8> {
    let cookie = generate_random_cookie();

    let mut kexinit_msg: Vec<u8> = vec![0x14]; // Message type SSH_MSG_KEXINIT

    // Add the cookie
    kexinit_msg.extend(cookie);

    // Add the key exchange algorithms (Diffie-Hellman Group14)
    kexinit_msg.extend([
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // Diffie-Hellman Group14
        0x64, 0x68, 0x66, 0x73, 0x68, 0x2d, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x31, 0x34, 0x2d, 0x73, 0x68, 0x61, 0x31,
    ]);

    // Add ciphers (AES-128-CTR)
    kexinit_msg.extend([
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // AES-128-CTR
        0x61, 0x65, 0x73, 0x31, 0x32, 0x38, 0x2d, 0x63, 0x74, 0x72, 0x00, 0x01,
    ]);

    // Add MAC (HMAC-SHA1)
    kexinit_msg.extend([
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // HMAC-SHA1
        0x68, 0x6d, 0x61, 0x63, 0x2d, 0x73, 0x68, 0x61, 0x31, 0x00, 0x01,
    ]);

    // Add Compression method (None)
    kexinit_msg.extend([
        0x00, 0x00, 0x00, 0x01, // None compression method
    ]);

    // Add Language
    kexinit_msg.extend([0x00, 0x01, 0x00, 0x01]); // Empty string for language

    // Padding (Ensure the message length is a multiple of 8)
    let padding_length = (8 - kexinit_msg.len() % 8) % 8;
    kexinit_msg.extend(vec![0u8; padding_length]);

    // Update the length of the message after padding
    let total_length = (kexinit_msg.len() + 4) as u32; // Add 4 bytes for the length field itself

    let mut key_init_payload: Vec<u8> = vec![];
    key_init_payload.extend(&total_length.to_be_bytes()); // Add the total length
    key_init_payload.extend([0x00]);
    key_init_payload.extend(kexinit_msg); // Add the actual KEXINIT message

    key_init_payload
}




async fn get_or_create_ssh_session(virtual_ip: Ipv4Addr, destination_ip: Ipv4Addr) -> Arc<Mutex<SSHSession>> {
    let mut sessions = SSH_SESSIONS.lock().await;
    let key = (virtual_ip, destination_ip);

    match sessions.get(&key) {
        Some(session) => Arc::clone(session),
        None => {
            
            let (tx, rx) = mpsc::channel::<String>(2000);
            let tx_sshd = Arc::new(Mutex::new(tx));
            let rx_sshd = Arc::new(Mutex::new(rx));

            let session = SSHSession {
                tx_sshd: tx_sshd.clone(),
                rx_sshd: rx_sshd.clone()
            };

            let tx_sshd_clone = Arc::clone(&tx_sshd);
            let rx_sshd_clone = Arc::clone(&rx_sshd);

            println!("Creating new thread for new connection");
            tokio::spawn(async move {
                handle_sshd(tx_sshd_clone, rx_sshd_clone).await;
            });

            let arc_session = Arc::new(Mutex::new(session));
            sessions.insert(key, arc_session.clone());
            arc_session
        }
    }
}



async fn handle_sshd(
    tx_sshd: Arc<Mutex<mpsc::Sender<String>>>, 
    rx_sshd: Arc<Mutex<mpsc::Receiver<String>>>,
){

    let stream = TcpStream::connect("127.0.0.1:22").await.expect("❌ Connessione al server SSH fallita");
    let mut session = Session::new().expect("Failed to create SSH session");
    session.set_tcp_stream(stream);
    session.handshake().expect("Failed to complete SSH handshake");

    let username = "edoardo"; 
    let private_key_path = "src/honeypot/proxy/keys/ssh"; 

    authenticate_with_public_key(&mut session, username, private_key_path).await;

    loop {
        match rx_sshd.lock().await.recv().await {
            Some(command) => {
                println!("Pacchetto che arriva: {:?}\n", command);

                let mut channel = session.channel_session().expect("Failed to create SSH channel");
                
                channel.exec(&command).unwrap();
                let mut s = String::new();
                channel.read_to_string(&mut s).unwrap();
                println!("{}", s);

                tx_sshd.lock().await.send(s.to_string()).await.expect("Failed sending response to command!");

            }
            _ => { break;}
        }
    }
}    


async fn authenticate_with_public_key(session: &mut Session, username: &str, private_key_path: &str){
    let private_key = Path::new(private_key_path);
    
    session.userauth_pubkey_file(username, None, &private_key, None)
        .expect("Failed authenticating with private key");
    
    println!("Authentication with public key succeeded!");
}


