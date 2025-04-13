use std::{collections::HashMap, io::Read, net::Ipv4Addr, path::Path, sync::Arc, time::Duration};
use pnet::{datalink::DataLinkSender, packet::{tcp::{TcpFlags, TcpPacket}, Packet}, util::MacAddr};
use ssh2::Session;
use tokio::{net::TcpStream, sync::{mpsc, Mutex}, time::sleep};
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

    if payload_from_client.starts_with(b"SSH-"){
        println!("Received banner: {:?}", payload_from_client);

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
            b"SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2\r\n"
        ).await;
    }else {

        let key_inix: &[u8] = &[
            0x00, 0x00, 0x04, 0x54, 0x0a, 0x14, 0x6e, 0xff, 0x2b, 0x5c, 0x01, 0xd4, 0x47, 0x13, 0x5f, 0x82,
            0x51, 0x4d, 0xca, 0x41, 0x7b, 0x22, 0x00, 0x00, 0x01, 0x26, 0x73, 0x6e, 0x74, 0x72, 0x75, 0x70,
            0x37, 0x36, 0x31, 0x78, 0x32, 0x35, 0x35, 0x31, 0x39, 0x2d, 0x73, 0x68, 0x61, 0x35, 0x31, 0x32,
            0x40, 0x6f, 0x70, 0x65, 0x6e, 0x73, 0x73, 0x68, 0x2e, 0x63, 0x6f, 0x6d, 0x2c, 0x63, 0x75, 0x72,
            0x76, 0x65, 0x32, 0x35, 0x35, 0x31, 0x39, 0x2d, 0x73, 0x68, 0x61, 0x32, 0x35, 0x36, 0x2c, 0x63,
            0x75, 0x72, 0x76, 0x65, 0x32, 0x35, 0x35, 0x31, 0x39, 0x2d, 0x73, 0x68, 0x61, 0x32, 0x35, 0x36,
            0x40, 0x6c, 0x69, 0x62, 0x73, 0x73, 0x68, 0x2e, 0x6f, 0x72, 0x67, 0x2c, 0x65, 0x63, 0x64, 0x68,
            0x2d, 0x73, 0x68, 0x61, 0x32, 0x2d, 0x6e, 0x69, 0x73, 0x74, 0x70, 0x32, 0x35, 0x36, 0x2c, 0x65,
            0x63, 0x64, 0x68, 0x2d, 0x73, 0x68, 0x61, 0x32, 0x2d, 0x6e, 0x69, 0x73, 0x74, 0x70, 0x33, 0x38,
            0x34, 0x2c, 0x65, 0x63, 0x64, 0x68, 0x2d, 0x73, 0x68, 0x61, 0x32, 0x2d, 0x6e, 0x69, 0x73, 0x74,
            0x70, 0x35, 0x32, 0x31, 0x2c, 0x64, 0x69, 0x66, 0x66, 0x69, 0x65, 0x2d, 0x68, 0x65, 0x6c, 0x6c,
            0x6d, 0x61, 0x6e, 0x2d, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x2d, 0x65, 0x78, 0x63, 0x68, 0x61, 0x6e,
            0x67, 0x65, 0x2d, 0x73, 0x68, 0x61, 0x32, 0x35, 0x36, 0x2c, 0x64, 0x69, 0x66, 0x66, 0x69, 0x65,
            0x2d, 0x68, 0x65, 0x6c, 0x6c, 0x6d, 0x61, 0x6e, 0x2d, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x31, 0x36,
            0x2d, 0x73, 0x68, 0x61, 0x35, 0x31, 0x32, 0x2c, 0x64, 0x69, 0x66, 0x66, 0x69, 0x65, 0x2d, 0x68,
            0x65, 0x6c, 0x6c, 0x6d, 0x61, 0x6e, 0x2d, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x31, 0x38, 0x2d, 0x73,
            0x68, 0x61, 0x35, 0x31, 0x32, 0x2c, 0x64, 0x69, 0x66, 0x66, 0x69, 0x65, 0x2d, 0x68, 0x65, 0x6c,
            0x6c, 0x6d, 0x61, 0x6e, 0x2d, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x31, 0x34, 0x2d, 0x73, 0x68, 0x61,
            0x32, 0x35, 0x36, 0x2c, 0x6b, 0x65, 0x78, 0x2d, 0x73, 0x74, 0x72, 0x69, 0x63, 0x74, 0x2d, 0x73,
            0x2d, 0x76, 0x30, 0x30, 0x40, 0x6f, 0x70, 0x65, 0x6e, 0x73, 0x73, 0x68, 0x2e, 0x63, 0x6f, 0x6d,
            0x00, 0x00, 0x00, 0x39, 0x72, 0x73, 0x61, 0x2d, 0x73, 0x68, 0x61, 0x32, 0x2d, 0x35, 0x31, 0x32,
            0x2c, 0x72, 0x73, 0x61, 0x2d, 0x73, 0x68, 0x61, 0x32, 0x2d, 0x32, 0x35, 0x36, 0x2c, 0x65, 0x63,
            0x64, 0x73, 0x61, 0x2d, 0x73, 0x68, 0x61, 0x32, 0x2d, 0x6e, 0x69, 0x73, 0x74, 0x70, 0x32, 0x35,
            0x36, 0x2c, 0x73, 0x73, 0x68, 0x2d, 0x65, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x00, 0x00, 0x00
        ];

        println!("Sending key inix: {:?}", payload_from_client);

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