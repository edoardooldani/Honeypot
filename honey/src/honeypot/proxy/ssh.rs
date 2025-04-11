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
        //println!("Payload empty: {:?}", tcp_received_packet.packet());
        return;
    }

    let payload_from_client = tcp_received_packet.payload();

    let ssh_session_mutex = get_or_create_ssh_session(virtual_ip, destination_ip).await;
    let SSHSession { tx_sshd, rx_sshd} = &mut *ssh_session_mutex.lock().await;

    let tx_sshd_clone = Arc::clone(&tx_sshd);
    let rx_sshd_clone = Arc::clone(&rx_sshd);

    tx_sshd_clone.lock().await.send("ls".to_string()).await.expect("Failed to send payload to SSHD");

    loop {
        sleep(Duration::from_millis(50)).await;
        match rx_sshd_clone.lock().await.recv().await {
            Some(response_packet) => {
                if response_packet == "ls".to_string(){
                    continue;
                }
                println!("Received from sshd: {:?}", response_packet);
                let src_port = tcp_received_packet.get_source();
                let next_ack: u32 = tcp_received_packet.get_sequence() + payload_from_client.len() as u32;
                let next_seq: u32 = tcp_received_packet.get_acknowledgement();

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

                tx_sshd.lock().await.send(s).await.expect("Failed sending response to command!");
                
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