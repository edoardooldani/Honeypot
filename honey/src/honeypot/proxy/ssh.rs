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
        println!("Received banner: {:?}\n Virtual ip: {:?}", payload_from_client, virtual_ip);

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
        let key_inix = b"000004540a146eff2b5c01d447135f82514dca417b2200000126736e747275703736317832353531392d736861353132406f70656e7373682e636f6d2c637572766532353531392d7368613235362c637572766532353531392d736861323536406c69627373682e6f72672c656364682d736861322d6e697374703235362c656364682d736861322d6e697374703338342c656364682d736861322d6e697374703532312c6469666669652d68656c6c6d616e2d67726f75702d65786368616e67652d7368613235362c6469666669652d68656c6c6d616e2d67726f757031362d7368613531322c6469666669652d68656c6c6d616e2d67726f757031382d7368613531322c6469666669652d68656c6c6d616e2d67726f757031342d7368613235362c6b65782d7374726963742d732d763030406f70656e7373682e636f6d000000397273612d736861322d3531322c7273612d736861322d3235362c65636473612d736861322d6e697374703235362c7373682d656432353531390000006c63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733132382d6374722c6165733139322d6374722c6165733235362d6374722c6165733132382d67636d406f70656e7373682e636f6d2c6165733235362d67636d406f70656e7373682e636f6d0000006c63686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733132382d6374722c6165733139322d6374722c6165733235362d6374722c6165733132382d67636d406f70656e7373682e636f6d2c6165733235362d67636d406f70656e7373682e636f6d000000d5756d61632d36342d65746d406f70656e7373682e636f6d2c756d61632d3132382d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3531322d65746d406f70656e7373682e636f6d2c686d61632d736861312d65746d406f70656e7373682e636f6d2c756d61632d3634406f70656e7373682e636f6d2c756d61632d313238406f70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d736861322d3531322c686d61632d73686131000000d5756d61632d36342d65746d406f70656e7373682e636f6d2c756d61632d3132382d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3531322d65746d406f70656e7373682e636f6d2c686d61632d736861312d65746d406f70656e7373682e636f6d2c756d61632d3634406f70656e7373682e636f6d2c756d61632d313238406f70656e7373682e636f6d2c686d61632d736861322d3235362c686d61632d736861";
        

        println!("Sending key inix: {:?}", tcp_received_packet.packet());

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