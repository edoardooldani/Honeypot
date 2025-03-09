use futures_util::{StreamExt, future, pin_mut};
use std::{
    env, path::PathBuf, sync::{Arc, Mutex}
};

use common::{
    packet::{build_packet, calculate_header}, 
    tls::{generate_client_session_id, rustls_client_config}, 
    types::{Header, NetworkPayload, PayloadType, ProcessPayload}};
use tokio_tungstenite::{connect_async_tls_with_config, tungstenite::protocol::Message, Connector, MaybeTlsStream};


use libproc::libproc::{
    proc_pid::{name, pidpath, pidinfo}, 
    task_info::TaskInfo,
};
use libproc::processes;
use pnet::util::MacAddr;
use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet as pnetPacket;


#[tokio::main]
async fn main() {
    let url = env::args()
        .nth(1)
        .unwrap_or_else(|| panic!("this program requires at least one argument"));


    let config = rustls_client_config(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("certs")
            .join("client-key.pem"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("certs")
            .join("client-cert.pem"),
    );

    let connector = Connector::Rustls(Arc::new(config));

    let (ws_stream, _) = connect_async_tls_with_config(&url, None, false, Some(connector))
        .await
        .expect("Failed to connect");
    println!("WebSocket handshake has been successfully completed");

    let maybe_tls_stream = ws_stream.get_ref();
    
    let session_id = Arc::new(Mutex::new(0));
    //let session_id: Arc<AtomicU32>;

    if let MaybeTlsStream::Rustls(tls_stream) = maybe_tls_stream {
        let tls_session = tls_stream.get_ref().1;
        
        {
            let mut id = session_id.lock().unwrap();
            *id = generate_client_session_id(tls_session);
        }

        //println!("Generated session_id: {}", *session_id.lock().unwrap());
    } else {
        return;
    }


    let (stdin_tx, stdin_rx) = futures_channel::mpsc::unbounded();

    let stdin_tx_pong = stdin_tx.clone();
    let stdin_tx_processes = stdin_tx.clone();
    let stdin_tx_network = stdin_tx.clone();

    tokio::spawn(monitor_connections(stdin_tx_network, Arc::clone(&session_id)));
    tokio::spawn(get_processes(stdin_tx_processes, Arc::clone(&session_id)));

    let (write, read) = ws_stream.split();

    let stdin_to_ws = stdin_rx.map(Ok).forward(write);
    let ws_to_stdout = read.for_each(|message| async {
        match message {
            Ok(msg) => match msg {
                Message::Binary(bin) => match bincode::deserialize::<Header>(&bin) {
                    Ok(net_data) => println!("Received (Binary): {:?}", net_data),
                    Err(e) => eprintln!("Errore di deserializzazione binaria: {}", e),
                },
                Message::Ping(ping_data) => {
                    println!("📡 Ricevuto PING, rispondendo con PONG...");
                    if let Err(e) = stdin_tx_pong.unbounded_send(Message::Pong(ping_data)) {
                        eprintln!("Errore nell'invio del PONG: {}", e);
                    }
                },
                _ => eprintln!("Tipo di messaggio non gestito"),
            },
            
            Err(e) => eprintln!("Errore nel messaggio: {}", e),
        }
    });

    pin_mut!(stdin_to_ws, ws_to_stdout);
    future::select(stdin_to_ws, ws_to_stdout).await;
}




/// Monitorizza le nuove connessioni su una specifica interfaccia e le invia via WebSocket
async fn monitor_connections(tx: futures_channel::mpsc::UnboundedSender<Message>, session_id: Arc<Mutex<u32>>) {
    let interface = get_primary_interface().expect("Interfaccia non trovata");

    let (_tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(rx, tx)) => (rx, tx),
        Ok(_) => panic!("Tipo di canale non supportato"),
        Err(e) => panic!("Errore nell'apertura del canale: {}", e),
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(ethernet_packet) = EthernetPacket::new(packet) {
                    handle_packet(&ethernet_packet, &tx, Arc::clone(&session_id));
                }
            }
            Err(e) => eprintln!("Errore nella lettura del pacchetto: {}", e),
        }
    }
}

/// Analizza i pacchetti per trovare nuove connessioni e inviarle al server WebSocket
fn handle_packet(ethernet_packet: &EthernetPacket, tx: &futures_channel::mpsc::UnboundedSender<Message>, session_id: Arc<Mutex<u32>>) {
    let mac_address: [u8; 6];
    match get_mac_address() {
        Some(mac) => mac_address = mac,
        None => return,
    }

    match ethernet_packet.get_ethertype() {
        pnet::packet::ethernet::EtherTypes::Ipv4 => {
            if let Some(ipv4_packet) = pnet::packet::ipv4::Ipv4Packet::new(ethernet_packet.payload()) {
                match ipv4_packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                            send_connection_info(
                                tx, 
                                session_id, 
                                "TCP".to_owned(), 
                                ipv4_packet.get_source().to_string(),
                                tcp_packet.get_source(),
                                ipv4_packet.get_destination().to_string(),
                                tcp_packet.get_destination(),
                                mac_address
                            );
                        }
                    }
                    IpNextHeaderProtocols::Udp => {
                        if let Some(udp_packet) = UdpPacket::new(ipv4_packet.payload()) {
                            send_connection_info(
                                tx, 
                                session_id, 
                                "UDP".to_owned(), 
                                ipv4_packet.get_source().to_string(),
                                udp_packet.get_source(),
                                ipv4_packet.get_destination().to_string(),
                                udp_packet.get_destination(),
                                mac_address
                            );
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
}


/// Costruisce e invia il messaggio WebSocket con le informazioni della connessione
fn send_connection_info(
    tx: &futures_channel::mpsc::UnboundedSender<Message>,
    session_id: Arc<Mutex<u32>>,
    protocol: String,
    src_ip: String,
    src_port: u16,
    dest_ip: String,
    dest_port: u16,
    mac_address: [u8; 6]
) {
    
    let network_payload = PayloadType::Network(NetworkPayload {
        protocol,
        src_ip,
        src_port,
        dest_ip,
        dest_port
    });           
    let data_type: u8 = 1;
    send_message(tx.clone(), network_payload, Arc::clone(&session_id), data_type, mac_address);
}



async fn get_processes(tx: futures_channel::mpsc::UnboundedSender<Message>, session_id: Arc<Mutex<u32>>) {

    let mac_address: [u8; 6];
    match get_mac_address() {
        Some(mac) => mac_address = mac,
        None => return,
    }
    
    match processes::pids_by_type(processes::ProcFilter::All) {
        
        Ok(pids) => {
            println!("There are currently {} processes active", pids.len());
            for pid in pids {
                
                let process_name = match name(pid as i32) {
                    Ok(name) => name,
                    Err(_) => String::from("Unknown"),
                };
                
                let task_info = match pidinfo::<TaskInfo>(pid as i32, 0) {
                    Ok(info) => info,
                    Err(_) => continue,
                };

                let process_path = match pidpath(pid as i32) {
                    Ok(path) => path,
                    Err(_) => String::from("Unknown"),
                };

                let process_payload = PayloadType::Process(ProcessPayload {
                    process_id: pid,
                    process_name: process_name,
                    path: process_path,
                    virtual_size: task_info.pti_virtual_size,
                    resident_size: task_info.pti_resident_size,
                    syscalls_unix: task_info.pti_syscalls_unix,
                    syscalls_mach: task_info.pti_syscalls_mach,
                    faults: task_info.pti_faults,
                    pageins: task_info.pti_pageins,
                    cow_faults: task_info.pti_cow_faults,
                    messages_sent: task_info.pti_messages_sent,
                    messages_received: task_info.pti_messages_received,
                    csw: task_info.pti_csw,
                    threadnum: task_info.pti_threadnum,
                    numrunning: task_info.pti_numrunning,
                    priority: task_info.pti_priority,
                });           

                let data_type: u8 = 2;
                send_message(tx.clone(), process_payload, Arc::clone(&session_id), data_type, mac_address);
                
            }

        }
        Err(err) => eprintln!("Error: {}", err),
    }

}



fn send_message(tx: futures_channel::mpsc::UnboundedSender<Message>, payload: PayloadType, session_id: Arc<Mutex<u32>>, data_type: u8, mac_address: [u8; 6]){
    let msg = {
        let mut id = session_id.lock().unwrap();
        *id += 1;

        let header = calculate_header(*id, data_type, 0, mac_address);
        let packet = build_packet(header, payload);
        let serialized = bincode::serialize(&packet).expect("Errore nella serializzazione");

        Message::Binary(serialized.into())
    };

    if let Err(e) = tx.unbounded_send(msg) {
        eprintln!("Errore nell'invio del messaggio WebSocket: {:?}", e);
    }


    
}



fn get_mac_address() -> Option<[u8; 6]> {
    let interfaces = datalink::interfaces();

    let preferred_interfaces = &["eth0", "wlan0", "en0", "can0", "modbus0"]; // Ethernet, Wi-Fi, CAN, Modbus
    let exclude_prefixes = &["lo", "utun", "stf", "gif", "awdl", "llw", "docker", "br"];
    
    let mac = interfaces
        .into_iter()
        .filter(|iface| {
            iface.mac.is_some()
                && iface.mac.unwrap() != MacAddr(0, 0, 0, 0, 0, 0) // Esclude MAC 00:00:00:00:00:00
                && !exclude_prefixes.iter().any(|&p| iface.name.starts_with(p))
        })
        .find(|iface| {
            preferred_interfaces.contains(&iface.name.as_str()) || true
        })
        .and_then(|iface| {
            let mac = iface.mac.unwrap(); // `MacAddr`
            Some([mac.0, mac.1, mac.2, mac.3, mac.4, mac.5]) // Converti in [u8; 6]
        });

    mac
}

fn get_primary_interface() -> Option<NetworkInterface> {
    let interfaces = datalink::interfaces();

    let preferred_interfaces = ["eth", "wlan", "en"]; // Ethernet, Wi-Fi, etc.

    interfaces
        .into_iter()
        .filter(|iface| {
            !iface.ips.is_empty()
            && !iface.is_loopback()
            && preferred_interfaces.iter().any(|p| iface.name.starts_with(p))
        })
        .next()
}