use futures_util::{StreamExt, future, pin_mut};
use std::{
    env,
    sync::{Arc, Mutex},
    path::PathBuf
};

use common::{
    packet::{build_packet, calculate_header}, 
    tls::{generate_client_session_id, rustls_client_config}, 
    types::{Header, ProcessPayload}};
use tokio_tungstenite::{connect_async_tls_with_config, tungstenite::protocol::Message, Connector, MaybeTlsStream};

// Port scanner
use libproc::libproc::{
    proc_pid::{name, pidpath, pidinfo}, 
    task_info::TaskInfo,
};
use libproc::processes;
use pnet::{datalink, util::MacAddr};




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
    
    let session_id = Arc::new(Mutex::new(0)); // Crea Arc<Mutex<u32>>

    if let MaybeTlsStream::Rustls(tls_stream) = maybe_tls_stream {
        let tls_session = tls_stream.get_ref().1;
        
        {
            let mut id = session_id.lock().unwrap();
            *id = generate_client_session_id(tls_session);
        }

        println!("Generated session_id: {}", *session_id.lock().unwrap());
    } else {
        return;
    }


    let (stdin_tx, stdin_rx) = futures_channel::mpsc::unbounded();
    tokio::spawn(network_scanner(stdin_tx, Arc::clone(&session_id)));

    let (write, read) = ws_stream.split();

    let stdin_to_ws = stdin_rx.map(Ok).forward(write);
    let ws_to_stdout = read.for_each(|message| async {
        match message {
            Ok(msg) => match msg {
                Message::Binary(bin) => match bincode::deserialize::<Header>(&bin) {
                    Ok(net_data) => println!("Received (Binary): {:?}", net_data),
                    Err(e) => eprintln!("Errore di deserializzazione binaria: {}", e),
                },
                _ => eprintln!("Tipo di messaggio non gestito"),
            },
            Err(e) => eprintln!("Errore nel messaggio: {}", e),
        }
    });

    pin_mut!(stdin_to_ws, ws_to_stdout);
    future::select(stdin_to_ws, ws_to_stdout).await;
}


async fn network_scanner(tx: futures_channel::mpsc::UnboundedSender<Message>, session_id: Arc<Mutex<u32>>) {
    get_processes(tx, Arc::clone(&session_id));
}


fn get_processes(tx: futures_channel::mpsc::UnboundedSender<Message>, session_id: Arc<Mutex<u32>>) {

    let mac_address: [u8; 6];
    match get_mac_address() {
        Some(mac) => mac_address = mac,
        None => return,
    }
    loop{}
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

                let process_payload = ProcessPayload {
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
                };           

                let session_id_value = {
                    let mut id = session_id.lock().unwrap();
                    *id += 1;
                    *id 
                };  

                let header = calculate_header(session_id_value, 1, 0, mac_address);
                let packet = build_packet(header, process_payload);

                let serialized = bincode::serialize(&packet).expect("Errore nella serializzazione");
                let msg = Message::Binary(serialized.into());

                if let Err(e) = tx.unbounded_send(msg.clone()) {
                    eprintln!("Errore nell'invio del messaggio WebSocket: {:?}", e);
                    return;  // Evita di continuare se il canale è chiuso
                }
            }

        }
        Err(err) => eprintln!("Error: {}", err),
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

