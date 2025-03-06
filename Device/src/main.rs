use futures_util::{StreamExt, future, pin_mut};
use std::{
    env,
    sync::Arc,
    path::PathBuf
};

use common::{packet::{build_packet, calculate_header}, tls::rustls_client_config, types::{Header, Packet, Payload, ProcessPayload}};
use tokio_tungstenite::{connect_async_tls_with_config, tungstenite::protocol::Message, Connector};

// Port scanner
use libproc::{libproc::proc_pid::{name, pidpath}};
use libproc::libproc::task_info::TaskInfo;
use libproc::libproc::file_info::{ListFDs, ProcFDType};
use libproc::proc_pid::pidinfo;
use libproc::processes;



#[tokio::main]
async fn main() {
    let url = env::args()
        .nth(1)
        .unwrap_or_else(|| panic!("this program requires at least one argument"));

    let (stdin_tx, stdin_rx) = futures_channel::mpsc::unbounded();
    tokio::spawn(network_scanner(stdin_tx));

    let config = rustls_client_config(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("certs")
            .join("client-key-decrypted.pem"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("certs")
            .join("client-cert.pem"),
    );

    let connector = Connector::Rustls(Arc::new(config));

    let (ws_stream, _) = connect_async_tls_with_config(&url, None, false, Some(connector))
        .await
        .expect("Failed to connect");
    println!("WebSocket handshake has been successfully completed");

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


async fn network_scanner(tx: futures_channel::mpsc::UnboundedSender<Message>){
    /* 
    let payload = Payload {
        number_of_devices: 3
    };
    let header = calculate_header(1, 0, 0, [0x00, 0x14, 0x22, 0x01, 0x23, 0x45]).await;
    let packet = build_packet(header, payload).await;

    let serialized = bincode::serialize(&packet).expect("Errore nella serializzazione");
    let msg = Message::Binary(serialized.into());
    */

    //tx.unbounded_send(msg.clone()).unwrap();

    //loop {
    let mut session_id: u32 = 0;
    get_available_port(tx, &mut session_id);

    //}
}




fn get_available_port(tx: futures_channel::mpsc::UnboundedSender<Message>, session_id: &mut u32) {

    match processes::pids_by_type(processes::ProcFilter::All) {
        Ok(pids) => {
            println!("There are currently {} processes active", pids.len());
            
            for pid in pids {
                
                let process_name = match name(pid as i32) {
                    Ok(name) => name,
                    Err(_) => String::from("Unknown"), // Default se errore
                };
                
                let task_info = match pidinfo::<TaskInfo>(pid as i32, 0) {
                    Ok(info) => info,
                    Err(_) => continue, // Skip se errore
                };

                let process_path = match pidpath(pid as i32) {
                    Ok(path) => path,
                    Err(_) => String::from("Unknown"), // Default se errore
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

                let header = calculate_header(*session_id, 1, 0, [0x00, 0x14, 0x22, 0x01, 0x23, 0x45]);
                let packet = build_packet(header, process_payload);

                let serialized = bincode::serialize(&packet).expect("Errore nella serializzazione");
                let msg = Message::Binary(serialized.into());

                tx.unbounded_send(msg.clone()).unwrap();

            }

        }
        Err(err) => eprintln!("Error: {}", err),
    }
}