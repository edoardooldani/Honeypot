use futures_util::{StreamExt, future, pin_mut};
use std::{
    env,
    sync::Arc,
    path::PathBuf
};

use common::{types::{Header, Payload}, packet::{build_packet, calculate_header}, certs::rustls_client_config};
use tokio_tungstenite::{connect_async_tls_with_config, tungstenite::protocol::Message, Connector};


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

    let payload = Payload {
        number_of_devices: 3
    };
    let header = calculate_header(1, 0, 0, [0x00, 0x14, 0x22, 0x01, 0x23, 0x45]).await;
    let packet = build_packet(header, payload).await;

    let serialized = bincode::serialize(&packet).expect("Errore nella serializzazione");
    let msg = Message::Binary(serialized.into());

    tx.unbounded_send(msg.clone()).unwrap();
}


