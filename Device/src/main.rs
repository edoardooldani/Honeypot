use futures_util::{StreamExt, future, pin_mut};
use rustls::{ClientConfig, RootCertStore, pki_types::CertificateDer};
use serde::{Deserialize, Serialize};
use std::{
    env,
    fs::File,
    io::{BufReader, Read},
    os::unix::raw::time_t,
    sync::Arc,
};
use tokio_tungstenite::{Connector, connect_async_tls_with_config, tungstenite::protocol::Message};

#[derive(Serialize, Deserialize, Debug)]
struct NetData {
    id: u32,
    data: time_t,
}

#[tokio::main]
async fn main() {
    let url = env::args()
        .nth(1)
        .unwrap_or_else(|| panic!("this program requires at least one argument"));

    let (stdin_tx, stdin_rx) = futures_channel::mpsc::unbounded();
    tokio::spawn(read_stdin(stdin_tx));

    let cert_file = File::open("certs/localhost.crt.der").unwrap();
    let mut cert_reader = BufReader::new(cert_file);

    let mut cert_data = Vec::new();
    cert_reader.read_to_end(&mut cert_data).unwrap();

    let cert = CertificateDer::from(cert_data);

    let mut root_cert_store = RootCertStore::empty();
    root_cert_store.add(cert).unwrap();

    let config = ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();

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
                Message::Binary(bin) => match bincode::deserialize::<NetData>(&bin) {
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

async fn read_stdin(tx: futures_channel::mpsc::UnboundedSender<Message>) {
    let net_data_instance = NetData {
        id: 42,
        data: 123456789,
    };
    let serialized = bincode::serialize(&net_data_instance).expect("Errore nella serializzazione");
    let msg = Message::Binary(serialized.into());
    loop {
        tx.unbounded_send(msg.clone()).unwrap();
    }
}
