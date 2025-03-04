use futures_util::{StreamExt, future, pin_mut};
use rustls::{pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer}, ClientConfig, RootCertStore};
use serde::{Deserialize, Serialize};
use std::{
    env,
    fs::File,
    io::BufReader,
    os::unix::raw::time_t,
    sync::Arc,
};
use tokio_tungstenite::{Connector, connect_async_tls_with_config, tungstenite::protocol::Message};
use rustls_pemfile::{pkcs8_private_keys, rsa_private_keys};  // Per leggere PEM


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

    // CERT

    let cert_file = File::open("certs/client-cert.pem").unwrap();
    let mut cert_reader = BufReader::new(cert_file);

    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_reader_iter(cert_reader)
            .filter_map(Result::ok)
            .collect();

    let mut root_store = RootCertStore::empty();
    let root_ca_file = File::open("certs/CA.pem").expect("❌ Impossibile aprire la root CA");
    let mut reader = BufReader::new(root_ca_file);

    for cert in rustls_pemfile::certs(&mut reader).expect("❌ Errore nella lettura della root CA") {
        root_store.add(CertificateDer::from(cert)).unwrap();
    }


    // KEY

    let key_file = File::open("certs/client-key-decrypted.pem").expect("Errore nell'aprire la chiave privata");
    let mut key_reader = BufReader::new(key_file);
    
    let keys = pkcs8_private_keys(&mut key_reader)
        .expect("Errore nella lettura della chiave PKCS#8");

    let private_key = if let Some(key) = keys.first() {
        PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.clone()))
    } else {
        // Se non trova PKCS#8, prova con RSA (PKCS#1)
        let mut key_reader = BufReader::new(File::open("certs/client-key-decrypted.pem").unwrap());
        let rsa_keys = rsa_private_keys(&mut key_reader)
            .expect("Errore nella lettura della chiave RSA");

        PrivateKeyDer::from(PrivatePkcs1KeyDer::from(
            rsa_keys.first().expect("❌ Nessuna chiave privata trovata!").clone(),
        ))
    };

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, private_key)
        .unwrap();

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
