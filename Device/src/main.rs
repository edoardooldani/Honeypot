use futures_util::{StreamExt, future, pin_mut};
use rustls::{pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer}, ClientConfig, RootCertStore};
use std::{
    env,
    fs::File,
    io::BufReader,
    sync::Arc,
};
use common::{Header, Payload, build_packet, calculate_header};

use tokio_tungstenite::{connect_async_tls_with_config, tungstenite::protocol::Message, Connector};
use rustls_pemfile::{pkcs8_private_keys, rsa_private_keys};



#[tokio::main]
async fn main() {
    let url = env::args()
        .nth(1)
        .unwrap_or_else(|| panic!("this program requires at least one argument"));

    let (stdin_tx, stdin_rx) = futures_channel::mpsc::unbounded();
    tokio::spawn(network_scanner(stdin_tx));

    let certs = load_certs().await;
    let root_ca = load_root_ca().await;
    let private_key = load_key().await;

    let config = ClientConfig::builder()
        .with_root_certificates(root_ca)
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



async fn load_certs() -> Vec<CertificateDer<'static>>{
    let cert_file = File::open("certs/client-cert.pem").unwrap();
    let cert_reader = BufReader::new(cert_file);

    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_reader_iter(cert_reader)
            .filter_map(Result::ok)
            .collect();

    certs
}

async fn load_root_ca() -> RootCertStore{

    let mut root_store = RootCertStore::empty();
    let root_ca_file = File::open("certs/CA.pem").expect("❌ Impossibile aprire la root CA");
    let mut reader = BufReader::new(root_ca_file);

    for cert in rustls_pemfile::certs(&mut reader).expect("❌ Errore nella lettura della root CA") {
        root_store.add(CertificateDer::from(cert)).unwrap();
    }

    root_store
}


async fn load_key() -> PrivateKeyDer<'static>{

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

    private_key
}