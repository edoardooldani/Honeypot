pub mod app_state;
mod database;
mod middleware;
mod queries;
mod router;
mod routes;
pub mod utilities;


use app_state::AppState;
use axum::{
    Router,
    extract::{
        Request,
        ws::{Message, WebSocket, WebSocketUpgrade}
    },
    response::IntoResponse,
    routing::get,
};
use futures_util::pin_mut;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use router::create_router_api;
use std::{
    fs::File, io::BufReader, path::{Path, PathBuf}, sync::Arc
};
use tokio::net::TcpListener;
use tokio_rustls::{
    TlsAcceptor,
    rustls::ServerConfig,
    rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject, CertificateRevocationListDer},
};
use tower_service::Service;
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use rustls::{server::WebPkiClientVerifier, RootCertStore};
use rustls_pemfile::crls;
use bincode;

use common::{Packet, verify_checksum};


pub async fn run(app_state: AppState) {
    let app = create_router_api(app_state);
    let address = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(address, app.into_make_service()).await.unwrap();
}

pub async fn run_ws() {

    rustls::crypto::ring::default_provider().install_default().expect("Failed to install rustls crypto provider");

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("{}=debug", env!("CARGO_CRATE_NAME")).into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    

    let rustls_config = rustls_server_config(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("certs")
            .join("server-key.pem"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("certs")
            .join("server-cert.pem"),
    );

    let tls_acceptor = TlsAcceptor::from(rustls_config);
    let bind = "[::1]:3001";
    let tcp_listener = TcpListener::bind(bind).await.unwrap();
    info!(
        "HTTPS server api: https://localhost:3000 or websocket: wss://localhost:3001/ws"
    );

    // Aggiungiamo una route per il websocket
    let app = Router::new()
        .route("/ws", get(ws_handler));

    pin_mut!(tcp_listener);
    loop {
        let tower_service = app.clone();
        let tls_acceptor = tls_acceptor.clone();

        let (cnx, addr) = tcp_listener.accept().await.unwrap();

        tokio::spawn(async move {
            let Ok(stream) = tls_acceptor.accept(cnx).await else {
                error!("errore durante l'handshake TLS dalla connessione {}", addr);
                return;
            };    
            
            let stream = TokioIo::new(stream);
            let hyper_service = hyper::service::service_fn(move |request: Request<Incoming>| {
                tower_service.clone().call(request)
            });
            
            let ret = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(stream, hyper_service)
                .await;

            if let Err(err) = ret {
                warn!("errore servendo la connessione da {}: {}", addr, err);
            }
        });
    }
}


// Handler per il WebSocket: esegue l'upgrade della connessione
async fn ws_handler(ws: WebSocketUpgrade,
) -> impl IntoResponse {
    ws.on_upgrade(handle_websocket)
}

// Funzione che gestisce il canale WebSocket una volta effettuato l'upgrade
async fn handle_websocket(mut socket: WebSocket) {
    // In questo esempio si fa un semplice echo dei messaggi di testo ricevuti
    while let Some(result) = socket.recv().await {
        match result {
            Ok(Message::Text(text)) => {
                if socket
                    .send(Message::Text(format!("echo: {}", text).into()))
                    .await
                    .is_err()
                {
                    // Se il client ha chiuso la connessione o c'è un errore, esci dal ciclo
                    break;
                }
            }
            Ok(Message::Binary(bin)) =>{
                match bincode::deserialize::<Packet>(&bin) {
                    Ok(packet) => {
                        if verify_checksum(packet.clone()).await{
                            println!("Checksum verified!: {:?}", packet);
                        }

                    },
                    Err(e) => eprintln!("Deserialization error: {}", e),
                }
                
            }
            Ok(Message::Close(_)) => break,
            _ => {}
        }
    }
}

// Configurazione TLS per il server
fn rustls_server_config(key: impl AsRef<Path>, cert: impl AsRef<Path>) -> Arc<ServerConfig> {
    
    let certs = CertificateDer::pem_file_iter(cert)
        .unwrap()
        .map(|cert| cert.unwrap())
        .collect();

    println!("{:?}", PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("certs").join("server-key.pem"));
    let key = PrivateKeyDer::from_pem_file(key).unwrap();

    let mut client_auth_roots = RootCertStore::empty();
    let root_ca_file = File::open("CA/CA.pem").expect("Impossibile aprire la root CA");
    let mut reader = BufReader::new(root_ca_file);
    for cert in rustls_pemfile::certs(&mut reader).expect("Errore nella lettura della root CA") {
        client_auth_roots.add(CertificateDer::from(cert)).unwrap();
    }    

    let crls = load_crls();
    let client_auth_verifier = WebPkiClientVerifier::builder(client_auth_roots.into())
                    .with_crls(crls)
                    .build()
                    .unwrap();

    let mut config = ServerConfig::builder()
        .with_client_cert_verifier(client_auth_verifier)
        .with_single_cert(certs, key)
        .expect("certificato/chiave non validi");

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Arc::new(config)
}


fn load_crls() -> Vec<CertificateRevocationListDer<'static>> {
    let crl_file = File::open("CA/CA.crl").expect("❌ Impossibile aprire la CRL");
    let mut reader = BufReader::new(crl_file);

    crls(&mut reader)
        .expect("❌ Errore nella lettura della CRL")
        .into_iter()
        .map(CertificateRevocationListDer::from)
        .collect()
}