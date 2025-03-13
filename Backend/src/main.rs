use honeypot::{app_state::{AppState, WssAppState}, conn::init_connections, run, run_ws, utilities::token_wrapper::TokenWrapper};
use tracing_subscriber::EnvFilter;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;

#[tokio::main]
async fn main() {

    let connections = match init_connections().await {
        Ok(conn) => conn,
        Err(e) => {
            eprintln!("❌ Errore nella connessione: {}", e);
            panic!();
        }
    };

    let app_state = AppState {
        db: connections.db,
        jwt_secret: TokenWrapper(std::env::var("JWT_SECRET").expect("Missing JWT_SECRET")),
    };

    let wss_state = Arc::new(WssAppState {
        connections: Arc::new(Mutex::new(HashMap::new())),
        influx_client: connections.influx,
        kafka: connections.kafka_producer
    });

    rustls::crypto::ring::default_provider().install_default().expect("Failed to install rustls crypto provider");
    tracing_subscriber::fmt()
    .with_env_filter(EnvFilter::new("info")) // Configura il logging via variabile d'ambiente
    .with_target(true) // Mostra il modulo di provenienza
    .with_line_number(true) // Mostra il numero di riga
    .init();

    tokio::join!(
        run(app_state),
        run_ws(wss_state),
    );
}
