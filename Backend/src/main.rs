use honeypot::{app_state::{ApiAppState, WssAppState}, conn::init_connections, run_api, run_ws, utilities::token_wrapper::TokenWrapper};
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

    let api_state = ApiAppState {
        db: connections.db,
        jwt_secret: TokenWrapper(std::env::var("JWT_SECRET").expect("Missing JWT_SECRET")),
    };

    let conn = Arc::new(Mutex::new(HashMap::new()));

    let wss_state = Arc::new(WssAppState {
        connections: conn.clone(),
        influx_client: connections.influx,
    });

    rustls::crypto::ring::default_provider().install_default().expect("Failed to install rustls crypto provider");
    tracing_subscriber::fmt()
    .with_env_filter(EnvFilter::new("info"))
    .with_target(true)
    .with_line_number(true)
    .init();

    tokio::join!(
        run_api(api_state),
        run_ws(wss_state),
    );
}
