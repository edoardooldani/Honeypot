use dotenvy::dotenv;
use honeypot::{app_state::{AppState, WssAppState}, run, run_ws, utilities::token_wrapper::TokenWrapper};
use sea_orm::Database;
use tracing_subscriber::EnvFilter;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::Mutex;
use influxdb2::Client;



#[tokio::main]
async fn main() {
    dotenv().ok();
    let database_url = std::env::var("DATABASE_URL")
        .expect("Missing environment variable DATABASE_URL")
        .to_owned();
    let jwt_secret = std::env::var("JWT_SECRET")
        .expect("Missing environment variable JWT_SECRET")
        .to_owned();
    let db = match Database::connect(database_url).await {
        Ok(db) => db,
        Err(error) => {
            eprintln!("Error connecting to the database: {:?}", error);
            panic!();
        }
    };

    let influx_url = std::env::var("INFLUX_URL")
        .expect("Missing environment variable DATABASE_URL")
        .to_owned();
    let influx_org = std::env::var("INFLUX_ORG")
        .expect("Missing environment variable JWT_SECRET")
        .to_owned();
    let influx_token = std::env::var("INFLUX_TOKEN")
        .expect("Missing environment variable JWT_SECRET")
        .to_owned();

    let influx_client = Client::new(influx_url, influx_org, influx_token);


    let app_state = AppState {
        db,
        jwt_secret: TokenWrapper(jwt_secret),
    };

    let wss_state = Arc::new(WssAppState {
        connections: Arc::new(Mutex::new(HashMap::new())),
        influx_client
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
