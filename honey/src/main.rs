pub mod graph;
pub mod honeypot;
pub mod interfaces;
pub mod ai;
use tokio::sync::Mutex;
use tracing::info;
use tracing_subscriber::EnvFilter;
use std::env;
use tokio_tungstenite::{connect_async_tls_with_config, Connector};
use std::sync::Arc;
use std::path::PathBuf;
use common::tls::rustls_client_config;
use crate::ai::model::{load_autoencoder_model, load_classifier_model};
use crate::graph::types::NetworkGraph;
use crate::interfaces::receiver::scan_datalink;
use crate::interfaces::ws::handle_websocket;

#[tokio::main]
async fn main() {
    
    tracing_subscriber::fmt()
    .with_env_filter(EnvFilter::new("info"))
    .with_target(true)
    .with_line_number(true)
    .init();

    //connect_websocket().await;
    let graph = Arc::new(Mutex::new(NetworkGraph::default()));
    let graph_clone = Arc::clone(&graph);


    let autoencoder_model = load_autoencoder_model();
    let autoencoder = Arc::new(autoencoder_model);

    let classifier_model = load_classifier_model();
    let classifier = Arc::new(classifier_model);
    scan_datalink(graph_clone, autoencoder.clone(), classifier.clone()).await;
}


async fn connect_websocket() {
    let url = env::args()
        .nth(1)
        .unwrap_or_else(|| panic!("this program requires at least one argument"));

    let config = rustls_client_config(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("certs")
            .join("localhost-key.pem"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("certs")
            .join("localhost-cert.pem"),
    );
    
    let connector = Connector::Rustls(Arc::new(config));
    info!("🔗 Connecting to WebSocket at: {}", url);
    let (ws_stream, _) = connect_async_tls_with_config(&url, None, false, Some(connector))
        .await
        .expect("Failed to connect");

    info!("✅ WebSocket handshake completed");

    handle_websocket(ws_stream).await;

}



