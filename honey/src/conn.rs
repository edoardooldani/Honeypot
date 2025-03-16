use tokio_tungstenite::{connect_async_tls_with_config, Connector};
use std::sync::Arc;
use std::env;
use std::path::PathBuf;
use common::tls::rustls_client_config;
use crate::ws::handle_websocket;


pub async fn connect_websocket() {
    let url = env::args()
        .nth(1)
        .unwrap_or_else(|| panic!("this program requires at least one argument"));

    let config = rustls_client_config(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("certs")
            .join("client-key.pem"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("certs")
            .join("client-cert.pem"),
    );

    let connector = Connector::Rustls(Arc::new(config));

    let (ws_stream, _) = connect_async_tls_with_config(&url, None, false, Some(connector))
        .await
        .expect("Failed to connect");

    println!("✅ WebSocket handshake completed");

    handle_websocket(ws_stream).await;

}



