use app_state::AppState;
use router::{create_router_api};
use tokio::net::TcpListener;

pub mod app_state;
mod database;
mod middleware;
mod queries;
mod router;
mod routes;
pub mod utilities;

use axum::{
    extract::{
        ws::{self, WebSocketUpgrade},
        State,
    },
    http::Version,
    routing::any,
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use std::{net::SocketAddr, path::PathBuf};
use tokio::sync::broadcast;
use tower_http::services::ServeDir;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub async fn run(app_state: AppState) {
    let app = create_router_api(app_state);
    let address = TcpListener::bind("0.0.0.0:4000").await.unwrap();

    axum::serve(address, app.into_make_service()).await.unwrap();

}

pub async fn run_ws() {

    tracing_subscriber::registry()
            .with(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| format!("{}=debug", env!("CARGO_CRATE_NAME")).into()),
            )
            .with(tracing_subscriber::fmt::layer())
            .init();

        let assets_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets");

        // configure certificate and private key used by https
        let config = RustlsConfig::from_pem_file(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("certs")
                .join("cert.pem"),
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("certs")
                .join("key.pem"),
        )
        .await
        .unwrap();

        let app = Router::new()
        .fallback_service(ServeDir::new(assets_dir).append_index_html_on_directories(true))
        .route("/ws", any(ws_handler))
        .with_state(broadcast::channel::<String>(16).0);

        let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
        tracing::debug!("listening on {}", addr);

        let mut server = axum_server::bind_rustls(addr, config);

        // IMPORTANT: This is required to advertise our support for HTTP/2 websockets to the client.
        // If you use axum::serve, it is enabled by default.
        server.http_builder().http2().enable_connect_protocol();

        server.serve(app.into_make_service()).await.unwrap();
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    version: Version,
    State(sender): State<broadcast::Sender<String>>,
) -> axum::response::Response {
    tracing::debug!("accepted a WebSocket using {version:?}");
    let mut receiver = sender.subscribe();
    ws.on_upgrade(|mut ws| async move {
        loop {
            tokio::select! {
                // Since `ws` is a `Stream`, it is by nature cancel-safe.
                res = ws.recv() => {
                    match res {
                        Some(Ok(ws::Message::Text(s))) => {
                            let _ = sender.send(s.to_string());
                        }
                        Some(Ok(_)) => {}
                        Some(Err(e)) => tracing::debug!("client disconnected abruptly: {e}"),
                        None => break,
                    }
                }
                // Tokio guarantees that `broadcast::Receiver::recv` is cancel-safe.
                res = receiver.recv() => {
                    match res {
                        Ok(msg) => if let Err(e) = ws.send(ws::Message::Text(msg.into())).await {
                            tracing::debug!("client disconnected abruptly: {e}");
                        }
                        Err(_) => continue,
                    }
                }
            }
        }
    })
}