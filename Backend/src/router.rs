use crate::{
    ws::ws_handler,
    app_state::AppState,
    middleware::require_authentication::require_authentication,
    routes::users::{create_user::create_user, login::login, logout::logout},
    routes::devices::create_device::create_device,

};
use axum::{
    middleware,
    routing::{get, post},
    Router,
    extract::Request
};

// WSS
use std::path::PathBuf;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower_service::Service;
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use hyper_util::rt::{TokioExecutor, TokioIo};
use futures_util::pin_mut;
use hyper::body::Incoming;

use common::tls::rustls_server_config;


pub fn create_router_api(app_state: AppState) -> Router {
    Router::new()
        .route("/api/auth/logout", post(logout))
        .route("/api/device/register", post(create_device))
        .route_layer(middleware::from_fn_with_state(
            app_state.clone(),
            require_authentication,
        ))
        .route("/api/auth/signup", post(create_user))
        .route("/api/auth/signin", post(login))
        .with_state(app_state)
}


pub async fn create_router_wss() {

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