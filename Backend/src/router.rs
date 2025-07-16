use crate::{
    app_state::{ApiAppState, WssAppState}, 
    middleware::require_authentication::require_authentication, 
    routes::{devices::create_device::create_device, users::{create_user::create_user, login::login, logout::logout}}, 
    ws::ws_handler

};
use axum::{
    middleware,
    routing::{get, post},
    Router,
    extract::Request
};
use rustls::pki_types::CertificateDer;

// WSS
use std::{path::PathBuf, sync::Arc};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tower_service::Service;
use tracing::{error, info, warn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use futures_util::pin_mut;
use hyper::body::Incoming;
use x509_parser::prelude::*;

use common::tls::{rustls_server_config, generate_server_session_id};


pub fn create_router_api(api_state: ApiAppState) -> Router {
    Router::new()
        .route("/api/auth/logout", post(logout))
        .route("/api/device/register", post(create_device))
        .route_layer(middleware::from_fn_with_state(
            api_state.clone(),
            require_authentication,
        ))
        .route("/api/auth/signup", post(create_user))
        .route("/api/auth/signin", post(login))
        .with_state(api_state)
}


pub async fn create_router_wss(wss_state: Arc<WssAppState>) {

    let rustls_config = rustls_server_config(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("certs")
            .join("server-key.pem"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("certs")
            .join("server-cert.pem"),
    );

    let tls_acceptor = TlsAcceptor::from(rustls_config);
    let bind = "0.0.0.0:3001";
    let tcp_listener = TcpListener::bind(bind).await.unwrap();
    info!(
        "HTTPS server api: https://localhost:3000 or websocket: wss://localhost:3001/ws"
    );

    let app = Router::new()
        .route("/ws", get(ws_handler))
        .with_state(Arc::clone(&wss_state));


    pin_mut!(tcp_listener);
    loop {
        let tower_service = app.clone();
        let tls_acceptor = tls_acceptor.clone();
        let wss_state = Arc::clone(&wss_state);

        let (cnx, addr) = tcp_listener.accept().await.unwrap();

        let tls_acceptor = tls_acceptor.clone();

        tokio::spawn(async move {

                //handle_ws_connection(stream, addr).await;
            let Ok(stream) = tls_acceptor.accept(cnx).await else {
                error!("errore durante l'handshake TLS dalla connessione {}", addr);
                return;
            };    

            let session = stream.get_ref().1;
            let device_name = session.peer_certificates()
                .and_then(|certs| certs.first())
                .and_then(|cert| extract_common_name(cert))
                .unwrap_or_else(|| addr.to_string());
            

            {
                let session_id = generate_server_session_id(session);

                let mut connections = wss_state.connections.lock().await;

                if connections.contains_key(&device_name) {
                    warn!("❌ Device already connected: {}!", device_name);
                    // Must notify close connection but couldn't do it
                    return
                }

                connections.insert(device_name.clone(), session_id);
                info!("✅ Connected with: {} - Session ID: {:?}", device_name, session_id);

            }

            let device_name_clone = device_name.clone();
            let stream = TokioIo::new(stream);
            let hyper_service = hyper::service::service_fn(move |mut request: Request<Incoming>| {
                request.extensions_mut().insert(device_name_clone.clone());
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


fn extract_common_name(cert: &CertificateDer) -> Option<String> {
    let (_, parsed) = X509Certificate::from_der(cert.as_ref()).ok()?;
    let subject = parsed.subject();
    for attr in subject.iter_common_name() {
        if let Ok(cn) = attr.as_str() {
            return Some(cn.to_string());
        }
    }
    None
}

