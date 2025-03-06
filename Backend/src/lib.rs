pub mod app_state;
mod database;
mod middleware;
mod queries;
mod router;
mod routes;
pub mod utilities;
pub mod ws;


use app_state::AppState;
use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::IntoResponse,
};

use router::{create_router_api, create_router_wss};
use tokio::net::TcpListener;
use bincode;

use common::types::Packet;


pub async fn run(app_state: AppState) {
    let app = create_router_api(app_state);
    let address = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(address, app.into_make_service()).await.unwrap();
}

pub async fn run_ws() {
    create_router_wss().await;
}

