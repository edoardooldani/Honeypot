mod auth;
use auth::{register, login};
use dotenv::dotenv;
use axum::{
  routing::{get, post},
  Router,
};
use std::net::SocketAddr;
mod conn;
mod models;
mod schema;

#[macro_use]
extern crate diesel; 


pub fn load_env() {
    dotenv().ok();
  }

#[tokio::main]
async fn main() {
    load_env();

    let app = Router::new()
    .route("/", get(root))
    .route("/register", post(register))
    .route("/login", post(login));

    let addr: SocketAddr = "127.0.0.1:3000".parse().unwrap();

    println!("Server in ascolto su {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}


async fn root() -> &'static str {
  "Root Honeypot by Astroboyz"
}