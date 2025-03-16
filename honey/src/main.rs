use tracing_subscriber::EnvFilter;
use honey::conn::connect_websocket;

#[tokio::main]
async fn main() {
    
    tracing_subscriber::fmt()
    .with_env_filter(EnvFilter::new("info"))
    .with_target(true)
    .with_line_number(true)
    .init();

    connect_websocket().await;
}

