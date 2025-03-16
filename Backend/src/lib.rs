pub mod app_state;
mod database;
mod middleware;
mod queries;
mod router;
mod routes;
pub mod utilities;
pub mod ws;
pub mod conn;

use std::sync::Arc;

use app_state::{ApiAppState, KafkaAppState, WssAppState};
use router::{create_router_api, create_router_wss};
use serde::{Serialize, Deserialize};
use tokio::net::TcpListener;
use tracing::{error, info};
use futures_util::StreamExt;
use rdkafka::message::Message; 


pub async fn run_api(api_state: ApiAppState) {
    let app = create_router_api(api_state);
    let address = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(address, app.into_make_service()).await.unwrap();
}

pub async fn run_ws(wss_state: Arc<WssAppState>) {
    create_router_wss(wss_state).await;
}


pub async fn run_kafka(kafka_state: KafkaAppState){
    info!("🎧 Listening on Kafka...");
 
    while let Some(result) = kafka_state.consumer.stream().next().await {
        match result {
            Ok(msg) => {
                if let Some(payload) = msg.payload() {
                    match serde_json::from_slice::<AnomalyAlert>(payload) {
                        Ok(anomaly) => {
                            info!("🚨 Anomaly received! {:?}", anomaly);
                            
                        }
                        Err(e) => error!("❌ Deserialization error: {}", e),
                    }
                }
            }
            Err(e) => error!("❌ Kafka message error: {:?}", e),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct AnomalyAlert {
    device: String,
    timestamp: String,
    anomaly_score: f32,
    data_type: String,
}
