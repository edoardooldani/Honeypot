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

use app_state::{AppState, WssAppState};
use influxdb2::{api::buckets::ListBucketsRequest, models::Buckets, Client, RequestError};
use router::{create_router_api, create_router_wss};
use tokio::net::TcpListener;
use tracing::{error, info};


pub async fn run(app_state: AppState) {
    let app = create_router_api(app_state);
    let address = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(address, app.into_make_service()).await.unwrap();
}

pub async fn run_ws(wss_state: Arc<WssAppState>) {

    match ensure_buckets_exists(&wss_state.influx_client).await {
        Ok(_) => info!("✅ Buckets exist and ready!"),
        Err(e) => {
            error!("❌ Failed to verify buckets: {e}!");
            return;
        }
    }
    create_router_wss(wss_state).await;
}


async fn ensure_buckets_exists(client: &Client) -> Result<(), String> {
    let request = ListBucketsRequest {
        name: None,
        after: None,
        id: None,
        limit: Some(5),
        offset: None,
        org: None,
        org_id: None,
    };

    let buckets_response: Result<Buckets, RequestError> = client.list_buckets(Some(request)).await;

    match buckets_response {
        Ok(buckets) => {
            let bucket_names: Vec<String> = buckets.buckets.iter().map(|b| b.name.clone()).collect();
            let required_buckets = vec!["network", "process"];

            let missing_buckets: Vec<&str> = required_buckets
                .into_iter()
                .filter(|bucket| !bucket_names.contains(&bucket.to_string()))
                .collect();

            if missing_buckets.is_empty() {
                Ok(())
            } else {
                let missing_buckets_str = missing_buckets.join(", "); // Convertiamo il Vec<&str> in una stringa
                error!("🛑 Missing bucket(s): {}", missing_buckets_str);
                Err(format!("🛑 Missing bucket(s): {}", missing_buckets_str))
            }
        }
        Err(e) => {
            error!("Error retrieving buckets: {:?}", e);
            Err(format!("Error retrieving buckets: {:?}", e))
        }
    }
}
