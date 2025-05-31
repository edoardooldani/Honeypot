use dotenvy::dotenv;
use rdkafka::{consumer::{Consumer, StreamConsumer}, producer::FutureProducer, ClientConfig};
use sea_orm::{Database, DatabaseConnection};
use tracing::{error, info};
use std::env;
use influxdb2::{api::buckets::ListBucketsRequest, models::Buckets, Client as InfluxClient, RequestError};


/// Struttura per contenere tutte le connessioni
pub struct Connections {
    pub db: DatabaseConnection,
    pub influx: InfluxClient,
}

/// Funzione per inizializzare tutte le connessioni
pub async fn init_connections() -> Result<Connections, String> {
    dotenv().ok();

    // MySQL
    let database_url = env::var("DATABASE_URL").map_err(|_| "Missing DATABASE_URL".to_string())?;
    let db = Database::connect(database_url)
        .await
        .map_err(|e| format!("Error connecting to MySQL: {:?}", e))?;

    // InfluxDB
    let influx_url = env::var("INFLUX_URL").map_err(|_| "Missing INFLUX_URL".to_string())?;
    let influx_org = env::var("INFLUX_ORG").map_err(|_| "Missing INFLUX_ORG".to_string())?;
    let influx_token = env::var("INFLUX_TOKEN").map_err(|_| "Missing INFLUX_TOKEN".to_string())?;

    let influx = InfluxClient::new(influx_url, influx_org, influx_token);

    match ensure_buckets_exists(&influx).await {
        Ok(_) => info!("✅ Buckets exist and ready!"),
        Err(e) => {
            error!("❌ Failed to verify buckets: {e}!");
        }
    }

    
    Ok(Connections {
        db,
        influx,
    })
}




async fn ensure_buckets_exists(client: &InfluxClient) -> Result<(), String> {
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
            let required_buckets = vec!["network", "process", "arp", "tcp"];

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
