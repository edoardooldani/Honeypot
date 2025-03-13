use dotenvy::dotenv;
use sea_orm::{Database, DatabaseConnection};
use influxdb2::Client as InfluxClient;
use rdkafka::config::ClientConfig;
use rdkafka::producer::FutureProducer;
use std::env;

/// Struttura per contenere tutte le connessioni
pub struct Connections {
    pub db: DatabaseConnection,
    pub influx: InfluxClient,
    pub kafka_producer: FutureProducer,
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

    // Kafka
    let kafka_brokers = env::var("KAFKA_BROKERS").map_err(|_| "Missing KAFKA_BROKERS".to_string())?;
    let kafka_producer: FutureProducer = ClientConfig::new()
        .set("bootstrap.servers", &kafka_brokers)
        .set("message.timeout.ms", "5000")
        .create()
        .map_err(|e| format!("Error creating Kafka producer: {:?}", e))?;


    Ok(Connections {
        db,
        influx,
        kafka_producer,
    })
}