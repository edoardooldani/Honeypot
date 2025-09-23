use influxdb2::models::DataPoint;
use influxdb2::Client;
use chrono::Utc;
use futures::stream;
use common::types::NetworkPayload;

/// Aggiunge un record al bucket `network`
pub async fn add_network_data(
    influx_client: &Client,
    device_name: &str,
    network_payload: &NetworkPayload
) -> Result<(), String> {
    let bucket_name = "network";  

    let point = DataPoint::builder("network_connections")
        .tag("device", device_name)
        .field("protocol", network_payload.protocol.clone())
        .field("src_ip", network_payload.src_ip.clone())
        .field("src_port", network_payload.src_port as i64)
        .field("dest_ip", network_payload.dest_ip.clone())
        .field("dest_port", network_payload.dest_port as i64)
        .timestamp(Utc::now().timestamp_nanos_opt().unwrap_or_else(|| Utc::now().timestamp() * 1_000_000_000))
        .build()
        .map_err(|e| format!("Error creating data point: {:?}", e))?;

    influx_client.write(bucket_name, stream::iter(vec![point])).await
        .map_err(|e| format!("Failed to write to InfluxDB: {:?}", e))
}
