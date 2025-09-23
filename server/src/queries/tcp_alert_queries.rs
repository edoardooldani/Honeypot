use influxdb2::models::DataPoint;
use influxdb2::Client;
use chrono::Utc;
use futures::stream;
use common::types::TcpAlertPayload;

use super::format_mac_address;

/// Aggiunge un record al bucket `network`
pub async fn add_tcp_alert_data(
    influx_client: &Client,
    device_name: &str,
    alert_payload: &TcpAlertPayload
) -> Result<(), String> {
    let bucket_name = "tcp";  

    let point = DataPoint::builder("tcp_alerts")
        .tag("device", device_name)
        .field("mac_address", format_mac_address(&alert_payload.mac_address))
        .field("ip_address", alert_payload.ip_address.clone())
        .field("dest_port", alert_payload.dest_port as i64)
        .field("tcp_attack_type", alert_payload.tcp_attack_type as i64)
        .timestamp(Utc::now().timestamp_nanos_opt().unwrap_or_else(|| Utc::now().timestamp() * 1_000_000_000))
        .build()
        .map_err(|e| format!("Error creating data point: {:?}", e))?;

    influx_client.write(bucket_name, stream::iter(vec![point])).await
        .map_err(|e| format!("Failed to write to InfluxDB: {:?}", e))
        
}


