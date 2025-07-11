use influxdb2::models::DataPoint;
use influxdb2::Client;
use chrono::Utc;
use futures::stream;
use common::types::ArpAlertPayload;

/// Aggiunge un record al bucket `network`
pub async fn add_arp_alert_data(
    influx_client: &Client,
    device_name: &str,
    alert_payload: &ArpAlertPayload
) -> Result<(), String> {
    let bucket_name = "arp";  

    let mac_addresses_str = alert_payload.mac_addresses
        .iter()
        .map(|mac| mac.iter().map(|b| format!("{:02X}", b)).collect::<Vec<String>>().join(":"))
        .collect::<Vec<String>>()
        .join(",");

    let point = DataPoint::builder("arp_alerts")
        .tag("device", device_name)
        .field("mac_addresses", mac_addresses_str)
        .field("ip_address", alert_payload.ip_address.clone())
        .field("arp_attack_type", alert_payload.arp_attack_type as i64)
        .timestamp(Utc::now().timestamp_nanos_opt().unwrap_or_else(|| Utc::now().timestamp() * 1_000_000_000))
        .build()
        .map_err(|e| format!("Error creating data point: {:?}", e))?;

    influx_client.write(bucket_name, stream::iter(vec![point])).await
        .map_err(|e| format!("Failed to write to InfluxDB: {:?}", e))

        
}
