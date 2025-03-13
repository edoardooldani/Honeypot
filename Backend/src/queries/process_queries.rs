use influxdb2::models::DataPoint;
use influxdb2::Client;
use chrono::Utc;
use futures::stream;
use common::types::ProcessPayload;

pub async fn add_process_data(
    influx_client: &Client,
    device_name: &str,
    process_payload: &ProcessPayload
) -> Result<(), String> {
    let bucket_name = "process";  

    let point = DataPoint::builder("process_activity")
        .tag("device", device_name)
        .field("process_id", process_payload.process_id as i64)
        .field("process_name", process_payload.process_name.clone())
        .field("path", process_payload.path.clone())
        .field("virtual_size", process_payload.virtual_size as i64)
        .field("resident_size", process_payload.resident_size as i64)
        .field("syscalls_unix", process_payload.syscalls_unix as i64)
        .field("syscalls_mach", process_payload.syscalls_mach as i64)
        .field("faults", process_payload.faults as i64)
        .field("pageins", process_payload.pageins as i64)
        .field("cow_faults", process_payload.cow_faults as i64)
        .field("messages_sent", process_payload.messages_sent as i64)
        .field("messages_received", process_payload.messages_received as i64)
        .field("csw", process_payload.csw as i64)
        .field("threadnum", process_payload.threadnum as i64)
        .field("numrunning", process_payload.numrunning as i64)
        .field("priority", process_payload.priority as i64)
        .timestamp(Utc::now().timestamp_nanos_opt().unwrap_or_else(|| Utc::now().timestamp() * 1_000_000_000))
        .build()
        .map_err(|e| format!("❌ Errore nella creazione del DataPoint: {:?}", e))?;

    influx_client.write(bucket_name, stream::iter(vec![point])).await
        .map_err(|e| format!("❌ Errore nella scrittura su InfluxDB: {:?}", e))
}