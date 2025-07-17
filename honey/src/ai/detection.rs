use tract_onnx::prelude::*;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::Packet;
use crate::ai::features::{flow::get_packet_flow_and_update, tensor::normalize_tensor, packet_features::PacketFeatures};
use crate::ai::model::run_inference;

pub async fn detect_anomaly<'a>(
    model: Arc<SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>>,
    ethernet_packet: EthernetPacket<'a>
) -> bool {
    let model = Arc::clone(&model);

    let raw_bytes = ethernet_packet.packet().to_vec();

    //tokio::spawn(async move {
        if let Some(packet) = EthernetPacket::owned(raw_bytes) {
            if let Some(packet_features) = get_packet_flow_and_update(&packet).await {

                let raw_tensor = packet_features.to_tensor();
                let feature_tensors = normalize_tensor(raw_tensor, "src/ai/models/scaler_params.json")
                    .expect("Errore nella normalizzazione");

                //println!("\nFeature tensor after norm: {:?}", feature_tensors);
                
                match run_inference(&model, feature_tensors) {
                    Ok(result) => {
                        println!("✅ Inference result: {:?}", result);
                        if result > 1.0 {

                            if let Err(e) = append_packet_to_csv("mdns_anomalies.csv", &packet_features) {
                                eprintln!("❌ Errore nel salvataggio CSV: {}", e);
                            }
                            println!("Packet features: {:?}", packet_features);
                            return true;
                        } 
                    }
                    Err(e) => {
                        eprintln!("❌ Errore nell'inferenza: {}", e);
                    }
                }
            }
        }
    //});

    false
}


use std::fs::OpenOptions;
use std::io::Write;

pub fn append_packet_to_csv(path: &str, pf: &PacketFeatures) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)?;

    // Se il file è vuoto, scrivi header (puoi fare meglio controllando il file una volta)
    // writeln!(file, "src_port,dst_port,flow_duration,...")?;

    writeln!(file, "{}", pf.to_csv_row())?;
    Ok(())
}