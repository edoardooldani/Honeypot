use tract_onnx::prelude::*;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::Packet;
use crate::ai::features::flow::get_packet_flow_and_update;
use crate::ai::model::run_inference;

pub fn detect_anomaly<'a>(
    model: Arc<SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>>,
    ethernet_packet: EthernetPacket<'a>
) -> bool {
    let model = Arc::clone(&model);

    let raw_bytes = ethernet_packet.packet().to_vec();

    tokio::spawn(async move {
        if let Some(packet) = EthernetPacket::owned(raw_bytes) {
            if let Some(packet_features) = get_packet_flow_and_update(&packet).await {
                let feature_tensors = packet_features.to_tensor();
                match run_inference(&model, feature_tensors) {
                    Ok(result) => {
                        println!("✅ Inference result: {:?}", result);
                    }
                    Err(e) => {
                        eprintln!("❌ Errore nell'inferenza: {}", e);
                    }
                }
            }
        }
    });

    false
}
