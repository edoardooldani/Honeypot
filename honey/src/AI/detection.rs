use tract_onnx::prelude::*;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::Packet;
use crate::ai::features::flow::get_packet_flow_and_update;
use crate::ai::model::run_inference;

pub fn detect_anomaly<'a>(
    model: SimplePlan<TypedFact, Box<dyn TypedOp>, tract_onnx::prelude::Graph<TypedFact, Box<dyn TypedOp>>>, 
    ethernet_packet: EthernetPacket<'a>
) -> bool {
    
    let raw_bytes = ethernet_packet.packet().to_vec();

    tokio::spawn(async move {
        if let Some(packet) = EthernetPacket::owned(raw_bytes) {
            let packet_features = get_packet_flow_and_update(&packet).await;

            if packet_features.is_none() {
                return false;
            }

            let feature_tensors: Tensor = packet_features.expect("Failed to extract packet features!").to_tensor();
            let result = run_inference(&model, feature_tensors).expect("Failed to run inference");
            println!("Inference result: {:?}", result);
        }
        false
    });

    false
}
