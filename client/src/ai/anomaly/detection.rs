use tract_onnx::prelude::*;
use pnet::packet::ethernet::EthernetPacket;
use crate::ai::{anomaly::anomalies::AnomalyClassification, features::{flow::get_flow, packet_features::PacketFeatures, tensor::{get_scaler, normalize_tensor}}};
use crate::ai::model::{run_autoencoder_inference, run_classifier_inference};
use tracing::warn;
use crate::graph::types::NetworkNode;

pub async fn detect_anomaly<'a>(
    autoencoder: Arc<SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>>,
    classifier: Arc<SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>>,
    ethernet_packet: EthernetPacket<'a>,
    src_node: &mut NetworkNode,
) -> bool {

    let packet_features = get_flow(&ethernet_packet).await;
    if packet_features.is_none() {
        return false;
    }

    let packet_features = packet_features.expect("Packet features should not be None");

    let scaler = get_scaler("src/ai/models/autoencoder_scaler_params.json");
    let raw_tensor = packet_features.to_tensor(&scaler.columns);

    let feature_tensors = normalize_tensor(raw_tensor, scaler)
        .expect("Errore nella normalizzazione");

    match run_autoencoder_inference(&autoencoder, feature_tensors.clone()) {
        Ok(result) => {
            if result > 0.15 {
                let classification = classify_anomaly(Arc::clone(&classifier), packet_features);
                src_node.add_anomaly(&ethernet_packet, classification);
                return classification != AnomalyClassification::Benign;
            }
            return false;
            
        }
        Err(e) => {
            eprintln!("❌ Errore nell'inferenza: {}", e);
        }
    }
    
    false
}

pub fn classify_anomaly(
    classifier: Arc<SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>>,
    packet_features: PacketFeatures
) -> AnomalyClassification {

    let scaler = get_scaler("src/ai/models/classifier_scaler_params.json");
    let raw_tensor = packet_features.to_tensor(&scaler.columns);

    let feature_tensors = normalize_tensor(raw_tensor, scaler)
        .expect("Errore nella normalizzazione");

    let array = feature_tensors.to_array_view::<f32>().unwrap();
    let cloned_array = array.to_owned();

    match run_classifier_inference(&classifier, feature_tensors) {
        Ok(score) => {
            if score != 0 {
                
                warn!("Anomaly score: {:?}", AnomalyClassification::from_index(score as u8));
                return AnomalyClassification::from_index(score as u8);
            }else {
                println!("\nNormalized tensor");
                for elem in cloned_array {
                    println!("{:?}", elem);
                }
                println!("Benign classified: {:?}", score);
            }
        }
        Err(e) => warn!("❌ Error in classifier inference: {}", e),
    }

    return AnomalyClassification::from_index(0);
}