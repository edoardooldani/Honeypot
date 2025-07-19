use tract_onnx::prelude::*;
use pnet::packet::ethernet::EthernetPacket;
use crate::ai::features::{flow::get_packet_flow_and_update, tensor::normalize_tensor};
use crate::ai::features::packet_features::PacketFeatures;
use crate::ai::model::{run_autoencoder_inference, run_classifier_inference};
use tracing::warn;


pub async fn detect_anomaly<'a>(
    autoencoder: Arc<SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>>,
    classifier: Arc<SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>>,
    ethernet_packet: EthernetPacket<'a>
) -> bool {
    let autoencoder = Arc::clone(&autoencoder);
    let classifier = Arc::clone(&classifier);

    let packet_features = get_packet_flow_and_update(&ethernet_packet).await;
    if packet_features.is_none() {
        return false;
    }
    let packet_features = packet_features.expect("Packet features should not be None");

    let raw_tensor = packet_features.to_autoencoder_tensor();
    let feature_tensors = normalize_tensor(raw_tensor, "src/ai/models/autoencoder_scaler_params.json", true)
        .expect("Errore nella normalizzazione");
    
    match run_autoencoder_inference(&autoencoder, feature_tensors) {
        Ok(result) => {
            if result > 1.0 {
                classify_anomaly(Arc::clone(&classifier), packet_features.clone());
                return true;
            } 
            //info!("No anomaly detected: {:?}", result);
            return false;
        }
        Err(e) => {
            eprintln!("❌ Errore nell'inferenza: {}", e);
        }
    }
    false
}

pub fn classify_anomaly(
    model: Arc<SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>>,
    features: PacketFeatures
) {//-> impl Future<Output = ()> {
    let model_clone = Arc::clone(&model);
    println!("Classifying anomaly with features: {:?}", features);
    let raw_tensor = features.to_classifier_tensor();
    let feature_tensors = normalize_tensor(raw_tensor, "src/ai/models/classifier_scaler_params.json", false)
        .expect("Errore nella normalizzazione");

    match run_classifier_inference(&model_clone, feature_tensors) {
        Ok(score) => {
            warn!("Anomaly score: {}", score);
        }
        Err(e) => warn!("❌ Error in classifier inference: {}", e),
    }
}