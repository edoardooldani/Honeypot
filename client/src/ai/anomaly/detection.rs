use common::packet_features::PacketFeatures;
use tract_onnx::prelude::*;
use pnet::packet::ethernet::EthernetPacket;
use crate::ai::{anomaly::anomalies::AnomalyClassification, features::{flow::get_flow, tensor::{get_scaler, normalize_tensor}}};
use crate::ai::model::{run_autoencoder_inference, run_classifier_inference};
use tracing::warn;

pub async fn detect_anomaly<'a>(
    autoencoder: Arc<SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>>,
    classifier: Arc<SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>>,
    ethernet_packet: EthernetPacket<'a>,
) -> AnomalyClassification {

    let packet_features = get_flow(&ethernet_packet).await;
    if packet_features.is_none() {
        return AnomalyClassification::Benign;
    }

    let packet_features = packet_features.expect("Packet features should not be None");

    let scaler = get_scaler("src/ai/models/autoencoder_scaler_params.json");
    let raw_tensor = packet_features.to_tensor(&scaler.columns);

    let feature_tensors = normalize_tensor(raw_tensor, scaler)
        .expect("Errore nella normalizzazione");

    match run_autoencoder_inference(&autoencoder, feature_tensors.clone()) {
        Ok(result) => {
            if result > 0.15 {
                return classify_anomaly(Arc::clone(&classifier), packet_features);
            }
            return AnomalyClassification::Benign;
            
        }
        Err(e) => {
            eprintln!("❌ Errore nell'inferenza: {}", e);
        }
    }
    
    return AnomalyClassification::Benign;
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
    let _cloned_array = array.to_owned();

    match run_classifier_inference(&classifier, feature_tensors) {
        Ok(score) => {
            if score != 0 {
                
                warn!("Anomaly score: {:?}", AnomalyClassification::from_index(score as u8));
                return AnomalyClassification::from_index(score as u8);
            }else {
                /*println!("\nNormalized tensor");
                for elem in cloned_array {
                    println!("{:?}", elem);
                }
                println!("Benign classified: {:?}", score);*/
            }
        }
        Err(e) => warn!("❌ Error in classifier inference: {}", e),
    }

    return AnomalyClassification::from_index(0);
}