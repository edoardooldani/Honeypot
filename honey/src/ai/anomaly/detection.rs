use tract_onnx::prelude::*;
use pnet::packet::ethernet::EthernetPacket;
use crate::ai::{anomaly::anomalies::AnomalyClassification, features::{flow::get_packet_flow_and_update, tensor::{get_scaler, normalize_tensor}}};
use crate::ai::features::packet_features::PacketFeatures;
use crate::ai::model::{run_autoencoder_inference, run_classifier_inference};
use tracing::warn;
use crate::graph::types::NetworkNode;

pub fn should_evaluate(flow: &PacketFeatures) -> bool {
    //let enough_pkts = flow.tot_fwd_pkts >= 5 && flow.tot_bwd_pkts >= 3;
    //let long_enough = flow.flow_duration > 2000.0;
    let likely_finished = flow.fin_flag_cnt > 0 || flow.rst_flag_cnt > 0;

    //enough_pkts || long_enough || 
    likely_finished
}

pub async fn detect_anomaly<'a>(
    autoencoder: Arc<SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>>,
    classifier: Arc<SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>>,
    ethernet_packet: EthernetPacket<'a>,
    src_node: &mut NetworkNode,
) -> bool {
    let autoencoder = Arc::clone(&autoencoder);
    let classifier = Arc::clone(&classifier);

    let packet_features = get_packet_flow_and_update(&ethernet_packet).await;
    if packet_features.is_none() {
        return false;
    }
    let packet_features = packet_features.expect("Packet features should not be None");

    if packet_features.dst_port == 22 || packet_features.src_port == 22 {
        return false;
    }

    let scaler = get_scaler("src/ai/models/autoencoder_scaler_params.json");
    let raw_tensor = packet_features.to_classifier_tensor(&scaler.columns);

    let feature_tensors = normalize_tensor(raw_tensor, scaler)
        .expect("Errore nella normalizzazione");


    let array = feature_tensors.to_array_view::<f32>().unwrap();
    let cloned_array = array.to_owned(); // Se ti serve conservarlo

    match run_autoencoder_inference(&autoencoder, feature_tensors.clone()) {
        Ok(result) => {
            if result > 0.15 {
                println!("\nNormalized tensor");
                for elem in cloned_array {
                    println!("{:?}", elem);
                }
                let classification = classify_anomaly(Arc::clone(&classifier), feature_tensors);
                src_node.add_anomaly(&ethernet_packet, classification);
                
            } else {
                //println!("No anomaly detected: {:?}", result);
                return false;
            }
        }
        Err(e) => {
            eprintln!("❌ Errore nell'inferenza: {}", e);
        }
    }
    
    false
}

pub fn classify_anomaly(
    model: Arc<SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>>,
    tensor: Tensor
) -> AnomalyClassification {
    let model_clone = Arc::clone(&model);

    match run_classifier_inference(&model_clone, tensor) {
        Ok(score) => {
            if score != 0 {
                warn!("Anomaly score: {}", score);
                return AnomalyClassification::from_index(score as u8);
            }else {
                println!("Benign classified: {:?}", score);
            }
        }
        Err(e) => warn!("❌ Error in classifier inference: {}", e),
    }

    return AnomalyClassification::from_index(0);
}