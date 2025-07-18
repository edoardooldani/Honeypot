use tract_onnx::prelude::*;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::Packet;
use crate::ai::features::{flow::get_packet_flow_and_update, tensor::normalize_tensor};
use crate::ai::model::run_inference;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio::sync::Mutex;
use common::types::PayloadType;
use common::packet::{build_packet, calculate_header};


pub async fn detect_anomaly<'a>(
    model: Arc<SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>>,
    ethernet_packet: EthernetPacket<'a>
) -> bool {
    let model = Arc::clone(&model);

    let raw_bytes = ethernet_packet.packet().to_vec();

    if let Some(packet) = EthernetPacket::owned(raw_bytes) {
        if let Some(packet_features) = get_packet_flow_and_update(&packet).await {

            let raw_tensor = packet_features.to_tensor();
            let feature_tensors = normalize_tensor(raw_tensor, "src/ai/models/scaler_params.json")
                .expect("Errore nella normalizzazione");
            
            match run_inference(&model, feature_tensors) {
                Ok(result) => {
                    println!("✅ Inference result: {:?}", result);
                    if result > 1.0 {
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

    false
}


async fn _send_anomaly_alert(
    tx: futures_channel::mpsc::UnboundedSender<Message>,
    payload: PayloadType,
    session_id: Arc<Mutex<u32>>,
    data_type: u8,
    mac_address: [u8; 6],
) {
    let msg = {
        let mut id = session_id.lock().await;
        *id += 1;

        let header = calculate_header(*id, data_type, 0, mac_address);
        let packet = build_packet(header, payload);
        let serialized = bincode::serialize(&packet).expect("Errore nella serializzazione");

        Message::Binary(serialized.into())
    };

    if let Err(e) = tx.unbounded_send(msg) {
        eprintln!("Errore nell'invio del messaggio WebSocket: {:?}", e);
    }
}