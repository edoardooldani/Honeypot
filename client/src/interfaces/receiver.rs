use common::packet::{build_header, build_packet};
use common::types::{AlertPayload, PayloadType};
use pnet::datalink::{self, Channel, Config, DataLinkSender, NetworkInterface};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::Packet;
use pnet::util::MacAddr;
use tokio_tungstenite::tungstenite::protocol::Message;
use tracing::{info, error};
use tokio::sync::Mutex;
use tract_onnx::prelude::*;
use std::sync::Arc;
use crate::ai::anomaly::anomalies::AnomalyClassification;
use crate::ai::features::flow::update_and_get_flow;
use crate::ai::model::load_models;
use crate::graph::utils::{get_primary_interface};
use crate::honeypot::handler::handle_virtual_packet;
use crate::graph::types::{NetworkGraph, NodeType};
use crate::ai::anomaly::detection::detect_anomaly;

pub async fn scan_datalink(
    ws_tx: futures_channel::mpsc::UnboundedSender<Message>, 
    session_id: Arc<Mutex<u32>>, 
    graph: Arc<Mutex<NetworkGraph>>,
) {

    let interface: NetworkInterface = get_primary_interface().expect("No valid interface found");
    
    let (tx_datalink, mut rx) = match datalink::channel(&interface, Config::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (
            Arc::new(tokio::sync::Mutex::new(tx as Box<dyn DataLinkSender + Send>)),
            rx
        ),
        Ok(_) => panic!("Channel not supported"),
        Err(e) => panic!("Error opening channel datalink: {}", e),
    };

    info!("📡 Listening to the network traffic...");
    let local_mac = interface.mac.expect("Couldn't get local mac address");

    let (autoencoder_model, classifier_model) = load_models();

    loop {
        match rx.next() {
            Ok(packet) => {
                scan_packet(packet, &graph, &autoencoder_model, &classifier_model, local_mac, tx_datalink.clone(), ws_tx.clone(), session_id.clone()).await;
            },
            Err(e) => {
                error!("❌ Error reading packet: {}", e);
                continue;
            }
        };
    }
}


async fn scan_packet(
    packet: &[u8],
    graph: &Arc<Mutex<NetworkGraph>>,
    autoencoder_model: &Arc<SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>>,
    classifier_model: &Arc<SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>>,
    local_mac: MacAddr,
    tx_datalink: Arc<Mutex<Box<dyn DataLinkSender + Send>>>,
    ws_tx: futures_channel::mpsc::UnboundedSender<Message>,
    session_id: Arc<Mutex<u32>>,
) {
    if let Some(ethernet_packet) = EthernetPacket::new(packet) {                    
        
        let (src_mac, src_ip, dest_is_virtual) = {
            let mut g = graph.lock().await;
            let (src_node, dest_node) = g.add_nodes_and_connections(&ethernet_packet, local_mac).await;

            (src_node.mac_address, src_node.ipv4_address, dest_node.node_type == NodeType::Virtual)
        };

        if dest_is_virtual {
            let tx_clone = tx_datalink.clone();
            let packet_data = ethernet_packet.packet().to_vec();
            tokio::spawn(async move {
                let packet = EthernetPacket::new(&packet_data).unwrap();
                info!("🤖 Handling virtual honeypot packet for {:?}", packet.get_destination());
                handle_virtual_packet(packet, tx_clone).await;
            });
        }

        
        let packet_data = ethernet_packet.packet().to_vec();
        let packet_ethernet = EthernetPacket::new(&packet_data).unwrap();
        let classification = detect_anomaly(Arc::clone(&autoencoder_model), Arc::clone(&classifier_model), packet_ethernet).await;   
        
        if classification != AnomalyClassification::Benign {
            info!("⚠️ Anomaly detected: {:?} from {:?}", classification, src_ip);

            let (anomalies_length, msg) = {
                let mut g = graph.lock().await;
                let anomalies_length = g.add_anomaly(&ethernet_packet, classification);

                let features = update_and_get_flow(&ethernet_packet)
                    .await
                    .expect("Failed to extract packet features when anomalies detected");

                let id = {
                    let mut id_lock = session_id.lock().await;
                    *id_lock += 1;
                    *id_lock
                };

                let priority = if anomalies_length > 10 { 3 }
                               else if anomalies_length > 5 { 2 }
                               else { 1 };

                let header = build_header(id, 1, priority, src_mac);
                let ws_packet = build_packet(
                    header,
                    PayloadType::Alert(AlertPayload {
                        mac_address: src_mac.octets(),
                        ip_address: src_ip.expect("Failed to extract ip").to_string(),
                        features
                    })
                );

                let serialized = bincode::serialize(&ws_packet).expect("serialize error");
                let msg = Message::Binary(serialized.into());
                (anomalies_length, msg)
            }; 

            info!("📤 Sending alert to server, anomalies count: {}", anomalies_length);
            ws_tx.unbounded_send(msg).unwrap();
        }
        else {
            //info!("✔️ Benign packet from {:?}", src_node.clone());
        }
    }

}