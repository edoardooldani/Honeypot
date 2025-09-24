use common::packet::build_packet;
use common::packet_features::PacketFeatures;
use common::types::{AlertPayload, Packet as WsPacket, PayloadType};
use pnet::datalink::{self, Channel, Config, DataLinkSender, NetworkInterface};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::Packet;
use pnet::util::MacAddr;
use tokio_tungstenite::tungstenite::protocol::Message;
use tracing::{info, error};
use tokio::sync::Mutex;
use tract_onnx::prelude::*;
use std::net::Ipv4Addr;
use std::ops::Add;
use std::sync::Arc;
use crate::ai::anomaly::anomalies::AnomalyClassification;
use crate::ai::features::flow::get_flow;
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
        let mut graph_lock = graph.lock().await;
        
        let (src_node, dest_node) = graph_lock.add_nodes_and_connections(&ethernet_packet, local_mac).await;
        
        if dest_node.node_type == NodeType::Virtual {
            let tx_clone = tx_datalink.clone();
            let packet_data = ethernet_packet.packet().to_vec();

            tokio::spawn(async move {
                let packet = EthernetPacket::new(&packet_data).unwrap();
                handle_virtual_packet(packet, tx_clone).await;  
            });
        }
        
        let packet_data = ethernet_packet.packet().to_vec();
        let packet_ethernet = EthernetPacket::new(&packet_data).unwrap();

        let classification = detect_anomaly(Arc::clone(&autoencoder_model), Arc::clone(&classifier_model), packet_ethernet).await;   
        if classification != AnomalyClassification::Benign {
            info!("⚠️ Anomaly detected: {:?} from {:?}", classification, src_node.clone());
            let mut graph_lock = graph.lock().await;
            let anomalies_length = graph_lock.add_anomaly(&ethernet_packet, classification);

            let msg_packet: WsPacket = build_ws_alert(get_flow(&ethernet_packet).await.expect("Failed to extract packet features when anomalies detected"), 
                session_id, 
                src_node.mac_address,
                src_node.ipv4_address,
                anomalies_length
            ).await;

            let serialized = bincode::serialize(&msg_packet).expect("Errore nella serializzazione");
            let msg = Message::Binary(serialized.into());

            ws_tx.unbounded_send(msg).unwrap();
        }
    }

}


pub async fn build_ws_alert(
    features: PacketFeatures, 
    session_id: Arc<Mutex<u32>>, 
    mac_address: MacAddr,
    ip_address: Option<Ipv4Addr>,
    anomalies_length: usize
)-> WsPacket {
    let priority = if anomalies_length > 10 { 3 } else if anomalies_length > 5 { 2 } else { 1 };
    let id = session_id.lock().await.add(1);
    let header = common::packet::build_header(id, 1, priority, mac_address);

    build_packet(header, PayloadType::Alert(AlertPayload { mac_address: mac_address.octets(), ip_address: ip_address.expect("Failed to extract ip").to_string(), features }))
}