use pnet::datalink::{self, Channel, Config, DataLinkSender, NetworkInterface};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::Packet;
use tokio_tungstenite::tungstenite::protocol::Message;
use tracing::{info, error};
use tract_onnx::prelude::SimplePlan;
use tokio::sync::Mutex;
use std::sync::Arc;
use crate::graph::utils::{get_primary_interface};
use crate::honeypot::handler::handle_virtual_packet;
use crate::graph::types::{NetworkGraph, NodeType};
use crate::ai::detection::detect_anomaly;
use tract_onnx::prelude::*;


pub async fn scan_datalink(
    _tx_ws: futures_channel::mpsc::UnboundedSender<Message>, 
    _session_id: Arc<Mutex<u32>>, 
    graph: Arc<Mutex<NetworkGraph>>,
    ai_model: Arc<SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>>
) {

    let interface: NetworkInterface = get_primary_interface().expect("No valid interface found");
    
    let (tx_datalink, mut rx) = match datalink::channel(&interface, Config::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (
            Arc::new(tokio::sync::Mutex::new(tx as Box<dyn DataLinkSender + Send>)),
            rx
        ),
        Ok(_) => panic!("Channel not supported"),
        Err(e) => panic!("Error opening channel: {}", e),
    };

    info!("📡 Listening to the network traffic...");
    let local_mac = interface.mac.expect("Couldn't get local mac address");

    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(ethernet_packet) = EthernetPacket::new(packet) {
                    
                    if ethernet_packet.get_source() == local_mac {
                        continue;
                    }
                    
                    let mut graph_lock = graph.lock().await;
                    
                    graph_lock.add_nodes_and_connections(&ethernet_packet, local_mac).await;
                    let dest_node = graph_lock.get_node_by_mac(ethernet_packet.get_destination()).expect("Destination node not found");
                    
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

                    if detect_anomaly(Arc::clone(&ai_model), packet_ethernet).await{
                        
                        let packet_data = ethernet_packet.packet().to_vec();
                        let packet_ethernet = EthernetPacket::new(&packet_data).unwrap();
                        dest_node.add_anomaly(&packet_ethernet);

                        println!("Anomaly detected and logged: {:?}", dest_node);
                    }
                    
                    
                }

            },
            Err(e) => {
                error!("❌ Error reading packet: {}", e);
                continue;
            }
        };
    }
}

