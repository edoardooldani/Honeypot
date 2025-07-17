use pnet::datalink::{self, Channel, Config, DataLinkSender, NetworkInterface};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::Packet;
use tokio_tungstenite::tungstenite::protocol::Message;
use tracing::{info, error};
use tract_onnx::prelude::SimplePlan;
use std::net::Ipv4Addr;
use tokio::sync::Mutex;
use std::sync::Arc;
use crate::graph::utils::{get_primary_interface};
use crate::honeypot::handler::handle_virtual_packet;
use crate::graph::types::{update_graph_from_packet, NetworkGraph};
use crate::ai::detection::detect_anomaly;
use tract_onnx::prelude::*;


pub async fn scan_datalink(
    _tx: futures_channel::mpsc::UnboundedSender<Message>, 
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
                    
                    let dest_ip: Ipv4Addr = update_graph_from_packet(graph.clone(), &ethernet_packet, packet.len()).await;
                    
                    // Handle virtual node
                    if let Some(dest_node) = graph.lock().await.find_virtual_node_by_ip_or_mac(ethernet_packet.get_destination(), dest_ip) {
                        let tx_clone = tx_datalink.clone();
                        let ethertype = ethernet_packet.get_ethertype();
                        let payload = ethernet_packet.payload().to_vec();
                        let source = ethernet_packet.get_source();
                        let virtual_mac = dest_node.mac_address.clone();
                        let virtual_ip = dest_node.ipv4_address.clone();

                        tokio::spawn(async move {
                            handle_virtual_packet(
                                ethertype,
                                payload,
                                &source,
                                &virtual_mac, 
                                &virtual_ip, 
                                tx_clone
                            ).await;  
                        });        
                    }

                    if let Some(ethernet_packet) = EthernetPacket::new(packet){
                        if ethernet_packet.get_destination() != local_mac {
                            if detect_anomaly(Arc::clone(&ai_model), ethernet_packet).await{

                            }
                        }
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

