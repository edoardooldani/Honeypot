use tract_onnx::prelude::*;
use pnet::packet::ethernet::EthernetPacket;
use crate::trackers::flow::get_packet_flow;

pub async fn detect_anomaly<'a>(
    model: SimplePlan<TypedFact, Box<dyn TypedOp>, tract_onnx::prelude::Graph<TypedFact, Box<dyn TypedOp>>>, 
    ethernet_packet: EthernetPacket<'a>
) -> bool {

    let packet_features = get_packet_flow(&ethernet_packet).await;

    if packet_features.is_none() {
        return false; // No tcp/udp found, no anomaly to detect
    }

    println!("Packet Features: {:?}", packet_features);
    false
}
