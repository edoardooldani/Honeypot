use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use pnet::util::MacAddr;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio::sync::Mutex;
use std::sync::Arc;
use crate::trackers::arp_tracker::{detect_arp_attacks, ArpRepliesTracker, ArpReqAlertTracker, ArpRequestTracker, ArpResAlertTracker};
use crate::trackers::tcp_tracker::{detect_tcp_syn_attack, TcpSynDetector};
use crate::network::graph::NetworkGraph;

pub async fn detect_attacks<'a>(
    tx: futures_channel::mpsc::UnboundedSender<Message>,
    session_id: Arc<Mutex<u32>>,
    ethernet_packet: &'a EthernetPacket<'a>, 
    graph: &mut NetworkGraph,
    local_mac: MacAddr,
    arp_req_alert_tracker: ArpReqAlertTracker,
    arp_res_alert_tracker: ArpResAlertTracker,
    arp_req_tracker: Arc<Mutex<ArpRequestTracker>>,
    arp_res_tracker: Arc<Mutex<ArpRepliesTracker>>,
    tcp_syn_tracker: Arc<Mutex<TcpSynDetector>>,
) {
    if ethernet_packet.get_ethertype() == EtherTypes::Arp {
        detect_arp_attacks(
            tx.clone(), 
            session_id.clone(),
            ethernet_packet, 
            arp_req_tracker, 
            arp_res_tracker,
            arp_req_alert_tracker,
            arp_res_alert_tracker,
            graph, 
            local_mac.clone()
        ).await;
    }
    if ethernet_packet.get_ethertype() == EtherTypes::Ipv4 {

        if let Some(ipv4_packet) = Ipv4Packet::new(ethernet_packet.payload()) {
            let next_protocol = ipv4_packet.get_next_level_protocol();
            match next_protocol {
                IpNextHeaderProtocols::Tcp => {
                    detect_tcp_syn_attack(
                        tx.clone(),
                        session_id.clone(),
                        &ipv4_packet,
                        ethernet_packet.get_source(),
                        local_mac,
                        tcp_syn_tracker,
                    ).await;    
                }
                _ => {
                    
                }
            }
            
        }
    }
}
