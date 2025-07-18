use pnet::{packet::ethernet::EthernetPacket, util::MacAddr};
use std::{collections::{HashMap, HashSet}, net::Ipv4Addr};

use crate::graph::utils::{generate_virtual_ip, generate_virtual_ipv6, generate_virtual_mac, get_src_and_dest_ip, get_src_and_dest_transport};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeType {
    Virtual,
    Physical,
    Device,
}

use std::time::SystemTime;

#[derive(Debug, Clone)]
pub struct Anomaly {
    pub src_ip: Option<Ipv4Addr>,
    pub dst_ip: Option<Ipv4Addr>,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub timestamp: SystemTime,
}

#[derive(Debug, Clone)]
pub struct NetworkNode {
    pub mac_address: MacAddr,
    pub ipv4_address: Option<Ipv4Addr>,
    pub ipv6_address: Option<String>,
    pub node_type: NodeType,
    pub anomalies: Vec<Anomaly>,
}

#[derive(Debug, Default)]
pub struct NetworkGraph {
    pub nodes: HashMap<MacAddr, NetworkNode>,
    pub edges: HashMap<MacAddr, HashSet<MacAddr>>,
}

impl NetworkGraph {
    pub fn add_node(&mut self, node: NetworkNode) {
        self.nodes.entry(node.mac_address).or_insert(node);
    }

    pub fn add_connection(&mut self, src_mac: MacAddr, dst_mac: MacAddr) {
        self.edges.entry(src_mac).or_default().insert(dst_mac);
        self.edges.entry(dst_mac).or_default().insert(src_mac);
    }

    pub fn find_by_ip(&self, ip: Ipv4Addr) -> Option<&NetworkNode> {
        self.nodes.values().find(|n| n.ipv4_address == Some(ip))
    }

    pub fn get_node_by_mac(&mut self, mac: MacAddr) -> Option<&mut NetworkNode> {
        self.nodes.get_mut(&mac)
    }

    pub async fn add_nodes_and_connections<'a>(
        &mut self,
        ethernet_packet: &'a EthernetPacket<'a>,
        local_mac: MacAddr,
    ) {
        let (src_ip, dst_ip) = get_src_and_dest_ip(ethernet_packet)
        .map(|(s, d)| (Some(s), Some(d)))
        .unwrap_or((None, None));

        let src_mac = ethernet_packet.get_source();
        let dst_mac = ethernet_packet.get_destination();

        if self.get_node_by_mac(src_mac).is_none(){
            self.add_node(NetworkNode {
                mac_address: src_mac,
                ipv4_address: src_ip,
                ipv6_address: None,
                node_type: if src_mac == local_mac { NodeType::Device } else { NodeType::Physical },
                anomalies: Vec::new(),
            });
        }

        if self.get_node_by_mac(dst_mac).is_none() {
            self.add_node(NetworkNode {
                mac_address: dst_mac,
                ipv4_address: dst_ip,
                ipv6_address: None,
                node_type: if dst_mac == local_mac { NodeType::Device } else { NodeType::Physical },
                anomalies: Vec::new(),
            });
        }

        self.add_connection(src_mac, dst_mac);
    }


    pub fn add_virtual_node(&mut self) -> MacAddr {
        let assigned_ip = generate_virtual_ip(self);
        let assigned_ipv6 = generate_virtual_ipv6();
        let assigned_mac = generate_virtual_mac();

        let node = NetworkNode {
            mac_address: assigned_mac,
            ipv4_address: Some(assigned_ip),
            ipv6_address: Some(assigned_ipv6),
            node_type: NodeType::Virtual,
            anomalies: Vec::new(),
        };

        self.nodes.insert(assigned_mac, node);

        assigned_mac
    }

    pub fn print_virtual_nodes(&self) {
        println!("\n📌 **Nodi VIRTUALI nel grafo:**");
        for node in self.nodes.values() {
            if node.node_type == NodeType::Virtual {
                println!("⭕️ Nodo Virtuale: MAC={} | IP={:?}", node.mac_address, node.ipv4_address);
            }
        }
    }
}

impl NetworkNode {
    pub fn add_anomaly(&mut self, ethernet_packet: &EthernetPacket) -> Anomaly {
        let (src_ip, dst_ip) = get_src_and_dest_ip(ethernet_packet)
            .map(|(s, d)| (Some(s), Some(d)))
            .unwrap_or((None, None));

        let (src_port, dst_port, protocol) = get_src_and_dest_transport(ethernet_packet);
        
        let anomaly = Anomaly {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            timestamp: SystemTime::now(),
        };
        self.anomalies.push(anomaly.clone());

        anomaly
    }
}
