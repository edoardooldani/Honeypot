use petgraph::graph::{Graph, NodeIndex};
use pnet::{packet::ethernet::EthernetPacket, util::MacAddr};
use tokio::sync::Mutex;
use std::{collections::HashMap, net::Ipv4Addr, sync::Arc};

use crate::graph::utils::{generate_virtual_ip, generate_virtual_ipv6, generate_virtual_mac, get_src_dest_ip};

#[derive(Debug, Clone)]
pub struct Connection {
    pub total_bytes: u64,
    pub protocols: HashMap<String, u64>,
}

impl Connection {
    pub fn add_traffic(&mut self, protocol: &str, bytes: u64) {
        *self.protocols.entry(protocol.to_string()).or_insert(0) += bytes;
        self.total_bytes += bytes;
    }
}


#[derive(Debug, Clone)]
pub struct NetworkNode {
    pub mac_address: MacAddr,
    pub ipv4_address: Ipv4Addr,
    pub ipv6_address: Option<String>,
    pub node_type: NodeType,
    pub anomalies: u32,
}

#[derive(Debug, Clone)]

pub struct NetworkGraph {
    pub graph: Graph<NetworkNode, Connection>,
    pub nodes: HashMap<MacAddr, NodeIndex>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeType {
    Real,
    Virtual,
    Multicast,
    Broadcast,
    Router
}


impl NetworkGraph {
    pub fn new() -> Self {
        Self {
            graph: Graph::new(),
            nodes: HashMap::new()     
        }
    }

    pub async fn add_node(&mut self, mac_address: MacAddr, ip_address: Ipv4Addr, node_type: NodeType) -> NodeIndex {
        if let Some(&existing_node) = self.nodes.get(&mac_address) {
            return existing_node;
        }

        let mut node = NetworkNode {
            mac_address: mac_address.clone(),
            ipv4_address: ip_address.clone(),
            ipv6_address: None,
            node_type,
            anomalies: 0,
        };
    
        if ip_address.octets()[3] == 254 {
            node.node_type = NodeType::Router;
        }
        
    
        let node_index = self.graph.add_node(node);
        self.nodes.insert(mac_address, node_index);
    
        node_index
        
    }


    pub async fn add_virtual_node(&mut self) -> NodeIndex {

        let assigned_ip = generate_virtual_ip(self).await;
        let assigned_ipv6 = generate_virtual_ipv6();
        let assigned_mac = generate_virtual_mac();

        let node = NetworkNode {
            mac_address: assigned_mac.clone(),
            ipv4_address: assigned_ip.clone(),
            ipv6_address: Some(assigned_ipv6.clone()),
            node_type: NodeType::Virtual,
            anomalies: 0,
        };

        let node_index = self.graph.add_node(node.clone());
        self.nodes.insert(assigned_mac.clone(), node_index);
        
        node_index
    }

    
    pub async fn add_connection(&mut self, src_mac: MacAddr, dst_mac: MacAddr, protocol: &str, bytes: u64) {
        let src_index = self.add_node(src_mac, Ipv4Addr::new(0, 0, 0, 0), NodeType::Real).await;
        let dst_index = self.add_node(dst_mac, Ipv4Addr::new(0, 0, 0, 0), NodeType::Real).await;

        if let Some(edge) = self.graph.find_edge(src_index, dst_index) {
            let connection = self.graph.edge_weight_mut(edge).unwrap();
            connection.add_traffic(protocol, bytes);

        } else {
            let mut new_connection = Connection {
                total_bytes: 0,
                protocols: HashMap::new(),
            };
            new_connection.add_traffic(protocol, bytes);
            self.graph.add_edge(src_index, dst_index, new_connection);
        }

    }

    pub fn find_virtual_node_by_ip_or_mac(&self, mac_address: MacAddr, ip: Ipv4Addr) -> Option<&NetworkNode> {
        self.graph.node_weights().find(|node| (node.ipv4_address == ip || node.mac_address == mac_address) && node.node_type == NodeType::Virtual)
    }


    pub fn print_graph(&self) {
        for node_index in self.graph.node_indices() {
            let node = &self.graph[node_index];
            println!(
                "Nodo: MAC={}, IP={:?}, Tipo={:?}",
                node.mac_address, node.ipv4_address, node.node_type
            );
        }

        for edge in self.graph.edge_indices() {
            let (src, dst) = self.graph.edge_endpoints(edge).unwrap();
            let connection = self.graph.edge_weight(edge).unwrap();
            println!(
                "Connessione: {} -> {} | Totale Bytes={} | Protocolli={:?}",
                self.graph[src].mac_address,
                self.graph[dst].mac_address,
                connection.total_bytes,
                connection.protocols
            );
        }
    }

    pub fn print_virtual_nodes(&self) {
        println!("\n📌 **Report finale dei nodi VIRTUALI nel grafo:**");
        for (_, &node_index) in &self.nodes {
            let node = &self.graph[node_index];
            if node.node_type == NodeType::Virtual {
                println!("⭕️ Nodo Virtuale: MAC={} | IP={:?}", node.mac_address, node.ipv4_address);
            }
        }
    }


}



pub async fn update_graph_from_packet<'a>(
    graph: Arc<Mutex<NetworkGraph>>,
    ethernet_packet: &'a EthernetPacket<'a>,
    packet_len: usize,
) -> Ipv4Addr {
    let src_mac = ethernet_packet.get_source();
    let dest_mac = ethernet_packet.get_destination();
    let protocol = ethernet_packet.get_ethertype();
    let bytes = packet_len as u64;

    let (src_ip, dest_ip) = get_src_dest_ip(ethernet_packet)
        .unwrap_or((Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 0)));

    let src_type = NodeType::Real;
    let dest_type = NodeType::Real;

    if dest_ip == Ipv4Addr::new(0, 0, 0, 0) {
        return Ipv4Addr::new(0, 0, 0, 0);
    }

    let mut graph = graph.lock().await;

    if !graph.nodes.contains_key(&src_mac) {
        graph.add_node(src_mac, src_ip, src_type).await;
    }

    if !graph.nodes.contains_key(&dest_mac) {
        graph.add_node(dest_mac, dest_ip, dest_type).await;
    }

    if graph.nodes.contains_key(&src_mac) && graph.nodes.contains_key(&dest_mac) {
        graph
            .add_connection(src_mac, dest_mac, &protocol.to_string(), bytes)
            .await;
    }

    return dest_ip;
}