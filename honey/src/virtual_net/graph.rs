use petgraph::graph::{Graph, NodeIndex};
use std::collections::HashMap;
use rand::Rng;

use crate::listeners::sender::find_ip_by_mac;


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
    pub mac_address: String,
    pub ip_address: Option<String>,
    pub node_type: NodeType,
}

pub struct NetworkGraph {
    pub graph: Graph<NetworkNode, Connection>,
    pub nodes: HashMap<String, NodeIndex>,
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
            nodes: HashMap::new(),
        }
    }

    pub fn add_node(&mut self, mac_address: String, ip_address: Option<String>, node_type: NodeType) -> NodeIndex {
        if let Some(&existing_node) = self.nodes.get(&mac_address) {
            return existing_node;
        }

        let ip_addr = match ip_address {
            Some(ip) => Some(ip),
            None => find_ip_by_mac(&mac_address),
        };

        let mut node = NetworkNode {
            mac_address: mac_address.clone(),
            ip_address: ip_addr.clone(),
            node_type,
        };

        if let Some(ref ip) = ip_addr {
            if ip.ends_with(".254") {
                node.node_type = NodeType::Router;
            }
        }

        let node_index = self.graph.add_node(node);
        self.nodes.insert(mac_address, node_index);

        self.add_virtual_node();
        node_index
    }


    fn add_virtual_node(&mut self) -> NodeIndex {

        let assigned_ip = Some(self.generate_virtual_ip());
        let assigned_mac = generate_virtual_mac();

        let node = NetworkNode {
            mac_address: assigned_mac.clone(),
            ip_address: assigned_ip,
            node_type: NodeType::Virtual,
        };

        let node_index = self.graph.add_node(node);
        self.nodes.insert(assigned_mac, node_index);
        node_index
    }


    fn generate_virtual_ip(&self) -> String {
        let mut rng = rand::rng();
        let mut last_octet = rng.random_range(30..100);
        let base_ip = "192.168.1".to_string();

        loop {
            let new_ip = format!("{}.{}", base_ip, last_octet);
            
            if !self.graph.node_weights().any(|node| node.ip_address.as_deref() == Some(&new_ip)) {
                return new_ip;
            }

            last_octet += 1;
            if last_octet > 253 {
                panic!("No IP address available!");
            }
        }
    }

    pub fn add_connection(&mut self, src_mac: &str, dst_mac: &str, protocol: &str, bytes: u64) {
        let src_index = self.add_node(src_mac.to_string(), None, NodeType::Real);
        let dst_index = self.add_node(dst_mac.to_string(), None, NodeType::Real);

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
    
    pub fn find_router(&self) -> Option<&NetworkNode> {
        let router = self.graph.node_weights().find(|node| {
            node.node_type == NodeType::Router
        });
    
        router
    }


    pub fn print_graph(&self) {
        for node_index in self.graph.node_indices() {
            let node = &self.graph[node_index];
            println!(
                "Nodo: MAC={}, IP={:?}, Tipo={:?}",
                node.mac_address, node.ip_address, node.node_type
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
}



fn generate_virtual_mac() -> String {
    let mac_prefixes = vec![
        "00:1A:2B", // Cisco
        "34:56:78", // Samsung
        "70:C9:32", // Apple
        "D8:21:DA", // TP-Link
        "60:1D:9D", // Dell
        "C4:3C:B0", // Asus
    ];

    let mut rng = rand::rng();
    let prefix = mac_prefixes[rng.random_range(0..mac_prefixes.len())];
    let suffix = format!(
        "{:02X}:{:02X}:{:02X}",
        rng.random_range(0..=255),
        rng.random_range(0..=255),
        rng.random_range(0..=255)
    );

    format!("{}:{}", prefix, suffix)
}