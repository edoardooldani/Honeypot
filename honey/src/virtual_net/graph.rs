use petgraph::graph::{Graph, NodeIndex};
use pnet::util::MacAddr;
use std::{collections::HashMap, net::Ipv4Addr, str::FromStr};
use rand::Rng;

use crate::utilities::network::find_ip_by_mac;


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

    pub async fn add_node(&mut self, mac_address: MacAddr, mut ip_address: Ipv4Addr, node_type: NodeType) -> NodeIndex {
        if let Some(&existing_node) = self.nodes.get(&mac_address) {
            return existing_node;
        }

        if ip_address != Ipv4Addr::new(0, 0, 0, 0){
            ip_address = find_ip_by_mac(&mac_address).await;
        }

        let mut node = NetworkNode {
            mac_address: mac_address.clone(),
            ipv4_address: ip_address.clone(),
            ipv6_address: None,
            node_type,
        };
    
        if ip_address.octets()[3] == 254 {
            node.node_type = NodeType::Router;
        }
        
    
        let node_index = self.graph.add_node(node);
        self.nodes.insert(mac_address, node_index);
    
        self.add_virtual_node();
        node_index
        
    }


    fn add_virtual_node(&mut self) -> NodeIndex {

        let assigned_ip = self.generate_virtual_ip();
        let assigned_ipv6 = self.generate_virtual_ipv6();

        let assigned_mac = generate_virtual_mac();

        let node = NetworkNode {
            mac_address: assigned_mac.clone(),
            ipv4_address: assigned_ip.clone(),
            ipv6_address: Some(assigned_ipv6.clone()),
            node_type: NodeType::Virtual,
        };

        let node_index = self.graph.add_node(node.clone());
        self.nodes.insert(assigned_mac.clone(), node_index);

        node_index
    }


    fn generate_virtual_ip(&self) -> Ipv4Addr {
        let mut rng = rand::rng();
        let mut last_octet = rng.random_range(100..120);
    
        let base_ip = [192, 168, 1];
    
        loop {
            let new_ip = Ipv4Addr::new(base_ip[0], base_ip[1], base_ip[2], last_octet);
    
            if !self.graph.node_weights().any(|node| node.ipv4_address == new_ip) {
                return new_ip;
            }
    
            last_octet += 1;
            if last_octet > 253 {
                panic!("No IP address available!");
            }
        }
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


    fn generate_virtual_ipv6(&self) -> String {
        let mut rng = rand::rng();
        let last_segment = rng.random_range(100..130);
        let base_ip = "fe80::1000:".to_string(); // Link-local address base
        
        format!("{}{:x}", base_ip, last_segment) // Concatenate to create a valid IPv6 address
    }
    
    pub fn is_router(&self, mac: MacAddr) -> bool {
        self.nodes.values().any(|&idx| {
            let node = &self.graph[idx];
            node.node_type == NodeType::Router && node.mac_address == mac
        })
    }

    pub fn find_node_by_ip(&self, ip: Ipv4Addr) -> Option<&NetworkNode> {
        self.graph.node_weights().find(|node| node.ipv4_address == ip)
    }

    pub fn find_virtual_node_by_ip(&self, ip: Ipv4Addr) -> Option<&NetworkNode> {
        self.graph.node_weights().find(|node| node.node_type == NodeType::Virtual && node.ipv4_address == ip)
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

    pub fn print_real_nodes(&self) {
        println!("\n📌 **Report finale dei nodi reali nel grafo:**");
        for (_, &node_index) in &self.nodes {
            let node = &self.graph[node_index];
            if node.node_type == NodeType::Real {
                println!("🟢 Nodo Reale: MAC={} | IP={:?}", node.mac_address, node.ipv4_address);
            }
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



fn generate_virtual_mac() -> MacAddr {
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
    
    let suffix = [
        rng.random_range(0..=255),
        rng.random_range(0..=255),
        rng.random_range(0..=255),
    ];

    let mac_string = format!("{}:{:02X}:{:02X}:{:02X}", prefix, suffix[0], suffix[1], suffix[2]);

    MacAddr::from_str(&mac_string).expect("Failed to parse MAC address")
}