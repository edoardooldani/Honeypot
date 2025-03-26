use petgraph::graph::{Graph, NodeIndex};
use pnet::util::MacAddr;
use tokio::{io, sync::mpsc};
use std::{collections::HashMap, net::{self, Ipv4Addr}, sync::Arc, time::Duration};
use rand::Rng;
use tun::{Device, Configuration};
use std::io::Read;
use tokio_tun::{TunBuilder, Tun};
use tokio::io::AsyncWriteExt;


use crate::network::sender::find_ip_by_mac;


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
    pub ip_address: String,
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

    pub fn add_node(&mut self, mac_address: String, mut ip_address: String, node_type: NodeType) -> NodeIndex {
        
        if let Some(&existing_node) = self.nodes.get(&mac_address) {
            return existing_node;
        }
        
        if ip_address != "0.0.0.0"{
            ip_address = find_ip_by_mac(&mac_address);
        }

        let mut node = NetworkNode {
            mac_address: mac_address.clone(),
            ip_address: ip_address.clone(),
            node_type,
        };
    
        if ip_address.ends_with(".254") {
            node.node_type = NodeType::Router;
        }
        
    
        let node_index = self.graph.add_node(node);
        self.nodes.insert(mac_address, node_index);
    
        self.add_virtual_node();
        node_index
    }


    fn add_virtual_node(&mut self) -> NodeIndex {

        let assigned_ip = self.generate_virtual_ip();
        let assigned_mac = generate_virtual_mac();

        create_virtual_tun_interface(&assigned_ip);

        let node = NetworkNode {
            mac_address: assigned_mac.clone(),
            ip_address: assigned_ip,
            node_type: NodeType::Virtual,
        };

        let node_index = self.graph.add_node(node);
        self.nodes.insert(assigned_mac, node_index);
        self.print_virtual_nodes();

        node_index
    }


    fn generate_virtual_ip(&self) -> String {
        let mut rng = rand::rng();
        let mut last_octet = rng.random_range(100..130);
        let base_ip = "192.168.1".to_string();

        loop {
            let new_ip = format!("{}.{}", base_ip, last_octet);
            
            if !self.graph.node_weights().any(|node| node.ip_address == new_ip) {
                return new_ip;
            }

            last_octet += 1;
            if last_octet > 253 {
                panic!("No IP address available!");
            }
        }
    }

    pub fn add_connection(&mut self, src_mac: &str, dst_mac: &str, protocol: &str, bytes: u64) {
        let src_index = self.add_node(src_mac.to_string(), "0.0.0.0".to_string(), NodeType::Real);
        let dst_index = self.add_node(dst_mac.to_string(), "0.0.0.0".to_string(), NodeType::Real);

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
    
    pub fn is_router(&self, mac: MacAddr) -> bool {
        self.nodes.values().any(|&idx| {
            let node = &self.graph[idx];
            node.node_type == NodeType::Router && node.mac_address == mac.to_string()
        })
    }

    pub fn find_virtual_node_by_ip(&self, ip: Ipv4Addr) -> Option<&NetworkNode> {
        self.graph.node_weights().find(|node| node.node_type == NodeType::Virtual && node.ip_address == ip.to_string())
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

    pub fn print_real_nodes(&self) {
        println!("\n📌 **Report finale dei nodi reali nel grafo:**");
        for (_, &node_index) in &self.nodes {
            let node = &self.graph[node_index];
            if node.node_type == NodeType::Real {
                println!("🟢 Nodo Reale: MAC={} | IP={:?}", node.mac_address, node.ip_address);
            }
        }
    }

    pub fn print_virtual_nodes(&self) {
        println!("\n📌 **Report finale dei nodi VIRTUALI nel grafo:**");
        for (_, &node_index) in &self.nodes {
            let node = &self.graph[node_index];
            if node.node_type == NodeType::Virtual {
                println!("⭕️ Nodo Virtuale: MAC={} | IP={:?}", node.mac_address, node.ip_address);
                io::stdout().flush().unwrap();

            }
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


fn create_virtual_tun_interface(ip: &str) {
    let parsed_ip: Ipv4Addr = ip.parse().map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid IP: {}", e))
    }).expect("Errore nel parsing dell'indirizzo IP");
    println!("IP: {ip}");
    io::stdout().flush().unwrap();

    let last_octet = parsed_ip.octets()[3];
    let tun_name = format!("tun{}", last_octet);

    let ip_address = ip.parse::<Ipv4Addr>().expect("Ip invalido");
    let netmask = "255.255.255.0".parse::<Ipv4Addr>().expect("Errore nel parsing della netmask");

    let tun = Arc::new(
        Tun::builder()
            .name(&tun_name)            
            .address(ip_address)
            .netmask(netmask)
            .up()                
            .build()
            .unwrap()
            .pop()
            .unwrap(),
    );

    let tun_reader = Arc::clone(&tun);
    tokio::spawn(async move {
        let mut buf = [0u8; 1024]; // Buffer per la lettura dei pacchetti

        loop {
            match tun_reader.recv(&mut buf).await {
                Ok(n) => {
                    if n > 0 {
                        println!("Lettura {} byte: {:?}", n, &buf[..n]);
                        io::stdout().flush().unwrap();

                    }
                }
                Err(e) => {
                    eprintln!("Errore nella lettura del dispositivo TUN: {:?}", e);
                    break;
                }
            }
        }
    });

    tokio::spawn(async move {
        let buf = b"Data to be written"; // Dati da inviare

        tun.send_all(buf).await.expect("Errore nell'invio dei dati TUN");
        println!("Dati inviati: {:?}", buf);
    });

}