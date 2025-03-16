use petgraph::graph;

use super::graph::NetworkNode;

pub fn handle_virtual_packet(dest_mac: &str, src_mac: &str, bytes: u64, protocol: &str, router: Option<&NetworkNode>) {
    if let Some(router_node) = router {
        if router_node.mac_address == src_mac {
            println!("❌ Pacchetto da router {} ignorato.", src_mac);
            return; // 🔹 Uscita immediata, il pacchetto non viene processato
        }
    }
    
}