use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;
use crate::graph::types::NetworkGraph;

const NUMBER_OF_HONEYPOTS: u8 = 10;

pub async fn create_honeypots(graph: &Arc<Mutex<NetworkGraph>>){
    for _ in 0..NUMBER_OF_HONEYPOTS {
        let mut graph_locked = graph.lock().await;
        graph_locked.add_virtual_node();
    }
    let graph_locked = graph.lock().await;
    graph_locked.print_virtual_nodes();

    info!("🤖 Virtual Honeypots created");

}
