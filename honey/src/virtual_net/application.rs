use std::net::Ipv4Addr;

use pnet::datalink::DataLinkSender;
use tokio::net::TcpStream;
use crate::proxy::ssh::start_ssh_proxy;

pub async fn handle_ssh_connection(
    tx: &mut dyn DataLinkSender,
    source_ip: Ipv4Addr,
    source_port: u16
){
    let addr = source_ip.to_string() + &source_port.to_string();
    let local_stream = TcpStream::connect(addr).await.expect("Failed creating local stream proxy");

    let _ = start_ssh_proxy(local_stream).await;

    return;
}