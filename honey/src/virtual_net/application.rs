use std::net::{Ipv4Addr, SocketAddr};

use pnet::datalink::DataLinkSender;
use tokio::{io::AsyncReadExt, net::TcpStream};
use tracing::info;
use crate::proxy::ssh::start_ssh_proxy;


pub async fn handle_ssh_connection(
    //tx: &mut dyn DataLinkSender,
    //source_ip: Ipv4Addr,
    //source_port: u16,
) -> Option<[u8; 1024]>{
    println!("Handling ssh");
    let sshd = TcpStream::connect("127.0.0.1:2022")
        .await
        .expect("❌ Connessione al server SSH fallita");

    // Leggi da sshd
    let mut sshd_reader = sshd;
    let mut buffer = [0u8; 1024];
    println!("Starting reading ssh");

    match sshd_reader.read(&mut buffer).await {
        Ok(n) => {
            //println!("📨 Risposta SSH ricevuta ({} bytes)", n);
            println!("Buffer: {:?}", buffer);
            return Some(buffer);
            // Costruisci pacchetto TCP con questo payload e invialo su tun
        }
        Err(e) => {
            eprintln!("❌ Errore lettura da SSH: {:?}", e);
            None
        }
    }
}