use std::{net::Ipv4Addr, sync::Arc};
use pnet::util::MacAddr;
use tokio_tun::Tun;
use tracing::info;



pub async fn send_tun_reply(reply_packet: Vec<u8>, virtual_mac: MacAddr, virtual_ip: Ipv4Addr){

    let last_octet = virtual_ip.octets()[3];
    let tun_name = format!("tun{}", last_octet);
    let netmask = "255.255.255.0".parse::<Ipv4Addr>().expect("Error parsing netmask");

    let tun = Arc::new(
        Tun::builder()
            .name(&tun_name)
            .address(virtual_ip)
            .netmask(netmask)
            .up()                
            .build()
            .unwrap()
            .pop()
            .unwrap()
    );  

    let tun_writer: Arc<Tun>= tun.clone();

    tokio::spawn(async move{

        let sliced = reply_packet.as_slice();
        println!("Vec : {:?} Sliced: {:?}", reply_packet, sliced);
        let result = tun_writer.send(sliced).await;

        match result {
            Ok(bytes) => {
                println!("Inviati {} bytes", bytes);
            }
            Err(e) => {
                eprintln!("Errore durante l'invio dei pacchetti: {}", e);
            }
        }
    });
}