use std::{net::Ipv4Addr, sync::Arc};
use pnet::{datalink, util::MacAddr};
use tokio::process::Command;
use tokio_tun::Tun;

pub async fn send_tun_reply(reply_packet: Vec<u8>, virtual_mac: MacAddr, virtual_ip: Ipv4Addr){

    let last_octet = virtual_ip.octets()[3];
    let tun_name = format!("tun{}", last_octet);
    let netmask = "255.255.255.0".parse::<Ipv4Addr>().expect("Error parsing netmask");

    let tun = Arc::new(
        Tun::builder()
            .name(&tun_name)
            .address(virtual_ip)
            .netmask(netmask)
            .tap()
            .up()                
            .build()
            .unwrap()
            .pop()
            .unwrap()
    );  

    let tun_writer: Arc<Tun>= tun.clone();

    change_mac_tun(&tun_name, virtual_mac).await;
    let sliced = reply_packet.as_slice();
    tun_writer.send(sliced).await;
    println!("AFTER SEND");
    print_interface(&tun_name);

    
}


async fn change_mac_tun(interface: &str, virtual_mac: MacAddr) {

    print_interface(interface);
    Command::new("ifconfig")
        .arg(interface)
        .arg("hw")
        .arg("ether")
        .arg(virtual_mac.to_string())
        .output()
        .await;

    println!("\nAFTER MODIFICATION");
    print_interface(interface);

}



fn print_interface(interface_name: &str){
    let interfaces = datalink::interfaces();

    let interface = interfaces.iter().find(|&iface| iface.name == interface_name);

    match interface {
        Some(iface) => {
            // Stampa le informazioni dell'interfaccia
            println!("Interfaccia trovata: {}", iface.name);
            println!("Indirizzo MAC: {}", iface.mac.unwrap_or_default());
            println!("Is running {:?}:", iface.is_running());
            println!("Is UP {:?}:", iface.is_up());

        }
        None => {
            println!("Interfaccia {} non trovata", interface_name);
        }
    }
}