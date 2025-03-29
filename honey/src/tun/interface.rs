use std::{net::Ipv4Addr, sync::Arc};
use pnet::{datalink, util::MacAddr};
use tokio::process::Command;
use std::error::Error;
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

    change_mac_tun(&tun_name, virtual_mac, &virtual_ip).await;
    let sliced = reply_packet.as_slice();
    tun_writer.send(sliced).await;
    print_interface(&tun_name);
    remove_forwarding_rule(&tun_name, &virtual_ip).await;

}


async fn change_mac_tun(tun_name: &str, virtual_mac: MacAddr, virtual_ip: &Ipv4Addr)  -> Result<(), Box<dyn Error>> {


    let result  = Command::new("ifconfig")
        .arg(tun_name)
        .arg("hw")
        .arg("ether")
        .arg(virtual_mac.to_string())
        .output()
        .await;

    match result {
        Ok(output) if output.status.success() => {
            add_forwarding_rule(&tun_name, &virtual_ip).await;

            Ok(())
        }
        Ok(output) => {
            eprintln!("Failed to change mac address: {:?}", output);
            Err("Failed to change mac address".into())
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            Err(Box::new(e))
        }
    }


}

async fn add_forwarding_rule(interface: &str, virtual_ip: &Ipv4Addr) -> Result<(), Box<dyn Error>> {
    let result = Command::new("ip")
        .arg("route")
        .arg("add")
        .arg("0.0.0.0/0")  
        .arg("via")
        .arg(virtual_ip.to_string())
        .arg("dev")
        .arg(interface)
        .output()
        .await;

    match result {
        Ok(output) if output.status.success() => {
            Ok(())
        }
        Ok(output) => {
            eprintln!("Failed to add forwarding rule: {:?}", output);
            Err("Failed to add forwarding rule".into())
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            Err(Box::new(e))
        }
    }
}

async fn remove_forwarding_rule(interface: &str, virtual_ip: &Ipv4Addr) -> Result<(), Box<dyn Error>> {
    let result = Command::new("ip")
        .arg("route")
        .arg("del")
        .arg("0.0.0.0/0")  // Aggiungi il prefisso di rete
        .arg("via")
        .arg(virtual_ip.to_string())  // Via l'IP virtuale
        .arg("dev")
        .arg(interface)
        .output()
        .await;

    match result {
        Ok(output) if output.status.success() => {
            Ok(())
        }
        Ok(output) => {
            eprintln!("Failed to remove forwarding rule: {:?}", output);
            Err("Failed to remove forwarding rule".into())
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            Err(Box::new(e))
        }
    }
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