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

    let router_ip = Ipv4Addr::new(192, 168, 1, 254);

    change_mac_tun(&tun_name, virtual_mac, &virtual_ip, &router_ip).await;

    let sliced = reply_packet.as_slice();
    tun_writer.send(sliced).await;
    print_ip_routes().await;

    remove_forwarding_rule(&tun_name, &router_ip, &virtual_ip).await;

}


async fn change_mac_tun(tun_name: &str, virtual_mac: MacAddr, virtual_ip: &Ipv4Addr, router_ip: &Ipv4Addr)  -> Result<(), Box<dyn Error>> {


    let result  = Command::new("ifconfig")
        .arg(tun_name)
        .arg("hw")
        .arg("ether")
        .arg(virtual_mac.to_string())
        .output()
        .await;

    match result {
        Ok(output) if output.status.success() => {
            add_forwarding_rule(&tun_name, &router_ip, virtual_ip).await;

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

async fn add_forwarding_rule(interface: &str, router_ip: &Ipv4Addr, virtual_ip: &Ipv4Addr) -> Result<(), Box<dyn Error>> {
    let result = Command::new("ip")
        .arg("route")
        .arg("add")
        .arg("0.0.0.0/0")  
        .arg("via")
        .arg(router_ip.to_string())
        .arg("dev")
        .arg(interface)
        .output()
        .await;

    match result {
        Ok(output) if output.status.success() => {

            let nat_result = Command::new("iptables")
                .arg("-t")
                .arg("nat")
                .arg("-A")
                .arg("POSTROUTING")
                .arg("-o")
                .arg("wlan0")  
                .arg("-j")
                .arg("MASQUERADE")
                .output()
                .await;

            match nat_result {
                Ok(nat_output) if nat_output.status.success() => Ok(()),
                Ok(nat_output) => {
                    eprintln!("Failed to add NAT rule: {:?}", nat_output);
                    Err("Failed to add NAT rule".into())
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    Err(Box::new(e))
                }
            }
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

async fn remove_forwarding_rule(interface: &str, router_ip: &Ipv4Addr, virtual_ip: &Ipv4Addr) -> Result<(), Box<dyn Error>> {
    let result = Command::new("ip")
        .arg("route")
        .arg("del")
        .arg("0.0.0.0/0")  // Aggiungi il prefisso di rete
        .arg("via")
        .arg(router_ip.to_string())  // Via l'IP virtuale
        .arg("dev")
        .arg(interface)
        .output()
        .await;

    match result {
        Ok(output) if output.status.success() => {
            let nat_result = Command::new("iptables")
                .arg("-t")
                .arg("nat")
                .arg("-D")
                .arg("POSTROUTING")
                .arg("-o")
                .arg("wlan0")  
                .arg("-j")
                .arg("MASQUERADE")
                .output()
                .await;

            match nat_result {
                Ok(nat_output) if nat_output.status.success() => Ok(()),
                Ok(nat_output) => {
                    eprintln!("Failed to remove NAT rule: {:?}", nat_output);
                    Err("Failed to remove NAT rule".into())
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    Err(Box::new(e))
                }
            }
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


async fn print_ip_routes() -> Result<(), Box<dyn Error>> {
    // Esegui il comando per mostrare le rotte IP
    let result = Command::new("ip")
        .arg("route")
        .arg("show")  // Mostra tutte le rotte
        .output()
        .await;

    match result {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            println!("IP Routes:\n{}", stdout);  // Stampa le rotte
            Ok(())
        }
        Ok(output) => {
            eprintln!("Failed to fetch IP routes: {:?}", output);
            Err("Failed to fetch IP routes".into())
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            Err(Box::new(e))
        }
    }
}