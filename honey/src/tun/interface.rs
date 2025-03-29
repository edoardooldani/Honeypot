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

    change_mac_tun(&tun_name, virtual_mac, &router_ip).await;

    let sliced = reply_packet.as_slice();
    tun_writer.send(sliced).await;

    remove_forwarding_rule(&tun_name, &router_ip).await;

}


async fn change_mac_tun(tun_name: &str, virtual_mac: MacAddr, router_ip: &Ipv4Addr)  -> Result<(), Box<dyn Error>> {

    let result  = Command::new("ifconfig")
        .arg(tun_name)
        .arg("hw")
        .arg("ether")
        .arg(virtual_mac.to_string())
        .output()
        .await;

    match result {
        Ok(output) if output.status.success() => {
            add_forwarding_rule(&tun_name, &router_ip).await;

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

async fn run_command(command: &str, args: Vec<&str>) -> Result<(), Box<dyn Error>> {
    let result = Command::new(command)
        .args(args)
        .output()
        .await;

    match result {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => {
            eprintln!("Failed to execute {}: {:?}", command, output);
            Err(format!("Failed to execute {}: {:?}", command, output).into())
        }
        Err(e) => {
            eprintln!("Error executing {}: {}", command, e);
            Err(Box::new(e))
        }
    }
}

async fn add_forwarding_rule(interface: &str, router_ip: &Ipv4Addr) -> Result<(), Box<dyn Error>> {
    run_command("ip", vec!["route", "add", "0.0.0.0/0", "via", &router_ip.to_string(), "dev", interface]).await?;
    run_command("iptables", vec!["-t", "nat", "-A", "POSTROUTING", "-o", "wlan0", "-j", "MASQUERADE"]).await?;
    run_command("iptables", vec!["-A", "FORWARD", "-i", interface, "-o", "wlan0", "-j", "ACCEPT"]).await?;
    run_command("brctl", vec!["addif", "br0", interface]).await?;

    Ok(())
}

async fn remove_forwarding_rule(interface: &str, router_ip: &Ipv4Addr) -> Result<(), Box<dyn Error>> {
    run_command("ip", vec!["route", "del", "0.0.0.0/0", "via", &router_ip.to_string(), "dev", interface]).await?;
    run_command("iptables", vec!["-t", "nat", "-D", "POSTROUTING", "-o", "wlan0", "-j", "MASQUERADE"]).await?;
    run_command("iptables", vec!["-D", "FORWARD", "-i", interface, "-o", "wlan0", "-j", "ACCEPT"]).await?;
    run_command("brctl", vec!["delif", "br0", interface]).await?;

    Ok(())
}

//sudo apt-get install bridge-utils
pub async fn create_interface_bridge() -> Result<(), Box<dyn Error>> {

    let bridge_ip = Ipv4Addr::new(192, 168, 1, 99);
    let netmask = Ipv4Addr::new(255, 255, 255, 0);

    let router_ip = Ipv4Addr::new(192, 168, 1, 254);

    run_command("brctl", vec!["addbr", "br0"]).await?;
    run_command("ip", vec!["addr", "add", &format!("{}/{}", bridge_ip, netmask),"dev", "br0"]).await?;
    run_command("ip", vec!["route", "add", "default", "via", &router_ip.to_string(), "dev", "br0"]).await?;
    run_command("ip", vec!["link", "set", "br0", "up"]).await?;

    Ok(())
}