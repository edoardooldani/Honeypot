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
    let result = run_command("iptables", vec!["-L", "-n", "-v"]).await;

    match result {
        Ok(output) => {
            println!("Command output: {}", output);
        },
        Err(e) => {
        }
    }

    remove_forwarding_rule(&tun_name, &router_ip).await;

}


async fn change_mac_tun(tun_name: &str, virtual_mac: MacAddr, router_ip: &Ipv4Addr){
    run_command("ifconfig", vec![tun_name, "hw", "ether", &virtual_mac.to_string()]);
    add_forwarding_rule(&tun_name, &router_ip).await;

}


async fn add_forwarding_rule(interface: &str, router_ip: &Ipv4Addr) -> Result<(), Box<dyn Error>> {
    run_command("iptables", vec!["-A", "FORWARD", "-i", interface, "-o", "eth0", "-j", "ACCEPT"]).await?;
    run_command("iptables", vec!["-A", "FORWARD", "-i", "eth0", "-o", interface, "-j", "ACCEPT"]).await?;

    println!("\nList: {}", run_command("iptables", vec!["-L", "-n", "-v"]).await?);

    Ok(())
}

async fn remove_forwarding_rule(interface: &str, router_ip: &Ipv4Addr) -> Result<(), Box<dyn Error>> {
    run_command("iptables", vec!["-D", "FORWARD", "-i", interface, "-o", "eth0", "-j", "ACCEPT"]).await?;
    run_command("iptables", vec!["-D", "FORWARD", "-i", "eth0", "-o", interface, "-j", "ACCEPT"]).await?;

    Ok(())
}



pub async fn run_command(command: &str, args: Vec<&str>) -> Result<String, Box<dyn Error>> {
    let result = Command::new(command)
        .args(args)
        .output()
        .await;

    match result {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            Ok(stdout.to_string())
        },
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