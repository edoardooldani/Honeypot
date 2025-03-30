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

    tokio::spawn(async move {
        change_mac_tun(&tun_name, virtual_mac, &router_ip).await;
        
        let sliced = reply_packet.as_slice();
        let bytes: usize = tun_writer.send(sliced).await.expect("No bytes sent");

        println!("Bytes sent: {:?}", bytes);
        run_command("brctl", vec!["delif", "br0", &tun_name]).await;

        //remove_forwarding_rule(&tun_name, &router_ip).await;
    });
    

}


async fn change_mac_tun(tun_name: &str, virtual_mac: MacAddr, router_ip: &Ipv4Addr){
    run_command("ifconfig", vec![tun_name, "hw", "ether", &virtual_mac.to_string()]).await;
    run_command("brctl", vec!["addif", "br0", tun_name]).await;
    run_command("ebtables", vec!["-t", "broute", "-A", "BROUTING", "-i", tun_name, "-j", "ACCEPT"]).await;

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

pub async fn create_bridge_interface() {
    run_command("brctl", vec!["addbr", "br0"]).await;
    run_command("brctl", vec!["addif", "br0", "eth0"]).await;
    run_command("ip", vec!["link", "set", "br0", "up"]).await;
}
