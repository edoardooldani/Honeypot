use std::{net::Ipv4Addr, process::Command, sync::Arc};
#[cfg(target_os = "linux")]
use tokio_tun::Tun;
use tracing::info;

pub fn create_virtual_tun_interface(ipv4_address: Ipv4Addr) {

    let last_octet = ipv4_address.octets()[3];
    let tun_name = format!("tun{}", last_octet);
    let netmask = "255.255.255.0".parse::<Ipv4Addr>().expect("Error parsing netmask");

    let tun = Arc::new(
        Tun::builder()
            .name(&tun_name)            
            .address(ipv4_address)
            .netmask(netmask)
            .up()                
            .build()
            .unwrap()
            .pop()
            .unwrap(),
    );
    add_iptables_rule(&tun_name);
    info!("TUN interface created: {tun_name}")

}



fn add_iptables_rule(tun_interface: &str) -> Result<(), String> {
    let check_result = Command::new("sudo")
        .arg("iptables")
        .arg("-C")
        .arg("FORWARD")
        .arg("-i")
        .arg(tun_interface)
        .arg("-o")
        .arg("main_tun")  
        .arg("-j")
        .arg("ACCEPT")
        .output()
        .map_err(|e| format!("Errore nell'esecuzione di iptables: {}", e))?;

    if check_result.status.success() {
        println!("La regola è già presente.");
        return Ok(());
    }

    let result = Command::new("sudo")
        .arg("iptables")
        .arg("-A")
        .arg("FORWARD")
        .arg("-i")
        .arg(tun_interface)
        .arg("-o")
        .arg("main_tun")
        .arg("-j")
        .arg("ACCEPT")
        .output()
        .map_err(|e| format!("Errore nell'esecuzione di iptables: {}", e))?;

    if !result.status.success() {
        return Err(format!("Comando iptables non riuscito: {}", String::from_utf8_lossy(&result.stderr)));
    }
    
    Ok(())
}