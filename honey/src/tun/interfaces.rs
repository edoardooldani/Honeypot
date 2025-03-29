use std::{collections::HashMap, fmt, net::Ipv4Addr, process::Command, sync::{Arc, RwLock, Mutex}};
#[cfg(target_os = "linux")]
use tokio_tun::Tun;
use tracing::{info, error};
use once_cell::sync::Lazy;

use crate::virtual_net::graph::NetworkGraph;


pub async fn create_virtual_tun_interface(ipv4_address: Ipv4Addr) -> Arc<Tun>{

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
            .unwrap()
    );
    let _ = add_iptables_rule(&tun_name);

    info!("TUN interface created: {tun_name}");

    tun
}

// Funzione per aggiungere regole iptables per il forwarding
fn add_iptables_rule(tun_interface: &str) -> Result<(), String> {
    // Controlla se la regola esiste già
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
        return Ok(());
    }

    // Se la regola non esiste, aggiungila
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
        error!("Couldn't launch iptables command!");
        return Err(format!("Comando iptables non riuscito: {}", String::from_utf8_lossy(&result.stderr)));
    }

    // Attiva il NAT (Network Address Translation) per la main_tun
    let nat_result = Command::new("sudo")
        .arg("iptables")
        .arg("-t")
        .arg("nat")
        .arg("-A")
        .arg("POSTROUTING")
        .arg("-o")
        .arg("main_tun")
        .arg("-j")
        .arg("MASQUERADE")
        .output()
        .map_err(|e| format!("Errore nell'esecuzione di iptables (NAT): {}", e))?;

    if !nat_result.status.success() {
        error!("Couldn't launch iptables NAT command!");
        return Err(format!("Comando iptables NAT non riuscito: {}", String::from_utf8_lossy(&nat_result.stderr)));
    }

    // Abilita il forwarding IP
    let forwarding_result = Command::new("sudo")
        .arg("sysctl")
        .arg("-w")
        .arg("net.ipv4.ip_forward=1")
        .output()
        .map_err(|e| format!("Errore nell'attivazione del forwarding IP: {}", e))?;

    if !forwarding_result.status.success() {
        error!("Couldn't enable IP forwarding!");
        return Err(format!("Errore nell'attivazione del forwarding IP: {}", String::from_utf8_lossy(&forwarding_result.stderr)));
    }

    Ok(())
}