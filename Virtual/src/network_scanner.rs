use pnet::datalink::{self, Channel, NetworkInterface};
use pnet::packet::arp::{ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket, EtherTypes};
use pnet::packet::Packet;
use tracing::info;
use std::net::Ipv4Addr;
use std::time::Duration;
use std::collections::HashSet;
use std::thread;
use tokio_tungstenite::tungstenite::protocol::Message;
use std::sync::{Arc, Mutex};


fn get_primary_interface() -> Option<NetworkInterface> {
    let interfaces = datalink::interfaces();

    interfaces
        .into_iter()
        .filter(|iface| !iface.is_loopback() && !iface.ips.is_empty())
        .find(|iface| iface.mac.is_some()) // Deve avere un indirizzo MAC valido
}


pub async fn scan_local_network(_tx: futures_channel::mpsc::UnboundedSender<Message>, _session_id: Arc<Mutex<u32>>) -> HashSet<Ipv4Addr> {
    let interface = get_primary_interface().expect("Nessuna interfaccia valida trovata");
    let my_ip = match interface.ips.iter().find(|ip| ip.is_ipv4()) {
        Some(ip) => match ip.ip() {
            std::net::IpAddr::V4(ipv4) => ipv4,
            _ => panic!("Non è un indirizzo IPv4 valido"),
        },
        None => panic!("Non ci sono IP assegnati all'interfaccia"),
    };

    let mac = interface.mac.unwrap();
    let subnet = (my_ip.octets()[0], my_ip.octets()[1], my_ip.octets()[2]);


    let (tx_datalink, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Tipo di canale non supportato"),
        Err(e) => panic!("Errore nell'apertura del canale: {}", e),
    };

    let tx_arc = Arc::new(Mutex::new(tx_datalink));

    let mut discovered_ips = HashSet::new();
    let mut handles = vec![];

    for i in 1..=254 {
        let target_ip = Ipv4Addr::new(subnet.0, subnet.1, subnet.2, i);
        let tx_clone = Arc::clone(&tx_arc); 
        let my_mac = mac.clone();
    
        let handle = thread::spawn(move || {
            let mut tx_lock = tx_clone.lock().unwrap(); 
            send_arp_request(&mut **tx_lock, my_mac, my_ip, target_ip); 
        });
    
        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.join();
    }

    let timeout = Duration::from_secs(3);
    let start_time = std::time::Instant::now();

    while start_time.elapsed() < timeout {
        match rx.next() {
            Ok(packet) => {
                if let Some(ethernet_packet) = EthernetPacket::new(packet) {
                    if ethernet_packet.get_ethertype() == EtherTypes::Arp {
                        if let Some(arp_packet) = ArpPacket::new(ethernet_packet.payload()) {
                            if arp_packet.get_operation() == ArpOperations::Reply {
                                discovered_ips.insert(arp_packet.get_sender_proto_addr());
                            }
                        }
                    }
                }
            }
            Err(_) => break,
        }
    }
    info!("🔎 Dispositivi trovati: {:?}", discovered_ips);
    discovered_ips
}


fn send_arp_request(tx: &mut dyn datalink::DataLinkSender, my_mac: pnet::util::MacAddr, my_ip: Ipv4Addr, target_ip: Ipv4Addr) {
    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
    ethernet_packet.set_destination(pnet::util::MacAddr::broadcast());
    ethernet_packet.set_source(my_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
    arp_packet.set_hardware_type(pnet::packet::arp::ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(my_mac);
    arp_packet.set_sender_proto_addr(my_ip);
    arp_packet.set_target_hw_addr(pnet::util::MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);

    ethernet_packet.set_payload(&arp_buffer);

    tx.send_to(ethernet_packet.packet(), None).unwrap().unwrap();
}
