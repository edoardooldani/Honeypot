use serde::{Deserialize, Serialize};
use std::os::unix::raw::time_t;
use std::time::{SystemTime, UNIX_EPOCH};
use sha2::{Sha256, Digest};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Header {
    pub id: u32,
    pub timestamp: time_t,
    pub data_type: u8,                  
    pub priority: u8,                   
    pub mac_address: [u8; 6],           
    pub checksum: Option<[u8; 32]>      
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Payload {
    pub number_of_devices: u16
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Packet {
    pub header: Header,
    pub payload: Payload,
}


pub async fn build_packet(header: Header, payload: Payload) -> Packet{
    let packet_instance = Packet {
        header,
        payload
    };

    calculate_checksum(packet_instance).await
}

pub async fn calculate_checksum(mut packet: Packet) -> Packet {

    let payload_bytes = serde_json::to_vec(&packet.clone()).expect("Errore serializzazione payload");

    let mut hasher = Sha256::new();
    hasher.update(&payload_bytes);
    let checksum = hasher.finalize();

    packet.header.checksum = Some(checksum.into());

    packet
}


pub async fn verify_checksum(mut packet: Packet) -> bool {
    let checksum_received = packet.header.checksum;

    packet.header.checksum = None;
    let payload_bytes = serde_json::to_vec(&packet.clone()).expect("Errore serializzazione payload");

    let mut hasher = Sha256::new();
    hasher.update(&payload_bytes);
    let checksum_calculated = hasher.finalize();
    let checksum_calculated_array: Option<[u8; 32]> = Some(checksum_calculated.into());

    checksum_received==checksum_calculated_array

}


pub async fn calculate_header(id: u32, data_type: u8, priority: u8, mac_address: [u8; 6]) -> Header {

    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH)
        .expect("Errore nel calcolo del tempo");


    let header_instance = Header {
        id,
        timestamp: since_the_epoch.as_secs() as i64,
        data_type,
        priority,
        mac_address,
        checksum: None
    };

    header_instance
}

