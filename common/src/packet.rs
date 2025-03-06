use crate::types::{Header, ProcessPayload, Packet};
use std::time::{SystemTime, UNIX_EPOCH};
use sha2::{Sha256, Digest};


impl Packet {
    pub fn verify_checksum(&mut self) -> bool {
        let checksum_received = self.header.checksum;

        self.header.checksum = None;
        let payload_bytes = serde_json::to_vec(&self.clone()).expect("Errore serializzazione payload");
    
        let mut hasher = Sha256::new();
        hasher.update(&payload_bytes);
        let checksum_calculated = hasher.finalize();
        let checksum_calculated_array: Option<[u8; 32]> = Some(checksum_calculated.into());

        self.header.checksum=checksum_received;
        checksum_received==checksum_calculated_array
    }

    pub fn calculate_checksum(&mut self) {

        let payload_bytes = serde_json::to_vec(&self.clone()).expect("Errore serializzazione payload");
    
        let mut hasher = Sha256::new();
        hasher.update(&payload_bytes);
        let checksum = hasher.finalize();
    
        self.header.checksum = Some(checksum.into());

    }
}


pub fn build_packet(header: Header, payload: ProcessPayload) -> Packet{
    let mut packet_instance = Packet {
        header,
        payload
    };
    packet_instance.calculate_checksum();
    packet_instance
}


pub fn calculate_header(id: u32, data_type: u8, priority: u8, mac_address: [u8; 6]) -> Header {

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