use serde::{Deserialize, Serialize};
use std::os::unix::raw::time_t;

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
