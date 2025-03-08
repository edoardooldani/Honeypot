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
#[serde(tag = "type")]
pub enum Payload {
    ProcessPayload(ProcessPayload),
    // Aggiungi altri tipi di payload qui se necessario
}


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProcessPayload {
    pub process_id: u32,
    pub process_name: String,
    pub path: String,
    pub virtual_size: u64,
    pub resident_size: u64,
    pub syscalls_unix: i32,
    pub syscalls_mach: i32,
    pub faults: i32,
    pub pageins: i32,
    pub cow_faults: i32,
    pub messages_sent: i32,
    pub messages_received: i32,
    pub csw: i32,
    pub threadnum: i32,
    pub numrunning: i32,
    pub priority: i32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Packet {
    pub header: Header,
    pub payload: ProcessPayload,
}


