use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Header {
    pub id: u32,
    pub timestamp: u64,
    pub data_type: u8,                  
    pub priority: u8,                   
    pub mac_address: [u8; 6],           
    pub checksum: Option<[u8; 32]>      
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Packet {
    pub header: Header,

    pub payload: PayloadType,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
//#[serde(tag = "type", content = "data")] 
pub enum PayloadType {
    Process(ProcessPayload),
    Network(NetworkPayload),
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
pub struct NetworkPayload {
    pub protocol: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dest_ip: String,
    pub dest_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    Honeypot = 1,
    Process = 2,
    EBPF = 3,
}

impl DeviceType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(DeviceType::Honeypot),
            2 => Some(DeviceType::Process),
            3 => Some(DeviceType::EBPF),
            _ => None, // Valore non valido
        }
    }

    pub fn to_u8(&self) -> u8 {
        *self as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]

pub enum DataType {
    Network = 1,
    Process = 2,
}

impl DataType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(DataType::Network),
            2 => Some(DataType::Process),
            _ => None, // Valore non valido
        }
    }

    pub fn to_u8(&self) -> u8 {
        *self as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PriorityLevel {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

impl PriorityLevel {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(PriorityLevel::Low),
            1 => Some(PriorityLevel::Medium),
            2 => Some(PriorityLevel::High),
            3 => Some(PriorityLevel::Critical),
            _ => None,
        }
    }

    pub fn to_u8(&self) -> u8 {
        *self as u8
    }
}