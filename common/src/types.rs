use serde::{Deserialize, Serialize};
use crate::packet_features::PacketFeatures;


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
    Alert(AlertPayload),
    ArpAlert(ArpAlertPayload),
    TcpAlert(TcpAlertPayload)
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AlertPayload {
    pub mac_address: [u8; 6],
    pub ip_address: String,
    pub features: PacketFeatures,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ArpAlertPayload {
    pub mac_addresses: Vec<[u8; 6]>,
    pub ip_address: String,
    pub arp_attack_type: u8,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TcpAlertPayload {
    pub mac_address: [u8; 6],
    pub ip_address: String,
    pub dest_port: u16,
    pub tcp_attack_type: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceType {
    Honeypot = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataType {
    Alert = 1,
    ArpAlert = 2,
    TcpAlert = 3,
}

impl DataType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(DataType::Alert),
            2 => Some(DataType::ArpAlert),
            3 => Some(DataType::TcpAlert),
            _ => None,
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


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpAttackType {
    ArpScanning = 0,
    ArpPoisoning = 1,
    ArpFlooding = 2,
}

impl ArpAttackType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(ArpAttackType::ArpScanning),
            1 => Some(ArpAttackType::ArpPoisoning),
            2 => Some(ArpAttackType::ArpFlooding),
            _ => None,
        }
    }

    pub fn to_u8(&self) -> u8 {
        *self as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpAttackType {
    TcpSyn = 0,
}