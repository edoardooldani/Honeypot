use std::time::SystemTime;
use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct Anomaly {
    pub src_ip: Option<Ipv4Addr>,
    pub dst_ip: Option<Ipv4Addr>,
    pub protocol: u8,
    pub timestamp: SystemTime,
    pub classification: AnomalyClassification
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AnomalyClassification {
    Benign = 0,
    DDoS = 1,
    DoSGoldenEye = 2,
    DoSHulk = 3,
    DoSSlowhttptest = 4,
    DoSSlowloris = 5,
    FTPPatator = 6,
    PortScan = 7,
}

impl AnomalyClassification {
    pub fn from_index(index: u8) -> Self {
        match index {
            1 => Self::DDoS,
            2 => Self::DoSGoldenEye,
            3 => Self::DoSHulk,
            4 => Self::DoSSlowhttptest,
            5 => Self::DoSSlowloris,
            6 => Self::FTPPatator,
            7 => Self::PortScan,
            _ => Self::Benign,
        }
    }

    pub fn to_index(self) -> u8 {
        self as u8
    }
}