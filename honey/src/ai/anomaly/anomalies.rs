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
    Bot = 1,
    DDoS = 2,
    DoSGoldenEye = 3,
    DoSHulk = 4,
    DoSSlowhttptest = 5,
    DoSSlowloris = 6,
    FTPPatator = 7,
    PortScan = 8,
    SSHPatator = 9,
    WebAttackBruteForce = 10,
}

impl AnomalyClassification {
    pub fn from_index(index: u8) -> Self {
        match index {
            1 => Self::Bot,
            2 => Self::DDoS,
            3 => Self::DoSGoldenEye,
            4 => Self::DoSHulk,
            5 => Self::DoSSlowhttptest,
            6 => Self::DoSSlowloris,
            7 => Self::FTPPatator,
            8 => Self::PortScan,
            9 => Self::SSHPatator,
            10 => Self::WebAttackBruteForce,
            _ => Self::Benign,
        }
    }

    pub fn to_index(self) -> u8 {
        self as u8
    }
}