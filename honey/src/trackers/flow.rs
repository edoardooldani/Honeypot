use std::collections::HashMap;
use crate::ai::features::PacketFeatures;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketDirection {
    Forward,
    Backward,
}

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct FlowKey {
    pub ip_src: String,
    pub ip_dst: String,
    pub port_src: u16,
    pub port_dst: u16,
    pub protocol: u8,
}

pub struct FlowTracker {
    pub flows: HashMap<FlowKey, PacketFeatures>,
}

impl FlowTracker {
    pub fn get_flow_or_insert(&mut self, key: FlowKey) -> &PacketFeatures {
        self.flows.entry(key).or_insert_with(PacketFeatures::default)
    }
}