use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketDirection {
    Forward,
    Backward,
}

#[derive(Debug, Clone)]
pub struct FlowPacket {
    pub timestamp: Instant,
    pub length: usize,
    pub direction: PacketDirection,
    pub flags: Option<u8>, 
}

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct FlowKey {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone)]
pub struct FlowStats {
    pub packets: Vec<FlowPacket>,
    pub start_time: Instant,
    pub last_seen: Instant,
    pub forward_addr: String,
    pub backward_addr: String,
}

pub struct FlowTracker {
    pub flows: HashMap<FlowKey, FlowStats>,
    pub timeout: Duration,
    pub max_packets: usize,
}

impl FlowTracker {
    pub fn update_flow(&mut self, key: FlowKey, packet: FlowPacket) -> Option<FlowStats> {
        let now = Instant::now();

        let flow = self.flows.entry(key.clone()).or_insert_with(|| FlowStats {
            start_time: packet.timestamp,
            last_seen: packet.timestamp,
            packets: Vec::new(),
            forward_addr: key.src_ip.clone(),
            backward_addr: key.dst_ip.clone(),
        });

        flow.last_seen = now;
        flow.packets.push(packet.clone());

        // 💥 Controllo chiusura esplicita (FIN o RST)
        if let Some(flags) = packet.flags {
            let fin = flags & 0x01 != 0;
            let rst = flags & 0x04 != 0;

            if fin || rst {
                let finished = flow.clone();
                self.flows.remove(&key);
                return Some(finished);
            }
        }

        // ⏱️ Timeout
        if now.duration_since(flow.last_seen) > self.timeout {
            let finished = flow.clone();
            self.flows.remove(&key);
            return Some(finished);
        }

        // 📦 Limite pacchetti
        if flow.packets.len() >= self.max_packets {
            let finished = flow.clone();
            self.flows.remove(&key);
            return Some(finished);
        }

        None
    }
}