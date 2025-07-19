use std::{time::Instant, u16};

use pnet::packet::{ipv4::Ipv4Packet, tcp::TcpPacket, Packet};
use crate::ai::features::flow::PacketDirection;
use tract_onnx::prelude::*;


#[derive(Debug, Clone)]
pub struct PacketFeatures {
    // Basic IP/TCP data
    pub src_port: u16,
    pub dst_port: u16,
    pub flow_duration: f64,              // in milliseconds

    // Packet counts
    pub tot_fwd_pkts: u32,
    pub tot_bwd_pkts: u32,

    // Byte totals
    pub totlen_fwd_pkts: u32,
    pub totlen_bwd_pkts: u32,

    // Forward packet length stats
    pub fwd_pkt_len_max: u16,
    pub fwd_pkt_len_min: u16,
    pub fwd_pkt_len_mean: f64,
    pub fwd_pkt_len_std: f64,

    // Backward packet length stats
    pub bwd_pkt_len_max: u16,
    pub bwd_pkt_len_min: u16,
    pub bwd_pkt_len_mean: f64,
    pub bwd_pkt_len_std: f64,

    // Flow rates
    pub flow_byts_per_s: f64,
    pub flow_pkts_per_s: f64,

    // Flow IAT
    pub flow_iat_mean: f64,
    pub flow_iat_std: f64,
    pub flow_iat_max: f64,
    pub flow_iat_min: f64,

    // Forward IAT
    pub fwd_iat_tot: f64,
    pub fwd_iat_mean: f64,
    pub fwd_iat_std: f64,
    pub fwd_iat_max: f64,
    pub fwd_iat_min: f64,

    // Backward IAT
    pub bwd_iat_tot: f64,
    pub bwd_iat_mean: f64,
    pub bwd_iat_std: f64,
    pub bwd_iat_max: f64,
    pub bwd_iat_min: f64,

    // Flag counts
    pub fwd_psh_flags: u32,
    pub bwd_psh_flags: u32,
    pub fwd_urg_flags: u32,
    pub bwd_urg_flags: u32,

    // Header lengths
    pub fwd_header_len: u32,
    pub bwd_header_len: u32,

    // Packet/s
    pub fwd_pkts_per_s: f64,
    pub bwd_pkts_per_s: f64,

    // Packet size stats
    pub pkt_len_min: u16,
    pub pkt_len_max: u16,
    pub pkt_len_mean: f64,
    pub pkt_len_std: f64,
    pub pkt_len_var: f64,

    // TCP Flags
    pub fin_flag_cnt: u32,
    pub syn_flag_cnt: u32,
    pub rst_flag_cnt: u32,
    pub psh_flag_cnt: u32,
    pub ack_flag_cnt: u32,
    pub urg_flag_cnt: u32,
    pub cwe_flag_cnt: u32,
    pub ece_flag_cnt: u32,

    // Directional ratios
    pub down_up_ratio: f64,

    // Segment size
    pub pkt_size_avg: f64,
    pub fwd_seg_size_avg: f64,
    pub bwd_seg_size_avg: f64,

    // Bulk / Rate stats
    pub fwd_byts_b_avg: f64,
    pub fwd_pkts_b_avg: f64,
    pub fwd_blk_rate_avg: f64,
    pub bwd_byts_b_avg: f64,
    pub bwd_pkts_b_avg: f64,
    pub bwd_blk_rate_avg: f64,

    // Subflow counters
    pub subflow_fwd_pkts: u32,
    pub subflow_fwd_byts: u32,
    pub subflow_bwd_pkts: u32,
    pub subflow_bwd_byts: u32,

    // Init window sizes
    pub init_fwd_win_byts: i16,
    pub init_bwd_win_byts: u16,

    // TCP data segments
    pub fwd_act_data_pkts: u32,
    pub fwd_seg_size_min: u16,

    // Active time windows
    pub active_mean: f64,
    pub active_std: f64,
    pub active_max: f64,
    pub active_min: f64,

    // Idle time windows
    pub idle_mean: f64,
    pub idle_std: f64,
    pub idle_max: f64,
    pub idle_min: f64,

    // Only for calculation purpose
    pub protocol: u8,
    fwd_pkt_len_sq_sum: f64,            
    bwd_pkt_len_sq_sum: f64,            
    pkt_len_sq_sum: f64,

    start_time: Option<std::time::Instant>,     
    end_time: Option<std::time::Instant>,     
    last_fwd_time: Option<std::time::Instant>,
    last_bwd_time: Option<std::time::Instant>, 

    fwd_bulk_start: Option<Instant>,
    fwd_bulk_bytes: u64,
    fwd_bulk_pkts: u32,
    fwd_bulk_duration: f64,

    bwd_bulk_start: Option<Instant>,
    bwd_bulk_bytes: u64,
    bwd_bulk_pkts: u32,
    bwd_bulk_duration: f64,

    packet_times: Vec<Instant>,
}

impl Default for PacketFeatures {
    fn default() -> Self {
        Self {
            src_port: 0,
            dst_port: 0,
            flow_duration: 0.0,

            tot_fwd_pkts: 0,
            tot_bwd_pkts: 0,

            totlen_fwd_pkts: 0,
            totlen_bwd_pkts: 0,

            fwd_pkt_len_max: 0,
            fwd_pkt_len_min: 0,
            fwd_pkt_len_mean: 0.0,
            fwd_pkt_len_std: 0.0,

            bwd_pkt_len_max: 0,
            bwd_pkt_len_min: 0,
            bwd_pkt_len_mean: 0.0,
            bwd_pkt_len_std: 0.0,

            flow_byts_per_s: 0.0,
            flow_pkts_per_s: 0.0,

            flow_iat_mean: 0.0,
            flow_iat_std: 0.0,
            flow_iat_max: 0.0,
            flow_iat_min: 0.0,

            fwd_iat_tot: 0.0,
            fwd_iat_mean: 0.0,
            fwd_iat_std: 0.0,
            fwd_iat_max: 0.0,
            fwd_iat_min: 10.0,

            bwd_iat_tot: 0.0,
            bwd_iat_mean: 0.0,
            bwd_iat_std: 0.0,
            bwd_iat_max: 0.0,
            bwd_iat_min: 10.0,

            fwd_psh_flags: 0,
            bwd_psh_flags: 0,
            fwd_urg_flags: 0,
            bwd_urg_flags: 0,

            fwd_header_len: 0,
            bwd_header_len: 0,

            fwd_pkts_per_s: 0.0,
            bwd_pkts_per_s: 0.0,

            pkt_len_min: 0,
            pkt_len_max: 0,
            pkt_len_mean: 0.0,
            pkt_len_std: 0.0,
            pkt_len_var: 0.0,

            fin_flag_cnt: 0,
            syn_flag_cnt: 0,
            rst_flag_cnt: 0,
            psh_flag_cnt: 0,
            ack_flag_cnt: 0,
            urg_flag_cnt: 0,
            cwe_flag_cnt: 0,
            ece_flag_cnt: 0,

            down_up_ratio: 0.0,

            pkt_size_avg: 0.0,
            fwd_seg_size_avg: 0.0,
            bwd_seg_size_avg: 0.0,

            fwd_byts_b_avg: 0.0,
            fwd_pkts_b_avg: 0.0,
            fwd_blk_rate_avg: 0.0,
            bwd_byts_b_avg: 0.0,
            bwd_pkts_b_avg: 0.0,
            bwd_blk_rate_avg: 0.0,

            subflow_fwd_pkts: 0,
            subflow_fwd_byts: 0,
            subflow_bwd_pkts: 0,
            subflow_bwd_byts: 0,

            init_fwd_win_byts: 0,
            init_bwd_win_byts: 0,

            fwd_act_data_pkts: 0,
            fwd_seg_size_min: 0,

            active_mean: 0.0,
            active_std: 0.0,
            active_max: 0.0,
            active_min: f64::MAX,

            idle_mean: 0.0,
            idle_std: 0.0,
            idle_max: 0.0,
            idle_min: 0.0,

            // Only for calculation purpose
            protocol: 0,
            fwd_pkt_len_sq_sum: 0.0,
            bwd_pkt_len_sq_sum: 0.0,
            pkt_len_sq_sum: 0.0,

            start_time: None,  
            end_time: None,     
            last_fwd_time: None,
            last_bwd_time: None,

            fwd_bulk_start: None,
            fwd_bulk_bytes: 0,
            fwd_bulk_pkts: 0,
            fwd_bulk_duration: 0.0,

            bwd_bulk_start: None,
            bwd_bulk_bytes: 0,
            bwd_bulk_pkts: 0,
            bwd_bulk_duration: 0.0,

            packet_times: vec![],
        }
    }
}

#[derive(Default)]
pub struct WindowStats {
    pub mean: f64,
    pub std: f64,
    pub max: f64,
    pub min: f64,
}


impl PacketFeatures {
    pub fn update_directional(&mut self, ip_packet: &Ipv4Packet,  dir: PacketDirection) {

        let now = Instant::now();
        self.update_timestamps_and_duration(now);
        self.update_flow_rates();

        let pkt_len = ip_packet.get_total_length() as u16;

        self.pkt_len_min = if self.pkt_len_min == 0 {
            pkt_len
        } else {
            self.pkt_len_min.min(pkt_len)
        };

        self.pkt_len_max = self.pkt_len_max.max(pkt_len);
        self.pkt_len_sq_sum += (pkt_len as f64).powi(2);

        self.update_flow_iat(dir); 

        match dir {
            PacketDirection::Forward => self.update_forward_metrics(pkt_len, now),
            PacketDirection::Backward => self.update_backward_metrics(pkt_len, now),
        }

        self.update_packet_length_stats();

        if self.protocol == 6 { 
            self.update_tcp_flags(ip_packet, dir);
        }

        if self.tot_fwd_pkts > 0 {
            self.down_up_ratio = self.tot_bwd_pkts as f64 / self.tot_fwd_pkts as f64;
        } else {
            self.down_up_ratio = 0.0;
        }

        self.update_bulk_stats();
        self.update_active_idle(1000.0);
    }

    fn update_timestamps_and_duration(&mut self, now: Instant) {
        self.packet_times.push(now);

        if self.start_time.is_none() {
            self.start_time = Some(now);
        }
        self.end_time = Some(now);

        self.flow_duration = self.start_time
            .and_then(|start| self.end_time.map(|end| end.duration_since(start).as_secs_f64() * 1000.0))
            .unwrap_or(0.0);
    }

    fn update_flow_rates(&mut self) {
        let duration_secs = self.flow_duration.max(1.0) / 1000.0;
        if duration_secs > 0.0001 {
            let total_bytes = self.totlen_fwd_pkts + self.totlen_bwd_pkts;
            let total_pkts = self.tot_fwd_pkts + self.tot_bwd_pkts;
            self.flow_byts_per_s = total_bytes as f64 / duration_secs;
            self.flow_pkts_per_s = total_pkts as f64 / duration_secs;
            self.fwd_pkts_per_s = self.tot_fwd_pkts as f64 / duration_secs;
            self.bwd_pkts_per_s = self.tot_bwd_pkts as f64 / duration_secs;
        } else {
            self.flow_byts_per_s = 0.0;
            self.flow_pkts_per_s = 0.0;
            self.fwd_pkts_per_s = 0.0;
            self.bwd_pkts_per_s = 0.0;
        }
    }

    fn update_packet_length_stats(&mut self) {
        let total_pkts = (self.tot_fwd_pkts + self.tot_bwd_pkts) as f64;

        if total_pkts > 0.0 {
            let total_len = (self.totlen_fwd_pkts + self.totlen_bwd_pkts) as f64;
            self.pkt_len_mean = total_len / total_pkts;
            self.pkt_len_var = (self.pkt_len_sq_sum / total_pkts) - self.pkt_len_mean.powi(2);
            self.pkt_len_std = self.pkt_len_var.sqrt();
            self.pkt_size_avg = total_len / total_pkts;
        }

        if self.tot_fwd_pkts > 0 {
            self.fwd_seg_size_avg = self.totlen_fwd_pkts as f64 / self.tot_fwd_pkts as f64;
        }
        if self.tot_bwd_pkts > 0 {
            self.bwd_seg_size_avg = self.totlen_bwd_pkts as f64 / self.tot_bwd_pkts as f64;
        }
    }

    fn update_tcp_flags(&mut self, ip_packet: &Ipv4Packet, dir: PacketDirection) {
        if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {
            let flags = tcp_packet.get_flags();

            if (flags & 0x01) != 0 { self.fin_flag_cnt += 1; }
            if (flags & 0x02) != 0 { self.syn_flag_cnt += 1; }
            if (flags & 0x04) != 0 { self.rst_flag_cnt += 1; }
            if (flags & 0x08) != 0 { self.psh_flag_cnt += 1; }
            if (flags & 0x10) != 0 { self.ack_flag_cnt += 1; }
            if (flags & 0x20) != 0 { self.urg_flag_cnt += 1; }
            if (flags & 0x40) != 0 { self.ece_flag_cnt += 1; }
            if (flags & 0x80) != 0 { self.cwe_flag_cnt += 1; }

            match dir {
                PacketDirection::Forward => {
                    if (flags & 0x08) != 0 { self.fwd_psh_flags += 1; }
                    if (flags & 0x20) != 0 { self.fwd_urg_flags += 1; }

                    self.fwd_header_len = ip_packet.get_header_length() as u32
                        + (tcp_packet.get_data_offset() * 4) as u32;

                    /* 
                    if self.init_fwd_win_byts == 0 {
                        self.init_fwd_win_byts = tcp_packet.get_window();
                    }
                    */
                    self.init_fwd_win_byts = -1;

                    if tcp_packet.payload().len() > 0 {
                        self.fwd_act_data_pkts += 1;
                    }
                }
                PacketDirection::Backward => {
                    if (flags & 0x08) != 0 { self.bwd_psh_flags += 1; }
                    if (flags & 0x20) != 0 { self.bwd_urg_flags += 1; }

                    self.bwd_header_len = ip_packet.get_header_length() as u32
                        + (tcp_packet.get_data_offset() * 4) as u32;
                    /* 
                    if self.init_bwd_win_byts == 0 {
                        self.init_bwd_win_byts = tcp_packet.get_window();
                    }
                    */
                    self.init_bwd_win_byts = 64240;

                }
            }
        }
    }

    fn update_flow_iat(&mut self, dir: PacketDirection) {
        let last_time = match dir {
            PacketDirection::Forward => self.last_fwd_time,
            PacketDirection::Backward => self.last_bwd_time,
        };

        if let (Some(end), Some(last)) = (self.end_time, last_time) {
            let iat = end.duration_since(last).as_secs_f64() * 1000.0;
            let total_pkts = self.tot_fwd_pkts + self.tot_bwd_pkts;

            if total_pkts > 1 {
                let prev_mean = self.flow_iat_mean;
                self.flow_iat_mean = (self.flow_iat_mean * (total_pkts as f64 - 1.0) + iat) / total_pkts as f64;
                self.flow_iat_std = (((self.flow_iat_std.powi(2) * (total_pkts as f64 - 1.0)
                    + (iat - prev_mean).powi(2)) / total_pkts as f64).max(0.0))
                    .sqrt();
            } else {
                self.flow_iat_mean = iat;
                self.flow_iat_std = 0.0;
            }

            self.flow_iat_max = self.flow_iat_max.max(iat);
            self.flow_iat_min = if self.flow_iat_min == 0.0 { iat } else { self.flow_iat_min.min(iat) };
        }
    }

    fn update_bulk_stats(&mut self) {
        if self.fwd_bulk_pkts > 0 && self.fwd_bulk_duration > 0.0 {
            self.fwd_byts_b_avg = self.fwd_bulk_bytes as f64 / self.fwd_bulk_pkts as f64;
            self.fwd_pkts_b_avg = self.fwd_bulk_pkts as f64 / self.fwd_bulk_duration;
            self.fwd_blk_rate_avg = self.fwd_bulk_bytes as f64 / self.fwd_bulk_duration;
        }

        if self.bwd_bulk_pkts > 0 && self.bwd_bulk_duration > 0.0 {
            self.bwd_byts_b_avg = self.bwd_bulk_bytes as f64 / self.bwd_bulk_pkts as f64;
            self.bwd_pkts_b_avg = self.bwd_bulk_pkts as f64 / self.bwd_bulk_duration;
            self.bwd_blk_rate_avg = self.bwd_bulk_bytes as f64 / self.bwd_bulk_duration;
        }
    }

    fn update_active_idle(&mut self, idle_threshold_ms: f64) {
        let mut actives = Vec::new();
        let mut idles = Vec::new();
        let mut current_active = 0.0;

        for i in 1..self.packet_times.len() {
            let delta = self.packet_times[i]
                .duration_since(self.packet_times[i - 1])
                .as_secs_f64() * 1000.0;

            if delta <= idle_threshold_ms {
                current_active += delta;
            } else {
                if current_active > 0.0 {
                    actives.push(current_active);
                    current_active = 0.0;
                }
                idles.push(delta);
            }
        }

        if current_active > 0.0 {
            actives.push(current_active);
        }

        fn calc_stats(vals: &[f64]) -> (f64, f64, f64, f64) {
            if vals.is_empty() {
                return (0.0, 0.0, 0.0, 0.0);
            }
            let n = vals.len() as f64;
            let sum: f64 = vals.iter().sum();
            let mean = sum / n;
            let var = vals.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n;
            let std = var.sqrt();
            let min = *vals.iter().min_by(|a, b| a.partial_cmp(b).unwrap()).unwrap();
            let max = *vals.iter().max_by(|a, b| a.partial_cmp(b).unwrap()).unwrap();
            (mean, std, min, max)
        }

        let (a_mean, a_std, a_min, a_max) = calc_stats(&actives);
        let (i_mean, i_std, i_min, i_max) = calc_stats(&idles);

        self.active_mean = a_mean;
        self.active_std  = a_std;
        self.active_min  = a_min;
        self.active_max  = a_max;

        self.idle_mean = i_mean;
        self.idle_std  = i_std;
        self.idle_min  = i_min;
        self.idle_max  = i_max;
    }

    fn update_forward_metrics(&mut self, pkt_len: u16, now: Instant) {
        const BULK_GAP_MS: f64 = 1.0;
        const SUBFLOW_TIMEOUT_MS: f64 = 1000.0;

        self.tot_fwd_pkts += 1;
        self.totlen_fwd_pkts += pkt_len as u32;
        self.fwd_pkt_len_sq_sum += (pkt_len as f64).powi(2);

        if pkt_len > self.fwd_pkt_len_max {
            self.fwd_pkt_len_max = pkt_len;
        }
        if self.fwd_pkt_len_min == 0 || pkt_len < self.fwd_pkt_len_min {
            self.fwd_pkt_len_min = pkt_len;
        }

        self.fwd_pkt_len_mean = self.totlen_fwd_pkts as f64 / self.tot_fwd_pkts as f64;
        self.fwd_pkt_len_std = ((self.fwd_pkt_len_sq_sum / self.tot_fwd_pkts as f64) - self.fwd_pkt_len_mean.powi(2)).sqrt();

        if let Some(prev) = self.last_fwd_time {
            let iat = now.duration_since(prev).as_secs_f64() * 1000.0;
            self.fwd_iat_tot += iat;

            let n = self.tot_fwd_pkts as f64;
            let prev_mean = self.fwd_iat_mean;
            self.fwd_iat_mean = ((n - 1.0) * self.fwd_iat_mean + iat) / n;
            self.fwd_iat_std = (((self.fwd_iat_std.powi(2) * (n - 1.0) + (iat - prev_mean).powi(2)) / n).max(0.0)).sqrt();

            self.fwd_iat_max = self.fwd_iat_max.max(iat);
            self.fwd_iat_min = if self.fwd_iat_min == 0.0 { iat } else { self.fwd_iat_min.min(iat) };

            let gap = iat;
            if gap > SUBFLOW_TIMEOUT_MS {
                self.subflow_fwd_pkts = 1;
                self.subflow_fwd_byts = pkt_len as u32;
            } else {
                self.subflow_fwd_pkts += 1;
                self.subflow_fwd_byts += pkt_len as u32;
            }

            if gap <= BULK_GAP_MS {
                self.fwd_bulk_bytes += pkt_len as u64;
                self.fwd_bulk_pkts += 1;
                if self.fwd_bulk_start.is_none() {
                    self.fwd_bulk_start = Some(prev);
                }
                if let Some(start) = self.fwd_bulk_start {
                    self.fwd_bulk_duration = now.duration_since(start).as_secs_f64();
                }
            } else {
                self.fwd_bulk_start = None;
            }
        } else {
            self.subflow_fwd_pkts = 1;
            self.subflow_fwd_byts = pkt_len as u32;
        }

        self.last_fwd_time = Some(now);
    }

    fn update_backward_metrics(&mut self, pkt_len: u16, now: Instant) {
        const BULK_GAP_MS: f64 = 1.0;
        const SUBFLOW_TIMEOUT_MS: f64 = 1000.0;

        self.tot_bwd_pkts += 1;
        self.totlen_bwd_pkts += pkt_len as u32;
        self.bwd_pkt_len_sq_sum += (pkt_len as f64).powi(2);

        if pkt_len > self.bwd_pkt_len_max {
            self.bwd_pkt_len_max = pkt_len;
        }
        if self.bwd_pkt_len_min == 0 || pkt_len < self.bwd_pkt_len_min {
            self.bwd_pkt_len_min = pkt_len;
        }
        self.bwd_pkt_len_mean = self.totlen_bwd_pkts as f64 / self.tot_bwd_pkts as f64;
        self.bwd_pkt_len_std = ((self.bwd_pkt_len_sq_sum / self.tot_bwd_pkts as f64) - self.bwd_pkt_len_mean.powi(2)).sqrt();

        if let Some(prev) = self.last_bwd_time {
            let iat = now.duration_since(prev).as_secs_f64() * 1000.0;
            self.bwd_iat_tot += iat;

            let n = self.tot_bwd_pkts as f64;
            let prev_mean = self.bwd_iat_mean;
            self.bwd_iat_mean = ((n - 1.0) * self.bwd_iat_mean + iat) / n;
            self.bwd_iat_std = (((self.bwd_iat_std.powi(2) * (n - 1.0) + (iat - prev_mean).powi(2)) / n).max(0.0)).sqrt();

            self.bwd_iat_max = self.bwd_iat_max.max(iat);
            self.bwd_iat_min = if self.bwd_iat_min == 0.0 { iat } else { self.bwd_iat_min.min(iat) };

            let gap = iat;
            if gap > SUBFLOW_TIMEOUT_MS {
                self.subflow_bwd_pkts = 1;
                self.subflow_bwd_byts = pkt_len as u32;
            } else {
                self.subflow_bwd_pkts += 1;
                self.subflow_bwd_byts += pkt_len as u32;
            }

            if gap <= BULK_GAP_MS {
                self.bwd_bulk_bytes += pkt_len as u64;
                self.bwd_bulk_pkts += 1;
                if self.bwd_bulk_start.is_none() {
                    self.bwd_bulk_start = Some(prev);
                }
                if let Some(start) = self.bwd_bulk_start {
                    self.bwd_bulk_duration = now.duration_since(start).as_secs_f64();
                }
            } else {
                self.bwd_bulk_start = None;
            }
        } else {
            self.subflow_bwd_pkts = 1;
            self.subflow_bwd_byts = pkt_len as u32;
        }

        self.last_bwd_time = Some(now);
    }

    pub fn to_autoencoder_tensor(&self) -> Tensor {
        let (proto_tcp, proto_udp, proto_icmp) = match self.protocol {
            6 => (1.0, 0.0, 0.0),
            17 => (0.0, 1.0, 0.0),
            0 => (0.0, 0.0, 1.0),
            _ => (0.0, 0.0, 0.0),
        };

        let input_data: Vec<f32> = vec![
            self.src_port as f32,           
            self.dst_port as f32, 
            self.flow_duration as f32,
            self.tot_fwd_pkts as f32,
            self.tot_bwd_pkts as f32,
            self.totlen_fwd_pkts as f32,
            self.totlen_bwd_pkts as f32,
            self.fwd_pkt_len_max as f32,
            self.fwd_pkt_len_min as f32,
            self.fwd_pkt_len_mean as f32,
            self.fwd_pkt_len_std as f32,
            self.bwd_pkt_len_max as f32,
            self.bwd_pkt_len_min as f32,
            self.bwd_pkt_len_mean as f32,
            self.bwd_pkt_len_std as f32,
            self.flow_byts_per_s as f32,
            self.flow_pkts_per_s as f32,
            self.flow_iat_mean as f32,
            self.flow_iat_std as f32,
            self.flow_iat_max as f32,
            self.flow_iat_min as f32,
            self.fwd_iat_tot as f32,
            self.fwd_iat_mean as f32,
            self.fwd_iat_std as f32,
            self.fwd_iat_max as f32,
            self.fwd_iat_min as f32,
            self.bwd_iat_tot as f32,
            self.bwd_iat_mean as f32,
            self.bwd_iat_std as f32,
            self.bwd_iat_max as f32,
            self.bwd_iat_min as f32,
            self.fwd_psh_flags as f32,
            self.bwd_psh_flags as f32,
            self.fwd_urg_flags as f32,
            self.bwd_urg_flags as f32,
            self.fwd_header_len as f32,
            self.bwd_header_len as f32,
            self.fwd_pkts_per_s as f32,
            self.bwd_pkts_per_s as f32,
            self.pkt_len_min as f32,
            self.pkt_len_max as f32,
            self.pkt_len_mean as f32,
            self.pkt_len_std as f32,
            self.pkt_len_var as f32,
            self.fin_flag_cnt as f32,
            self.syn_flag_cnt as f32,
            self.rst_flag_cnt as f32,
            self.psh_flag_cnt as f32,
            self.ack_flag_cnt as f32,
            self.urg_flag_cnt as f32,
            self.cwe_flag_cnt as f32,
            self.ece_flag_cnt as f32,
            self.down_up_ratio as f32,
            self.pkt_size_avg as f32,
            self.fwd_seg_size_avg as f32,
            self.bwd_seg_size_avg as f32,
            //self.fwd_header_len as u32,   only for anomaly classification
            self.fwd_byts_b_avg as f32,
            self.fwd_pkts_b_avg as f32,
            self.fwd_blk_rate_avg as f32,
            self.bwd_byts_b_avg as f32,
            self.bwd_pkts_b_avg as f32,
            self.bwd_blk_rate_avg as f32,
            self.subflow_fwd_pkts as f32,
            self.subflow_fwd_byts as f32,
            self.subflow_bwd_pkts as f32,
            self.subflow_bwd_byts as f32,
            self.init_fwd_win_byts as f32,
            self.init_bwd_win_byts as f32,
            self.fwd_act_data_pkts as f32,
            self.fwd_seg_size_min as f32,
            self.active_mean as f32,
            self.active_std as f32,
            self.active_max as f32,
            self.active_min as f32,
            self.idle_mean as f32,
            self.idle_std as f32,
            self.idle_max as f32,
            self.idle_min as f32,
            proto_icmp,
            proto_tcp,
            proto_udp,
        ];
        
        debug_assert_eq!(input_data.len(), 81);
        tract_ndarray::Array2::from_shape_vec((1, input_data.len()), input_data)
            .unwrap()
            .into()
    }

    pub fn to_classifier_tensor(&self) -> Tensor {
        let fwd_header_len_1 = self.fwd_header_len;
        let input_data: Vec<f32> = vec![
            self.dst_port as f32, 
            self.flow_duration as f32,
            self.tot_fwd_pkts as f32,
            self.tot_bwd_pkts as f32,
            self.totlen_fwd_pkts as f32,
            self.totlen_bwd_pkts as f32,

            self.fwd_pkt_len_max as f32,
            self.fwd_pkt_len_min as f32,
            self.fwd_pkt_len_mean as f32,
            self.fwd_pkt_len_std as f32,
            self.bwd_pkt_len_max as f32,
            self.bwd_pkt_len_min as f32,
            self.bwd_pkt_len_mean as f32,
            self.bwd_pkt_len_std as f32,

            self.flow_byts_per_s as f32,
            self.flow_pkts_per_s as f32,

            self.flow_iat_mean as f32,
            self.flow_iat_std as f32,
            self.flow_iat_max as f32,
            self.flow_iat_min as f32,

            self.fwd_iat_tot as f32,
            self.fwd_iat_mean as f32,
            self.fwd_iat_std as f32,
            self.fwd_iat_max as f32,
            self.fwd_iat_min as f32,

            self.bwd_iat_tot as f32,
            self.bwd_iat_mean as f32,
            self.bwd_iat_std as f32,
            self.bwd_iat_max as f32,
            self.bwd_iat_min as f32,

            self.fwd_psh_flags as f32,
            self.bwd_psh_flags as f32,
            self.fwd_urg_flags as f32,
            self.bwd_urg_flags as f32,

            self.fwd_header_len as f32,
            self.bwd_header_len as f32,

            self.fwd_pkts_per_s as f32,
            self.bwd_pkts_per_s as f32,

            self.pkt_len_min as f32,
            self.pkt_len_max as f32,
            self.pkt_len_mean as f32,
            self.pkt_len_std as f32,
            self.pkt_len_var as f32,

            self.fin_flag_cnt as f32,
            self.syn_flag_cnt as f32,
            self.rst_flag_cnt as f32,
            self.psh_flag_cnt as f32,
            self.ack_flag_cnt as f32,
            self.urg_flag_cnt as f32,
            self.cwe_flag_cnt as f32,
            self.ece_flag_cnt as f32,

            self.down_up_ratio as f32,
            self.pkt_size_avg as f32,
            self.fwd_seg_size_avg as f32,
            self.bwd_seg_size_avg as f32,
            fwd_header_len_1 as f32,
            self.fwd_byts_b_avg as f32,
            self.fwd_pkts_b_avg as f32,
            self.fwd_blk_rate_avg as f32,
            self.bwd_byts_b_avg as f32,
            self.bwd_pkts_b_avg as f32,
            self.bwd_blk_rate_avg as f32,
            self.subflow_fwd_pkts as f32,
            self.subflow_fwd_byts as f32,
            self.subflow_bwd_pkts as f32,
            self.subflow_bwd_byts as f32,
            self.init_fwd_win_byts as f32,
            self.init_bwd_win_byts as f32,
            self.fwd_act_data_pkts as f32,
            self.fwd_seg_size_min as f32,
            self.active_mean as f32,
            self.active_std as f32,
            self.active_max as f32,
            self.active_min as f32,
            self.idle_mean as f32,
            self.idle_std as f32,
            self.idle_max as f32,
            self.idle_min as f32,
        ];
        
        debug_assert_eq!(input_data.len(), 78);
        tract_ndarray::Array2::from_shape_vec((1, input_data.len()), input_data)
            .unwrap()
            .into()
    }

}
