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
    pub init_fwd_win_byts: u16,
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
            fwd_iat_min: 0.0,

            bwd_iat_tot: 0.0,
            bwd_iat_mean: 0.0,
            bwd_iat_std: 0.0,
            bwd_iat_max: 0.0,
            bwd_iat_min: 0.0,

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
            active_min: 0.0,

            idle_mean: 0.0,
            idle_std: 0.0,
            idle_max: 0.0,
            idle_min: 0.0,
        }
    }
}
/* 
impl PacketFeatures {
    pub fn new(src_port: u16, dst_port: u16) -> Self {
        Self {
            src_port,
            dst_port,
            ..Default::default()
        }
    }
}
    */