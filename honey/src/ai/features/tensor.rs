use tract_onnx::tract_core::ndarray::Array2;
use tract_onnx::{prelude::*, tract_core::ndarray::ArrayView2};
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ScalerParams {
    mean: Vec<f64>,
    scale: Vec<f64>,
    columns: Vec<String>,
}

fn get_feature_index_map_autoencoder() -> HashMap<String, usize> {
    vec![
        "src_port", "dst_port", "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts",
        "totlen_fwd_pkts", "totlen_bwd_pkts", "fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_mean",
        "fwd_pkt_len_std", "bwd_pkt_len_max", "bwd_pkt_len_min", "bwd_pkt_len_mean", "bwd_pkt_len_std",
        "flow_byts_per_s", "flow_pkts_per_s", "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
        "fwd_iat_tot", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",
        "bwd_iat_tot", "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min",
        "fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags",
        "fwd_header_len", "bwd_header_len", "fwd_pkts_per_s", "bwd_pkts_per_s",
        "pkt_len_min", "pkt_len_max", "pkt_len_mean", "pkt_len_std", "pkt_len_var",
        "fin_flag_cnt", "syn_flag_cnt", "rst_flag_cnt", "psh_flag_cnt", "ack_flag_cnt",
        "urg_flag_cnt", "cwe_flag_count", "ece_flag_cnt", "down_up_ratio",
        "pkt_size_avg", "fwd_seg_size_avg", "bwd_seg_size_avg", "fwd_byts_b_avg",
        "fwd_pkts_b_avg", "fwd_blk_rate_avg", "bwd_byts_b_avg", "bwd_pkts_b_avg",
        "bwd_blk_rate_avg", "subflow_fwd_pkts", "subflow_fwd_byts", "subflow_bwd_pkts",
        "subflow_bwd_byts", "init_fwd_win_byts", "init_bwd_win_byts", "fwd_act_data_pkts",
        "fwd_seg_size_min", "active_mean", "active_std", "active_max", "active_min",
        "idle_mean", "idle_std", "idle_max", "idle_min",
        "protocol_0", "protocol_6", "protocol_17"
    ]
    .into_iter()
    .enumerate()
    .map(|(i, name)| (name.to_string(), i))
    .collect()
}

fn get_feature_index_map_classifier() -> HashMap<String, usize> {
    let columns = vec![
        "dst_port", "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts",
        "totlen_fwd_pkts", "totlen_bwd_pkts", "fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_mean",
        "fwd_pkt_len_std", "bwd_pkt_len_max", "bwd_pkt_len_min", "bwd_pkt_len_mean", "bwd_pkt_len_std",
        "flow_byts_per_s", "flow_pkts_per_s", "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
        "fwd_iat_tot", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",
        "bwd_iat_tot", "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min",
        "fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags",
        "fwd_header_len", "bwd_header_len", "fwd_pkts_per_s", "bwd_pkts_per_s",
        "pkt_len_min", "pkt_len_max", "pkt_len_mean", "pkt_len_std", "pkt_len_var",
        "fin_flag_cnt", "syn_flag_cnt", "rst_flag_cnt", "psh_flag_cnt", "ack_flag_cnt",
        "urg_flag_cnt", "cwe_flag_count", "ece_flag_cnt", "down_up_ratio",
        "pkt_size_avg", "fwd_seg_size_avg", "bwd_seg_size_avg", "fwd_header_len", "fwd_byts_b_avg",
        "fwd_pkts_b_avg", "fwd_blk_rate_avg", "bwd_byts_b_avg", "bwd_pkts_b_avg",
        "bwd_blk_rate_avg", "subflow_fwd_pkts", "subflow_fwd_byts", "subflow_bwd_pkts",
        "subflow_bwd_byts", "init_fwd_win_byts", "init_bwd_win_byts", "fwd_act_data_pkts",
        "fwd_seg_size_min", "active_mean", "active_std", "active_max", "active_min",
        "idle_mean", "idle_std", "idle_max", "idle_min"
    ];

    columns.iter().enumerate().map(|(i, name)| (name.to_string(), i)).collect()
}

pub fn normalize_tensor(tensor: Tensor, scaler_path: &str, model: bool) -> TractResult<Tensor> {
    let file = File::open(scaler_path).expect("Impossibile aprire scaler_params.json");
    let reader = BufReader::new(file);
    let scaler: ScalerParams = serde_json::from_reader(reader).expect("Errore nel parsing JSON");

    let array: ArrayView2<f32> = tensor.to_array_view::<f32>()?.into_dimensionality()?;

    let shape = array.shape();
    assert_eq!(shape.len(), 2);
    let input = array.row(0).to_vec(); // 1D: len == 81

    let feature_index_map: HashMap<String, usize>;
    if model {
        feature_index_map = get_feature_index_map_autoencoder();
    }else {
        feature_index_map = get_feature_index_map_classifier();
    }
    
    let mut normalized = input.clone();

    for (i, feature_name) in scaler.columns.iter().enumerate() {
        if let Some(&idx) = feature_index_map.get(feature_name) {
            let mean = scaler.mean[i];
            let scale = scaler.scale[i];
            let val = input[idx] as f64;
            normalized[idx] = if scale.abs() < 1e-8 {
                0.0
            } else {
                ((val - mean) / scale) as f32
            };
        }
    }

    let norm_array = Array2::from_shape_vec((1, normalized.len()), normalized).unwrap();
    Ok(norm_array.into())
}