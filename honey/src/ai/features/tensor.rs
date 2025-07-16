use tract_onnx::tract_core::ndarray::Array2;
use tract_onnx::{prelude::*, tract_core::ndarray::ArrayView2};
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use serde::Deserialize;

pub fn print_tensor(tensor: &Tensor) {
    let array: ArrayView2<f32> = tensor.to_array_view::<f32>().unwrap().into_dimensionality::<tract_ndarray::Ix2>().unwrap();
    for row in array.rows() {
        println!("{:?}", row);
    }
}
    

#[derive(Debug, Deserialize)]
struct ScalerParams {
    mean: Vec<f64>,
    scale: Vec<f64>,
    columns: Vec<String>,
}

fn get_feature_index_map() -> HashMap<String, usize> {
    vec![
        "Src Port", "Dst Port", "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts",
        "TotLen Fwd Pkts", "TotLen Bwd Pkts", "Fwd Pkt Len Max", "Fwd Pkt Len Min", "Fwd Pkt Len Mean",
        "Fwd Pkt Len Std", "Bwd Pkt Len Max", "Bwd Pkt Len Min", "Bwd Pkt Len Mean", "Bwd Pkt Len Std",
        "Flow Byts/s", "Flow Pkts/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
        "Fwd IAT Tot", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
        "Bwd IAT Tot", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
        "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
        "Fwd Header Len", "Bwd Header Len", "Fwd Pkts/s", "Bwd Pkts/s",
        "Pkt Len Min", "Pkt Len Max", "Pkt Len Mean", "Pkt Len Std", "Pkt Len Var",
        "FIN Flag Cnt", "SYN Flag Cnt", "RST Flag Cnt", "PSH Flag Cnt", "ACK Flag Cnt",
        "URG Flag Cnt", "CWE Flag Count", "ECE Flag Cnt", "Down/Up Ratio",
        "Pkt Size Avg", "Fwd Seg Size Avg", "Bwd Seg Size Avg", "Fwd Byts/b Avg",
        "Fwd Pkts/b Avg", "Fwd Blk Rate Avg", "Bwd Byts/b Avg", "Bwd Pkts/b Avg",
        "Bwd Blk Rate Avg", "Subflow Fwd Pkts", "Subflow Fwd Byts", "Subflow Bwd Pkts",
        "Subflow Bwd Byts", "Init Fwd Win Byts", "Init Bwd Win Byts", "Fwd Act Data Pkts",
        "Fwd Seg Size Min", "Active Mean", "Active Std", "Active Max", "Active Min",
        "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
        "Protocol_0", "Protocol_6", "Protocol_17"
    ].into_iter().enumerate().map(|(i, name)| (name.to_string(), i)).collect()
}

pub fn normalize_tensor(tensor: Tensor, scaler_path: &str) -> TractResult<Tensor> {
    let file = File::open(scaler_path).expect("Impossibile aprire scaler_params.json");
    let reader = BufReader::new(file);
    let scaler: ScalerParams = serde_json::from_reader(reader).expect("Errore nel parsing JSON");

    let array: ArrayView2<f32> = tensor.to_array_view::<f32>()?.into_dimensionality()?;
    let shape = array.shape();
    assert_eq!(shape.len(), 2);
    let input = array.row(0).to_vec(); // 1D: len == 81

    let feature_index_map = get_feature_index_map();
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