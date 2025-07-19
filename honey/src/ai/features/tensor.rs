use tract_onnx::tract_core::ndarray::Array2;
use tract_onnx::{prelude::*, tract_core::ndarray::ArrayView2};
use std::fs::File;
use std::io::BufReader;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ScalerParams {
    mean: Vec<f64>,
    scale: Vec<f64>,
    pub columns: Vec<String>,
}


pub fn get_scaler(scaler_path: &str) -> ScalerParams {
    let file = File::open(scaler_path)
        .expect("Impossibile aprire scaler JSON");

    let reader = BufReader::new(file);
    serde_json::from_reader(reader)
        .expect("Errore nel parsing dello scaler JSON")
    
}


pub fn normalize_tensor(raw_tensor: Tensor, scaler: ScalerParams) -> Option<Tensor> {
    let array: ArrayView2<f32> = raw_tensor.to_array_view::<f32>().ok()?.into_dimensionality().ok()?;

    let input = array.row(0).to_vec();
    let mut normalized = input.clone();

    for (i, val) in input.iter().enumerate() {
        let mean = scaler.mean.get(i)?;
        let scale = scaler.scale.get(i)?;
        normalized[i] = if scale.abs() < 1e-8 {
            0.0
        } else {
            ((*val as f64 - mean) / scale) as f32
        };
    }

    let norm_array = Array2::from_shape_vec((1, normalized.len()), normalized).ok()?;
    Some(norm_array.into())
}