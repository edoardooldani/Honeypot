use tract_onnx::tract_core::ndarray::Array2;
use tract_onnx::{prelude::*, tract_core::ndarray::ArrayView2};
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
}

pub fn normalize_tensor(tensor: Tensor, scaler_path: &str) -> TractResult<Tensor> {
    let file = File::open(scaler_path).expect("Impossibile aprire scaler_params.json");
    let reader = BufReader::new(file);
    let scaler: ScalerParams = serde_json::from_reader(reader).expect("Errore nel parsing JSON");

    let array = tensor.to_array_view::<f32>()?;
    let shape = array.shape();
    assert_eq!(shape, &[1, scaler.mean.len()]);

    let input_vec: Vec<f32> = array
        .iter()
        .enumerate()
        .map(|(i, &v)| {
            let mean = scaler.mean[i];
            let scale = scaler.scale[i];
            if scale.abs() < 1e-8 {
                0.0
            } else {
                ((v as f64 - mean) / scale) as f32
            }
        })
        .collect();

    let norm_array = Array2::from_shape_vec((1, input_vec.len()), input_vec).unwrap();
    Ok(norm_array.into())
}
