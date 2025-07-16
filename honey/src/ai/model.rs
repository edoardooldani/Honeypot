use tract_onnx::tract_core::ndarray::Array2;
use tract_onnx::{prelude::*, tract_core::ndarray::ArrayView2};
use std::fs::File;
use std::io::BufReader;
use serde::Deserialize;

pub fn load_model() -> SimplePlan<TypedFact, Box<dyn TypedOp>, tract_onnx::prelude::Graph<TypedFact, Box<dyn TypedOp>>>{
    let model = tract_onnx::onnx()
    .model_for_path("src/ai/models/autoencoder.onnx").expect("Failed to load model")
    .into_optimized().expect("Failed to optimize model")
    .into_runnable().expect("Failed to create runnable model");
    return model;
}


pub fn run_inference(model: &SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>, input_tensor: Tensor) -> TractResult<f32> {
    let input = input_tensor.clone();
    print_tensor(&input_tensor.clone());

    let result = model.run(tvec!(input_tensor.into()))?;
    let output_tensor = result[0].to_array_view::<f32>()?;

    let input_array = input.to_array_view::<f32>()?;

    let mse = input_array
        .iter()
        .zip(output_tensor.iter())
        .map(|(x, y)| (x - y).powi(2))
        .sum::<f32>() / input_array.len() as f32;


    print_tensor(&result[0]);
    Ok(mse)
}


fn print_tensor(tensor: &Tensor) {
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
    assert_eq!(shape.len(), 2); // deve essere (1, N)

    let input_vec: Vec<f32> = array
        .iter()
        .enumerate()
        .map(|(i, &v)| {
            let mean = scaler.mean[i];
            let scale = scaler.scale[i];
            if scale.abs() < 1e-8 {
                0.0 // Evita divisione per zero
            } else {
                ((v as f64 - mean) / scale) as f32
            }
        })
        .collect();

    let norm_array = Array2::from_shape_vec((1, input_vec.len()), input_vec).unwrap();
    Ok(norm_array.into())
}
