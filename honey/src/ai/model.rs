use tract_onnx::prelude::*;
use crate::ai::features::tensor::print_tensor;

pub fn load_model() -> SimplePlan<TypedFact, Box<dyn TypedOp>, tract_onnx::prelude::Graph<TypedFact, Box<dyn TypedOp>>>{
    let model = tract_onnx::onnx()
    .model_for_path("src/ai/models/autoencoder.onnx").expect("Failed to load model")
    .into_optimized().expect("Failed to optimize model")
    .into_runnable().expect("Failed to create runnable model");
    return model;
}


pub fn run_inference(model: &SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>, input_tensor: Tensor) -> TractResult<f32> {
    let input = input_tensor.clone();
    println!("\nTensor input inference: ");

    //print_tensor(&input_tensor.clone());

    let result = model.run(tvec!(input_tensor.into()))?;
    let output_tensor = result[0].to_array_view::<f32>()?;

    let input_array = input.to_array_view::<f32>()?;

    let mae = input_array
        .iter()
        .zip(output_tensor.iter())
        .map(|(x, y)| (x - y).abs())
        .sum::<f32>() / input_array.len() as f32;

    println!("\nTensor output inference: ");

    //print_tensor(&result[0]);
    Ok(mae)
}

