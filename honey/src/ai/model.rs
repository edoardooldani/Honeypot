use tract_onnx::prelude::*;

pub fn load_model() -> SimplePlan<TypedFact, Box<dyn TypedOp>, tract_onnx::prelude::Graph<TypedFact, Box<dyn TypedOp>>>{
    let model = tract_onnx::onnx()
    .model_for_path("src/ai/models/autoencoder.onnx").expect("Failed to load model")
    .into_optimized().expect("Failed to optimize model")
    .into_runnable().expect("Failed to create runnable model");
    return model;
}


pub fn run_inference(model: &SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>, input_tensor: Tensor) -> TractResult<Tensor> {
    let result = model.run(tvec!(input_tensor.into())).expect("Failed to run inference");
    let output_tensor = result[0].clone(); // direttamente il tensore di output, senza scalarizzazione
    Ok(output_tensor)
}

