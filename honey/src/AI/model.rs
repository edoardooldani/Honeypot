use tract_onnx::prelude::*;

pub fn load_model() -> SimplePlan<TypedFact, Box<dyn TypedOp>, tract_onnx::prelude::Graph<TypedFact, Box<dyn TypedOp>>>{
    let model = tract_onnx::onnx()
    .model_for_path("src/ai/models/autoencoder.onnx").expect("Failed to load model")
    .into_optimized().expect("Failed to optimize model")
    .into_runnable().expect("Failed to create runnable model");
    return model;
}


pub fn run_inference(model: &SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>, input_data: Vec<f32>){// -> TractResult<Tensor> {

    let input_tensor = Tensor::from_shape(&[1, 100], &input_data);

    //let result = model.run(tvec!(input_tensor))?;
    //Ok(result[0].clone())
}

