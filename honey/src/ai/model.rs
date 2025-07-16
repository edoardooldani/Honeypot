use tract_onnx::{prelude::*, tract_core::ndarray::ArrayView2};

pub fn load_model() -> SimplePlan<TypedFact, Box<dyn TypedOp>, tract_onnx::prelude::Graph<TypedFact, Box<dyn TypedOp>>>{
    let model = tract_onnx::onnx()
    .model_for_path("src/ai/models/autoencoder.onnx").expect("Failed to load model")
    .into_optimized().expect("Failed to optimize model")
    .into_runnable().expect("Failed to create runnable model");
    return model;
}


pub fn run_inference(model: &SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>, input_tensor: Tensor) -> TractResult<Tensor> {
    print_tensor(&input_tensor);
    let result = model.run(tvec!(input_tensor.into())).expect("Failed to run inference");
    let output_tensor = result[0].clone();
    Ok(output_tensor.into_tensor())
}


fn print_tensor(tensor: &Tensor) {
    let array: ArrayView2<f32> = tensor.to_array_view::<f32>().unwrap().into_dimensionality::<tract_ndarray::Ix2>().unwrap();

    for row in array.rows() {
        println!("{:?}", row);
    }
}

