use tract_onnx::prelude::*;


pub fn load_models() -> (Arc<SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>>, Arc<SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>>) {
    let autoencoder_model = load_autoencoder_model();
    let autoencoder = Arc::new(autoencoder_model);

    let classifier_model = load_classifier_model();
    let classifier = Arc::new(classifier_model);

    return (autoencoder, classifier);
}


fn load_autoencoder_model() -> SimplePlan<TypedFact, Box<dyn TypedOp>, tract_onnx::prelude::Graph<TypedFact, Box<dyn TypedOp>>>{
    let model = tract_onnx::onnx()
    .model_for_path("src/ai/models/autoencoder.onnx").expect("Failed to load autoencoder model")
    .into_optimized().expect("Failed to optimize autoencoder model")
    .into_runnable().expect("Failed to create runnable autoencoder model");
    return model;
}


pub fn run_autoencoder_inference(model: &SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>, input_tensor: Tensor) -> TractResult<f32> {
    let input = input_tensor.clone();

    let result = model.run(tvec!(input_tensor.into()))?;
    let output_tensor = result[0].to_array_view::<f32>()?;

    let input_array = input.to_array_view::<f32>()?;

    let mae = input_array
        .iter()
        .zip(output_tensor.iter())
        .map(|(x, y)| (x - y).abs())
        .sum::<f32>() / input_array.len() as f32;

    Ok(mae)
}


pub fn load_classifier_model() -> SimplePlan<TypedFact, Box<dyn TypedOp>, tract_onnx::prelude::Graph<TypedFact, Box<dyn TypedOp>>>{
    let model = tract_onnx::onnx()
    .model_for_path("src/ai/models/classifier.onnx").expect("Failed to load classifier model")
    .into_optimized().expect("Failed to optimize classifier model")
    .into_runnable().expect("Failed to create runnable classifier model");
    return model;
}


pub fn run_classifier_inference(
    model: &SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>,
    input_tensor: Tensor,
) -> TractResult<usize> {
    let result = model.run(tvec!(input_tensor.into()))?;
    let output_tensor = result[0].to_array_view::<f32>()?;

    //println!("🔮 Class probabilities: {:?}", output_tensor);

    // Assumiamo output di forma [1, num_classes]
    let class_index = output_tensor
        .iter()
        .enumerate()
        .max_by(|a, b| a.1.partial_cmp(b.1).unwrap())
        .map(|(idx, _)| idx)
        .unwrap();

    Ok(class_index)
}