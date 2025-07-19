from preprocessing import load_and_preprocess_autoencoder
from autoencoder import Autoencoder, export_to_onnx, train_autoencoder
from preprocessing import load_and_preprocess_classifier
from classifier import Classifier, train_classifier, export_classifier_to_onnx
import matplotlib.pyplot as plt
import onnxruntime as ort
import numpy as np
import onnx



def autoencoder_pipeline():
    X_scaled, labels = load_and_preprocess_autoencoder('dataset/Normal_data.csv')

    model = Autoencoder(input_dim=X_scaled.shape[1])
    trained_model, train_loss, val_loss = train_autoencoder(model, X_scaled)
    export_to_onnx(trained_model, X_scaled)

    plt.figure(figsize=(10, 5))
    plt.plot(train_loss, label="Train Loss")
    plt.plot(val_loss, label="Validation Loss")
    plt.xlabel("Epoch")
    plt.ylabel("Loss (MSE)")
    plt.title("Training vs Validation Loss")
    plt.grid(True)
    plt.legend()
    plt.show()



#autoencoder_pipeline()
def classifier_pipeline():
    X_scaled, y_encoded, label_encoder = load_and_preprocess_classifier("dataset/CICIDS2017/")

    model = Classifier(input_dim=X_scaled.shape[1], num_classes=len(label_encoder.classes_))
    trained_model, train_acc, val_acc = train_classifier(model, X_scaled, y_encoded)
    export_classifier_to_onnx(trained_model, X_scaled)

    plt.figure(figsize=(10, 5))
    plt.plot(train_acc, label="Train Accuracy")
    plt.plot(val_acc, label="Validation Accuracy")
    plt.xlabel("Epoch")
    plt.ylabel("Accuracy")
    plt.title("Train vs Validation Accuracy")
    plt.grid(True)
    plt.legend()
    plt.show()

#classifier_pipeline()

custom_tensor = np.array([[
    2.648185, -0.469573, 3.052187, -0.010950, 83.540039, -0.007566, 1.677435, 1.394718,
    1.534160, 0.986787, -0.478315, -0.608911, -0.538480, -0.427380, -0.052387, -0.233129,
    -0.308790, -0.387542, -0.399784, -0.056537, -0.460798, -0.291446, -0.361646, -0.392450,
    -0.125357, -0.367533, -0.215868, -0.251675, -0.290615, -0.123460, -0.226182, 0.000000,
    -0.005634, 0.000000, 0.000000, 0.001660, -0.211151, -0.170758, 3.407109, 0.205614,
    0.542974, 0.060648, -0.235343, -0.182098, -0.226182, -0.016499, -0.650928, -0.673215,
    -0.335907, -0.005634, -0.016535, -1.006882, 0.437270, 1.534160, -0.538480, 0.001309,
    0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 0.000000, 3.050928, 83.630547,
    -0.010950, -0.007566, -0.497715, -0.249734, -0.008911, 0.002681, -0.109526, -0.110882,
    -0.143376, -0.080325, -0.374534, -0.116080, -0.379932, -0.360508
]], dtype=np.float32)


onnx_model = onnx.load("models/classifier.onnx")
print(onnx_model.graph.output)

# Load session
session = ort.InferenceSession("models/classifier.onnx")
print("Inputs:", session.get_inputs())
print("Outputs:", session.get_outputs())
input_name = session.get_inputs()[0].name
output_name = session.get_outputs()[0].name

# Run inference
output = session.run([output_name], {input_name: custom_tensor})
predicted_probabilities = output[0]
predicted_class_idx = predicted_probabilities.argmax()

print("🔮 Probabilities:", predicted_probabilities)
print("🏷️ Predicted class index:", predicted_class_idx)
