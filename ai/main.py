from preprocessing import load_and_preprocess_autoencoder
from autoencoder import Autoencoder, export_to_onnx, train_autoencoder
from preprocessing import load_and_preprocess_classifier
from classifier import Classifier, train_classifier, export_classifier_to_onnx
import matplotlib.pyplot as plt
import onnxruntime as ort
import numpy as np


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

classifier_pipeline()

custom_tensor = np.array([[
    -0.340223, -0.470914, -0.010425, -0.010950, -0.046839, -0.007566,
    -0.221093, 0.539431, -0.028151, -0.240242, -0.478315, -0.608911,
    -0.538480, -0.427380, -0.052767, -0.232716, -0.308792, -0.387637,
    -0.400986, -0.056535, -0.462141, -0.291448, -0.361724, -0.393648,
    -0.125356, -0.367533, -0.215868, -0.251675, -0.290615, -0.123460,
    -0.226182, 0.0, -0.005634, 0.0, 0.001309, 0.001660, -0.210718,
    -0.170758, 1.374601, -0.471204, -0.416687, -0.490553, -0.314280,
    -0.182098, -0.226182, -0.016499, -0.650928, -0.673215, -0.335907,
    -0.005634, -0.016535, -1.006882, -0.446988, -0.028151, -0.538480,
    0.001309, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, -0.010425, -0.046902,
    -0.010950, -0.007566, -0.497715, -0.249734, -0.008911, 0.002681,
    -0.133359, -0.110882, -0.158451, -0.107102, -0.375777, -0.116080,
    -0.381137, -0.361764
]], dtype=np.float32)

# Load session
session = ort.InferenceSession("models/classifier.onnx")
input_name = session.get_inputs()[0].name
output_name = session.get_outputs()[0].name

# Run inference
output = session.run([output_name], {input_name: custom_tensor})
predicted_probabilities = output[0]
predicted_class_idx = predicted_probabilities.argmax()

print("🔮 Probabilities:", predicted_probabilities)
print("🏷️ Predicted class index:", predicted_class_idx)
