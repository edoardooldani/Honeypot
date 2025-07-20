from autoencoder import Autoencoder, export_to_onnx, train_autoencoder
from preprocessing import preprocess_autoencoder_data, preprocess_classifier_data
from classifier import Classifier, train_classifier, export_classifier_to_onnx, plot_training_metrics
import matplotlib.pyplot as plt
import onnxruntime as ort
import numpy as np
import onnx
from collections import Counter
from imblearn.over_sampling import SMOTE


def autoencoder_pipeline():
    X_scaled = preprocess_autoencoder_data("dataset/CICIDS2017/", "models/autoencoder_scaler_params.json")

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


def classifier_pipeline():
    X_scaled, y_encoded, label_encoder = preprocess_classifier_data("dataset/CICIDS2017/", "models/classifier_scaler_params.json")

    smote_target = {
        1: 3000,   # Bot
        9: 4500,  # SSH-Patator
        10: 2000,   # Brute Force
    }

    smote = SMOTE(sampling_strategy=smote_target, random_state=42)
    X_balanced, y_balanced = smote.fit_resample(X_scaled, y_encoded)

    print("✅ Distribuzione dopo SMOTE:", Counter(y_balanced))

    model = Classifier(input_dim=X_balanced.shape[1], num_classes=len(label_encoder.classes_))
    trained_model, history = train_classifier(model, X_balanced, y_balanced)
    export_classifier_to_onnx(trained_model, X_balanced)
    plot_training_metrics(history)



def classifier_test():
    custom_tensor = np.array([[
        2.648185, -0.470146, 3.726893, -0.010950, 104.703468, -0.007566,
        1.650993, 1.131553, 1.584489, 1.067336, -0.478315, -0.608911,
        -0.538480, -0.427380, -0.051550, -0.232841, -0.308792, -0.387630,
        -0.400885, -0.056536, -0.461372, -0.291447, -0.361719, -0.393547,
        -0.125356, -0.367533, -0.215868, -0.251675, -0.290615, -0.123460,
        -0.226182, 0.000000, -0.005634, 0.000000, 0.000000, 0.001660,
        -0.210849, -0.170758, 2.781722, 0.196188, 0.573889, 0.096832,
        -0.224815, -0.182098, -0.226182, -0.016499, -0.650928, -0.673215,
        -0.335907, -0.005634, -0.016535, -1.006882, 0.465756, 1.584489,
        -0.538480, 0.001309, 0.000000, 0.000000, 0.000000, 0.000000,
        0.000000, 0.000000, 3.725635, 104.822655, -0.010950, -0.007566,
        -0.497715, -0.249734, -0.008911, 0.002681, -0.097771, -0.110882,
        -0.135941, -0.067118, -0.375672, -0.116080, -0.381036, -0.361658
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

def autoencoder_test():
    model = onnx.load("models/autoencoder.onnx")
    print("ONNX input shape:", model.graph.input[0].type.tensor_type.shape.dim[-1].dim_value)


#classifier_pipeline()
autoencoder_pipeline()