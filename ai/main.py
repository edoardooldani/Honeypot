from preprocessing import load_and_preprocess_autoencoder
from autoencoder import Autoencoder, export_to_onnx, train_autoencoder
from preprocessing import load_and_preprocess_classifier
from classifier import Classifier, train_classifier, export_classifier_to_onnx
import matplotlib.pyplot as plt


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