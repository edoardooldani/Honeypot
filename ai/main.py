from preprocessing import load_and_preprocess
from model import Autoencoder, export_to_onnx, train_autoencoder
import matplotlib.pyplot as plt

X_scaled, labels = load_and_preprocess('dataset/Normal_data.csv')

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