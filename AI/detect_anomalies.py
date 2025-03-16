
import numpy as np
from tensorflow.keras.models import load_model

# ✅ Carichiamo i modelli
network_encoder = load_model("network_encoder.keras")
process_encoder = load_model("process_encoder.keras")
hybrid_model = load_model("hybrid_model.keras")


# 🔹 Ottieni la forma attesa dagli encoder
EXPECTED_NETWORK_SHAPE = network_encoder.input_shape[1]  # Deve essere 5
EXPECTED_PROCESS_SHAPE = process_encoder.input_shape[1]  # Deve essere 16

print(EXPECTED_NETWORK_SHAPE)
print(EXPECTED_PROCESS_SHAPE)

def analyze_anomalies(data, data_type):
    """Determina se un dato è un'anomalia basandosi sul modello ibrido."""
    
    if data_type == "Network":
        latent_network = network_encoder.predict(data)
        latent_process = np.zeros((1, EXPECTED_PROCESS_SHAPE))  # Placeholder per process
    elif data_type == "Process":
        latent_process = process_encoder.predict(data)
        latent_network = np.zeros((1, EXPECTED_NETWORK_SHAPE))  # Placeholder per network
    else:
        print("⚠️ Tipo di dato sconosciuto.")
        return

    # 🔥 Controlliamo e adattiamo le dimensioni
    if latent_network.shape[1] != EXPECTED_NETWORK_SHAPE:
        print(f"⚠️ Dimensione errata per Network: atteso {EXPECTED_NETWORK_SHAPE}, trovato {latent_network.shape[1]}")
        latent_network = latent_network[:, :EXPECTED_NETWORK_SHAPE]  # 🔥 Tronca o adatta

    if latent_process.shape[1] != EXPECTED_PROCESS_SHAPE:
        print(f"⚠️ Dimensione errata per Process: atteso {EXPECTED_PROCESS_SHAPE}, trovato {latent_process.shape[1]}")
        latent_process = latent_process[:, :EXPECTED_PROCESS_SHAPE]  # 🔥 Tronca o adatta

    # 🔥 Ora il modello riceve sempre input con la forma giusta
    return hybrid_model.predict([latent_network, latent_process])[0][0]

