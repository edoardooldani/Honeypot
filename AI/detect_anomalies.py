import numpy as np
import tensorflow as tf
from tensorflow.keras.models import load_model
from tensorflow.keras.layers import Dense



def detect_anomalies():
    # **📌 1️⃣ Carichiamo i modelli**
    network_encoder = load_model("network_encoder.keras")
    process_encoder = load_model("process_encoder.keras")
    hybrid_model = load_model("hybrid_model.keras")

    # **📌 2️⃣ Carichiamo i parametri di normalizzazione**
    scaler_net = np.load("scaler_net.npy")
    scaler_proc = np.load("scaler_proc.npy")

    # **📌 3️⃣ Carichiamo i nuovi dati reali da analizzare (da InfluxDB o da file)**
    # ⚠️ Qui dovresti sostituire i dati casuali con dati reali estratti dal database!
    network_data = np.random.rand(10, len(scaler_net))  # 10 nuove righe, colonne uguali a scaler_net
    process_data = np.random.rand(10, len(scaler_proc)) # 10 nuove righe, colonne uguali a scaler_proc

    # **📌 4️⃣ Normalizziamo i dati con gli stessi parametri usati per l'addestramento**
    network_data /= scaler_net
    process_data /= scaler_proc

    # **📌 5️⃣ Otteniamo i codici latenti dai due autoencoder**
    network_latent = network_encoder.predict(network_data)
    process_latent = process_encoder.predict(process_data)

    network_latent_adjusted = Dense(5, activation="relu")(network_latent)
    process_latent_adjusted = Dense(14, activation="relu")(process_latent)

    # Rileviamo le anomalie
    anomaly_scores = hybrid_model.predict([network_latent_adjusted, process_latent_adjusted])


    # **📌 7️⃣ Definiamo la soglia per le anomalie**
    THRESHOLD = 0.7  # ⚠️ Può essere regolata in base ai falsi positivi/negativi

    print("\n🔍 **Risultati dell'Analisi delle Anomalie:**\n")
    for i, score in enumerate(anomaly_scores):
        if score > THRESHOLD:
            print(f"🚨 Anomalia rilevata nel campione {i}! Score: {score[0]:.4f}")
        else:
            print(f"✅ Campione {i} normale. Score: {score[0]:.4f}")

    print("\n✅ Analisi completata!")




if __name__ == "__main__":
    detect_anomalies()