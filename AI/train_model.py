from tensorflow.keras.layers import Input, Dense, Concatenate, BatchNormalization, Dropout # type: ignore
from tensorflow.keras.models import Model # type: ignore
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint # type: ignore
import numpy as np # type: ignore


# **2️⃣ Creiamo gli autoencoder**
def build_autoencoder(input_dim):
    """Costruisce un autoencoder con batch normalization e dropout."""
    input_layer = Input(shape=(input_dim,))
    encoded = Dense(32, activation='relu')(input_layer)
    encoded = BatchNormalization()(encoded)
    encoded = Dense(16, activation='relu')(encoded)
    encoded = Dense(8, activation='relu')(encoded)

    decoded = Dense(16, activation='relu')(encoded)
    decoded = Dense(32, activation='relu')(decoded)
    decoded = Dense(input_dim, activation='sigmoid')(decoded)

    autoencoder = Model(input_layer, decoded)
    encoder = Model(input_layer, encoded)

    return autoencoder, encoder



print("✅ Modelli addestrati e salvati!")

def train_model():

    network_data = np.load("network_data.npy")
    process_data = np.load("process_data.npy")

    if network_data.shape[0] > process_data.shape[0]:
        process_data = np.tile(process_data, (network_data.shape[0] // process_data.shape[0] + 1, 1))[:network_data.shape[0]]
    else:
        network_data = np.tile(network_data, (process_data.shape[0] // network_data.shape[0] + 1, 1))[:process_data.shape[0]]

    # 🔹 Creiamo le etichette con la stessa lunghezza
    labels = np.zeros((network_data.shape[0], 1)) 

    # **🔍 Determiniamo il numero di feature**
    N_FEATURES_NETWORK = network_data.shape[1]
    N_FEATURES_PROCESS = process_data.shape[1]

    network_autoencoder, network_encoder = build_autoencoder(N_FEATURES_NETWORK)
    process_autoencoder, process_encoder = build_autoencoder(N_FEATURES_PROCESS)

    # **🔹 Compiliamo i modelli**
    network_autoencoder.compile(optimizer='adam', loss='mse')
    process_autoencoder.compile(optimizer='adam', loss='mse')

    # **🔹 Callback per early stopping**
    early_stopping = EarlyStopping(monitor='loss', patience=3, restore_best_weights=True)

    # **3️⃣ Addestriamo gli autoencoder**
    print("🔵 Training network autoencoder...")
    network_autoencoder.fit(network_data, network_data, epochs=20, batch_size=32, callbacks=[early_stopping])

    print("🟢 Training process autoencoder...")
    process_autoencoder.fit(process_data, process_data, epochs=20, batch_size=32, callbacks=[early_stopping])

    # **4️⃣ Modello combinato per rilevare anomalie**
    combined = Concatenate()([network_encoder.output, process_encoder.output])
    combined = Dense(16, activation='relu')(combined)
    combined = BatchNormalization()(combined)
    combined = Dropout(0.2)(combined)  # Aiuta contro overfitting
    combined_layer = Dense(8, activation='relu')(combined)
    anomaly_score = Dense(1, activation='sigmoid')(combined_layer)

    hybrid_model = Model(inputs=[network_encoder.input, process_encoder.input], outputs=anomaly_score)
    hybrid_model.compile(optimizer='adam', loss='binary_crossentropy')

    # **🔹 Creiamo etichette di addestramento (normali)**
    labels = np.zeros((network_data.shape[0], 1))  # Tutti i dati di addestramento sono normali

    # **🔹 Callback per il modello ibrido**
    checkpoint = ModelCheckpoint("hybrid_model_best.keras", save_best_only=True, monitor="loss")
    early_stopping_hybrid = EarlyStopping(monitor='loss', patience=3, restore_best_weights=True)

    # **5️⃣ Addestriamo il modello ibrido**
    print("🟣 Training hybrid model...")
    hybrid_model.fit([network_data, process_data], labels, epochs=10, batch_size=32, callbacks=[early_stopping_hybrid, checkpoint])

    # **6️⃣ Salviamo i modelli**
    network_encoder.save("network_encoder.keras")
    process_encoder.save("process_encoder.keras")
    hybrid_model.save("hybrid_model.keras")



if __name__ == "__main__":
    train_model()