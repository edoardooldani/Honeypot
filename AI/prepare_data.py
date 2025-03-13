import pandas as pd
import numpy as np
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
import hashlib
from db import InfluxDB


def preprocess_network_data(network_df):
    # Encoding protocollo (es. TCP → 0, UDP → 1)
    protocol_encoder = LabelEncoder()
    network_df["protocol"] = protocol_encoder.fit_transform(network_df["protocol"])

    # Hashing degli IP per convertirli in numeri
    def hash_ip(ip):
        return int(hashlib.md5(ip.encode()).hexdigest(), 16) % 10**6  # Riduci a valori numerici

    network_df["src_ip"] = network_df["src_ip"].map(hash_ip)
    network_df["dest_ip"] = network_df["dest_ip"].map(hash_ip)

    # Selezione delle feature numeriche
    network_features = ["protocol", "src_ip", "dest_ip", "src_port", "dest_port"]
    network_df = network_df[network_features].fillna(0)

    # Normalizzazione
    scaler_net = MinMaxScaler()
    network_data = scaler_net.fit_transform(network_df)

    return network_data, scaler_net


# **🔹 Funzione per preprocessare i dati dei processi**
def preprocess_process_data(process_df):
    # Selezione delle feature numeriche (escludiamo "process_name" e "path")
    process_features = [
        "process_id", "virtual_size", "resident_size", "priority", 
        "syscalls_unix", "syscalls_mach", "faults", "pageins", 
        "cow_faults", "messages_sent", "messages_received", "csw", 
        "threadnum", "numrunning"
    ]

    process_df = process_df[process_features].fillna(0)  # Riempie i NaN con 0

    # Normalizzazione
    scaler_proc = MinMaxScaler()
    process_data = scaler_proc.fit_transform(process_df)

    return process_data, scaler_proc



def prepare_data():
    db = InfluxDB()

    network_df = db.get_network_data(days=7)
    process_df = db.get_process_data(days=7)  

    network_data, scaler_net = preprocess_network_data(network_df)
    process_data, scaler_proc = preprocess_process_data(process_df)

    # **5️⃣ Salva i dati normalizzati e gli scaler**
    np.save("network_data.npy", network_data)
    np.save("process_data.npy", process_data)
    np.save("scaler_net.npy", scaler_net.scale_)
    np.save("scaler_proc.npy", scaler_proc.scale_)

    print("✅ Dati reali estratti, normalizzati e salvati!")


if __name__ == "__main__":
    prepare_data()