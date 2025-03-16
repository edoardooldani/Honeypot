import numpy as np
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
import hashlib
import joblib  # Per salvare gli oggetti scaler
from db import InfluxDB

def hash_string(s):
    """Converte una stringa in un hash numerico."""
    return int(hashlib.md5(s.encode()).hexdigest(), 16) % 10**8

def preprocess_network_data(network_df):
    """Preprocessa il dataset di rete per il training."""
    protocol_encoder = LabelEncoder()
    network_df["protocol"] = protocol_encoder.fit_transform(network_df["protocol"])

    network_df["src_ip"] = network_df["src_ip"].map(hash_string)
    network_df["dest_ip"] = network_df["dest_ip"].map(hash_string)

    network_features = ["protocol", "src_ip", "dest_ip", "src_port", "dest_port"]
    network_df = network_df[network_features].fillna(0)

    scaler_net = joblib.load("scaler_net.pkl")
    network_data = scaler_net.transform(network_df)

    return network_data, scaler_net



def preprocess_process_data(process_df):
    """Preprocessa il dataset dei processi per il training e l'inferenza."""
    
    process_features = [
        "process_id", "virtual_size", "resident_size", "priority", 
        "syscalls_unix", "syscalls_mach", "faults", "pageins", 
        "cow_faults", "messages_sent", "messages_received", "csw", 
        "threadnum", "numrunning", "process_name", "path"  
    ]

    if "process_name" in process_df.columns:
        process_df["process_name"] = process_df["process_name"].apply(hash_string)
    if "path" in process_df.columns:
        process_df["path"] = process_df["path"].apply(hash_string)

    process_df = process_df[process_features].fillna(0)

    scaler_proc = joblib.load("scaler_proc.pkl")
    process_data = scaler_proc.transform(process_df)

    return process_data, scaler_proc



def prepare_training_data():
    """Prepara i dati per il training e salva gli scaler."""
    db = InfluxDB()

    network_df = db.get_network_data(days=7)
    process_df = db.get_process_data(days=7)  

    network_data, scaler_net, protocol_encoder = preprocess_network_data(network_df)
    process_data, scaler_proc = preprocess_process_data(process_df)

    # Salviamo i dati e gli scaler
    np.save("network_data.npy", network_data)
    np.save("process_data.npy", process_data)
    
    joblib.dump(scaler_net, "scaler_net.pkl")
    joblib.dump(scaler_proc, "scaler_proc.pkl")
    joblib.dump(protocol_encoder, "protocol_encoder.pkl")

    print("✅ Dati reali estratti, normalizzati e salvati!")


if __name__ == "__main__":
    prepare_training_data()