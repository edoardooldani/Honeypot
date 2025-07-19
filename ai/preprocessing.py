import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
import json
import os
import numpy as np

def load_and_preprocess_autoencoder(csv_path):
    df = pd.read_csv(csv_path)
    df.drop_duplicates(inplace=True)

    labels = df["Label"]
    df = df.drop(columns=['Flow ID', 'Src IP', 'Dst IP', 'Timestamp', 'Label'], errors='ignore')
    df = pd.get_dummies(df, columns=['Protocol'])

    numeric_cols = df.select_dtypes(include=['float64', 'int64']).columns
    stds = df[numeric_cols].std()

    # Evitiamo colonne costanti o quasi-costanti
    cols_to_scale = stds[stds > 1e-3].index.tolist()
    cols_to_keep = [c for c in df.columns if c not in cols_to_scale]

    scaler = StandardScaler()
    scaled_part = pd.DataFrame(scaler.fit_transform(df[cols_to_scale]), columns=cols_to_scale, index=df.index)

    # Unione normalizzato + non normalizzato
    df_final = pd.concat([scaled_part, df[cols_to_keep]], axis=1)
    df_final = df_final[df.columns]

    def normalize_column_name(col):
        return col.lower().replace(' ', '_')

    scaler_params = {
        "mean": scaler.mean_.tolist(),
        "scale": scaler.scale_.tolist(),
        "columns": [normalize_column_name(c) for c in cols_to_scale]
    }

    with open("models/autoencoder_scaler_params.json", "w") as f:
        json.dump(scaler_params, f, indent=4)

    return df_final.values, labels


def load_and_preprocess_classifier(folder_path: str):
    dfs = []
    for filename in os.listdir(folder_path):
        if filename.endswith(".csv"):
            df = pd.read_csv(os.path.join(folder_path, filename), low_memory=False)
            dfs.append(df)

    df = pd.concat(dfs, ignore_index=True)
    df = df.dropna()
    df = df.drop_duplicates()

    df.columns = df.columns.str.strip()

    rename_map = {
        "Destination Port": "dst_port",
        "Flow Duration": "flow_duration",
        "Total Fwd Packets": "tot_fwd_pkts",
        "Total Backward Packets": "tot_bwd_pkts",
        "Total Length of Fwd Packets": "totlen_fwd_pkts",
        "Total Length of Bwd Packets": "totlen_bwd_pkts",
        "Fwd Packet Length Max": "fwd_pkt_len_max",
        "Fwd Packet Length Min": "fwd_pkt_len_min",
        "Fwd Packet Length Mean": "fwd_pkt_len_mean",
        "Fwd Packet Length Std": "fwd_pkt_len_std",
        "Bwd Packet Length Max": "bwd_pkt_len_max",
        "Bwd Packet Length Min": "bwd_pkt_len_min",
        "Bwd Packet Length Mean": "bwd_pkt_len_mean",
        "Bwd Packet Length Std": "bwd_pkt_len_std",
        "Flow Bytes/s": "flow_byts_per_s",
        "Flow Packets/s": "flow_pkts_per_s",
        "Flow IAT Mean": "flow_iat_mean",
        "Flow IAT Std": "flow_iat_std",
        "Flow IAT Max": "flow_iat_max",
        "Flow IAT Min": "flow_iat_min",
        "Fwd IAT Total": "fwd_iat_tot",
        "Fwd IAT Mean": "fwd_iat_mean",
        "Fwd IAT Std": "fwd_iat_std",
        "Fwd IAT Max": "fwd_iat_max",
        "Fwd IAT Min": "fwd_iat_min",
        "Bwd IAT Total": "bwd_iat_tot",
        "Bwd IAT Mean": "bwd_iat_mean",
        "Bwd IAT Std": "bwd_iat_std",
        "Bwd IAT Max": "bwd_iat_max",
        "Bwd IAT Min": "bwd_iat_min",
        "Fwd PSH Flags": "fwd_psh_flags",
        "Bwd PSH Flags": "bwd_psh_flags",
        "Fwd URG Flags": "fwd_urg_flags",
        "Bwd URG Flags": "bwd_urg_flags",
        "Fwd Header Length": "fwd_header_len",
        "Bwd Header Length": "bwd_header_len",
        "Fwd Packets/s": "fwd_pkts_per_s",
        "Bwd Packets/s": "bwd_pkts_per_s",
        "Min Packet Length": "pkt_len_min",
        "Max Packet Length": "pkt_len_max",
        "Packet Length Mean": "pkt_len_mean",
        "Packet Length Std": "pkt_len_std",
        "Packet Length Variance": "pkt_len_var",
        "FIN Flag Count": "fin_flag_cnt",
        "SYN Flag Count": "syn_flag_cnt",
        "RST Flag Count": "rst_flag_cnt",
        "PSH Flag Count": "psh_flag_cnt",
        "ACK Flag Count": "ack_flag_cnt",
        "URG Flag Count": "urg_flag_cnt",
        "CWE Flag Count": "cwe_flag_count",
        "ECE Flag Count": "ece_flag_cnt",
        "Down/Up Ratio": "down_up_ratio",
        "Average Packet Size": "pkt_size_avg",
        "Avg Fwd Segment Size": "fwd_seg_size_avg",
        "Avg Bwd Segment Size": "bwd_seg_size_avg",
        "Fwd Header Length.1": "fwd_header_len_1",
        "Fwd Avg Bytes/Bulk": "fwd_byts_b_avg",
        "Fwd Avg Packets/Bulk": "fwd_pkts_b_avg",
        "Fwd Avg Bulk Rate": "fwd_blk_rate_avg",
        "Bwd Avg Bytes/Bulk": "bwd_byts_b_avg",
        "Bwd Avg Packets/Bulk": "bwd_pkts_b_avg",
        "Bwd Avg Bulk Rate": "bwd_blk_rate_avg",
        "Subflow Fwd Packets": "subflow_fwd_pkts",
        "Subflow Fwd Bytes": "subflow_fwd_byts",
        "Subflow Bwd Packets": "subflow_bwd_pkts",
        "Subflow Bwd Bytes": "subflow_bwd_byts",
        "Init_Win_bytes_forward": "init_fwd_win_byts",
        "Init_Win_bytes_backward": "init_bwd_win_byts",
        "act_data_pkt_fwd": "fwd_act_data_pkts",
        "min_seg_size_forward": "fwd_seg_size_min",
        "Active Mean": "active_mean",
        "Active Std": "active_std",
        "Active Max": "active_max",
        "Active Min": "active_min",
        "Idle Mean": "idle_mean",
        "Idle Std": "idle_std",
        "Idle Max": "idle_max",
        "Idle Min": "idle_min"
    }

    df.rename(columns=rename_map, inplace=True)

    # Rimuovi colonne inutili o ridondanti
    if "Label" not in df.columns:
        raise ValueError("Colonna 'Label' non trovata nel dataset.")
    
    print(df["Label"].value_counts())

    y_raw = df["Label"]
    X_raw = df.select_dtypes(include=[np.number]).drop(columns=["Flow ID", "Timestamp"], errors="ignore")

    X_raw.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Rimuovi righe con NaN risultanti
    X_raw.dropna(inplace=True)
    y_raw = y_raw.loc[X_raw.index]


    # Normalizza
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_raw)

    # Codifica le label
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y_raw)

    print(label_encoder.classes_)

    scaler_params = {
        "mean": scaler.mean_.tolist(),
        "scale": scaler.scale_.tolist(),
        "columns": X_raw.columns.tolist()
    }

    with open("models/classifier_scaler_params.json", "w") as f:
        json.dump(scaler_params, f, indent=4)

    return X_scaled, y_encoded, label_encoder