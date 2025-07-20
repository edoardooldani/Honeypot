import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
import json
import os
import numpy as np

def normalize_column_name(col):
    return col.strip().lower().replace(' ', '_').replace('/', '_').replace('-', '_')

def load_and_preprocess_common(folder_path):
    dfs = []
    for filename in os.listdir(folder_path):
        if filename.endswith(".csv"):
            df = pd.read_csv(os.path.join(folder_path, filename), low_memory=False)
            dfs.append(df)

    df = pd.concat(dfs, ignore_index=True)
    df = df.dropna()
    df = df.drop_duplicates()
    df.columns = df.columns.str.strip()

    df = df.drop(columns=["Destination Port"], errors="ignore")

    return df

def rename(df):
    rename_map = {
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
    return df

def preprocess_autoencoder_data(folder_path, output_scaler_path):
    df = load_and_preprocess_common(folder_path)
    df = df[df["Label"] == "BENIGN"]

    df = rename(df)
    df = df.rename(columns=lambda c: normalize_column_name(c))
    if "label" not in df.columns:
        raise ValueError("Colonna 'Label' non trovata nel dataset.")

    y_raw = df["label"]
    X_raw = df.select_dtypes(include=[np.number]).drop(columns=["flow_id", "timestamp"], errors="ignore")

    X_raw.replace([np.inf, -np.inf], np.nan, inplace=True)
    X_raw.dropna(inplace=True)
    y_raw = y_raw.loc[X_raw.index]

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_raw)

    scaler_params = {
        "mean": scaler.mean_.tolist(),
        "scale": scaler.scale_.tolist(),
        "columns": X_raw.columns.tolist()
    }

    with open(output_scaler_path, "w") as f:
        json.dump(scaler_params, f, indent=4)

    return X_scaled


def preprocess_classifier_data(folder_path, output_scaler_path):
    df = load_and_preprocess_common(folder_path)

    target_benign = 500000
    benign_df = df[df["Label"] == "BENIGN"]
    attack_df = df[df["Label"] != "BENIGN"]
    benign_sampled = benign_df.sample(n=target_benign, random_state=42)
    df = pd.concat([benign_sampled, attack_df], ignore_index=True).sample(frac=1.0, random_state=42)

    classes_to_remove = [
        "Infiltration",
        "Web Attack � Sql Injection",
        "Heartbleed",
        "Web Attack � XSS",
        "Web Attack � Brute Force",
        "SSH-Patator",
        "Bot"
    ]
    df = df[~df["Label"].isin(classes_to_remove)]

    df = rename(df)
    df = df.rename(columns=lambda c: normalize_column_name(c))
    if "label" not in df.columns:
        raise ValueError("Colonna 'Label' non trovata nel dataset.")

    y_raw = df["label"]
    X_raw = df.select_dtypes(include=[np.number]).drop(columns=["flow_id", "timestamp"], errors="ignore")

    X_raw.replace([np.inf, -np.inf], np.nan, inplace=True)
    X_raw.dropna(inplace=True)
    y_raw = y_raw.loc[X_raw.index]

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X_raw)

    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y_raw)

    scaler_params = {
        "mean": scaler.mean_.tolist(),
        "scale": scaler.scale_.tolist(),
        "columns": X_raw.columns.tolist()
    }

    with open(output_scaler_path, "w") as f:
        json.dump(scaler_params, f, indent=4)

    return X_scaled, y_encoded, label_encoder


def preprocess_evaluate(folder_path, scaler_path):
    dfs = []
    for filename in os.listdir(folder_path):
        if filename.endswith(".csv"):
            df = pd.read_csv(os.path.join(folder_path, filename), low_memory=False)
            dfs.append(df)

    df = pd.concat(dfs, ignore_index=True)
    df = df.dropna().drop_duplicates()
    df.columns = df.columns.str.strip()
    df = df[df["Label"] != "BENIGN"]

    classes_to_remove = [
        "Infiltration",
        "Web Attack � Sql Injection",
        "Heartbleed",
        "Web Attack � XSS"
    ]
    df = df[~df["Label"].isin(classes_to_remove)]

    df = rename(df)
    df = df.rename(columns=lambda c: normalize_column_name(c))

    if "label" not in df.columns:
        raise ValueError("Colonna 'label' non trovata.")

    y_raw = df["label"]
    X_raw = df.select_dtypes(include=[np.number]).drop(columns=["flow_id", "timestamp"], errors="ignore")
    X_raw.replace([np.inf, -np.inf], np.nan, inplace=True)
    X_raw.dropna(inplace=True)
    y_raw = y_raw.loc[X_raw.index]

    # === Load scaler
    with open(scaler_path, "r") as f:
        scaler_params = json.load(f)

    mean = np.array(scaler_params["mean"])
    scale = np.array(scaler_params["scale"])
    columns = scaler_params["columns"]

    X_raw = X_raw[columns]
    X_scaled = (X_raw - mean) / scale

    return X_scaled, y_raw