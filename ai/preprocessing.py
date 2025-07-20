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
    return df


def preprocess_autoencoder_data(folder_path, output_scaler_path):
    df = load_and_preprocess_common(folder_path)
    df = df[df["Label"] == "BENIGN"]

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

    target_benign = 500_000
    benign_df = df[df["Label"] == "BENIGN"]
    attack_df = df[df["Label"] != "BENIGN"]
    benign_sampled = benign_df.sample(n=target_benign, random_state=42)
    df = pd.concat([benign_sampled, attack_df], ignore_index=True).sample(frac=1.0, random_state=42)

    classes_to_remove = [
        "Infiltration",
        "Web Attack � Sql Injection",
        "Heartbleed",
        "Web Attack � XSS"
    ]
    df = df[~df["Label"].isin(classes_to_remove)]

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
