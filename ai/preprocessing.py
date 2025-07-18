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
    print(df.columns.tolist())

    # Rimuovi colonne inutili o ridondanti
    if "Label" not in df.columns:
        raise ValueError("Colonna 'Label' non trovata nel dataset.")
    
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

    def normalize_column_name(col):
        return col.lower().replace(' ', '_')

    scaler_params = {
        "mean": scaler.mean_.tolist(),
        "scale": scaler.scale_.tolist(),
        "columns": [normalize_column_name(c) for c in X_raw.columns]
    }

    with open("models/classifier_scaler_params.json", "w") as f:
        json.dump(scaler_params, f, indent=4)

    return X_scaled, y_encoded, label_encoder