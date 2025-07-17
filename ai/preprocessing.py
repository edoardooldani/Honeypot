import pandas as pd
from sklearn.preprocessing import StandardScaler
import json

def load_and_preprocess(csv_path):
    df = pd.read_csv(csv_path, sep=';')
    df.drop_duplicates(inplace=True)

    labels = df["Label"]
    df = df.drop(columns=['Flow ID', 'Src IP', 'Dst IP', 'Timestamp', 'Label'], errors='ignore')
    
    # One-hot encode protocolli (non normalizzare questi!)
    df = pd.get_dummies(df, columns=['Protocol'])

    # Separiamo le colonne da normalizzare
    numeric_cols = df.select_dtypes(include=['float64', 'int64']).columns
    stds = df[numeric_cols].std()

    # Evitiamo colonne costanti o quasi-costanti
    cols_to_scale = stds[stds > 1e-3].index.tolist()

    # Colonne non da normalizzare (booleane, dummy, costanti)
    cols_to_keep = [c for c in df.columns if c not in cols_to_scale]

    # Scaler
    scaler = StandardScaler()
    scaled_part = pd.DataFrame(scaler.fit_transform(df[cols_to_scale]), columns=cols_to_scale, index=df.index)

    # Unione normalizzato + non normalizzato
    df_final = pd.concat([scaled_part, df[cols_to_keep]], axis=1)
    df_final = df_final[df.columns]  # manteniamo ordine originale


    print("🚨 Ordine delle feature usate:")
    print(df_final.columns.tolist()) 

    def normalize_column_name(col):
        return col.lower().replace(' ', '_')

    scaler_params = {
        "mean": scaler.mean_.tolist(),
        "scale": scaler.scale_.tolist(),
        "columns": [normalize_column_name(c) for c in cols_to_scale]
    }

    with open("models/scaler_params.json", "w") as f:
        json.dump(scaler_params, f, indent=4)

    return df_final.values, labels