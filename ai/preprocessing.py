import pandas as pd
from sklearn.preprocessing import StandardScaler

def load_and_preprocess(csv_path):
    df = pd.read_csv(csv_path)
    df.drop_duplicates(inplace=True)

    labels = df["Label"]
    df = df.drop(columns=['Flow ID', 'Src IP', 'Dst IP', 'Timestamp', 'Label'], errors='ignore')
    df = pd.get_dummies(df, columns=['Protocol'])

    df_numeric = df.select_dtypes(include=['int64', 'float64', 'uint8', 'bool'])

    print(df_numeric.columns.tolist())
    
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(df_numeric)

    scaler_params = {
        "mean": scaler.mean_.tolist(),
        "scale": scaler.scale_.tolist()
    }

    import json
    with open("models/scaler_params.json", "w") as f:
        json.dump(scaler_params, f, indent=4)
        

    return X_scaled, labels