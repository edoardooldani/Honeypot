import pandas as pd

# File path
original_file = "dataset/Normal_data.csv"
mdns_file = "dataset/mdns_captured.csv"
output_file = "dataset/Normal_data_2.csv"

# Carica il dataset originale per capire quante colonne ha
df_orig = pd.read_csv(original_file, header=None)
n_cols = df_orig.shape[1]

# Carica mDNS
df_mdns = pd.read_csv(mdns_file, header=None)

# Se ha meno colonne, aggiungi colonne vuote
if df_mdns.shape[1] < n_cols:
    diff = n_cols - df_mdns.shape[1]
    for _ in range(diff):
        df_mdns[df_mdns.shape[1]] = None  # Aggiunge colonna vuota

# Ora unisci
df_final = pd.concat([df_orig, df_mdns], ignore_index=True)
df_final.to_csv(output_file, index=False, header=False)

print(f"✅ Dataset finale salvato come: {output_file}")