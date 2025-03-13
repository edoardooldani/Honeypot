import time
from prepare_data import prepare_data
from train_model import train_model
from detect_anomalies import detect_anomalies

def main():
    print("🔄 Inizio pipeline di analisi...\n")

    # **1️⃣ Prepara i dati**
    print("📌 [1/3] Preparazione dei dati in corso...")
    start_time = time.time()
    prepare_data()
    print(f"✅ Dati preparati in {time.time() - start_time:.2f} sec\n")

    # **2️⃣ Addestra il modello**
    print("📌 [2/3] Addestramento del modello in corso...")
    start_time = time.time()
    train_model()
    print(f"✅ Modello addestrato in {time.time() - start_time:.2f} sec\n")

    # **3️⃣ Rileva anomalie**
    print("📌 [3/3] Rilevamento anomalie in corso...")
    start_time = time.time()
    detect_anomalies()
    print(f"✅ Analisi completata in {time.time() - start_time:.2f} sec\n")

    print("🎉 **Pipeline completata con successo!**")

if __name__ == "__main__":
    main()