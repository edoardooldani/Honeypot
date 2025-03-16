import time
from prepare_data import prepare_training_data
from train_model import train_model
from kafka_consumer import start_kafka_listener



def model_train():
    print("🔄 Inizio pipeline di analisi...\n")

    # **1️⃣ Prepara i dati**
    print("📌 [1/3] Preparazione dei dati in corso...")
    start_time = time.time()
    prepare_training_data()
    print(f"✅ Dati preparati in {time.time() - start_time:.2f} sec\n")

    # **2️⃣ Addestra il modello**
    print("📌 [2/3] Addestramento del modello in corso...")
    start_time = time.time()
    train_model()
    print(f"✅ Modello addestrato in {time.time() - start_time:.2f} sec\n")




if __name__ == "__main__":
    #model_train()
    start_kafka_listener()    


# source ../../../../honeypot-env/bin/activate