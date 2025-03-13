import time
from prepare_data import prepare_data
from train_model import train_model
from detect_anomalies import detect_anomalies
from confluent_kafka import Consumer, KafkaError
from kafka import KafkaConsumer
import json

# Configura il consumer Kafka
KAFKA_BROKER = "localhost:9092"  # Modifica se usi un server remoto
KAFKA_TOPIC = "network_logs"  # Nome del topic che vuoi consumare

consumer_conf = {
    "bootstrap.servers": KAFKA_BROKER,
    "group.id": "honeypot-consumer-group",
    "auto.offset.reset": "earliest",  # Legge dall'inizio se è la prima connessione
}

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


def kafka_server():

    consumer = KafkaConsumer(
    "honeypot_packets",
    bootstrap_servers="localhost:9092",
    auto_offset_reset="earliest",
    group_id="honeypot_group",
    value_deserializer=lambda x: json.loads(x.decode("utf-8"))
    )

    print("🎧 In ascolto su Kafka...") 
    for message in consumer:
        print(f"📥 Messaggio ricevuto: {message.value}")
    

if __name__ == "__main__":
    #main()
    kafka_server()