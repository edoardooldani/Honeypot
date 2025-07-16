import json
import pandas as pd  # type: ignore
from kafka import KafkaConsumer, KafkaProducer  # type: ignore
from datetime import datetime, timezone
from prepare_data import preprocess_network_data, preprocess_process_data
from detect_anomalies import analyze_anomalies
import numpy as np

pd.set_option("display.max_columns", None)  # Mostra tutte le colonne
pd.set_option("display.max_rows", None)  # Mostra tutte le righe (opzionale)
pd.set_option("display.expand_frame_repr", False)  # Evita la visualizzazione su più righe
pd.set_option("display.max_colwidth", None)


def setup_consumer():
    """Configura il consumer Kafka."""
    return KafkaConsumer(
        "honeypot_packets",
        bootstrap_servers="localhost:9092",
        auto_offset_reset="latest",
        group_id="honeypot_group",
        value_deserializer=lambda x: json.loads(x.decode("utf-8"))
    )

def setup_producer():
    """Configura il producer Kafka."""
    return KafkaProducer(
        bootstrap_servers="localhost:9092",
        value_serializer=lambda x: json.dumps(x, default=lambda o: float(o) if isinstance(o, np.float32) else o).encode("utf-8")
    )

def process_kafka_message(message, device_name):
    """Estrae dinamicamente il payload e lo trasforma in DataFrame normalizzato."""
    try:
        payload = message["payload"]
        if "Process" in payload:
            process_data = payload["Process"]
            process_data["time"] = datetime.fromtimestamp(message["header"]["timestamp"], tz=timezone.utc).isoformat()
            process_data["device"] = device_name

            df = pd.DataFrame([process_data])
            data, scaler = preprocess_process_data(df)
            return data, "Process"
        
        if "Network" in payload:
            process_data = payload["Network"]
            process_data["time"] = datetime.fromtimestamp(message["header"]["timestamp"], tz=timezone.utc).isoformat()
            process_data["device"] = device_name

            df = pd.DataFrame([process_data])
            data, scaler = preprocess_network_data(df)

            return data, "Network"
        else:
            print("⚠️ Messaggio non contiene dati di processi.")
            return None

    except Exception as e:
        print(f"❌ Errore nell'elaborazione del messaggio: {e}")
        return None


THRESHOLD = 0.7  # Soglia per determinare anomalie

def start_kafka_listener():
    """Avvia il consumer Kafka per ascoltare i messaggi in tempo reale."""
    consumer = setup_consumer()
    producer = setup_producer()
    
    print("🎧 In ascolto su Kafka...") 
    for message in consumer:
        #print(f"📥 Messaggio ricevuto: {message.value}") 
        device_name = message.key.decode("utf-8") if message.key else "unknown"

        data, data_type = process_kafka_message(message.value, device_name)

        if data is not None:
            anomaly_score = analyze_anomalies(data, data_type)
            if anomaly_score > THRESHOLD:
                alert_message = {
                    "device": device_name,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "anomaly_score": anomaly_score,
                    "data_type": data_type
                }

                # Invia il messaggio su Kafka (nuovo topic)
                producer.send("anomaly_alerts", value=alert_message)
                print(f"🚨 Anomalia rilevata! Score: {anomaly_score:.4f}")
                
            else:
                print(f"✅ Nessuna anomalia. Score: {anomaly_score:.4f}")
