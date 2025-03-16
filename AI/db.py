import os
from influxdb_client import InfluxDBClient, Point  # type: ignore
from influxdb_client.client.write_api import SYNCHRONOUS  # type: ignore

# **CONFIGURAZIONE INFLUXDB**
INFLUX_URL = os.getenv("INFLUX_URL", "http://localhost:8086")
INFLUX_TOKEN = os.getenv("INFLUX_TOKEN", "QjYhdnFD6YvSXxMC5HCb8HcOy-dSCdj703pXN8lpyhhQXhnu1APAAoAZHA7gC1KXCIC3-jG9EjCHN34f1q9h-Q==")
INFLUX_ORG = os.getenv("INFLUX_ORG", "honeypot")
NETWORK_BUCKET = "network"
PROCESS_BUCKET = "process"


class InfluxDB:
    def __init__(self):
        self.client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
        self.query_api = self.client.query_api()
        self.write_api = self.client.write_api(write_options=SYNCHRONOUS)

    def get_network_data(self, days=30):
        """ Estrae i dati di traffico di rete degli ultimi giorni """
        query = f"""
        from(bucket: "{NETWORK_BUCKET}")
            |> range(start: -{days}d)
            |> filter(fn: (r) => r["_measurement"] == "network_connections")  // Correggo sintassi
            |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
            |> keep(columns: ["_time", "protocol", "src_ip", "dest_ip", "src_port", "dest_port", "device"])
        """

        try:
            df_list = self.query_api.query_data_frame(query)
            
            if isinstance(df_list, list) and len(df_list) > 0:
                df = pd.concat(df_list, ignore_index=True)
            else:
                df = df_list

            return df

        except Exception as e:
            print(f"❌ Errore durante la query a InfluxDB: {e}")
            return pd.DataFrame()  # Restituisce un DataFrame vuoto in caso di errore  


    def get_process_data(self, days=30):
        """ Estrae i dati dei processi attivi negli ultimi giorni """
        query = f"""
        from(bucket: "{PROCESS_BUCKET}")
            |> range(start: -{days}d)
            |> filter(fn: (r) => r["_measurement"] == "process_activity")  // Correzione sintassi
            |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
            |> keep(columns: [
                "_time", "device", "process_id", "process_name", "path", "virtual_size", "resident_size",
                "syscalls_unix", "syscalls_mach", "faults", "pageins", "cow_faults",
                "messages_sent", "messages_received", "csw", "threadnum", "numrunning",
                "priority"
            ])
        """

        try:
            df_list = self.query_api.query_data_frame(query)
            
            if isinstance(df_list, list) and len(df_list) > 0:
                df = pd.concat(df_list, ignore_index=True)
            else:
                df = df_list

            print(df)
            return df

        except Exception as e:
            print(f"❌ Errore durante la query a InfluxDB: {e}")
            return pd.DataFrame()
