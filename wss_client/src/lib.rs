use bincode;
use futures_util::{SinkExt, StreamExt, future, pin_mut, stream::SplitSink, stream::SplitStream};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::{collections::VecDeque, path::PathBuf, sync::Arc, time::Duration};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc};
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, connect_async_tls_with_config,
    tungstenite::protocol::Message,
};

// Struttura di configurazione per il client WebSocket
pub struct ClientConfig {
    // URL del server WebSocket
    pub url: String,
    // Percorso della chiave privata del client
    pub client_key_path: PathBuf,
    // Percorso del certificato del client
    pub client_cert_path: PathBuf,
    // Dimensione del buffer circolare
    pub buffer_size: usize,
    // Timeout per la riconnessione (in millisecondi)
    pub reconnect_timeout_ms: u64,
}

type WsStreamSink = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;
type WsStreamReader = SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;

// Rappresenta un client WebSocket con buffer circolare
pub struct WebSocketClient {
    config: ClientConfig,
    buffer: Arc<Mutex<VecDeque<Message>>>,
    writer_tx: Option<mpsc::Sender<Message>>,
    connected: Arc<Mutex<bool>>,
}

// Tipo di callback per gestire i messaggi ricevuti
pub type MessageHandler<T> = fn(T) -> ();

impl WebSocketClient {
    pub fn new(config: ClientConfig) -> Self {
        let buffer = Arc::new(Mutex::new(VecDeque::with_capacity(config.buffer_size)));

        Self {
            config,
            buffer,
            writer_tx: None,
            connected: Arc::new(Mutex::new(false)),
        }
    }

    pub async fn send<T: Serialize + Debug>(&self, message: T) -> Result<(), String> {
        let serialized = bincode::serialize(&message)
            .map_err(|e| format!("Errore di serializzazione: {}", e))?;

        let msg = Message::Binary(serialized.into());

        // Se siamo connessi, invia direttamente attraverso il canale writer
        if *self.connected.lock().await && self.writer_tx.is_some() {
            if let Some(tx) = &self.writer_tx {
                tx.send(msg.clone())
                    .await
                    .map_err(|e| format!("Errore nell'invio al canale: {}", e))?;
                return Ok(());
            }
        }

        // Altrimenti, aggiungi al buffer circolare
        let mut buffer = self.buffer.lock().await;

        // Se il buffer è pieno, rimuovi l'elemento più vecchio
        if buffer.len() >= self.config.buffer_size {
            buffer.pop_front();
        }

        buffer.push_back(msg);
        Ok(())
    }

    pub async fn run<T: for<'de> Deserialize<'de> + Debug + Send + 'static>(
        &mut self,
        message_handler: MessageHandler<T>,
    ) -> Result<(), String> {
        let config_rustls = common::tls::rustls_client_config(
            self.config.client_key_path.clone(),
            self.config.client_cert_path.clone(),
        );

        let connector = Connector::Rustls(Arc::new(config_rustls));

        let (writer_tx, mut writer_rx) = mpsc::channel::<Message>(100);
        self.writer_tx = Some(writer_tx);

        // Clona i valori necessari per il task di riconnessione
        let url = self.config.url.clone();
        let buffer = self.buffer.clone();
        let connected = self.connected.clone();
        let reconnect_timeout = Duration::from_millis(self.config.reconnect_timeout_ms);

        // Avvia il task di gestione della connessione
        tokio::spawn(async move {
            loop {
                match connect_async_tls_with_config(&url, None, false, Some(connector.clone()))
                    .await
                {
                    Ok((ws_stream, _)) => {
                        println!("WebSocket connesso a {}", url);
                        *connected.lock().await = true;

                        let (write, read) = ws_stream.split();

                        // Avvia i task di lettura e scrittura
                        let read_task = Self::handle_read_messages(read, message_handler);
                        let write_task =
                            Self::handle_write_messages(write, buffer.clone(), &mut writer_rx);

                        // Attendi che uno dei due task termini
                        pin_mut!(read_task, write_task);
                        future::select(read_task, write_task).await;

                        // Se arriva qui, la connessione è stata interrotta
                        *connected.lock().await = false;
                        println!(
                            "WebSocket disconnesso, tentativo di riconnessione tra {} ms",
                            reconnect_timeout.as_millis()
                        );
                    }
                    Err(e) => {
                        eprintln!("Errore di connessione WebSocket: {}", e);
                        *connected.lock().await = false;
                    }
                }

                // Attendi prima di tentare la riconnessione
                tokio::time::sleep(reconnect_timeout).await;
            }
        });

        Ok(())
    }

    // Gestisce i messaggi in lettura
    async fn handle_read_messages<T: for<'de> Deserialize<'de> + Debug + Send + 'static>(
        mut read: WsStreamReader,
        message_handler: MessageHandler<T>,
    ) {
        while let Some(message_result) = read.next().await {
            match message_result {
                Ok(msg) => match msg {
                    Message::Binary(bin) => match bincode::deserialize::<T>(&bin) {
                        Ok(data) => {
                            message_handler(data);
                        }
                        Err(e) => eprintln!("Errore di deserializzazione: {}", e),
                    },
                    Message::Close(_) => {
                        println!("Connessione chiusa dal server");
                        break;
                    }
                    _ => {} // Ignora altri tipi di messaggi
                },
                Err(e) => {
                    eprintln!("Errore nella lettura del messaggio: {}", e);
                    break;
                }
            }
        }
    }

    async fn handle_write_messages(
        mut write: WsStreamSink,
        buffer: Arc<Mutex<VecDeque<Message>>>,
        writer_rx: &mut mpsc::Receiver<Message>,
    ) {
        // Prima invia tutti i messaggi nel buffer
        let mut buffer_lock = buffer.lock().await;
        while let Some(msg) = buffer_lock.pop_front() {
            if let Err(e) = write.send(msg).await {
                eprintln!("Errore nell'invio del messaggio: {}", e);
                break;
            }
        }
        drop(buffer_lock);

        // Poi processa i nuovi messaggi in arrivo
        while let Some(msg) = writer_rx.recv().await {
            if let Err(e) = write.send(msg.clone()).await {
                eprintln!("Errore nell'invio del messaggio: {}", e);

                // Se c'è un errore, reinserisci il messaggio nel buffer
                let mut buffer_lock = buffer.lock().await;
                if buffer_lock.len() < buffer_lock.capacity() {
                    buffer_lock.push_back(msg);
                }

                break;
            }
        }
    }

    pub async fn is_connected(&self) -> bool {
        *self.connected.lock().await
    }

    pub async fn buffer_size(&self) -> usize {
        self.buffer.lock().await.len()
    }
}

#[cfg(test)]
mod example {
    use super::*;
    use common::{
        packet::{build_packet, calculate_header},
        types::{Header, NetworkPayload, PayloadType},
    };

    // Funzione di esempio che mostra come utilizzare la libreria
    async fn example_usage() {
        // Configurazione del client
        let config = ClientConfig {
            url: "wss://echo.websocket.org/".to_string(),
            client_key_path: PathBuf::from("certs/client-key-decrypted.pem"),
            client_cert_path: PathBuf::from("certs/client-cert.pem"),
            buffer_size: 50,
            reconnect_timeout_ms: 3000,
        };

        // Creazione del client
        let mut client = WebSocketClient::new(config);

        // Definizione dell'handler per i messaggi ricevuti
        let message_handler = |header: Header| {
            println!("Ricevuto messaggio: {:?}", header);
        };

        // Avvio del client
        client
            .run(message_handler)
            .await
            .expect("Errore nell'avvio del client");

        // Invio di un messaggio
        let payload = PayloadType::Network(NetworkPayload {
            protocol: "HTTP".to_string(),
            src_ip: "192.168.0.1".to_string(),
            src_port: 9000,
            dest_ip: "192.168.0.2".to_string(),
            dest_port: 9000,
        });

        let header = calculate_header(1, 0, 0, [0x00, 0x14, 0x22, 0x01, 0x23, 0x45]);
        let packet = build_packet(header, payload);

        client
            .send(packet)
            .await
            .expect("Errore nell'invio del messaggio");
    }
}
