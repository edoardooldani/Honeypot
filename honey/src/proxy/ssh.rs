use tokio::net::TcpStream;
use tokio::io::copy_bidirectional;
use tracing::info;
use std::net::SocketAddr;

pub async fn start_ssh_proxy(mut client_stream: TcpStream) -> Result<(), Box<dyn std::error::Error>> {

    let target_addr: SocketAddr = "127.0.0.1:2022".parse()?;
    let mut sshd_stream = TcpStream::connect(target_addr).await?;

    info!("🔁 Proxy SSH: connessione da attaccante al server finto avviata");

    tokio::spawn(async move {
        if let Err(e) = copy_bidirectional(&mut client_stream, &mut sshd_stream).await {
            eprintln!("❌ Errore nel proxy SSH: {:?}", e);
        }
    });

    Ok(())
}