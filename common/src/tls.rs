use std::{
    fs::File, io::BufReader, path::Path, sync::Arc
};
use rustls::{ServerConnection, ClientConnection};
use tokio_rustls::{
    rustls::{ServerConfig, ClientConfig},
    rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject, CertificateRevocationListDer},
    rustls::{server::WebPkiClientVerifier, RootCertStore}
};
use rustls_pemfile::crls;
use sha2::{Sha256, Digest};



pub fn rustls_client_config(key: impl AsRef<Path>, cert: impl AsRef<Path>) -> ClientConfig {
    let certs = load_cert(cert);
    
    let root_ca = load_root("certs/CA.pem");
    let private_key = load_key(key);
    
    let config = ClientConfig::builder()
        .with_root_certificates(root_ca)
        .with_client_auth_cert(certs, private_key)
        .unwrap();

    config
}



pub fn rustls_server_config(key: impl AsRef<Path>, cert: impl AsRef<Path>) -> Arc<ServerConfig> {
    
    let certs = load_cert(cert);
    let key = load_key(key);
    let client_auth_roots = load_root("CA/CA.pem");  

    let crls = load_crls();
    let client_auth_verifier = WebPkiClientVerifier::builder(client_auth_roots.into())
                    .with_crls(crls)
                    .build()
                    .unwrap();

    let mut config = ServerConfig::builder()
        .with_client_cert_verifier(client_auth_verifier)
        .with_single_cert(certs, key)
        .expect("certificato/chiave non validi");

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Arc::new(config)
}


fn load_crls() -> Vec<CertificateRevocationListDer<'static>> {
    let crl_file = File::open("CA/CA.crl").expect("❌ Impossibile aprire la CRL");
    let mut reader = BufReader::new(crl_file);

    crls(&mut reader)
        .expect("❌ Errore nella lettura della CRL")
        .into_iter()
        .map(CertificateRevocationListDer::from)
        .collect()
}



fn load_cert(cert: impl AsRef<Path>) -> Vec<CertificateDer<'static>>{
    let certs = CertificateDer::pem_file_iter(cert)
    .unwrap()
    .map(|cert| cert.unwrap())
    .collect();

    certs
}


fn load_key(key: impl AsRef<Path>) -> PrivateKeyDer<'static>{
    PrivateKeyDer::from_pem_file(key).unwrap()
}



fn load_root(path: &str) -> RootCertStore{
    let mut client_auth_roots = RootCertStore::empty();
    let root_ca_file = File::open(path).expect("Impossibile aprire la root CA");
    let mut reader = BufReader::new(root_ca_file);
    for cert in rustls_pemfile::certs(&mut reader).expect("Errore nella lettura della root CA") {
        client_auth_roots.add(CertificateDer::from(cert)).unwrap();
    }  

    client_auth_roots
}



pub fn generate_server_session_id(session: &ServerConnection) -> u32 {
    let mut keying_material = [0u8; 32]; 
    let label = b"session-id-export"; 

    if let Err(e) = session.export_keying_material(&mut keying_material, label, None) {
        eprintln!("❌ Errore nell'export_keying_material: {:?}", e);
        return 0;
    }

    // Hash dei dati esportati per generare un session_id unico
    let mut hasher = Sha256::new();
    hasher.update(&keying_material);
    let result = hasher.finalize();
    let bytes = &result[..4]; // Prendi i primi 4 byte per creare un u32
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}


pub fn generate_client_session_id(session: &ClientConnection) -> u32 {
    let mut keying_material = [0u8; 32];
    let label = b"session-id-export";

    if let Err(e) = session.export_keying_material(&mut keying_material, label, None) {
        eprintln!("❌ Errore nell'export_keying_material: {:?}", e);
        return 0;
    }

    let mut hasher = Sha256::new();
    hasher.update(&keying_material);
    let result = hasher.finalize();
    let bytes = &result[..4];
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}
