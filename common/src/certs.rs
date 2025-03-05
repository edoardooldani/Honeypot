use std::{
    fs::File, io::BufReader, path::Path, sync::Arc
};
use tokio_rustls::{
    rustls::ServerConfig,
    rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject, CertificateRevocationListDer},
};
use rustls::{server::WebPkiClientVerifier, RootCertStore};
use rustls::ClientConfig;
use rustls_pemfile::crls;

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





/* 
async fn load_key() -> PrivateKeyDer<'static>{

    let key_file = File::open("certs/client-key-decrypted.pem").expect("Errore nell'aprire la chiave privata");
    let mut key_reader = BufReader::new(key_file);

    let keys = pkcs8_private_keys(&mut key_reader)
        .expect("Errore nella lettura della chiave PKCS#8");

    let private_key = if let Some(key) = keys.first() {
        PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.clone()))
    } else {
        // Se non trova PKCS#8, prova con RSA (PKCS#1)
        let mut key_reader = BufReader::new(File::open("certs/client-key-decrypted.pem").unwrap());
        let rsa_keys = rsa_private_keys(&mut key_reader)
            .expect("Errore nella lettura della chiave RSA");

        PrivateKeyDer::from(PrivatePkcs1KeyDer::from(
            rsa_keys.first().expect("❌ Nessuna chiave privata trovata!").clone(),
        ))
    };

    private_key
}

    */