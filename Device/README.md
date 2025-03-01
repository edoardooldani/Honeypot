README

How to run:
- cargo run wss://127.0.0.1:12345/

How to create certificates (run these commands in certs root):

# Create unencrypted private key and a CSR (certificate signing request)
openssl req -newkey rsa:2048 -nodes -keyout localhost.key -out localhost.csr

# Create self-signed certificate (`localhost.crt`) with the private key and CSR
openssl x509 -signkey localhost.key -in localhost.csr -req -days 365 -out localhost.crt

# Create a self-signed root CA
openssl req -x509 -sha256 -days 1825 -newkey rsa:2048 -keyout rootCA.key -out rootCA.crt

Create file localhost.ext with the following content:

authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost

# Sign the CSR (`localhost.csr`) with the root CA certificate and private key
# => this overwrites `localhost.crt` because it gets signed
openssl x509 -req -CA rootCA.crt -CAkey rootCA.key -in localhost.csr -out localhost.crt -days 365 -CAcreateserial -extfile localhost.ext

# Convert `localhost.crt` (PEM) to DER
openssl x509 -in localhost.crt -outform der -out localhost.crt.der

# Convert `rootCA.crt` (PEM) to DER
openssl x509 -in rootCA.crt -outform der -out rootCA.crt.der
