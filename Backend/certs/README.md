Per generare un nuovo certificato dalla CA ufficiale:

openssl genpkey -algorithm RSA -out server-key.pem -pkeyopt rsa_keygen_bits:2048

openssl req -new -key server-key.pem -out server-csr.pem -config openssl.cnf

openssl x509 -req -in server-csr.pem -CA CA.pem -CAkey CA-key.pem -CAcreateserial -out server-cert.pem -days 365 -extensions v3_req -extfile openssl.cnf

openssl x509 -in server-cert.pem -text -noout