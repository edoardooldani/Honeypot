Per generare un nuovo certificato dalla CA ufficiale:
DA Backend/certs/

openssl genrsa -out server-key.pem 2048

openssl req -new -key server-key.pem -out server.csr -config ../CA/server.cnf

openssl x509 -req -in server.csr \
  -CA ../CA/CA.pem -CAkey ../CA/CA.key -CAcreateserial \
  -out server-cert.pem -days 365 -sha256 \
  -extfile ../CA/server.cnf -extensions v3_req