# Dittor

UserRequest:
    attribute: "user123"
    timestamp: 1234567890

Credential (Resposta da CA):
    pseudonym: "ABCD01"
    signature: signedMessage

Para gerar os certificados e chaves (Bash):
CA:
    openssl genrsa -out ca.key 2048
    openssl req -x509 -new -key ca.key -out ca.cer
User:
    openssl genrsa -out user.key 2048
    openssl req -new -key user.key -out user.csr

Assinar User:
openssl x509 -req -in user.csr -CA ca.cer -CAkey ca.key -CAcreateserial -out user.cer -days 365

Converter para PKCS12:
openssl pkcs12 -export -out user.p12 -inkey user.key -in user.cer
openssl pkcs12 -export -out ca.p12 -inkey ca.key -in ca.cer
