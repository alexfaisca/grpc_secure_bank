#! /bin/bash

# Create server ssl certificate
openssl req -x509 -newkey rsa:4096 -keyout Bank/resources/certificates/key.pem -out Bank/resources/certificates/cert.pem -sha256 -days 365
openssl pkcs8 -topk8 -in Bank/resources/certificates/key.pem -out Bank/resources/certificates/server.key
# Import certificate in client
keytool -importcert -alias BlingBank -file resources/certificates/server_ca.jks -keystore  "$JAVA_HOME/lib/security/cacerts"
# Import certificate in client
cp Bank/resources/certificates/cert.pem User/resources/certificates/cert.pem
