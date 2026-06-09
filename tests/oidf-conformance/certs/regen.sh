#!/usr/bin/env bash
# Regenerate the OIDF conformance harness's test CA + server cert +
# Java truststore. The output materials are committed to the repo so CI
# is deterministic; only re-run when the cert is close to expiry or you
# want a fresh keypair.
#
# Output:
#   ca.crt          test CA (self-signed, 10-year validity)
#   ca.key          test CA private key (committed — test-only material)
#   server.crt      server cert for host.docker.internal, signed by ca
#   server.key      server private key
#   truststore.jks  Java keystore containing ca.crt as a trusted root —
#                   mounted into the harness container so its JVM accepts
#                   our self-signed chain.
#
# The materials are LOCAL TO THIS HARNESS — they trust nothing outside
# the docker-compose network. Do not deploy these in production.
#
# Requires: openssl (LibreSSL or OpenSSL 1.1+), keytool (from any JDK).

set -euo pipefail

cd "$(dirname "$0")"

CN="host.docker.internal"
DAYS=3650               # 10 years; test-only material
TRUSTSTORE_PASSWORD="changeit"   # the JVM-default that requires the least friction

cat > openssl-server.cnf <<EOF
[req]
distinguished_name = req_distinguished_name
prompt             = no

[req_distinguished_name]
CN = ${CN}

[v3_ca]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:TRUE
keyUsage               = critical, digitalSignature, cRLSign, keyCertSign

[v3_server]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
basicConstraints       = CA:FALSE
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth
subjectAltName         = @alt_names

[alt_names]
DNS.1 = host.docker.internal
DNS.2 = localhost
IP.1  = 127.0.0.1
EOF

echo "==> Generating test CA (10-year validity, RSA 2048)"
openssl req -x509 -nodes -newkey rsa:2048 -days "${DAYS}" \
  -keyout ca.key -out ca.crt \
  -subj "/CN=oneauth OIDF test CA" \
  -extensions v3_ca -config openssl-server.cnf

echo "==> Generating server keypair"
openssl req -nodes -newkey rsa:2048 \
  -keyout server.key -out server.csr \
  -config openssl-server.cnf

echo "==> Signing server cert with CA (SAN: host.docker.internal, localhost, 127.0.0.1)"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days "${DAYS}" -sha256 \
  -extfile openssl-server.cnf -extensions v3_server

rm -f server.csr ca.srl openssl-server.cnf

echo "==> Building Java truststore for the OIDF harness JVM"
rm -f truststore.jks
keytool -importcert -noprompt \
  -alias oneauth-test-ca \
  -file ca.crt \
  -keystore truststore.jks \
  -storepass "${TRUSTSTORE_PASSWORD}" \
  -storetype JKS

echo ""
echo "Done. Materials regenerated:"
ls -1 ca.crt ca.key server.crt server.key truststore.jks
echo ""
echo "Note: ca.key + server.key are committed test material — the cert is"
echo "      trusted only by this docker-compose's harness JVM."
