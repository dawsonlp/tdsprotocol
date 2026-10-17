#!/bin/sh
# Makes the test container's TLS certificate, signed by a test certificate authority (D-10).
#
#   docker/macos/tls/make-test-certificates.sh
#
# Writes, next to this script:
#   test-ca.pem       the test authority's certificate: tests trust this, and nothing else
#   test-ca.key       its private key, used only here to sign; never mounted
#   server.pem        the server's certificate: CN localhost, also valid for 127.0.0.1 and mssql-2025
#   server.key        its private key, mounted read-only into the container
#
# The certificate meets SQL Server's requirements: server authentication key usage, key encipherment, SHA-256, and a
# name matching the host the client connects to. It also names its authority's key (Authority Key Identifier), which
# Python 3.13 and later require when verifying (VERIFY_X509_STRICT). It is for tests only: the key is readable by the container's
# mssql user (so 0644), and the authority exists only on this machine.
set -e
cd "$(dirname "$0")"
DAYS=3650

cat > server.ext <<'EXT'
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, IP:127.0.0.1, DNS:mssql-2025
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EXT

openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days "$DAYS" -subj "/CN=TDS test authority" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout test-ca.key -out test-ca.pem 2>/dev/null
openssl req -newkey rsa:3072 -sha256 -nodes -subj "/CN=localhost" -keyout server.key -out server.csr 2>/dev/null
openssl x509 -req -in server.csr -CA test-ca.pem -CAkey test-ca.key -CAcreateserial -days "$DAYS" -sha256 \
    -extfile server.ext -out server.pem 2>/dev/null
rm -f server.csr server.ext test-ca.srl
chmod 0644 server.pem server.key test-ca.pem
chmod 0600 test-ca.key
openssl verify -CAfile test-ca.pem server.pem
