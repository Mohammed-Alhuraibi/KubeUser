#!/bin/bash

# Generate self-signed certificates for local webhook testing

CERT_DIR="/tmp/k8s-webhook-server/serving-certs"
mkdir -p "$CERT_DIR"

echo "Generating self-signed certificates for local webhook testing..."

# Generate private key
openssl genrsa -out "$CERT_DIR/tls.key" 2048

# Generate certificate signing request
openssl req -new -key "$CERT_DIR/tls.key" -out "$CERT_DIR/tls.csr" -subj "/CN=localhost/O=kubeuser"

# Generate self-signed certificate
openssl x509 -req -in "$CERT_DIR/tls.csr" -signkey "$CERT_DIR/tls.key" -out "$CERT_DIR/tls.crt" -days 365 -extensions v3_req -extfile <(
cat <<EOF
[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
DNS.2 = kubeuser-webhook-service
DNS.3 = kubeuser-webhook-service.kubeuser
DNS.4 = kubeuser-webhook-service.kubeuser.svc
DNS.5 = kubeuser-webhook-service.kubeuser.svc.cluster.local
IP.1 = 127.0.0.1
IP.2 = ::1
EOF
)

# Clean up CSR
rm "$CERT_DIR/tls.csr"

echo "✅ Certificates generated in $CERT_DIR"
echo "   - tls.crt (certificate)"
echo "   - tls.key (private key)"
echo
echo "You can now run: make run"