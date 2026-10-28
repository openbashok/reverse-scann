#!/bin/sh
set -e

CERT_DIR=/certs
CN="${TLS_CN:-localhost}"

# Genera un certificado autofirmado la primera vez (persiste en el volumen /certs)
if [ ! -f "$CERT_DIR/server.crt" ] || [ ! -f "$CERT_DIR/server.key" ]; then
    echo "[entrypoint] Generando certificado autofirmado CN=$CN ..."
    openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
        -subj "/CN=$CN" \
        -keyout "$CERT_DIR/server.key" \
        -out "$CERT_DIR/server.crt"
fi

mkdir -p /data/captures

exec /usr/local/openresty/bin/openresty -g "daemon off;"
