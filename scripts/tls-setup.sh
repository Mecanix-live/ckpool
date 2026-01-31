#!/bin/bash

# Pool operator TLS setup tool

set -e

CERTS_DIR="$(pwd)/certs"

echo "=== CKPool TLS Setup ==="
echo ""

if [ "$1" = "--self-signed" ]; then
    # Generate self-signed certs
    openssl req -x509 -newkey rsa:4096 \
        -keyout "$CERTS_DIR/server.key" \
        -out "$CERTS_DIR/server.crt" \
        -days 365 -nodes \
        -subj "/C=US/ST=California/L=San Francisco/O=My Mining Pool/CN=pool.example.com"
    
    cp "$CERTS_DIR/server.crt" "$CERTS_DIR/ca.crt"
    
    echo "Self-signed certificates generated in $CERTS_DIR/"
    
elif [ "$1" = "--ca" ]; then
    # Generate CA infrastructure
    openssl genrsa -out "$CERTS_DIR/ca.key" 4096
    openssl req -x509 -new -nodes -key "$CERTS_DIR/ca.key" \
        -subj "/C=US/ST=California/L=San Francisco/O=Mining Pool Co Ltd CA/CN=ca.pool.example.com" \
        -days 3650 -out "$CERTS_DIR/ca.crt"
    
    openssl genrsa -out "$CERTS_DIR/server.key" 4096
    openssl req -new -key "$CERTS_DIR/server.key" \
        -subj "/C=US/ST=California/L=San Francisco/O=Mining Pool Co Ltd/CN=pool.example.com" \
        -out "$CERTS_DIR/server.csr"
    
    openssl x509 -req -in "$CERTS_DIR/server.csr" \
        -CA "$CERTS_DIR/ca.crt" -CAkey "$CERTS_DIR/ca.key" -CAcreateserial \
        -out "$CERTS_DIR/server.crt" -days 365 -sha256
    
    rm -f "$CERTS_DIR/server.csr" "$CERTS_DIR/ca.srl"
    
    echo "CA-signed certificates generated in $CERTS_DIR/"
    
elif [ "$1" = "--letsencrypt" ]; then
    # Instructions for Let's Encrypt
    echo "=== Let's Encrypt Setup ==="
    echo "1. Install certbot: sudo apt install certbot"
    echo "2. Run: sudo certbot certonly --standalone -d pool.example.com"
    echo "3. Certificates will be in /etc/letsencrypt/live/pool.example.com/"
    echo "4. Configure ckpool.conf with:"
    echo "   \"tls_cert\": \"/etc/letsencrypt/live/pool.example.com/fullchain.pem\","
    echo "   \"tls_key\": \"/etc/letsencrypt/live/pool.example.com/privkey.pem\","
    
else
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  --self-signed    Generate self-signed certificates (testing)"
    echo "  --ca             Generate CA infrastructure (internal use)"
    echo "  --letsencrypt    Instructions for Let's Encrypt (production)"
    echo ""
    echo "For production, we recommend:"
    echo "  1. Use Let's Encrypt for public pools"
    echo "  2. Use commercial CA for enterprise"
    echo "  3. Self-signed only for testing"
fi