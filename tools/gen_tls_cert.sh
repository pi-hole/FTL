#!/bin/bash
# This script generates a self-signed certificate valid for 10 years
openssl req -new -newkey rsa:4096 -days 3650 -nodes -x509 \
    -subj "/C=DE/ST=NRW/L=Bonn/O=Pi.hole/CN=pi.hole" \
    -keyout pihole.key -out pihole.crt

# Alternatively, generate a ECDSA certificate
# openssl ecparam -out pihole.key -name prime256v1 -genkey
# openssl req -new -days 3650 -nodes -x509 \
#     -subj "/C=DE/ST=NRW/L=Bonn/O=Pi.hole/CN=pi.hole" \
#     -key pihole.key -out pihole.cert

# Combine key and certificate into a single PEM file
cp pihole.crt pihole.pem
cat pihole.key >> pihole.pem
