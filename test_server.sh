#!/bin/bash

# Test script for FIDO2 WebAuthn server

echo "Building the server..."
cargo build --release

echo "Starting the server in background..."
cargo run --release &
SERVER_PID=$!

# Give server time to start
sleep 2

echo "Testing health endpoint..."
curl -s http://127.0.0.1:8080/health

echo -e "\n\nTesting attestation/options endpoint..."
curl -s -X POST http://127.0.0.1:8080/attestation/options \
  -H "Content-Type: application/json" \
  -d '{
    "username": "test@example.com",
    "displayName": "Test User",
    "attestation": "none"
  }' | jq .

echo -e "\n\nTesting attestation/options with invalid data..."
curl -s -X POST http://127.0.0.1:8080/attestation/options \
  -H "Content-Type: application/json" \
  -d '{
    "username": "",
    "displayName": "Test User",
    "attestation": "none"
  }' | jq .

echo -e "\n\nTesting assertion/options with non-existent user..."
curl -s -X POST http://127.0.0.1:8080/assertion/options \
  -H "Content-Type: application/json" \
  -d '{
    "username": "nonexistent@example.com"
  }' | jq .

echo -e "\n\nStopping server..."
kill $SERVER_PID

echo "Test completed!"