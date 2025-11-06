#!/bin/bash

# Script to test FIDO2 WebAuthn server against conformance test patterns

echo "Starting FIDO2 WebAuthn Server..."
cargo run &
SERVER_PID=$!

# Wait for server to start
sleep 3

echo "Testing server endpoints..."

echo "1. Testing valid registration request..."
curl -X POST http://localhost:8080/attestation/options \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "displayName": "Test User"}' \
  | jq .

echo -e "\n2. Testing empty username (should fail)..."
curl -X POST http://localhost:8080/attestation/options \
  -H "Content-Type: application/json" \
  -d '{"username": "", "displayName": "Test User"}' \
  | jq .

echo -e "\n3. Testing missing displayName (should fail)..."  
curl -X POST http://localhost:8080/attestation/options \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser"}' \
  | jq .

echo -e "\n4. Testing invalid credential type (should fail)..."
curl -X POST http://localhost:8080/attestation/result \
  -H "Content-Type: application/json" \
  -d '{"id": "test", "type": "invalid", "response": {"clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0", "attestationObject": "dGVzdA"}}' \
  | jq .

echo -e "\n5. Testing missing id field (should fail)..."
curl -X POST http://localhost:8080/attestation/result \
  -H "Content-Type: application/json" \
  -d '{"type": "public-key", "response": {"clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0", "attestationObject": "dGVzdA"}}'

echo -e "\n6. Testing health check..."
curl -X GET http://localhost:8080/health | jq .

echo -e "\n\nStopping server..."
kill $SERVER_PID

echo "Tests complete!"