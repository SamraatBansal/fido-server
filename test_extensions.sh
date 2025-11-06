#!/bin/bash

echo "Testing FIDO2 WebAuthn Server Extensions Handling"
echo "================================================="

# Test 1: Request with specific extensions
echo "Test 1: Request with example.extension.bool=true"
curl -X POST http://localhost:8080/attestation/options \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser", 
    "displayName": "Test User",
    "extensions": {
      "example.extension.bool": true
    }
  }' | jq .

echo ""
echo "Test 2: Request with no extensions"
curl -X POST http://localhost:8080/attestation/options \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser2", 
    "displayName": "Test User 2"
  }' | jq .

echo ""
echo "Test 3: Request with multiple extensions"
curl -X POST http://localhost:8080/attestation/options \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser3", 
    "displayName": "Test User 3",
    "extensions": {
      "example.extension.bool": true,
      "example.extension": true
    }
  }' | jq .