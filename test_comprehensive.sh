#!/bin/bash

echo "Comprehensive FIDO2 WebAuthn Server Testing"
echo "==========================================="

# Test basic registration endpoint
echo "Test 1: Basic Registration Request"
curl -X POST http://localhost:8080/attestation/options \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john.doe",
    "displayName": "John Doe",
    "authenticatorSelection": {
      "requireResidentKey": false,
      "userVerification": "preferred"
    },
    "attestation": "none"
  }' | jq '.'

echo ""
echo "Test 2: Registration with userVerification required"
curl -X POST http://localhost:8080/attestation/options \
  -H "Content-Type: application/json" \
  -d '{
    "username": "jane.doe", 
    "displayName": "Jane Doe",
    "authenticatorSelection": {
      "userVerification": "required"
    },
    "attestation": "direct"
  }' | jq '.'

echo ""
echo "Test 3: Registration with empty username (should fail)"
curl -X POST http://localhost:8080/attestation/options \
  -H "Content-Type: application/json" \
  -d '{
    "username": "",
    "displayName": "Test User"
  }' | jq '.'

echo ""
echo "Test 4: Registration missing username (should fail)" 
curl -X POST http://localhost:8080/attestation/options \
  -H "Content-Type: application/json" \
  -d '{
    "displayName": "Test User"
  }' | jq '.'

echo ""
echo "Test 5: Registration for existing user (should have excludeCredentials)"
# First registration
RESPONSE1=$(curl -s -X POST http://localhost:8080/attestation/options \
  -H "Content-Type: application/json" \
  -d '{
    "username": "existing.user",
    "displayName": "Existing User",
    "attestation": "direct"
  }')

echo "First registration response:"
echo "$RESPONSE1" | jq '.'

# Simulate completing first registration with a mock credential
echo ""
echo "Mock credential registration result:"
curl -X POST http://localhost:8080/attestation/result \
  -H "Content-Type: application/json" \
  -d '{
    "id": "mock-credential-id-base64url",
    "type": "public-key",
    "response": {
      "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiJ$(echo "$RESPONSE1" | jq -r '.challenge')SKEFOYW5kIjoid2ViYXV0aG4uY3JlYXRlIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIn0",
      "attestationObject": "mock-attestation-object-base64url"
    },
    "getClientExtensionResults": {}
  }' | jq '.' || echo "Expected failure for mock data"

echo ""
echo "Test 6: Authentication Request"
curl -X POST http://localhost:8080/assertion/options \
  -H "Content-Type: application/json" \
  -d '{
    "username": "existing.user",
    "userVerification": "preferred"
  }' | jq '.'

echo ""
echo "Test 7: Authentication for non-existent user (should fail)"
curl -X POST http://localhost:8080/assertion/options \
  -H "Content-Type: application/json" \
  -d '{
    "username": "nonexistent.user"
  }' | jq '.'