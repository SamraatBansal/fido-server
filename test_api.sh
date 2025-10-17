#!/bin/bash

# Comprehensive API test script for FIDO2/WebAuthn endpoints
# This simulates the Newman validation tests

BASE_URL="http://localhost:8080"

echo "Starting FIDO2 API validation tests..."

# Start server in background
cargo run --bin fido-server > server.log 2>&1 & 
SERVER_PID=$!
echo "Started server with PID: $SERVER_PID"

# Wait for server to start
sleep 5

# Test 1: Attestation Options
echo "Test 1: POST /attestation/options"
RESPONSE1=$(curl -s -X POST "$BASE_URL/attestation/options" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "johndoe@example.com",
    "displayName": "John Doe",
    "authenticatorSelection": {
      "requireResidentKey": false,
      "authenticatorAttachment": "cross-platform",
      "userVerification": "preferred"
    },
    "attestation": "direct"
  }')

echo "Response: $RESPONSE1"

# Validate response has required fields
if echo "$RESPONSE1" | jq -e '.status == "ok"' > /dev/null && \
   echo "$RESPONSE1" | jq -e '.sessionId' > /dev/null && \
   echo "$RESPONSE1" | jq -e '.challenge' > /dev/null && \
   echo "$RESPONSE1" | jq -e '.rp' > /dev/null && \
   echo "$RESPONSE1" | jq -e '.user' > /dev/null && \
   echo "$RESPONSE1" | jq -e '.pubKeyCredParams' > /dev/null; then
  echo "✅ Attestation Options test PASSED"
else
  echo "❌ Attestation Options test FAILED"
fi

# Test 2: Attestation Result (with invalid data - should return 400)
echo "Test 2: POST /attestation/result"
RESPONSE2=$(curl -s -X POST "$BASE_URL/attestation/result" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "invalid-credential-id",
    "response": {
      "clientDataJSON": "invalid-base64",
      "attestationObject": "invalid-base64"
    },
    "type": "public-key"
  }')

echo "Response: $RESPONSE2"

# Should return error status
if echo "$RESPONSE2" | jq -e '.status == "failed"' > /dev/null; then
  echo "✅ Attestation Result error handling PASSED"
else
  echo "❌ Attestation Result error handling FAILED"
fi

# Test 3: Assertion Options
echo "Test 3: POST /assertion/options"
RESPONSE3=$(curl -s -X POST "$BASE_URL/assertion/options" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "johndoe@example.com",
    "userVerification": "required"
  }')

echo "Response: $RESPONSE3"

# Validate response has required fields
if echo "$RESPONSE3" | jq -e '.status == "ok"' > /dev/null && \
   echo "$RESPONSE3" | jq -e '.sessionId' > /dev/null && \
   echo "$RESPONSE3" | jq -e '.challenge' > /dev/null && \
   echo "$RESPONSE3" | jq -e '.rpId' > /dev/null && \
   echo "$RESPONSE3" | jq -e '.allowCredentials' > /dev/null; then
  echo "✅ Assertion Options test PASSED"
else
  echo "❌ Assertion Options test FAILED"
fi

# Test 4: Assertion Result (with invalid data - should return 400)
echo "Test 4: POST /assertion/result"
RESPONSE4=$(curl -s -X POST "$BASE_URL/assertion/result" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "invalid-credential-id",
    "response": {
      "authenticatorData": "invalid-base64",
      "signature": "invalid-base64",
      "userHandle": "",
      "clientDataJSON": "invalid-base64"
    },
    "type": "public-key"
  }')

echo "Response: $RESPONSE4"

# Should return error status
if echo "$RESPONSE4" | jq -e '.status == "failed"' > /dev/null; then
  echo "✅ Assertion Result error handling PASSED"
else
  echo "❌ Assertion Result error handling FAILED"
fi

# Cleanup
kill $SERVER_PID 2>/dev/null
echo "Server stopped"

echo "API validation tests completed!"