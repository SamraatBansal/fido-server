#!/bin/bash

echo "Testing FIDO2/WebAuthn Server API Endpoints"
echo "=========================================="

BASE_URL="http://localhost:8080"

# Test 1: attestation/options with valid request
echo "Test 1: POST /attestation/options (valid request)"
RESPONSE=$(curl -s -w "%{http_code}" -X POST "$BASE_URL/attestation/options" \
  -H "Content-Type: application/json" \
  -d '{"username": "johndoe@example.com", "displayName": "John Doe", "authenticatorSelection": {"requireResidentKey": false, "authenticatorAttachment": "cross-platform", "userVerification": "preferred"}, "attestation": "direct"}' \
  -o /tmp/response1.json)

HTTP_CODE="${RESPONSE: -3}"
echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "✅ PASS: Status code 200"
else
    echo "❌ FAIL: Expected 200, got $HTTP_CODE"
fi

# Check for required fields
if grep -q '"errorMessage"' /tmp/response1.json; then
    echo "✅ PASS: Has errorMessage field"
else
    echo "❌ FAIL: Missing errorMessage field"
fi

if grep -q '"status":"ok"' /tmp/response1.json; then
    echo "✅ PASS: Has status: ok"
else
    echo "❌ FAIL: Missing or incorrect status"
fi

# Test 2: attestation/result with invalid request (should return 400)
echo -e "\nTest 2: POST /attestation/result (invalid request)"
RESPONSE=$(curl -s -w "%{http_code}" -X POST "$BASE_URL/attestation/result" \
  -H "Content-Type: application/json" \
  -d '{"id": "", "response": {"clientDataJSON": "invalid", "attestationObject": "invalid"}, "type": "public-key"}' \
  -o /tmp/response2.json)

HTTP_CODE="${RESPONSE: -3}"
echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "400" ]; then
    echo "✅ PASS: Status code 400 for invalid request"
else
    echo "❌ FAIL: Expected 400, got $HTTP_CODE"
fi

# Check error response format
if grep -q '"status":"failed"' /tmp/response2.json; then
    echo "✅ PASS: Has status: failed"
else
    echo "❌ FAIL: Missing or incorrect error status"
fi

# Test 3: assertion/options with valid request
echo -e "\nTest 3: POST /assertion/options (valid request)"
RESPONSE=$(curl -s -w "%{http_code}" -X POST "$BASE_URL/assertion/options" \
  -H "Content-Type: application/json" \
  -d '{"username": "johndoe@example.com", "userVerification": "required"}' \
  -o /tmp/response3.json)

HTTP_CODE="${RESPONSE: -3}"
echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "✅ PASS: Status code 200"
else
    echo "❌ FAIL: Expected 200, got $HTTP_CODE"
fi

# Test 4: assertion/result with invalid request (should return 400)
echo -e "\nTest 4: POST /assertion/result (invalid request)"
RESPONSE=$(curl -s -w "%{http_code}" -X POST "$BASE_URL/assertion/result" \
  -H "Content-Type: application/json" \
  -d '{"id": "", "response": {"authenticatorData": "invalid", "signature": "invalid", "clientDataJSON": "invalid"}, "type": "public-key"}' \
  -o /tmp/response4.json)

HTTP_CODE="${RESPONSE: -3}"
echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "400" ]; then
    echo "✅ PASS: Status code 400 for invalid request"
else
    echo "❌ FAIL: Expected 400, got $HTTP_CODE"
fi

echo -e "\n=========================================="
echo "API Testing Complete"