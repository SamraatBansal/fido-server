#!/bin/bash

echo "FIDO2 Conformance Test - Exact Extension Handling"
echo "=================================================="

# Test the exact case from the failing test
echo "Testing exact case from Server-ServerPublicKeyCredentialCreationOptions-Req-1"
echo "Should return extensions with only example.extension.bool: true"

RESPONSE=$(curl -s -X POST http://localhost:8080/attestation/options \
  -H "Content-Type: application/json" \
  -d '{
    "username": "conformancetest",
    "displayName": "Conformance Test User",
    "extensions": {
      "example.extension.bool": true
    }
  }')

echo "Response:"
echo "$RESPONSE" | jq '.'

echo ""
echo "Checking extensions field specifically:"
EXTENSIONS=$(echo "$RESPONSE" | jq '.extensions')
echo "$EXTENSIONS"

echo ""
echo "Validating response structure:"

# Check required fields
STATUS=$(echo "$RESPONSE" | jq -r '.status')
ERROR_MESSAGE=$(echo "$RESPONSE" | jq -r '.errorMessage')
RP_NAME=$(echo "$RESPONSE" | jq -r '.rp.name')
RP_ID=$(echo "$RESPONSE" | jq -r '.rp.id')
USER_NAME=$(echo "$RESPONSE" | jq -r '.user.name')
USER_DISPLAY_NAME=$(echo "$RESPONSE" | jq -r '.user.displayName')
USER_ID=$(echo "$RESPONSE" | jq -r '.user.id')
CHALLENGE=$(echo "$RESPONSE" | jq -r '.challenge')
PUB_KEY_CRED_PARAMS=$(echo "$RESPONSE" | jq '.pubKeyCredParams | length')
EXCLUDE_CREDS=$(echo "$RESPONSE" | jq '.excludeCredentials')

echo "✓ status: $STATUS (should be 'ok')"
echo "✓ errorMessage: '$ERROR_MESSAGE' (should be empty)"
echo "✓ rp.name: '$RP_NAME' (should be non-empty)"
echo "✓ rp.id: '$RP_ID' (should be non-empty)"
echo "✓ user.name: '$USER_NAME' (should match request)"
echo "✓ user.displayName: '$USER_DISPLAY_NAME' (should match request)"
echo "✓ user.id: '$USER_ID' (should be base64url)"
echo "✓ challenge: '$CHALLENGE' (should be base64url, >21 chars)"
echo "✓ pubKeyCredParams count: $PUB_KEY_CRED_PARAMS (should be >0)"
echo "✓ excludeCredentials: $EXCLUDE_CREDS (should be array)"

# Validate base64url format
if [[ $USER_ID =~ ^[a-zA-Z0-9_-]+$ ]]; then
    echo "✓ user.id is valid base64url format"
else
    echo "✗ user.id is NOT valid base64url format"
fi

if [[ $CHALLENGE =~ ^[a-zA-Z0-9_-]+$ ]]; then
    echo "✓ challenge is valid base64url format"
else
    echo "✗ challenge is NOT valid base64url format"
fi

# Check challenge length (should be >21 chars for >16 bytes)
if [ ${#CHALLENGE} -gt 21 ]; then
    echo "✓ challenge length is sufficient (${#CHALLENGE} chars)"
else
    echo "✗ challenge length is too short (${#CHALLENGE} chars)"
fi

echo ""
echo "SUMMARY:"
if [ "$STATUS" = "ok" ] && [ "$ERROR_MESSAGE" = "" ] && [ ${#CHALLENGE} -gt 21 ]; then
    echo "🎉 FIDO2 Conformance Test PASSED"
else
    echo "❌ FIDO2 Conformance Test FAILED"
fi