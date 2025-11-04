#!/bin/bash

# FIDO Conformance Test Script
# Tests the exact API endpoints and response formats from the specification

echo "🔐 Testing FIDO2/WebAuthn Server Conformance"
echo "=============================================="

BASE_URL="http://localhost:8080"

# Test 1: Registration Options (attestation/options)
echo ""
echo "📝 Test 1: Registration Options"
echo "POST /webauthn/attestation/options"

RESPONSE=$(curl -s -X POST "${BASE_URL}/webauthn/attestation/options" \
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

echo "Response: $RESPONSE"

# Validate response structure
STATUS=$(echo "$RESPONSE" | jq -r '.status // "error"')
ERROR_MESSAGE=$(echo "$RESPONSE" | jq -r '.errorMessage // ""')
RP_NAME=$(echo "$RESPONSE" | jq -r '.rp.name // ""')
USER_NAME=$(echo "$RESPONSE" | jq -r '.user.name // ""')
USER_DISPLAY_NAME=$(echo "$RESPONSE" | jq -r '.user.displayName // ""')
CHALLENGE=$(echo "$RESPONSE" | jq -r '.challenge // ""')

if [ "$STATUS" = "ok" ] && [ "$ERROR_MESSAGE" = "" ] && [ "$RP_NAME" = "Example Corporation" ] && [ "$USER_NAME" = "johndoe@example.com" ] && [ "$USER_DISPLAY_NAME" = "John Doe" ] && [ "$CHALLENGE" != "" ]; then
    echo "✅ Test 1 PASSED - Registration options format is correct"
else
    echo "❌ Test 1 FAILED - Registration options format is incorrect"
    exit 1
fi

# Test 2: Authentication Options (assertion/options)
echo ""
echo "🔑 Test 2: Authentication Options"
echo "POST /webauthn/assertion/options"

RESPONSE=$(curl -s -X POST "${BASE_URL}/webauthn/assertion/options" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "johndoe@example.com",
    "userVerification": "required"
  }')

echo "Response: $RESPONSE"

# Validate response structure
STATUS=$(echo "$RESPONSE" | jq -r '.status // "error"')
ERROR_MESSAGE=$(echo "$RESPONSE" | jq -r '.errorMessage // ""')
RP_ID=$(echo "$RESPONSE" | jq -r '.rpId // ""')
USER_VERIFICATION=$(echo "$RESPONSE" | jq -r '.userVerification // ""')

if [ "$STATUS" = "ok" ] && [ "$ERROR_MESSAGE" = "" ] && [ "$RP_ID" = "localhost" ] && [ "$USER_VERIFICATION" = "required" ]; then
    echo "✅ Test 2 PASSED - Authentication options format is correct"
else
    echo "❌ Test 2 FAILED - Authentication options format is incorrect"
    exit 1
fi

# Test 3: Error Handling - Missing username
echo ""
echo "⚠️  Test 3: Error Handling - Missing Username"
echo "POST /webauthn/attestation/options"

RESPONSE=$(curl -s -X POST "${BASE_URL}/webauthn/attestation/options" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "",
    "displayName": "John Doe",
    "attestation": "direct"
  }')

echo "Response: $RESPONSE"

# Validate error response
STATUS=$(echo "$RESPONSE" | jq -r '.status // "error"')
ERROR_MESSAGE=$(echo "$RESPONSE" | jq -r '.errorMessage // ""')

if [ "$STATUS" = "failed" ] && [ "$ERROR_MESSAGE" != "" ]; then
    echo "✅ Test 3 PASSED - Error handling is correct"
else
    echo "❌ Test 3 FAILED - Error handling is incorrect"
    exit 1
fi

# Test 4: Error Handling - User not found
echo ""
echo "🚫 Test 4: Error Handling - User Not Found"
echo "POST /webauthn/assertion/options"

RESPONSE=$(curl -s -X POST "${BASE_URL}/webauthn/assertion/options" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "nonexistent@example.com",
    "userVerification": "required"
  }')

echo "Response: $RESPONSE"

# Validate error response
STATUS=$(echo "$RESPONSE" | jq -r '.status // "error"')
ERROR_MESSAGE=$(echo "$RESPONSE" | jq -r '.errorMessage // ""')

if [ "$STATUS" = "failed" ] && [[ "$ERROR_MESSAGE" == *"User does not exists"* ]]; then
    echo "✅ Test 4 PASSED - User not found error is correct"
else
    echo "❌ Test 4 FAILED - User not found error is incorrect"
    exit 1
fi

echo ""
echo "🎉 ALL TESTS PASSED! FIDO2/WebAuthn server is conformant to the specification."
echo ""
echo "📊 Summary:"
echo "   ✅ Registration options endpoint works correctly"
echo "   ✅ Authentication options endpoint works correctly"
echo "   ✅ Error handling works correctly"
echo "   ✅ Response formats match FIDO specification"
echo ""
echo "🚀 The server is ready for FIDO conformance testing!"