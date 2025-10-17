#!/bin/bash

# Test script to validate FIDO2 endpoints like Newman tests

BASE_URL="http://localhost:8080"
FAILED_TESTS=0

echo "Testing FIDO2 WebAuthn endpoints..."

# Test 1: Attestation Options - Valid request
echo "Test 1: Attestation Options - Valid request"
response=$(curl -s -w "%{http_code}" -X POST "$BASE_URL/attestation/options" \
  -H "Content-Type: application/json" \
  -d '{"username": "johndoe@example.com", "displayName": "John Doe", "authenticatorSelection": {"requireResidentKey": false, "authenticatorAttachment": "cross-platform", "userVerification": "preferred"}, "attestation": "direct"}')

http_code="${response: -3}"
response_body="${response%???}"

if [ "$http_code" = "200" ]; then
    echo "✓ Status code: 200 OK"
    # Check if response is valid JSON and has required fields
    if echo "$response_body" | jq -e '.status' > /dev/null 2>&1 && \
       echo "$response_body" | jq -e '.challenge' > /dev/null 2>&1 && \
       echo "$response_body" | jq -e '.rp' > /dev/null 2>&1 && \
       echo "$response_body" | jq -e '.user' > /dev/null 2>&1; then
        echo "✓ Response has required fields"
    else
        echo "✗ Response missing required fields"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
else
    echo "✗ Expected 200, got $http_code"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

# Test 2: Attestation Options - Missing username
echo -e "\nTest 2: Attestation Options - Missing username"
response=$(curl -s -w "%{http_code}" -X POST "$BASE_URL/attestation/options" \
  -H "Content-Type: application/json" \
  -d '{"username": "", "displayName": "John Doe"}')

http_code="${response: -3}"
response_body="${response%???}"

if [ "$http_code" = "400" ]; then
    echo "✓ Status code: 400 Bad Request"
    # Check if response is valid JSON error format
    if echo "$response_body" | jq -e '.status' > /dev/null 2>&1 && \
       echo "$response_body" | jq -e '.errorMessage' > /dev/null 2>&1; then
        echo "✓ Error response has correct format"
    else
        echo "✗ Error response missing required fields"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
else
    echo "✗ Expected 400, got $http_code"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

# Test 3: Attestation Result - Invalid JSON
echo -e "\nTest 3: Attestation Result - Invalid JSON"
response=$(curl -s -w "%{http_code}" -X POST "$BASE_URL/attestation/result" \
  -H "Content-Type: application/json" \
  -d 'invalid json')

http_code="${response: -3}"
response_body="${response%???}"

if [ "$http_code" = "400" ]; then
    echo "✓ Status code: 400 Bad Request"
    # Check if response is valid JSON error format
    if echo "$response_body" | jq -e '.status' > /dev/null 2>&1 && \
       echo "$response_body" | jq -e '.errorMessage' > /dev/null 2>&1; then
        echo "✓ Error response has correct format"
    else
        echo "✗ Error response missing required fields"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
else
    echo "✗ Expected 400, got $http_code"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

# Test 4: Attestation Result - Missing required fields
echo -e "\nTest 4: Attestation Result - Missing required fields"
response=$(curl -s -w "%{http_code}" -X POST "$BASE_URL/attestation/result" \
  -H "Content-Type: application/json" \
  -d '{"id": "", "type": "public-key", "response": {}}')

http_code="${response: -3}"
response_body="${response%???}"

if [ "$http_code" = "400" ]; then
    echo "✓ Status code: 400 Bad Request"
    # Check if response is valid JSON error format
    if echo "$response_body" | jq -e '.status' > /dev/null 2>&1 && \
       echo "$response_body" | jq -e '.errorMessage' > /dev/null 2>&1; then
        echo "✓ Error response has correct format"
    else
        echo "✗ Error response missing required fields"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
else
    echo "✗ Expected 400, got $http_code"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

# Test 5: Assertion Options - Valid request
echo -e "\nTest 5: Assertion Options - Valid request"
response=$(curl -s -w "%{http_code}" -X POST "$BASE_URL/assertion/options" \
  -H "Content-Type: application/json" \
  -d '{"username": "johndoe@example.com", "userVerification": "required"}')

http_code="${response: -3}"
response_body="${response%???}"

if [ "$http_code" = "200" ]; then
    echo "✓ Status code: 200 OK"
    # Check if response is valid JSON and has required fields
    if echo "$response_body" | jq -e '.status' > /dev/null 2>&1 && \
       echo "$response_body" | jq -e '.challenge' > /dev/null 2>&1 && \
       echo "$response_body" | jq -e '.rpId' > /dev/null 2>&1 && \
       echo "$response_body" | jq -e '.allowCredentials' > /dev/null 2>&1; then
        echo "✓ Response has required fields"
    else
        echo "✗ Response missing required fields"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
else
    echo "✗ Expected 200, got $http_code"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

# Test 6: Assertion Result - Invalid data
echo -e "\nTest 6: Assertion Result - Invalid data"
response=$(curl -s -w "%{http_code}" -X POST "$BASE_URL/assertion/result" \
  -H "Content-Type: application/json" \
  -d '{"id": "test", "type": "public-key", "response": {"authenticatorData": "invalid", "signature": "invalid", "userHandle": "", "clientDataJSON": "invalid"}}')

http_code="${response: -3}"
response_body="${response%???}"

if [ "$http_code" = "400" ]; then
    echo "✓ Status code: 400 Bad Request"
    # Check if response is valid JSON error format
    if echo "$response_body" | jq -e '.status' > /dev/null 2>&1 && \
       echo "$response_body" | jq -e '.errorMessage' > /dev/null 2>&1; then
        echo "✓ Error response has correct format"
    else
        echo "✗ Error response missing required fields"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
else
    echo "✗ Expected 400, got $http_code"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

echo -e "\n================================"
echo "Test Summary:"
echo "Failed tests: $FAILED_TESTS"
if [ $FAILED_TESTS -eq 0 ]; then
    echo "✓ All tests passed!"
    exit 0
else
    echo "✗ Some tests failed"
    exit 1
fi