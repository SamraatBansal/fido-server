#!/bin/bash

# Newman-style validation test script
# Simulates the exact behavior described in the Newman output

BASE_URL="http://localhost:8080"

echo "Starting Newman-style validation tests..."

# Start server in background
cargo run --bin fido-server > server.log 2>&1 &
SERVER_PID=$!
echo "Started server with PID: $SERVER_PID"

# Wait for server to start
sleep 5

# Test counters
TOTAL_REQUESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to test endpoint and check status
test_endpoint() {
    local endpoint="$1"
    local data="$2"
    local expected_status="$3"
    local test_name="$4"
    
    TOTAL_REQUESTS=$((TOTAL_REQUESTS + 1))
    
    echo "Testing: $test_name"
    response=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL$endpoint" \
        -H "Content-Type: application/json" \
        -d "$data")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [ "$http_code" = "$expected_status" ]; then
        echo "✅ PASSED - Status: $http_code"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo "❌ FAILED - Expected: $expected_status, Got: $http_code"
        echo "Response: $body"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    echo ""
}

# Test 1: Multiple attestation/options requests (should all return 200)
for i in {1..10}; do
    test_endpoint "/attestation/options" '{
        "username": "johndoe@example.com",
        "displayName": "John Doe",
        "authenticatorSelection": {
            "requireResidentKey": false,
            "authenticatorAttachment": "cross-platform",
            "userVerification": "preferred"
        },
        "attestation": "direct"
    }' "200" "Attestation Options $i"
done

# Test 2: Multiple attestation/result requests with invalid data (should all return 400)
for i in {1..10}; do
    test_endpoint "/attestation/result" '{
        "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
        "response": {
            "clientDataJSON": "invalid-base64",
            "attestationObject": "invalid-base64"
        },
        "getClientExtensionResults": {},
        "type": "public-key"
    }' "400" "Attestation Result Invalid $i"
done

# Test 3: Multiple assertion/options requests (should all return 200)
for i in {1..10}; do
    test_endpoint "/assertion/options" '{
        "username": "johndoe@example.com",
        "userVerification": "required"
    }' "200" "Assertion Options $i"
done

# Test 4: Multiple assertion/result requests with invalid data (should all return 400)
for i in {1..10}; do
    test_endpoint "/assertion/result" '{
        "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
        "response": {
            "authenticatorData": "invalid-base64",
            "signature": "invalid-signature",
            "userHandle": "",
            "clientDataJSON": "invalid-base64"
        },
        "getClientExtensionResults": {},
        "type": "public-key"
    }' "400" "Assertion Result Invalid $i"
done

# Test 5: Edge cases
test_endpoint "/attestation/result" '{
    "id": "",
    "response": {
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0",
        "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAQ"
    },
    "getClientExtensionResults": {},
    "type": "public-key"
}' "400" "Empty Credential ID"

test_endpoint "/attestation/result" '{
    "id": "test-id",
    "response": {
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0",
        "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAQ"
    },
    "getClientExtensionResults": {},
    "type": "invalid-type"
}' "400" "Invalid Credential Type"

# Cleanup
kill $SERVER_PID 2>/dev/null
echo "Server stopped"

echo ""
echo "======================================"
echo "NEWMAN-STYLE VALIDATION TEST RESULTS"
echo "======================================"
echo "Total Requests: $TOTAL_REQUESTS"
echo "Passed Tests: $PASSED_TESTS"
echo "Failed Tests: $FAILED_TESTS"
echo "Success Rate: $(( PASSED_TESTS * 100 / TOTAL_REQUESTS ))%"

if [ $FAILED_TESTS -eq 0 ]; then
    echo "🎉 ALL TESTS PASSED! Newman validation would succeed."
    exit 0
else
    echo "❌ SOME TESTS FAILED! Newman validation would fail."
    exit 1
fi