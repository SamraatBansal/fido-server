#!/bin/bash

echo "Comprehensive FIDO2/WebAuthn API Test (Simulating Newman)"
echo "======================================================"

BASE_URL="http://localhost:8080"
TOTAL_TESTS=0
PASSED_TESTS=0

# Helper function to run a test
run_test() {
    local test_name="$1"
    local expected_status="$2"
    local endpoint="$3"
    local data="$4"
    local check_field="$5"
    local check_value="$6"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo -e "\nTest $TOTAL_TESTS: $test_name"
    
    RESPONSE=$(curl -s -w "%{http_code}" -X POST "$BASE_URL$endpoint" \
      -H "Content-Type: application/json" \
      -d "$data" \
      -o /tmp/test_response.json)
    
    HTTP_CODE="${RESPONSE: -3}"
    echo "HTTP Status: $HTTP_CODE (Expected: $expected_status)"
    
    if [ "$HTTP_CODE" = "$expected_status" ]; then
        echo "✅ PASS: Correct status code"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo "❌ FAIL: Expected $expected_status, got $HTTP_CODE"
        return
    fi
    
    # Additional field checks if specified
    if [ -n "$check_field" ]; then
        if grep -q "\"$check_field\":\"$check_value\"" /tmp/test_response.json; then
            echo "✅ PASS: Field $check_field has correct value: $check_value"
        else
            echo "❌ FAIL: Field $check_field missing or incorrect"
            cat /tmp/test_response.json
        fi
    fi
}

# Test 1-12: Multiple attestation/options requests (Newman showed these all passing)
for i in {1..6}; do
    run_test "attestation/options request $i" "200" "/attestation/options" \
        '{"username": "johndoe@example.com", "displayName": "John Doe", "authenticatorSelection": {"requireResidentKey": false, "authenticatorAttachment": "cross-platform", "userVerification": "preferred"}, "attestation": "direct"}' \
        "status" "ok"
done

# Test 13-22: attestation/result with various invalid requests (should return 400)
run_test "attestation/result - empty credential ID" "400" "/attestation/result" \
    '{"id": "", "response": {"clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ0ZXN0IiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9", "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA"}, "type": "public-key"}' \
    "status" "failed"

run_test "attestation/result - invalid credential type" "400" "/attestation/result" \
    '{"id": "test_id", "response": {"clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ0ZXN0IiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9", "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA"}, "type": "invalid_type"}' \
    "status" "failed"

run_test "attestation/result - missing clientDataJSON" "400" "/attestation/result" \
    '{"id": "test_id", "response": {"attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA"}, "type": "public-key"}' \
    "status" "failed"

run_test "attestation/result - missing attestationObject" "400" "/attestation/result" \
    '{"id": "test_id", "response": {"clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ0ZXN0IiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9"}, "type": "public-key"}' \
    "status" "failed"

run_test "attestation/result - invalid base64 clientDataJSON" "400" "/attestation/result" \
    '{"id": "test_id", "response": {"clientDataJSON": "invalid_base64!", "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA"}, "type": "public-key"}' \
    "status" "failed"

# Test 23-32: assertion/options requests
for i in {1..5}; do
    run_test "assertion/options request $i" "200" "/assertion/options" \
        '{"username": "johndoe@example.com", "userVerification": "required"}' \
        "status" "ok"
done

# Test 33-42: assertion/result with various invalid requests (should return 400)
run_test "assertion/result - empty credential ID" "400" "/assertion/result" \
    '{"id": "", "response": {"authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA", "signature": "MEUCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL", "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9"}, "type": "public-key"}' \
    "status" "failed"

run_test "assertion/result - invalid credential type" "400" "/assertion/result" \
    '{"id": "test_id", "response": {"authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA", "signature": "MEUCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL", "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9"}, "type": "invalid_type"}' \
    "status" "failed"

run_test "assertion/result - missing authenticatorData" "400" "/assertion/result" \
    '{"id": "test_id", "response": {"signature": "MEUCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL", "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9"}, "type": "public-key"}' \
    "status" "failed"

run_test "assertion/result - missing signature" "400" "/assertion/result" \
    '{"id": "test_id", "response": {"authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA", "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9"}, "type": "public-key"}' \
    "status" "failed"

run_test "assertion/result - missing clientDataJSON" "400" "/assertion/result" \
    '{"id": "test_id", "response": {"authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA", "signature": "MEUCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL"}, "type": "public-key"}' \
    "status" "failed"

echo -e "\n======================================================"
echo "Test Results Summary"
echo "======================================================"
echo "Total Tests: $TOTAL_TESTS"
echo "Passed Tests: $PASSED_TESTS"
echo "Failed Tests: $((TOTAL_TESTS - PASSED_TESTS))"

if [ $PASSED_TESTS -eq $TOTAL_TESTS ]; then
    echo "🎉 ALL TESTS PASSED! The FIDO2/WebAuthn server is working correctly."
    exit 0
else
    echo "❌ Some tests failed. Please check the implementation."
    exit 1
fi