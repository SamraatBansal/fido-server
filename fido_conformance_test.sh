#!/bin/bash

# Comprehensive FIDO Conformance Validation Test
# Tests exact API response formats as specified in FIDO conformance requirements

BASE_URL="http://localhost:8080"

echo "Starting FIDO Conformance Validation Test..."
echo "================================================"

# Start server
cargo run --bin fido-server > server.log 2>&1 &
SERVER_PID=$!
echo "Server PID: $SERVER_PID"

# Wait for server to start
sleep 3

# Test counters
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to test API response format
test_api_response() {
    local endpoint="$1"
    local data="$2"
    local expected_status="$3"
    local test_name="$4"
    local required_fields="$5"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    echo "Testing: $test_name"
    response=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL$endpoint" \
        -H "Content-Type: application/json" \
        -d "$data")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    if [ "$http_code" != "$expected_status" ]; then
        echo "❌ FAILED - Expected status $expected_status, got $http_code"
        echo "Response: $body"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return 1
    fi
    
    # Check required fields in response
    if [ -n "$required_fields" ]; then
        for field in $required_fields; do
            if ! echo "$body" | jq -e ".$field" > /dev/null 2>&1; then
                echo "❌ FAILED - Missing required field: $field"
                echo "Response: $body"
                FAILED_TESTS=$((FAILED_TESTS + 1))
                return 1
            fi
        done
    fi
    
    echo "✅ PASSED - Status: $http_code"
    PASSED_TESTS=$((PASSED_TESTS + 1))
    return 0
}

# Test 1: Attestation Options - Exact format validation
echo ""
echo "=== ATTESTATION OPTIONS TESTS ==="

attestation_options_request='{
    "username": "johndoe@example.com",
    "displayName": "John Doe",
    "authenticatorSelection": {
        "requireResidentKey": false,
        "authenticatorAttachment": "cross-platform",
        "userVerification": "preferred"
    },
    "attestation": "direct"
}'

test_api_response "/attestation/options" "$attestation_options_request" "200" \
    "Attestation Options Format" "status rp user challenge pubKeyCredParams timeout"

# Test 2: Attestation Result - Invalid signature (should fail)
echo ""
echo "=== ATTESTATION RESULT TESTS ==="

invalid_attestation='{
    "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
    "response": {
        "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJOeHlab3B3VktiRmw3RW5uTWFlXzVGbmlyN1FKN1FXcDFVRlVLakZIbGZrIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
        "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI"
    },
    "getClientExtensionResults": {},
    "type": "public-key"
}'

test_api_response "/attestation/result" "$invalid_attestation" "400" \
    "Attestation Result Invalid Signature" "status errorMessage"

# Test 3: Assertion Options - Exact format validation
echo ""
echo "=== ASSERTION OPTIONS TESTS ==="

assertion_options_request='{
    "username": "johndoe@example.com",
    "userVerification": "required"
}'

test_api_response "/assertion/options" "$assertion_options_request" "200" \
    "Assertion Options Format" "status challenge timeout rpId allowCredentials userVerification"

# Test 4: Assertion Result - Invalid signature (should fail)
echo ""
echo "=== ASSERTION RESULT TESTS ==="

invalid_assertion='{
    "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
    "response": {
        "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
        "signature": "MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
        "userHandle": "",
        "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9"
    },
    "getClientExtensionResults": {},
    "type": "public-key"
}'

test_api_response "/assertion/result" "$invalid_assertion" "400" \
    "Assertion Result Invalid Signature" "status errorMessage"

# Test 5: Edge cases
echo ""
echo "=== EDGE CASE TESTS ==="

empty_credential_id='{
    "id": "",
    "response": {
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0=",
        "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAQ=="
    },
    "getClientExtensionResults": {},
    "type": "public-key"
}'

test_api_response "/attestation/result" "$empty_credential_id" "400" \
    "Empty Credential ID" "status errorMessage"

invalid_credential_type='{
    "id": "test-id",
    "response": {
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0=",
        "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAQ=="
    },
    "getClientExtensionResults": {},
    "type": "invalid-type"
}'

test_api_response "/attestation/result" "$invalid_credential_type" "400" \
    "Invalid Credential Type" "status errorMessage"

# Cleanup
kill $SERVER_PID 2>/dev/null
echo ""
echo "Server stopped"

echo ""
echo "================================================"
echo "FIDO CONFORMANCE VALIDATION TEST RESULTS"
echo "================================================"
echo "Total Tests: $TOTAL_TESTS"
echo "Passed Tests: $PASSED_TESTS"
echo "Failed Tests: $FAILED_TESTS"
echo "Success Rate: $(( PASSED_TESTS * 100 / TOTAL_TESTS ))%"

if [ $FAILED_TESTS -eq 0 ]; then
    echo "🎉 ALL TESTS PASSED! FIDO conformance validation successful."
    exit 0
else
    echo "❌ SOME TESTS FAILED! FIDO conformance validation failed."
    exit 1
fi