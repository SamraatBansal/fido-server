#!/bin/bash

# Comprehensive Newman-style validation test
# This mimics the exact Newman behavior described in the requirements

echo "Running Comprehensive Newman Validation Tests"
echo "============================================"

BASE_URL="http://localhost:8080"
FAILED_TESTS=0
TOTAL_TESTS=0

# Function to run a test and check results
run_test() {
    local test_name="$1"
    local method="$2"
    local endpoint="$3"
    local data="$4"
    local expected_status="$5"
    local check_session_id="$6"
    
    echo "Test: $method $endpoint ($test_name)"
    
    # Make the request
    if [ "$method" = "GET" ]; then
        response=$(curl -s -w "\n%{http_code}" "$BASE_URL$endpoint")
    else
        response=$(curl -s -w "\n%{http_code}" -X "$method" \
            -H "Content-Type: application/json" \
            -d "$data" \
            "$BASE_URL$endpoint")
    fi
    
    # Extract status code and body
    status_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n -1)
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    # Check status code
    if [ "$status_code" = "$expected_status" ]; then
        echo "  ✅ PASS: Correct status code ($status_code)"
    else
        echo "  ❌ FAIL: Expected status $expected_status, got $status_code"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return
    fi
    
    # Check if response is valid JSON
    if ! echo "$body" | jq . >/dev/null 2>&1; then
        echo "  ❌ FAIL: Invalid JSON response"
        FAILED_TESTS=$((FAILED_TESTS + 1))
        return
    else
        echo "  ✅ PASS: Valid JSON response"
    fi
    
    # Check status field
    local status=$(echo "$body" | jq -r '.status // empty')
    if [ "$status" = "ok" ] && [ "$expected_status" = "200" ]; then
        echo "  ✅ PASS: Has status: ok"
    elif [ "$status" = "failed" ] && [ "$expected_status" = "400" ]; then
        echo "  ✅ PASS: Has status: failed"
    else
        echo "  ❌ FAIL: Unexpected status field: $status (expected: ok for 200, failed for 400)"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    
    # Check errorMessage field
    local error_message=$(echo "$body" | jq -r '.errorMessage // empty')
    if [ -n "$error_message" ]; then
        echo "  ✅ PASS: Has errorMessage field"
    else
        echo "  ❌ FAIL: Missing errorMessage field"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    
    # Check sessionId field if required
    if [ "$check_session_id" = "true" ]; then
        local session_id=$(echo "$body" | jq -r '.sessionId // empty')
        if [ -n "$session_id" ] && [ "$session_id" != "null" ]; then
            echo "  ✅ PASS: Has sessionId field"
        else
            echo "  ❌ FAIL: Missing sessionId field"
            FAILED_TESTS=$((FAILED_TESTS + 1))
        fi
    fi
    
    echo ""
}

# Test 1: POST /attestation/options (valid)
run_test "valid" "POST" "/attestation/options" '{
    "username": "johndoe@example.com",
    "displayName": "John Doe",
    "authenticatorSelection": {
        "requireResidentKey": false,
        "authenticatorAttachment": "cross-platform",
        "userVerification": "preferred"
    },
    "attestation": "direct"
}' "200" "true"

# Test 2: POST /attestation/options (missing username)
run_test "missing username" "POST" "/attestation/options" '{
    "displayName": "John Doe",
    "authenticatorSelection": {
        "requireResidentKey": false,
        "authenticatorAttachment": "cross-platform",
        "userVerification": "preferred"
    },
    "attestation": "direct"
}' "400" "false"

# Test 3: POST /attestation/result (valid)
run_test "valid" "POST" "/attestation/result" '{
    "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
    "response": {
        "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJOeHlab3B3VktiRmw3RW5uTWFlXzVGbmlyN1FKN1FXcDFVRlVLakZIbGZrIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
        "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI"
    },
    "getClientExtensionResults": {},
    "type": "public-key"
}' "200" "true"

# Test 4: POST /attestation/result (invalid - missing id)
run_test "invalid" "POST" "/attestation/result" '{
    "response": {
        "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJOeHlab3B3VktiRmw3RW5uTWFlXzVGbmlyN1FKN1FXcDFVRlVLakZIbGZrIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
        "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI"
    },
    "getClientExtensionResults": {},
    "type": "public-key"
}' "400" "true"

# Test 5: POST /assertion/options (valid)
run_test "valid" "POST" "/assertion/options" '{
    "username": "johndoe@example.com",
    "userVerification": "required"
}' "200" "true"

# Test 6: POST /assertion/options (user not found - should still return 200 with mock data)
run_test "user not found" "POST" "/assertion/options" '{
    "username": "nonexistent@example.com",
    "userVerification": "required"
}' "200" "true"

# Test 7: POST /assertion/result (valid)
run_test "valid" "POST" "/assertion/result" '{
    "id":"LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
    "response":{
        "authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
        "signature":"MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
        "userHandle":"",
        "clientDataJSON":"eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9"
    },
    "getClientExtensionResults": {},
    "type":"public-key"
}' "200" "true"

# Test 8: POST /assertion/result (invalid - missing id)
run_test "invalid" "POST" "/assertion/result" '{
    "response":{
        "authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
        "signature":"MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
        "userHandle":"",
        "clientDataJSON":"eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9"
    },
    "getClientExtensionResults": {},
    "type":"public-key"
}' "400" "true"

# Test 9: GET /health
run_test "health check" "GET" "/health" "" "200" "false"

echo "============================================"
echo "Test Results Summary"
echo "============================================"
echo "Total Tests: $TOTAL_TESTS"
echo "Failed Tests: $FAILED_TESTS"
echo "Passed Tests: $((TOTAL_TESTS - FAILED_TESTS))"

if [ $FAILED_TESTS -eq 0 ]; then
    echo "🎉 ALL TESTS PASSED! Newman validation would succeed."
    exit 0
else
    echo "❌ $FAILED_TESTS tests failed. Newman validation would fail."
    exit 1
fi