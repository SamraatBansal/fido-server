#!/bin/bash

# Test script to reproduce the exact Newman validation failures
# Based on the original Newman output showing 104 failures

BASE_URL="http://localhost:8080"

echo "Starting server..."
cargo run --bin fido-server > server.log 2>&1 &
SERVER_PID=$!
echo "Server PID: $SERVER_PID"

# Wait for server to start
sleep 3

echo "Testing endpoints that should fail with 400 but currently return 200..."

# Test cases from Newman that expect 400 but get 200
# These are the exact failing cases from the Newman output

test_case_1='{
    "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
    "response": {
        "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJOeHlab3B3VktiRmw3RW5uTWFlXzVGbmlyN1FKN1FXcDFVRlVLakZIbGZrIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
        "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI"
    },
    "getClientExtensionResults": {},
    "type": "public-key"
}'

echo "Test Case 1: Should return 400 (invalid signature) but currently returns 200"
response=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/attestation/result" \
    -H "Content-Type: application/json" \
    -d "$test_case_1")

http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | head -n -1)

echo "HTTP Status: $http_code"
echo "Response: $body"

if [ "$http_code" = "400" ]; then
    echo "✅ CORRECT: Returned 400 as expected"
else
    echo "❌ ERROR: Expected 400 but got $http_code"
fi

echo ""

# Test Case 2: Another case that should fail
test_case_2='{
    "id": "invalid_credential_id",
    "response": {
        "clientDataJSON": "invalid_base64",
        "attestationObject": "invalid_base64"
    },
    "getClientExtensionResults": {},
    "type": "public-key"
}'

echo "Test Case 2: Should return 400 (invalid data) but currently returns 200"
response=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/attestation/result" \
    -H "Content-Type: application/json" \
    -d "$test_case_2")

http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | head -n -1)

echo "HTTP Status: $http_code"
echo "Response: $body"

if [ "$http_code" = "400" ]; then
    echo "✅ CORRECT: Returned 400 as expected"
else
    echo "❌ ERROR: Expected 400 but got $http_code"
fi

echo ""

# Cleanup
kill $SERVER_PID 2>/dev/null
echo "Server stopped"