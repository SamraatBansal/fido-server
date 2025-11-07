#!/bin/bash

echo "Testing FIDO Server Endpoints..."

# Base URL
BASE_URL="http://localhost:8080"

echo -e "\n1. Testing health endpoint..."
curl -s -X GET "$BASE_URL/health" | jq '.'

echo -e "\n2. Testing attestation/options (registration begin)..."
REGISTRATION_REQUEST='{
  "username": "testuser@example.com",
  "displayName": "Test User",
  "authenticatorSelection": {
    "requireResidentKey": false,
    "authenticatorAttachment": "cross-platform",
    "userVerification": "preferred"
  },
  "attestation": "direct"
}'

REGISTRATION_RESPONSE=$(curl -s -X POST "$BASE_URL/attestation/options" \
  -H "Content-Type: application/json" \
  -d "$REGISTRATION_REQUEST")

echo "$REGISTRATION_RESPONSE" | jq '.'

# Extract challenge for testing
CHALLENGE=$(echo "$REGISTRATION_RESPONSE" | jq -r '.challenge')
echo "Challenge: $CHALLENGE"

echo -e "\n3. Testing attestation/result (registration complete) with mock data..."
# This would normally come from the authenticator, but we're using mock data
REGISTRATION_COMPLETE_REQUEST='{
  "id": "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
  "response": {
    "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJOeHlab3B3VktiRmw3RW5uTWFlXzVGbmlyN1FKN1FXcDFVRlVLakZIbGZrIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
    "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgVzzvX3Nyp_g9j9f2B-tPWy6puW01aZHI8RXjwqfDjtQCIQDLsdniGPO9iKr7tdgVV-FnBYhvzlZLG3u28rVt10YXfGN4NWOBWQJOMIICSjCCATKgAwIBAgIEVxb3wDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowLDEqMCgGA1UEAwwhWXViaWNvIFUyRiBFRSBTZXJpYWwgMjUwNTY5MjI2MTc2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZNkcVNbZV43TsGB4TEY21UijmDqvNSfO6y3G4ytnnjP86ehjFK28-FdSGy9MSZ-Ur3BVZb4iGVsptk5NrQ3QYqM7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAHibGMqbpNt2IOL4i4z96VEmbSoid9Xj--m2jJqg6RpqSOp1TO8L3lmEA22uf4uj_eZLUXYEw6EbLm11TUo3Ge-odpMPoODzBj9aTKC8oDFPfwWj6l1O3ZHTSma1XVyPqG4A579f3YAjfrPbgj404xJns0mqx5wkpxKlnoBKqo1rqSUmonencd4xanO_PHEfxU0iZif615Xk9E4bcANPCfz-OLfeKXiT-1msixwzz8XGvl2OTMJ_Sh9G9vhE-HjAcovcHfumcdoQh_WM445Za6Pyn9BZQV3FCqMviRR809sIATfU5lu86wu_5UGIGI7MFDEYeVGSqzpzh6mlcn8QSIZoYXV0aERhdGFYxEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAEAsV2gIUlPIHzZnNIlQdz5zvbKtpFz_WY-8ZfxOgTyy7f3Ffbolyp3fUtSQo5LfoUgBaBaXqK0wqqYO-u6FrrLApQECAyYgASFYIPr9-YH8DuBsOnaI3KJa0a39hyxh9LDtHErNvfQSyxQsIlgg4rAuQQ5uy4VXGFbkiAt0uwgJJodp-DymkoBcrGsLtkI"
  },
  "getClientExtensionResults": {},
  "type": "public-key"
}'

echo "Note: This will likely fail with mock data since the challenge doesn't match"
curl -s -X POST "$BASE_URL/attestation/result" \
  -H "Content-Type: application/json" \
  -d "$REGISTRATION_COMPLETE_REQUEST" | jq '.'

echo -e "\n4. Testing assertion/options (authentication begin)..."
AUTHENTICATION_REQUEST='{
  "username": "testuser@example.com",
  "userVerification": "required"
}'

AUTHENTICATION_RESPONSE=$(curl -s -X POST "$BASE_URL/assertion/options" \
  -H "Content-Type: application/json" \
  -d "$AUTHENTICATION_REQUEST")

echo "$AUTHENTICATION_RESPONSE" | jq '.'

echo -e "\n5. Testing with invalid requests..."
echo "Invalid registration request:"
curl -s -X POST "$BASE_URL/attestation/options" \
  -H "Content-Type: application/json" \
  -d '{"invalid": "request"}' | jq '.' || echo "Raw response: $(curl -s -X POST "$BASE_URL/attestation/options" -H "Content-Type: application/json" -d '{"invalid": "request"}')"

echo -e "\nInvalid authentication request:"
curl -s -X POST "$BASE_URL/assertion/options" \
  -H "Content-Type: application/json" \
  -d '{"invalid": "request"}' | jq '.' || echo "Raw response: $(curl -s -X POST "$BASE_URL/assertion/options" -H "Content-Type: application/json" -d '{"invalid": "request"}')"

echo -e "\nTesting complete!"