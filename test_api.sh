#!/bin/bash

# Test script for FIDO2/WebAuthn API endpoints
BASE_URL="http://localhost:8080"

echo "Testing FIDO2/WebAuthn API endpoints..."
echo "Base URL: $BASE_URL"
echo ""

# Test 1: Health check
echo "1. Testing health endpoint..."
curl -s -X GET "$BASE_URL/health" | jq '.' 2>/dev/null || curl -s -X GET "$BASE_URL/health"
echo -e "\n"

# Test 2: Registration options
echo "2. Testing registration options endpoint..."
curl -s -X POST "$BASE_URL/attestation/options" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser@example.com",
    "displayName": "Test User",
    "attestation": "direct"
  }' | jq '.' 2>/dev/null || curl -s -X POST "$BASE_URL/attestation/options" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser@example.com",
    "displayName": "Test User", 
    "attestation": "direct"
  }'
echo -e "\n"

# Test 3: Authentication options (should fail for non-existent user)
echo "3. Testing authentication options endpoint (expected to fail)..."
curl -s -X POST "$BASE_URL/assertion/options" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "nonexistentuser@example.com"
  }' | jq '.' 2>/dev/null || curl -s -X POST "$BASE_URL/assertion/options" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "nonexistentuser@example.com"
  }'
echo -e "\n"

# Test 4: Invalid registration (missing fields)
echo "4. Testing invalid registration request (missing displayName)..."
curl -s -X POST "$BASE_URL/attestation/options" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser@example.com"
  }' | jq '.' 2>/dev/null || curl -s -X POST "$BASE_URL/attestation/options" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser@example.com"
  }'
echo -e "\n"

# Test 5: Invalid registration result (missing fields)
echo "5. Testing invalid registration result (missing fields)..."
curl -s -X POST "$BASE_URL/attestation/result" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "test",
    "type": "public-key"
  }' | jq '.' 2>/dev/null || curl -s -X POST "$BASE_URL/attestation/result" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "test",
    "type": "public-key"
  }'
echo -e "\n"

echo "API testing completed!"
echo ""
echo "Expected results:"
echo "  1. Health check: {'status': 'ok', 'errorMessage': ''}"
echo "  2. Registration options: Success with challenge, user info, etc."
echo "  3. Authentication options: Failure (user not found)"
echo "  4. Invalid registration: Failure (missing displayName)"
echo "  5. Invalid registration result: Failure (missing response)"