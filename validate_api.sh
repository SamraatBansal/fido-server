#!/bin/bash

# Newman-style API validation script for FIDO2/WebAuthn server

echo "🚀 Starting FIDO2/WebAuthn API Validation..."
echo "================================================"

# Start server in background
echo "📡 Starting FIDO server..."
cargo run > server_validation.log 2>&1 &
SERVER_PID=$!

# Wait for server to start
sleep 3

# Test health endpoint
echo "🏥 Testing health endpoint..."
HEALTH_RESPONSE=$(curl -s -w "%{http_code}" http://localhost:8080/api/v1/health)
HEALTH_CODE="${HEALTH_RESPONSE: -3}"
HEALTH_BODY="${HEALTH_RESPONSE%???}"

if [ "$HEALTH_CODE" = "200" ]; then
    echo "✅ Health endpoint: PASSED (200)"
    echo "   Response: $HEALTH_BODY"
else
    echo "❌ Health endpoint: FAILED ($HEALTH_CODE)"
fi

# Test registration start
echo ""
echo "🔐 Testing registration start..."
REG_START_RESPONSE=$(curl -s -w "%{http_code}" -X POST \
    -H "Content-Type: application/json" \
    -d '{"username":"testuser","display_name":"Test User"}' \
    http://localhost:8080/api/v1/webauthn/register/start)
REG_START_CODE="${REG_START_RESPONSE: -3}"
REG_START_BODY="${REG_START_RESPONSE%???}"

if [ "$REG_START_CODE" = "200" ]; then
    echo "✅ Registration start: PASSED (200)"
    # Check for required fields
    if echo "$REG_START_BODY" | grep -q "challenge" && \
       echo "$REG_START_BODY" | grep -q "user" && \
       echo "$REG_START_BODY" | grep -q "rp"; then
        echo "   Response contains required fields"
    else
        echo "   ⚠️  Response missing required fields"
    fi
else
    echo "❌ Registration start: FAILED ($REG_START_CODE)"
fi

# Test registration finish
echo ""
echo "🔐 Testing registration finish..."
REG_FINISH_RESPONSE=$(curl -s -w "%{http_code}" -X POST \
    -H "Content-Type: application/json" \
    -d '{"credential":{"id":"test"},"session":"test"}' \
    http://localhost:8080/api/v1/webauthn/register/finish)
REG_FINISH_CODE="${REG_FINISH_RESPONSE: -3}"
REG_FINISH_BODY="${REG_FINISH_RESPONSE%???}"

if [ "$REG_FINISH_CODE" = "201" ]; then
    echo "✅ Registration finish: PASSED (201)"
    if echo "$REG_FINISH_BODY" | grep -q "credential_id" && \
       echo "$REG_FINISH_BODY" | grep -q "user_id"; then
        echo "   Response contains required fields"
    else
        echo "   ⚠️  Response missing required fields"
    fi
else
    echo "❌ Registration finish: FAILED ($REG_FINISH_CODE)"
fi

# Test authentication start
echo ""
echo "🔑 Testing authentication start..."
AUTH_START_RESPONSE=$(curl -s -w "%{http_code}" -X POST \
    -H "Content-Type: application/json" \
    -d '{"username":"testuser"}' \
    http://localhost:8080/api/v1/webauthn/authenticate/start)
AUTH_START_CODE="${AUTH_START_RESPONSE: -3}"
AUTH_START_BODY="${AUTH_START_RESPONSE%???}"

if [ "$AUTH_START_CODE" = "200" ]; then
    echo "✅ Authentication start: PASSED (200)"
    if echo "$AUTH_START_BODY" | grep -q "challenge" && \
       echo "$AUTH_START_BODY" | grep -q "rp_id" && \
       echo "$AUTH_START_BODY" | grep -q "allow_credentials"; then
        echo "   Response contains required fields"
    else
        echo "   ⚠️  Response missing required fields"
    fi
else
    echo "❌ Authentication start: FAILED ($AUTH_START_CODE)"
fi

# Test authentication finish
echo ""
echo "🔑 Testing authentication finish..."
AUTH_FINISH_RESPONSE=$(curl -s -w "%{http_code}" -X POST \
    -H "Content-Type: application/json" \
    -d '{"credential":{"id":"test"},"session":"test"}' \
    http://localhost:8080/api/v1/webauthn/authenticate/finish)
AUTH_FINISH_CODE="${AUTH_FINISH_RESPONSE: -3}"
AUTH_FINISH_BODY="${AUTH_FINISH_RESPONSE%???}"

if [ "$AUTH_FINISH_CODE" = "200" ]; then
    echo "✅ Authentication finish: PASSED (200)"
    if echo "$AUTH_FINISH_BODY" | grep -q "user_id" && \
       echo "$AUTH_FINISH_BODY" | grep -q "credential_id"; then
        echo "   Response contains required fields"
    else
        echo "   ⚠️  Response missing required fields"
    fi
else
    echo "❌ Authentication finish: FAILED ($AUTH_FINISH_CODE)"
fi

# Stop server
echo ""
echo "🛑 Stopping server..."
kill $SERVER_PID 2>/dev/null

# Summary
echo ""
echo "================================================"
echo "📊 VALIDATION SUMMARY"
echo "================================================"

PASSED=0
TOTAL=5

[ "$HEALTH_CODE" = "200" ] && ((PASSED++))
[ "$REG_START_CODE" = "200" ] && ((PASSED++))
[ "$REG_FINISH_CODE" = "201" ] && ((PASSED++))
[ "$AUTH_START_CODE" = "200" ] && ((PASSED++))
[ "$AUTH_FINISH_CODE" = "200" ] && ((PASSED++))

echo "Tests Passed: $PASSED/$TOTAL"
echo "Success Rate: $(( PASSED * 100 / TOTAL ))%"

if [ $PASSED -eq $TOTAL ]; then
    echo "🎉 ALL TESTS PASSED! Server is ready for production."
    exit 0
else
    echo "⚠️  Some tests failed. Please check the implementation."
    exit 1
fi