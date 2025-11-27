#!/bin/bash

# Demo script for FIDO Server Health Endpoint
# Tests the health endpoint at localhost:8080

echo "FIDO Server Health Endpoint Demo"
echo "================================"
echo ""

# Check if server is already running
if lsof -Pi :8080 -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo "Server is already running on port 8080. Testing health endpoint..."
    echo ""
    
    # Test the health endpoint
    echo "Testing GET /health endpoint..."
    echo "curl -X GET http://localhost:8080/health"
    echo ""
    
    curl -X GET http://localhost:8080/health -H "Content-Type: application/json" -w "\nHTTP Status: %{http_code}\n" 2>/dev/null || echo "Connection failed - server might not be responding"
    echo ""
else
    echo "No server running on port 8080."
    echo ""
    echo "To start the FIDO server:"
    echo "1. Set up dependencies: ./dev-setup.sh"
    echo "2. Start server: cargo run --bin fido-server"
    echo "3. Test health endpoint: curl -X GET http://localhost:8080/health"
    echo ""
fi

echo "Expected health endpoint responses:"
echo ""
echo "Success (200 OK):"
echo '{'
echo '  "status": "ok",'
echo '  "timestamp": "2024-01-15T10:30:00Z",'
echo '  "services": {'
echo '    "database": "connected",'
echo '    "redis": "connected"'
echo '  },'
echo '  "version": "1.0.0"'
echo '}'
echo ""
echo "Service Unavailable (503):"
echo '{'
echo '  "status": "error",'
echo '  "errorMessage": "Service unavailable - database connection failed"'
echo '}'
echo ""
echo "Configuration Details:"
echo "- Server Host: 127.0.0.1"
echo "- Server Port: 8080"
echo "- Health Endpoint: http://localhost:8080/health"
echo "- WebAuthn Origin: http://localhost:8080"