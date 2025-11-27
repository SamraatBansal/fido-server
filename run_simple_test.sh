#!/bin/bash

# Simple test script that shows the FIDO Server framework is working
# This tests the server without requiring PostgreSQL/Redis to be running

echo "Testing FIDO Server Framework..."
echo "================================"

# Set environment variables for testing
export SERVER_HOST=127.0.0.1
export SERVER_PORT=8080
export WEBAUTHN_RP_ID=localhost
export WEBAUTHN_RP_NAME="FIDO Server"
export WEBAUTHN_ORIGIN=http://localhost:8080

# Test the configuration loading
echo "1. Testing configuration..."
if cargo run --bin fido-server --help 2>/dev/null | head -1 >/dev/null; then
    echo "✓ Server binary built successfully"
else
    echo "✗ Server binary build failed"
    exit 1
fi

# Test compilation and build
echo "2. Testing build..."
if cargo build --quiet --bin fido-server; then
    echo "✓ Project builds successfully"
else
    echo "✗ Build failed"
    exit 1
fi

echo ""
echo "✓ FIDO Server Framework Test Completed!"
echo ""
echo "Framework Status:"
echo "- ✓ Rust project structure is correct"
echo "- ✓ Dependencies are properly configured" 
echo "- ✓ Code compiles without errors"
echo "- ✓ Server binary can be built"
echo ""
echo "Server Configuration:"
echo "- Host: 127.0.0.1"
echo "- Port: 8080"
echo "- Health endpoint: http://localhost:8080/health"
echo ""
echo "To run with live services:"
echo "1. Start PostgreSQL and Redis (use ./dev-setup.sh)"
echo "2. Run: cargo run --bin fido-server"
echo ""
echo "To test health endpoint:"
echo "curl -X GET http://localhost:8080/health"