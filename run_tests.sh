#!/bin/bash
# Run FIDO2 server tests

set -e

echo "🚀 Starting FIDO2 Server Test Suite"
echo "=================================="

# Build the project
echo "🔨 Building FIDO2 server..."
cargo build --bin fido-server

echo "✅ Build successful"

# Check if we can start the server (even without DB)
echo "🌐 Testing server startup..."

# Start server in background
cargo run --bin fido-server &
SERVER_PID=$!

# Function to cleanup on exit
cleanup() {
    echo "🧹 Cleaning up..."
    if kill -0 $SERVER_PID 2>/dev/null; then
        kill $SERVER_PID
        wait $SERVER_PID 2>/dev/null || true
    fi
}

# Set trap to cleanup on script exit
trap cleanup EXIT

# Give server a moment to start
echo "⏳ Waiting for server to start..."
sleep 3

# Check if server process is still running
if kill -0 $SERVER_PID 2>/dev/null; then
    echo "✅ Server started successfully (PID: $SERVER_PID)"
    
    # Run basic endpoint tests
    echo "🧪 Running endpoint tests..."
    if command -v python3 &> /dev/null; then
        python3 test_basic.py
    else
        echo "⚠️  Python3 not found, skipping endpoint tests"
    fi
else
    echo "❌ Server failed to start"
    exit 1
fi

echo ""
echo "🎉 FIDO2 Server basic tests completed!"
echo ""
echo "📋 Next steps:"
echo "1. Set up PostgreSQL database: ./setup_test_db.sh"
echo "2. Run server: cargo run --bin fido-server"
echo "3. Test with FIDO conformance tools"
echo ""
echo "🔗 Endpoints available:"
echo "  - Health: GET http://localhost:8080/health"
echo "  - Registration: POST http://localhost:8080/attestation/options"
echo "  - Registration Complete: POST http://localhost:8080/attestation/result"
echo "  - Authentication: POST http://localhost:8080/assertion/options"
echo "  - Authentication Complete: POST http://localhost:8080/assertion/result"