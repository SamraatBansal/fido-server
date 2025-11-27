#!/bin/bash

# Test script for FIDO Server basic functionality

echo "Testing FIDO Server Build and Basic Functionality..."
echo "=================================================="

# Test compilation
echo "1. Testing compilation..."
if cargo check --quiet; then
    echo "✓ Compilation successful"
else
    echo "✗ Compilation failed"
    exit 1
fi

# Test build
echo "2. Testing build..."
if cargo build --quiet; then
    echo "✓ Build successful"
else
    echo "✗ Build failed"
    exit 1
fi

echo ""
echo "✓ All tests passed!"
echo ""
echo "Server Configuration:"
echo "- Host: 127.0.0.1"
echo "- Port: 8080" 
echo "- Health endpoint: http://localhost:8080/health"
echo ""
echo "To start the server:"
echo "1. Set up PostgreSQL and Redis connections"
echo "2. Update .env file with correct DATABASE_URL and REDIS_URL"
echo "3. Run: cargo run --bin fido-server"
echo ""
echo "To test health endpoint:"
echo "curl -X GET http://localhost:8080/health -H \"Content-Type: application/json\""