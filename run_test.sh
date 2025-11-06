#!/bin/bash

echo "Building FIDO2/WebAuthn server..."
cargo build --bin main_memory

echo "Starting server on port 8080..."
cargo run --bin main_memory &
SERVER_PID=$!

echo "Waiting for server to start..."
sleep 3

echo "Running tests..."
python3 test_endpoints.py

echo "Stopping server..."
kill $SERVER_PID

echo "Test complete!"