#!/bin/bash

echo "🚀 Starting FIDO2/WebAuthn Relying Party Server..."
echo "📍 Server will be available at: http://localhost:8080"
echo "🩺 Health check: http://localhost:8080/health"
echo ""

# Set logging level to info for production-like output
export RUST_LOG=info

# Start the server
echo "⚡ Starting server..."
cargo run --release

echo ""
echo "🛑 Server stopped."