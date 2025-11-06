#!/bin/bash

echo "🚀 Starting FIDO2/WebAuthn Relying Party Server"
echo "================================================"

# Build the project if needed
if [ ! -f "target/release/fido2-webauthn-server" ]; then
    echo "📦 Building server..."
    cargo build --release
fi

# Set environment variables for localhost:8080
export RP_ID="localhost"
export RP_NAME="FIDO2 WebAuthn Server"
export RP_ORIGIN="http://localhost:8080"
export BIND_ADDRESS="0.0.0.0:8080"

echo "🔧 Configuration:"
echo "   RP ID: $RP_ID"
echo "   RP Name: $RP_NAME" 
echo "   RP Origin: $RP_ORIGIN"
echo "   Bind Address: $BIND_ADDRESS"
echo ""

echo "🌐 Server will be available at: http://localhost:8080"
echo "📋 API Endpoints:"
echo "   POST /attestation/options  - Start registration"
echo "   POST /attestation/result   - Finish registration"
echo "   POST /assertion/options    - Start authentication"
echo "   POST /assertion/result     - Finish authentication"
echo "   GET  /health               - Health check"
echo ""

echo "🏃 Starting server..."
./target/release/fido2-webauthn-server