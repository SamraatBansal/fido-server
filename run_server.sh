#!/bin/bash

# Start the FIDO2/WebAuthn Server
echo "Starting FIDO2/WebAuthn Relying Party Server..."

# Set environment variables
export DATABASE_URL="postgres://postgres:password@localhost/fido2_webauthn"
export RP_ID="localhost"
export RP_NAME="FIDO2 WebAuthn Server"
export RP_ORIGIN="http://localhost:8080"
export BIND_ADDRESS="0.0.0.0:8080"
export RUST_LOG="info"

echo "Configuration:"
echo "  RP ID: $RP_ID"
echo "  RP Origin: $RP_ORIGIN"
echo "  Bind Address: $BIND_ADDRESS"
echo "  Database URL: $DATABASE_URL"
echo ""

# Check if PostgreSQL is running and database exists
echo "Checking database connection..."
if ! command -v psql &> /dev/null; then
    echo "Warning: PostgreSQL client not found. Make sure PostgreSQL is installed."
else
    # Try to connect to database
    if psql -h localhost -U postgres -d postgres -c "SELECT 1;" &> /dev/null; then
        echo "Database connection successful"
        
        # Create database if it doesn't exist
        psql -h localhost -U postgres -d postgres -c "CREATE DATABASE fido2_webauthn;" 2>/dev/null || echo "Database already exists"
    else
        echo "Warning: Could not connect to PostgreSQL. Please ensure:"
        echo "  1. PostgreSQL is running on localhost:5432"
        echo "  2. User 'postgres' exists and can connect"
        echo "  3. Database 'fido2_webauthn' exists or can be created"
        echo ""
        echo "To setup PostgreSQL:"
        echo "  createdb fido2_webauthn"
        echo "  or"
        echo "  psql -c 'CREATE DATABASE fido2_webauthn;'"
        echo ""
    fi
fi

# Build and run the server
echo "Building and starting server..."
cargo run