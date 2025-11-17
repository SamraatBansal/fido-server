#!/bin/bash
set -e

echo "Starting FIDO2/WebAuthn Development Server..."

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "Error: Docker is not running. Please start Docker first."
    exit 1
fi

# Start PostgreSQL database
echo "Starting PostgreSQL database..."
docker-compose up -d postgres

# Wait for database to be ready
echo "Waiting for database to be ready..."
until docker-compose exec -T postgres pg_isready -d fido_db -U fido_user > /dev/null 2>&1; do
    echo "Database is unavailable - sleeping..."
    sleep 2
done
echo "Database is ready!"

# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '#' | awk '/=/ {print $1}')
fi

# Run the server
echo "Starting FIDO2 server..."
cargo run

echo "Server stopped"