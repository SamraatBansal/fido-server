#!/bin/bash

# Development setup script for FIDO Server
# This script sets up PostgreSQL and Redis for local development

echo "Setting up development environment for FIDO Server..."

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    echo "Docker is required but not installed. Please install Docker first."
    exit 1
fi

echo "Starting PostgreSQL container..."
docker run --name fido-postgres -d \
    -e POSTGRES_USER=postgres \
    -e POSTGRES_PASSWORD=postgres \
    -e POSTGRES_DB=fido_server \
    -p 5432:5432 \
    postgres:15 2>/dev/null || echo "PostgreSQL container already running or Docker not available"

echo "Starting Redis container..."
docker run --name fido-redis -d \
    -p 6379:6379 \
    redis:7 2>/dev/null || echo "Redis container already running or Docker not available"

# Wait for services to be ready
echo "Waiting for services to start..."
sleep 5

echo "Development environment setup complete!"
echo ""
echo "Services:"
echo "- PostgreSQL: localhost:5432 (user: postgres, password: postgres, database: fido_server)"
echo "- Redis: localhost:6379"
echo ""
echo "To start the server:"
echo "cargo run --bin fido-server"
echo ""
echo "To stop the development environment:"
echo "docker stop fido-postgres fido-redis"
echo "docker rm fido-postgres fido-redis"