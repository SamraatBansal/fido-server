#!/bin/bash
# Simple test database setup script

set -e

echo "🗃️  Setting up test database for FIDO2 server"

# Check if PostgreSQL is available
if ! command -v psql &> /dev/null; then
    echo "❌ PostgreSQL not found. Please install PostgreSQL first."
    echo "On macOS: brew install postgresql"
    echo "On Ubuntu: sudo apt install postgresql postgresql-contrib"
    exit 1
fi

# Database configuration
DB_NAME="fido_server_test"
DB_USER="${POSTGRES_USER:-postgres}"
DB_HOST="${POSTGRES_HOST:-localhost}"
DB_PORT="${POSTGRES_PORT:-5432}"

echo "Database: $DB_NAME"
echo "User: $DB_USER"
echo "Host: $DB_HOST"
echo "Port: $DB_PORT"

# Try to connect to PostgreSQL
if ! pg_isready -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" &> /dev/null; then
    echo "❌ PostgreSQL is not running or not accessible."
    echo "Please start PostgreSQL service first."
    echo "On macOS: brew services start postgresql"
    echo "On Ubuntu: sudo service postgresql start"
    exit 1
fi

echo "✅ PostgreSQL is running"

# Create database if it doesn't exist
if psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -lqt | cut -d \| -f 1 | grep -qw "$DB_NAME"; then
    echo "✅ Database '$DB_NAME' already exists"
else
    echo "📦 Creating database '$DB_NAME'..."
    createdb -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" "$DB_NAME"
    echo "✅ Database '$DB_NAME' created successfully"
fi

# Update .env file
echo "📝 Updating .env file..."
cat > .env << EOF
# FIDO Server Configuration
FIDO_SERVER_SERVER__HOST=127.0.0.1
FIDO_SERVER_SERVER__PORT=8080
FIDO_SERVER_DATABASE__URL=postgres://$DB_USER@$DB_HOST:$DB_PORT/$DB_NAME
FIDO_SERVER_DATABASE__MAX_POOL_SIZE=10
FIDO_SERVER_WEBAUTHN__RP_ID=localhost
FIDO_SERVER_WEBAUTHN__RP_NAME=FIDO Server Test
FIDO_SERVER_WEBAUTHN__ORIGIN=http://localhost:8080
EOF

echo "✅ Environment configuration updated"
echo ""
echo "🎉 Test database setup complete!"
echo "You can now run: cargo run --bin fido-server"