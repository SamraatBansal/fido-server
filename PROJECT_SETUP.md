# FIDO2/WebAuthn Server - Project Setup Guide

## Overview

This guide provides step-by-step instructions for setting up the FIDO2/WebAuthn Relying Party Server development environment, including database setup, configuration, and initial project structure.

## 1. Prerequisites

### 1.1 System Requirements

- **Operating System**: Linux (Ubuntu 20.04+), macOS (10.15+), or Windows 10+
- **Rust**: 1.70.0 or later
- **PostgreSQL**: 13.0 or later
- **Git**: 2.30.0 or later
- **Docker**: 20.10+ (optional, for containerized development)
- **Make**: Build tool for project automation

### 1.2 Development Tools

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Install required Rust components
rustup component add rustfmt clippy rust-src

# Install development tools
cargo install cargo-watch cargo-tarpaulin cargo-audit cargo-deny

# Install PostgreSQL (Ubuntu/Debian)
sudo apt update
sudo apt install postgresql postgresql-contrib libpq-dev

# Install PostgreSQL (macOS with Homebrew)
brew install postgresql
brew services start postgresql

# Install PostgreSQL (Windows)
# Download and install from https://www.postgresql.org/download/windows/
```

## 2. Project Initialization

### 2.1 Create Project Structure

```bash
# Create project directory
mkdir fido-server
cd fido-server

# Initialize Rust project
cargo init --name fido-server

# Create directory structure
mkdir -p src/{config,controllers,services,db,middleware,routes,error,utils,schema}
mkdir -p tests/{unit,integration,common}
mkdir -p config/{environments,migrations}
mkdir -p docs/{api,security,compliance}
mkdir -p scripts/{dev,test,deploy}
mkdir -p docker/{development,production}

# Create initial files
touch src/lib.rs src/main.rs
touch README.md CHANGELOG.md LICENSE
touch .gitignore .env.example docker-compose.yml
touch Makefile rust-toolchain.toml
```

### 2.2 Configure Git Repository

```bash
# Initialize git repository
git init

# Create .gitignore
cat > .gitignore << 'EOF'
# Rust
/target/
**/*.rs.bk
Cargo.lock

# Environment
.env
.env.local
.env.*.local

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db

# Database
*.db
*.sqlite

# Logs
logs/
*.log

# Coverage
tarpaulin-report.html
coverage/

# Temporary
tmp/
temp/

# Docker
.dockerignore
EOF

# Create rust-toolchain.toml
cat > rust-toolchain.toml << 'EOF'
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy", "rust-src"]
EOF

# Initial commit
git add .
git commit -m "Initial project structure"
```

## 3. Database Setup

### 3.1 PostgreSQL Configuration

```bash
# Create database user
sudo -u postgres createuser --interactive fido_user

# Create database
sudo -u postgres createdb -O fido_user fido_server

# Set password for user
sudo -u postgres psql -c "ALTER USER fido_user PASSWORD 'secure_password';"

# Test connection
psql -h localhost -U fido_user -d fido_server -c "SELECT version();"
```

### 3.2 Database Migration Setup

```bash
# Install diesel CLI
cargo install diesel_cli --no-default-features --features postgres

# Set up diesel
echo "DATABASE_URL=postgresql://fido_user:secure_password@localhost/fido_server" > .env

# Run initial migration
diesel setup
diesel migration generate create_users_table
diesel migration generate create_credentials_table
diesel migration generate create_challenges_table
diesel migration generate create_sessions_table
diesel migration generate create_audit_log_table
```

### 3.3 Migration Files

```sql
-- migrations/2023-01-01-000001_create_users_table/up.sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_active ON users(is_active);

-- migrations/2023-01-01-000001_create_users_table/down.sql
DROP TABLE users;

-- migrations/2023-01-01-000002_create_credentials_table/up.sql
CREATE TABLE credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA UNIQUE NOT NULL,
    credential_public_key BYTEA NOT NULL,
    attestation_type VARCHAR(50) NOT NULL,
    aaguid BYTEA,
    sign_count BIGINT DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true,
    backup_eligible BOOLEAN DEFAULT false,
    backup_state BOOLEAN DEFAULT false,
    transports JSONB,
    user_verification VARCHAR(20) DEFAULT 'preferred'
);

CREATE INDEX idx_credentials_user_id ON credentials(user_id);
CREATE INDEX idx_credentials_credential_id ON credentials(credential_id);
CREATE INDEX idx_credentials_active ON credentials(is_active);
CREATE INDEX idx_credentials_user_active ON credentials(user_id, is_active);

-- migrations/2023-01-01-000002_create_credentials_table/down.sql
DROP TABLE credentials;

-- migrations/2023-01-01-000003_create_challenges_table/up.sql
CREATE TABLE challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    challenge BYTEA NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    challenge_type VARCHAR(20) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    used BOOLEAN DEFAULT false,
    metadata JSONB
);

CREATE INDEX idx_challenges_user_id ON challenges(user_id);
CREATE INDEX idx_challenges_expires_at ON challenges(expires_at);
CREATE INDEX idx_challenges_type ON challenges(challenge_type);
CREATE INDEX idx_challenges_used ON challenges(used);

-- migrations/2023-01-01-000003_create_challenges_table/down.sql
DROP TABLE challenges;

-- migrations/2023-01-01-000004_create_sessions_table/up.sql
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT true,
    metadata JSONB
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_token ON sessions(session_token);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_sessions_active ON sessions(is_active);

-- migrations/2023-01-01-000004_create_sessions_table/down.sql
DROP TABLE sessions;

-- migrations/2023-01-01-000005_create_audit_log_table/up.sql
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id UUID,
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX idx_audit_log_action ON audit_log(action);
CREATE INDEX idx_audit_log_resource ON audit_log(resource_type, resource_id);
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at);

-- migrations/2023-01-01-000005_create_audit_log_table/down.sql
DROP TABLE audit_log;
```

## 4. Configuration Setup

### 4.1 Environment Configuration

```bash
# Create .env.example
cat > .env.example << 'EOF'
# Application
APP_ENV=development
RUST_LOG=debug

# Server
SERVER_HOST=127.0.0.1
SERVER_PORT=8080
SERVER_WORKERS=4

# Database
DATABASE_URL=postgresql://fido_user:secure_password@localhost/fido_server
DATABASE_MAX_CONNECTIONS=10
DATABASE_MIN_CONNECTIONS=1

# WebAuthn
WEBAUTHN_RP_ID=localhost
WEBAUTHN_RP_NAME=FIDO2 Test Server
WEBAUTHN_RP_ORIGIN=http://localhost:8080
WEBAUTHN_CHALLENGE_TIMEOUT=300
WEBAUTHN_ATTESTATION_PREFERENCE=direct
WEBAUTHN_USER_VERIFICATION=preferred

# Security
SESSION_TIMEOUT=3600
MAX_LOGIN_ATTEMPTS=5
RATE_LIMIT_WINDOW=60
RATE_LIMIT_MAX=100
CSRF_TOKEN_LENGTH=32
BCRYPT_COST=12

# Encryption
ENCRYPTION_KEY=your-32-byte-encryption-key-here

# TLS (for production)
TLS_CERT_PATH=/path/to/cert.pem
TLS_KEY_PATH=/path/to/key.pem
EOF

# Copy to .env for development
cp .env.example .env
```

### 4.2 Configuration Files

```toml
# config/default.toml
[server]
host = "127.0.0.1"
port = 8080
workers = 4
keep_alive = 75
client_timeout = 5000

[database]
max_connections = 10
min_connections = 1
connection_timeout = 30
idle_timeout = 600

[webauthn]
rp_id = "localhost"
rp_name = "FIDO2 Test Server"
rp_origin = "http://localhost:8080"
challenge_timeout = 300
attestation_preference = "direct"
user_verification = "preferred"

[security]
session_timeout = 3600
max_login_attempts = 5
rate_limit_window = 60
rate_limit_max = 100
csrf_token_length = 32
bcrypt_cost = 12

[logging]
level = "debug"
format = "json"
```

```toml
# config/production.toml
[server]
host = "0.0.0.0"
port = 443
workers = 8
keep_alive = 75
client_timeout = 5000

[database]
max_connections = 20
min_connections = 5
connection_timeout = 30
idle_timeout = 600

[webauthn]
rp_id = "your-domain.com"
rp_name = "Your FIDO2 Server"
rp_origin = "https://your-domain.com"
challenge_timeout = 300
attestation_preference = "direct"
user_verification = "required"

[security]
session_timeout = 1800
max_login_attempts = 3
rate_limit_window = 60
rate_limit_max = 50
csrf_token_length = 32
bcrypt_cost = 14

[logging]
level = "info"
format = "json"
file = "/var/log/fido-server/app.log"
```

## 5. Docker Setup

### 5.1 Docker Compose for Development

```yaml
# docker-compose.yml
version: '3.8'

services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: fido_server
      POSTGRES_USER: fido_user
      POSTGRES_PASSWORD: secure_password
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./scripts/init-db.sql:/docker-entrypoint-initdb.d/init-db.sql
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U fido_user -d fido_server"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  fido-server:
    build:
      context: .
      dockerfile: docker/development/Dockerfile
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=postgresql://fido_user:secure_password@postgres:5432/fido_server
      - REDIS_URL=redis://redis:6379
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    volumes:
      - .:/app
      - cargo_cache:/usr/local/cargo/registry
    command: cargo watch -x run

volumes:
  postgres_data:
  redis_data:
  cargo_cache:
```

### 5.2 Development Dockerfile

```dockerfile
# docker/development/Dockerfile
FROM rust:1.75-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libpq-dev \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy Cargo files
COPY Cargo.toml Cargo.lock ./

# Create dummy main.rs for dependency caching
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies
RUN cargo build --release && rm -rf src

# Copy source code
COPY . .

# Build application
RUN cargo build --release

# Expose port
EXPOSE 8080

# Run application
CMD ["cargo", "run", "--release"]
```

### 5.3 Production Dockerfile

```dockerfile
# docker/production/Dockerfile
FROM rust:1.75-slim as builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy Cargo files
COPY Cargo.toml Cargo.lock ./

# Create dummy main.rs for dependency caching
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies
RUN cargo build --release && rm -rf src

# Copy source code
COPY . .

# Build application
RUN cargo build --release

# Production stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl3 \
    libpq5 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd -r -s /bin/false fido

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/fido-server .

# Change ownership
RUN chown fido:fido /app/fido-server

# Switch to non-root user
USER fido

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run application
CMD ["./fido-server"]
```

## 6. Development Scripts

### 6.1 Makefile

```makefile
# Makefile
.PHONY: help build run test clean docker-build docker-run docker-stop lint format audit

# Default target
help:
	@echo "Available commands:"
	@echo "  build      - Build the application"
	@echo "  run        - Run the application"
	@echo "  test       - Run tests"
	@echo "  test-coverage - Run tests with coverage"
	@echo "  lint       - Run linter"
	@echo "  format     - Format code"
	@echo "  audit      - Security audit"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-run - Run with Docker Compose"
	@echo "  docker-stop - Stop Docker Compose"
	@echo "  clean      - Clean build artifacts"

# Build
build:
	cargo build --release

# Run
run:
	cargo run

# Development run with hot reload
dev:
	cargo watch -x run

# Test
test:
	cargo test

# Test with coverage
test-coverage:
	cargo tarpaulin --out Html --output-dir target/coverage

# Lint
lint:
	cargo clippy -- -D warnings

# Format
format:
	cargo fmt --all

# Security audit
audit:
	cargo audit
	cargo deny check

# Docker commands
docker-build:
	docker-compose build

docker-run:
	docker-compose up -d

docker-stop:
	docker-compose down

docker-logs:
	docker-compose logs -f fido-server

# Database
db-migrate:
	diesel migration run

db-rollback:
	diesel migration revert

db-reset:
	diesel database reset

# Clean
clean:
	cargo clean
	docker-compose down -v
	rm -rf target/

# Setup
setup:
	cp .env.example .env
	diesel setup
	diesel migration run
	cargo build

# CI/CD
ci: lint test audit
```

### 6.2 Development Scripts

```bash
#!/bin/bash
# scripts/dev/setup.sh

set -e

echo "Setting up FIDO2 Server development environment..."

# Check prerequisites
command -v cargo >/dev/null 2>&1 || { echo "Rust is required but not installed."; exit 1; }
command -v psql >/dev/null 2>&1 || { echo "PostgreSQL is required but not installed."; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "Docker is required but not installed."; exit 1; }

# Install Rust components
echo "Installing Rust components..."
rustup component add rustfmt clippy rust-src

# Install cargo tools
echo "Installing cargo tools..."
cargo install cargo-watch cargo-tarpaulin cargo-audit cargo-deny diesel_cli --no-default-features --features postgres

# Setup environment
echo "Setting up environment..."
cp .env.example .env

# Setup database
echo "Setting up database..."
createdb fido_server || echo "Database already exists"
diesel setup
diesel migration run

# Build project
echo "Building project..."
cargo build

echo "Development environment setup complete!"
echo "Run 'make dev' to start the development server."
```

```bash
#!/bin/bash
# scripts/test/run-all.sh

set -e

echo "Running comprehensive test suite..."

# Unit tests
echo "Running unit tests..."
cargo test --lib

# Integration tests
echo "Running integration tests..."
cargo test --test integration

# Documentation tests
echo "Running documentation tests..."
cargo test --doc

# Coverage report
echo "Generating coverage report..."
cargo tarpaulin --out Html --output-dir target/coverage

# Security audit
echo "Running security audit..."
cargo audit

echo "Test suite complete!"
echo "Coverage report available at target/coverage/tarpaulin-report.html"
```

## 7. IDE Configuration

### 7.1 VS Code Configuration

```json
// .vscode/settings.json
{
    "rust-analyzer.checkOnSave.command": "clippy",
    "rust-analyzer.cargo.loadOutDirsFromCheck": true,
    "rust-analyzer.procMacro.enable": true,
    "files.exclude": {
        "**/target": true,
        "**/.git": true,
        "**/Cargo.lock": true
    },
    "editor.formatOnSave": true,
    "editor.codeActionsOnSave": {
        "source.fixAll": true
    },
    "rust-analyzer.inlayHints.typeHints.enable": true,
    "rust-analyzer.inlayHints.parameterHints.enable": true,
    "rust-analyzer.inlayHints.chainingHints.enable": true
}
```

```json
// .vscode/extensions.json
{
    "recommendations": [
        "rust-lang.rust-analyzer",
        "vadimcn.vscode-lldb",
        "serayuzgur.crates",
        "tamasfe.even-better-toml",
        "ms-vscode.makefile-tools"
    ]
}
```

```json
// .vscode/launch.json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Debug FIDO Server",
            "type": "lldb",
            "request": "launch",
            "program": "${workspaceFolder}/target/debug/fido-server",
            "args": [],
            "cwd": "${workspaceFolder}",
            "environment": [
                {
                    "name": "RUST_LOG",
                    "value": "debug"
                }
            ]
        }
    ]
}
```

### 7.2 Git Hooks

```bash
#!/bin/bash
# .git/hooks/pre-commit

set -e

echo "Running pre-commit checks..."

# Format check
echo "Checking code formatting..."
cargo fmt --all -- --check

# Lint
echo "Running linter..."
cargo clippy -- -D warnings

# Run tests
echo "Running tests..."
cargo test --lib

echo "Pre-commit checks passed!"
```

```bash
#!/bin/bash
# .git/hooks/pre-push

set -e

echo "Running pre-push checks..."

# Security audit
echo "Running security audit..."
cargo audit

# Full test suite
echo "Running full test suite..."
cargo test

echo "Pre-push checks passed!"
```

## 8. Initial Project Files

### 8.1 Basic Cargo.toml

```toml
[package]
name = "fido-server"
version = "0.1.0"
edition = "2021"
authors = ["FIDO Server Team"]
license = "MIT"
repository = "https://github.com/yourorg/fido-server"
readme = "README.md"
description = "A secure FIDO2/WebAuthn Relying Party Server"

[lib]
name = "fido_server"
path = "src/lib.rs"

[[bin]]
name = "fido-server"
path = "src/main.rs"

[dependencies]
# Add dependencies from implementation guide here

[dev-dependencies]
# Add dev dependencies from implementation guide here

[profile.dev]
opt-level = 0
debug = true

[profile.release]
opt-level = 3
lto = true
codegen-units = 1
panic = "abort"
strip = true
```

### 8.2 Basic README.md

```markdown
# FIDO2/WebAuthn Server

A secure, compliant FIDO2/WebAuthn Relying Party Server implemented in Rust.

## Features

- FIDO2/WebAuthn Level 2 compliance
- Secure credential storage with encryption
- Comprehensive test coverage
- RESTful API design
- PostgreSQL database support
- Docker containerization
- Security-first architecture

## Quick Start

### Prerequisites

- Rust 1.70+
- PostgreSQL 13+
- Docker (optional)

### Development Setup

```bash
# Clone repository
git clone https://github.com/yourorg/fido-server.git
cd fido-server

# Setup development environment
make setup

# Start development server
make dev
```

### Docker Setup

```bash
# Start with Docker Compose
make docker-run

# View logs
make docker-logs
```

## Documentation

- [Technical Specification](FIDO2_TECHNICAL_SPECIFICATION.md)
- [Test Specification](TEST_SPECIFICATION.md)
- [Implementation Guide](IMPLEMENTATION_GUIDE.md)
- [API Documentation](docs/api/)

## License

MIT License - see [LICENSE](LICENSE) file for details.
```

## 9. Next Steps

After completing the setup:

1. **Review the technical specification** to understand requirements
2. **Implement the core services** following the implementation guide
3. **Write comprehensive tests** as outlined in the test specification
4. **Set up CI/CD pipeline** for automated testing and deployment
5. **Configure monitoring and logging** for production readiness
6. **Perform security audit** before production deployment

## 10. Troubleshooting

### Common Issues

1. **Database Connection Errors**
   - Verify PostgreSQL is running
   - Check connection string in .env
   - Ensure database user has proper permissions

2. **Build Errors**
   - Run `cargo clean && cargo build`
   - Check Rust version compatibility
   - Verify all dependencies are installed

3. **Test Failures**
   - Ensure database migrations are applied
   - Check test environment configuration
   - Verify test data setup

### Getting Help

- Check the [documentation](docs/)
- Review [GitHub Issues](https://github.com/yourorg/fido-server/issues)
- Contact the development team

This setup guide provides a complete foundation for developing the FIDO2/WebAuthn server with proper tooling, configuration, and development workflow.