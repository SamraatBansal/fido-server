# FIDO2/WebAuthn Relying Party Server

A production-ready FIDO2/WebAuthn conformant server implementation in Rust, designed to pass FIDO Alliance conformance tests.

## 🎯 Features

- **FIDO2/WebAuthn Compliant**: Implements WebAuthn Level 2 specification
- **Production Ready**: Comprehensive error handling, logging, and security controls
- **High Performance**: Built with Actix-web and Diesel for optimal performance
- **Secure by Design**: Challenge entropy validation, origin verification, and replay protection
- **Test Driven**: Designed to pass FIDO Alliance conformance test suites

## 🏗️ Architecture

- **Web Framework**: Actix-web 4.x with CORS support
- **WebAuthn Library**: webauthn-rs 0.5 (FIDO2 implementation)
- **Database**: PostgreSQL with Diesel ORM and connection pooling
- **Async Runtime**: Tokio with full async/await support
- **Configuration**: Environment-based configuration with defaults

## 🚀 Quick Start

### Prerequisites

- Rust 1.70+ (with Cargo)
- PostgreSQL 12+
- Python 3.7+ (for testing scripts)

### 1. Clone and Build

```bash
git clone <repository-url>
cd fido-server
cargo build --release
```

### 2. Database Setup

```bash
# Install PostgreSQL (macOS)
brew install postgresql
brew services start postgresql

# Install PostgreSQL (Ubuntu)
sudo apt install postgresql postgresql-contrib
sudo service postgresql start

# Setup test database
./setup_test_db.sh
```

### 3. Run Server

```bash
# Development mode
cargo run --bin fido-server

# Production mode
cargo run --release --bin fido-server
```

### 4. Test Endpoints

```bash
# Run basic tests
./run_tests.sh

# Test specific endpoint
curl -X GET http://localhost:8080/health
```

## 📡 API Endpoints

### Registration Flow

#### 1. Begin Registration
```http
POST /attestation/options
Content-Type: application/json

{
    "username": "user@example.com",
    "displayName": "User Name",
    "authenticatorSelection": {
        "requireResidentKey": false,
        "authenticatorAttachment": "cross-platform",
        "userVerification": "preferred"
    },
    "attestation": "direct"
}
```

**Response:**
```json
{
    "status": "ok",
    "errorMessage": "",
    "rp": {
        "name": "FIDO Server Test",
        "id": "localhost"
    },
    "user": {
        "id": "base64url-encoded-user-id",
        "name": "user@example.com",
        "displayName": "User Name"
    },
    "challenge": "base64url-encoded-challenge",
    "pubKeyCredParams": [
        {"type": "public-key", "alg": -7},
        {"type": "public-key", "alg": -257}
    ],
    "timeout": 10000,
    "excludeCredentials": [],
    "authenticatorSelection": { /* same as request */ },
    "attestation": "direct"
}
```

#### 2. Complete Registration
```http
POST /attestation/result
Content-Type: application/json

{
    "id": "base64url-credential-id",
    "response": {
        "clientDataJSON": "base64url-encoded-client-data",
        "attestationObject": "base64url-encoded-attestation"
    },
    "getClientExtensionResults": {},
    "type": "public-key"
}
```

**Response:**
```json
{
    "status": "ok",
    "errorMessage": ""
}
```

### Authentication Flow

#### 1. Begin Authentication
```http
POST /assertion/options
Content-Type: application/json

{
    "username": "user@example.com",
    "userVerification": "required"
}
```

**Response:**
```json
{
    "status": "ok",
    "errorMessage": "",
    "challenge": "base64url-encoded-challenge",
    "timeout": 20000,
    "rpId": "localhost",
    "allowCredentials": [
        {
            "type": "public-key",
            "id": "base64url-credential-id"
        }
    ],
    "userVerification": "required"
}
```

#### 2. Complete Authentication
```http
POST /assertion/result
Content-Type: application/json

{
    "id": "base64url-credential-id",
    "response": {
        "authenticatorData": "base64url-encoded-auth-data",
        "signature": "base64url-encoded-signature",
        "userHandle": "",
        "clientDataJSON": "base64url-encoded-client-data"
    },
    "getClientExtensionResults": {},
    "type": "public-key"
}
```

**Response:**
```json
{
    "status": "ok",
    "errorMessage": ""
}
```

### Health Check
```http
GET /health
```

**Response:**
```json
{
    "status": "ok",
    "service": "FIDO Server",
    "timestamp": "2024-01-15T10:30:00Z"
}
```

## ⚙️ Configuration

Configuration is handled through environment variables with the `FIDO_SERVER_` prefix:

### Environment Variables

```bash
# Server Configuration
FIDO_SERVER_SERVER__HOST=127.0.0.1
FIDO_SERVER_SERVER__PORT=8080

# Database Configuration
FIDO_SERVER_DATABASE__URL=postgres://user:pass@localhost/dbname
FIDO_SERVER_DATABASE__MAX_POOL_SIZE=10

# WebAuthn Configuration
FIDO_SERVER_WEBAUTHN__RP_ID=localhost
FIDO_SERVER_WEBAUTHN__RP_NAME=My FIDO Server
FIDO_SERVER_WEBAUTHN__ORIGIN=http://localhost:8080
```

### Configuration File

You can also use a `.env` file in the project root (see `.env.example`).

## 🧪 Testing

### FIDO Conformance Testing

This server is designed to pass FIDO Alliance conformance tests. To test with the official FIDO conformance tools:

1. **Start the server:**
   ```bash
   cargo run --release --bin fido-server
   ```

2. **Configure conformance tool:**
   - Server URL: `http://localhost:8080`
   - Registration endpoint: `/attestation/options` and `/attestation/result`
   - Authentication endpoint: `/assertion/options` and `/assertion/result`

3. **Run conformance tests** using your FIDO conformance tool

### Unit Tests

```bash
# Run all tests
cargo test

# Run specific test module
cargo test services::fido

# Run with output
cargo test -- --nocapture
```

### Integration Tests

```bash
# Basic endpoint tests
./run_tests.sh

# Manual endpoint testing
python3 test_basic.py
```

## 🛡️ Security Features

- **Challenge Security**: 256-bit cryptographically secure challenges with one-time use
- **Origin Validation**: Strict RP ID and origin verification
- **Replay Protection**: Challenge expiration and consumption tracking
- **Input Validation**: Comprehensive request validation and sanitization
- **Rate Limiting**: Configurable per-client request limits
- **Error Sanitization**: Security-sensitive error message sanitization
- **Audit Logging**: Comprehensive security event logging

## 📊 Database Schema

### Users Table
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(255) NOT NULL UNIQUE,
    display_name VARCHAR(255) NOT NULL,
    user_id BYTEA NOT NULL UNIQUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### Credentials Table
```sql
CREATE TABLE credentials (
    id BYTEA PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    public_key BYTEA NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    credential_type VARCHAR(50) NOT NULL DEFAULT 'public-key',
    transports TEXT[],
    backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,
    backup_state BOOLEAN NOT NULL DEFAULT FALSE,
    attestation_type VARCHAR(50),
    attestation_trust_path JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE
);
```

### Challenge States Table
```sql
CREATE TABLE challenge_states (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    challenge BYTEA NOT NULL UNIQUE,
    user_id UUID REFERENCES users(id),
    operation VARCHAR(20) NOT NULL,
    state_data JSONB NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

## 🐛 Troubleshooting

### Common Issues

1. **Database Connection Failed**
   ```
   Error: Database connection failed
   ```
   - Ensure PostgreSQL is running: `pg_isready`
   - Check database URL in `.env` file
   - Verify database exists: `psql -l`

2. **WebAuthn Build Error**
   ```
   Error: WebAuthn builder error
   ```
   - Check `rp_id` matches your domain
   - Ensure `origin` URL is valid
   - Verify HTTPS in production

3. **Challenge Not Found**
   ```
   Error: Challenge not found or expired
   ```
   - Check challenge expiration time
   - Ensure challenges are unique
   - Verify database cleanup function

### Debugging

Enable debug logging:
```bash
RUST_LOG=debug cargo run --bin fido-server
```

## 🚀 Production Deployment

### Docker Deployment

```dockerfile
FROM rust:1.70 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bullseye-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/fido-server /usr/local/bin/
CMD ["fido-server"]
```

### Environment Configuration

```bash
# Production environment variables
export FIDO_SERVER_SERVER__HOST=0.0.0.0
export FIDO_SERVER_SERVER__PORT=8080
export FIDO_SERVER_DATABASE__URL=postgres://user:pass@db:5432/fido_server
export FIDO_SERVER_WEBAUTHN__RP_ID=yourdomain.com
export FIDO_SERVER_WEBAUTHN__RP_NAME="Your FIDO Server"
export FIDO_SERVER_WEBAUTHN__ORIGIN=https://yourdomain.com
export RUST_LOG=info
```

## 📚 Additional Resources

- [WebAuthn Specification](https://www.w3.org/TR/webauthn-2/)
- [FIDO Alliance](https://fidoalliance.org/)
- [webauthn-rs Documentation](https://docs.rs/webauthn-rs/)
- [Actix Web Guide](https://actix.rs/docs/)

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 🔒 Security

For security vulnerabilities, please email security@yourcompany.com instead of opening public issues.