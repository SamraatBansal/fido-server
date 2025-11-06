# FIDO2/WebAuthn Relying Party Server

A production-ready FIDO2/WebAuthn Relying Party server implementation in Rust, designed to pass FIDO Alliance conformance testing.

## Features

- Complete FIDO2/WebAuthn implementation using webauthn-rs
- PostgreSQL database backend with Diesel ORM
- Async/await support with Actix Web
- Comprehensive error handling and validation
- FIDO Alliance conformance test compatibility
- Production-ready security practices

## API Endpoints

### Registration
- `POST /attestation/options` - Start registration
- `POST /attestation/result` - Complete registration

### Authentication  
- `POST /assertion/options` - Start authentication
- `POST /assertion/result` - Complete authentication

### Health Check
- `GET /health` - Server health status

## Setup

### Prerequisites
- Rust 1.70+
- PostgreSQL 12+
- Diesel CLI: `cargo install diesel_cli --no-default-features --features postgres`

### Database Setup
1. Install PostgreSQL and create database:
```bash
sudo -u postgres psql -f setup_database.sql
```

2. Run migrations:
```bash
diesel migration run
```

### Environment Configuration
Copy `.env.example` to `.env` and configure:
```env
DATABASE_URL=postgresql://fido_user:fido_password@localhost/fido_db
RUST_LOG=debug
WEBAUTHN_RP_ID=localhost
WEBAUTHN_RP_NAME=FIDO2 Test Server
WEBAUTHN_RP_ORIGIN=http://localhost:8080
SERVER_HOST=127.0.0.1
SERVER_PORT=8080
```

### Build and Run
```bash
cargo build --release
cargo run
```

The server will start at `http://localhost:8080`.

## FIDO Conformance Testing

This server is designed to pass FIDO Alliance conformance tests. Key features:

- Strict validation of all input parameters
- Proper error responses for invalid requests
- Correct WebAuthn challenge/response handling
- Support for multiple attestation formats
- Proper credential lifecycle management

### Running Conformance Tests

1. Start the server: `cargo run`
2. Configure FIDO conformance tool to test `http://localhost:8080`
3. Run the conformance test suite

## Security Features

- Challenge uniqueness and expiration
- Origin validation
- Attestation verification
- Sign count validation
- CORS protection
- Input sanitization and validation
- Secure session management

## API Examples

### Registration
```bash
# Start registration
curl -X POST http://localhost:8080/attestation/options \
  -H "Content-Type: application/json" \
  -d '{"username":"test@example.com","displayName":"Test User"}'

# Complete registration  
curl -X POST http://localhost:8080/attestation/result \
  -H "Content-Type: application/json" \
  -d '{"id":"credential_id","type":"public-key","response":{...}}'
```

### Authentication
```bash
# Start authentication
curl -X POST http://localhost:8080/assertion/options \
  -H "Content-Type: application/json" \
  -d '{"username":"test@example.com"}'

# Complete authentication
curl -X POST http://localhost:8080/assertion/result \
  -H "Content-Type: application/json" \
  -d '{"id":"credential_id","type":"public-key","response":{...}}'
```

## Architecture

- **Database Layer**: PostgreSQL with Diesel ORM
- **Service Layer**: WebAuthn business logic with webauthn-rs
- **API Layer**: Actix Web HTTP handlers
- **Validation**: Comprehensive input validation
- **Error Handling**: Structured error responses
- **Security**: Production-ready security practices

## Development

### Adding Features
1. Update database schema in `migrations/`
2. Update models in `src/models.rs`
3. Add business logic to `src/webauthn_service.rs`
4. Add API endpoints to `src/handlers.rs`
5. Update tests and documentation

### Testing
```bash
cargo test
```

## License

MIT License - see LICENSE file for details.