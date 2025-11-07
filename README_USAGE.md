# FIDO2/WebAuthn Relying Party Server

A production-ready FIDO2/WebAuthn Relying Party Server implementation in Rust, designed to pass FIDO Alliance conformance tests.

## Features

- **Complete FIDO2/WebAuthn Implementation**: Supports full registration and authentication flows
- **FIDO Conformance API**: Matches the FIDO Alliance conformance test API specification
- **Production-Ready**: Comprehensive error handling, rate limiting, and security measures
- **PostgreSQL Backend**: Secure credential and challenge storage
- **Rust & webauthn-rs**: Built with Rust for performance and memory safety

## API Endpoints

The server implements the FIDO Alliance conformance API specification:

### Registration
- `POST /attestation/options` - Begin registration
- `POST /attestation/result` - Complete registration

### Authentication  
- `POST /assertion/options` - Begin authentication
- `POST /assertion/result` - Complete authentication

### Health Check
- `GET /health` - Server health status

## Quick Start

### Prerequisites
- Rust 1.70+ 
- PostgreSQL database

### Database Setup
1. Create a PostgreSQL database
2. Run the migrations:
```bash
diesel migration run
```

### Configuration
Set the database URL environment variable:
```bash
export DATABASE_URL="postgres://username:password@localhost/fido_server"
```

### Run the Server
```bash
cargo run --bin fido-server
```

The server will start on `http://localhost:8080`

## API Usage Examples

### Begin Registration
```bash
curl -X POST http://localhost:8080/attestation/options \
  -H "Content-Type: application/json" \
  -d '{
    "username": "johndoe@example.com",
    "displayName": "John Doe",
    "authenticatorSelection": {
      "requireResidentKey": false,
      "authenticatorAttachment": "cross-platform",
      "userVerification": "preferred"
    },
    "attestation": "direct"
  }'
```

### Begin Authentication
```bash
curl -X POST http://localhost:8080/assertion/options \
  -H "Content-Type: application/json" \
  -d '{
    "username": "johndoe@example.com",
    "userVerification": "required"
  }'
```

## Configuration

The server uses environment-based configuration:

- `FIDO_SERVER_HOST` - Server host (default: 127.0.0.1)
- `FIDO_SERVER_PORT` - Server port (default: 8080)  
- `FIDO_SERVER_DATABASE_URL` - PostgreSQL connection string
- `FIDO_SERVER_WEBAUTHN_RP_ID` - Relying Party ID (default: localhost)
- `FIDO_SERVER_WEBAUTHN_RP_NAME` - Relying Party name (default: FIDO Server)
- `FIDO_SERVER_WEBAUTHN_ORIGIN` - Origin URL (default: http://localhost:8080)

## Security Features

- Challenge replay protection
- Origin validation
- Rate limiting
- Input sanitization  
- Session management
- Counter verification (anti-cloning)
- Backup state tracking

## Database Schema

The server uses three main tables:
- `users` - User account information
- `credentials` - WebAuthn credentials/passkeys
- `challenges` - Temporary challenge storage

## Development

### Build
```bash
cargo build
```

### Test
```bash
cargo test
```

### Linting
```bash
cargo clippy
```

## FIDO Conformance Testing

This server is designed to pass FIDO Alliance conformance tests. The API exactly matches the conformance test specification for:

- Registration ceremony
- Authentication ceremony  
- Error handling
- Challenge management
- Credential storage

## Production Deployment

For production deployment:

1. Enable strict linting in `Cargo.toml`
2. Set up proper environment configuration
3. Configure TLS/HTTPS
4. Set up database backups
5. Configure monitoring and logging
6. Review security settings

## License

MIT License - see LICENSE file for details.