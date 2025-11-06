# FIDO2/WebAuthn Relying Party Server

A production-ready FIDO2/WebAuthn Relying Party server implementation in Rust, designed to pass FIDO Alliance conformance tests.

## Features

- ✅ Full FIDO2/WebAuthn specification compliance
- ✅ Comprehensive input validation and error handling  
- ✅ PostgreSQL database backend with migrations
- ✅ RESTful API matching FIDO Alliance test requirements
- ✅ Support for all FIDO2 cryptographic algorithms
- ✅ Proper challenge management and replay protection
- ✅ Attestation object validation and processing
- ✅ Authentication assertion validation
- ✅ Extensive test suite for conformance validation

## API Endpoints

### Registration
- `POST /attestation/options` - Start credential registration
- `POST /attestation/result` - Complete credential registration

### Authentication  
- `POST /assertion/options` - Start authentication
- `POST /assertion/result` - Complete authentication

### Utilities
- `GET /health` - Health check endpoint

## Quick Start

### Prerequisites

- Rust 1.70+
- PostgreSQL 12+
- Diesel CLI: `cargo install diesel_cli --no-default-features --features postgres`

### Setup

1. **Clone and setup database:**
```bash
# Set up database
createdb fido2_webauthn
export DATABASE_URL="postgres://postgres:password@localhost/fido2_webauthn"

# Run migrations
diesel migration run
```

2. **Configure environment:**
```bash
cp .env.example .env
# Edit .env with your settings
```

3. **Build and run:**
```bash
cargo build --release
cargo run
```

The server will start on `http://localhost:8080` by default.

### Configuration

Environment variables:

- `DATABASE_URL` - PostgreSQL connection string
- `RP_ID` - Relying Party identifier (default: localhost)
- `RP_NAME` - Relying Party display name
- `RP_ORIGIN` - Allowed origin URL (default: http://localhost:8080)
- `BIND_ADDRESS` - Server bind address (default: 0.0.0.0:8080)
- `RUST_LOG` - Log level (info, debug, etc.)

## API Usage

### Registration Flow

1. **Start Registration:**
```bash
curl -X POST http://localhost:8080/attestation/options \
  -H "Content-Type: application/json" \
  -d '{
    "username": "user@example.com",
    "displayName": "John Doe", 
    "attestation": "direct"
  }'
```

2. **Complete Registration:**
```bash
curl -X POST http://localhost:8080/attestation/result \
  -H "Content-Type: application/json" \
  -d '{
    "id": "credential-id-base64url",
    "type": "public-key",
    "response": {
      "clientDataJSON": "client-data-base64url",
      "attestationObject": "attestation-object-base64url"
    }
  }'
```

### Authentication Flow

1. **Start Authentication:**
```bash
curl -X POST http://localhost:8080/assertion/options \
  -H "Content-Type: application/json" \
  -d '{
    "username": "user@example.com"
  }'
```

2. **Complete Authentication:**  
```bash
curl -X POST http://localhost:8080/assertion/result \
  -H "Content-Type: application/json" \
  -d '{
    "id": "credential-id-base64url",
    "type": "public-key", 
    "response": {
      "clientDataJSON": "client-data-base64url",
      "authenticatorData": "authenticator-data-base64url",
      "signature": "signature-base64url",
      "userHandle": ""
    }
  }'
```

## Testing

### Unit and Integration Tests
```bash
cargo test
```

### FIDO Conformance Tests

This server is designed to pass the official FIDO Alliance conformance test suite. The implementation includes:

- Proper JSON response formatting with `status` and `errorMessage` fields
- Comprehensive input validation matching FIDO test requirements
- Support for `excludeCredentials` in registration responses  
- Challenge generation and validation per FIDO specifications
- Attestation object parsing and validation
- All required cryptographic algorithm support
- Proper error responses for all failure scenarios

## Security Features

- **Challenge Replay Protection** - Challenges expire after 5 minutes and are single-use
- **Input Validation** - Comprehensive validation of all request fields
- **Origin Validation** - Strict origin checking per WebAuthn specification  
- **Attestation Verification** - Full attestation object validation
- **Database Security** - Parameterized queries prevent SQL injection
- **Error Handling** - No information leakage in error responses

## Database Schema

The server uses PostgreSQL with the following tables:

- `users` - User accounts with username and display name
- `credentials` - Stored FIDO2 credentials with public keys and metadata
- `challenges` - Temporary challenge storage with expiration

## Production Deployment

### Docker

```bash
docker build -t fido2-server .
docker run -p 8080:8080 --env-file .env fido2-server
```

### Performance Considerations

- Connection pooling for database access
- Async/await throughout for non-blocking I/O
- Efficient base64url encoding/decoding
- Minimal memory allocations in hot paths

## Compliance

This implementation follows:

- FIDO2/WebAuthn Level 2 specification
- W3C Credential Management API
- FIDO Alliance conformance test requirements
- RFC 8152 (CBOR Object Signing and Encryption)
- RFC 8230 (Using RSA Algorithms with CBOR)

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality  
4. Ensure all tests pass including conformance tests
5. Submit a pull request

## Support

For issues, questions, or contributions, please use the GitHub issue tracker.