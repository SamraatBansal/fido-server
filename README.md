# FIDO Server

A FIDO2/WebAuthn conformant server implementation in Rust.

## Overview

This project implements a secure, scalable FIDO2/WebAuthn Relying Party Server that provides passwordless authentication capabilities. The implementation follows FIDO Alliance specifications and Rust best practices for security and performance.

## Features

- **FIDO2/WebAuthn Compliance**: Full support for WebAuthn Level 2 specification
- **Multiple Attestation Formats**: Packed, FIDO-U2F, TPM, Android Key, Apple Anonymous
- **User Verification**: Support for UV levels (required, preferred, discouraged)
- **Security Features**: Rate limiting, CSRF protection, secure headers
- **Async Architecture**: Built on tokio for high performance
- **Database Integration**: PostgreSQL with Diesel ORM
- **Comprehensive Testing**: Unit, integration, and security tests

## Architecture

The project follows a layered architecture:

```
├── Controllers/     # HTTP request handlers
├── Services/        # Business logic layer
├── DB/             # Database layer with repositories
├── Middleware/     # HTTP middleware (auth, CORS, security)
├── Routes/         # API routing configuration
├── Schema/         # Data transfer objects
├── Config/         # Configuration management
├── Error/          # Error handling
└── Utils/          # Utility functions
```

## API Endpoints

### Registration Flow
- `POST /api/v1/register/start` - Start registration
- `POST /api/v1/register/finish` - Complete registration

### Authentication Flow
- `POST /api/v1/authenticate/start` - Start authentication
- `POST /api/v1/authenticate/finish` - Complete authentication

### Credential Management
- `GET /api/v1/credentials` - List user credentials
- `DELETE /api/v1/credentials/{id}` - Delete credential

### Health Checks
- `GET /health` - Basic health check
- `GET /health/ready` - Readiness probe
- `GET /health/live` - Liveness probe

## Security Features

- **TLS Enforcement**: HTTPS-only communication
- **Rate Limiting**: Prevent brute force attacks
- **CSRF Protection**: Cross-site request forgery prevention
- **Security Headers**: HSTS, X-Frame-Options, CSP
- **Input Validation**: Strict JSON schema validation
- **Replay Protection**: Challenge-based authentication

## Getting Started

### Prerequisites

- Rust 1.70+
- PostgreSQL 12+
- Diesel CLI

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourorg/fido-server.git
cd fido-server
```

2. Install Diesel CLI:
```bash
cargo install diesel_cli --no-default-features --features postgres
```

3. Set up database:
```bash
createdb fido_server
diesel setup
diesel migration run
```

4. Configure environment:
```bash
cp .env.example .env
# Edit .env with your configuration
```

5. Run the server:
```bash
cargo run
```

The server will start on `http://localhost:8080`.

## Configuration

The server can be configured through environment variables or a configuration file:

```toml
[server]
host = "127.0.0.1"
port = 8080

[security]
allowed_origins = ["http://localhost:3000"]
max_session_duration_secs = 3600
challenge_expiry_secs = 300
rate_limit_per_minute = 60

[database]
url = "postgres://localhost/fido_server"
max_connections = 10

[webauthn]
rp_id = "localhost"
rp_name = "FIDO Server"
rp_origin = "http://localhost:8080"
```

## Development

### Running Tests

```bash
# Unit tests
cargo test

# Integration tests
cargo test --test integration

# Security tests
cargo test --test security
```

### Code Quality

```bash
# Format code
cargo fmt

# Run clippy
cargo clippy -- -D warnings

# Run security audit
cargo audit
```

## FIDO Compliance

This implementation aims for FIDO2/WebAuthn Level 2 compliance:

- ✅ Registration flow support
- ✅ Authentication flow support
- ✅ Multiple attestation formats
- ✅ User verification handling
- ✅ RP ID and origin validation
- ✅ Sign count tracking
- ✅ Secure credential storage

## Performance

- **Async Architecture**: Non-blocking I/O throughout
- **Connection Pooling**: Database connection management
- **In-Memory Caching**: Challenge and session caching
- **Optimized Queries**: Efficient database operations

## Security Considerations

- **Replay Attack Prevention**: Challenge-based authentication with expiration
- **Man-in-the-Middle Protection**: TLS enforcement and origin validation
- **Credential Theft Protection**: Encrypted storage and access controls
- **Denial of Service Prevention**: Rate limiting and resource management

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run the test suite
6. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support and questions:

- Create an issue on GitHub
- Check the documentation
- Review the FIDO2 specification

## Acknowledgments

- [FIDO Alliance](https://fidoalliance.org/) for the WebAuthn specification
- [webauthn-rs](https://github.com/kanidm/webauthn-rs) for the Rust WebAuthn implementation
- [Actix Web](https://actix.rs/) for the web framework