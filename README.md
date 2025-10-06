# FIDO2/WebAuthn Relying Party Server

A secure, FIDO2-compliant WebAuthn server implementation in Rust using Actix-web and Diesel.

## Features

- **FIDO2/WebAuthn Compliance**: Implements core WebAuthn operations for registration and authentication
- **Secure Architecture**: Follows security best practices with proper error handling and validation
- **Database Integration**: PostgreSQL backend with Diesel ORM
- **Rate Limiting**: Built-in protection against brute force attacks
- **CORS Support**: Configurable cross-origin resource sharing
- **Security Headers**: Comprehensive security header implementation
- **Challenge Management**: Secure challenge generation and validation with TTL

## Architecture

```
src/
├── config/           # Configuration management
├── controllers/      # HTTP request handlers
├── db/              # Database models and connections
├── error/           # Error handling types
├── middleware/      # Custom middleware (CORS, rate limiting, security)
├── routes/          # API route definitions
├── schema/          # Request/Response DTOs
├── services/        # Business logic layer
└── utils/           # Utility functions
```

## API Endpoints

### Registration
- `POST /api/v1/register/start` - Start credential registration
- `POST /api/v1/register/finish` - Complete credential registration

### Authentication
- `POST /api/v1/authenticate/start` - Start authentication
- `POST /api/v1/authenticate/finish` - Complete authentication

### Credential Management
- `GET /api/v1/credentials/{user_id}` - List user credentials
- `DELETE /api/v1/credentials/{user_id}/{credential_id}` - Delete credential

### User Management
- `POST /api/v1/users` - Create user
- `GET /api/v1/users/{user_id}` - Get user by ID
- `GET /api/v1/users/username/{username}` - Get user by username
- `PUT /api/v1/users/{user_id}` - Update user
- `DELETE /api/v1/users/{user_id}` - Delete user
- `GET /api/v1/users` - List users
- `GET /api/v1/users/{user_id}/credentials` - Get user with credentials

## Configuration

The server can be configured through environment variables:

- `SERVER_HOST` - Server host (default: 127.0.0.1)
- `SERVER_PORT` - Server port (default: 8080)
- `DATABASE_URL` - PostgreSQL connection string
- `RP_ID` - Relying Party ID (default: localhost)
- `RP_NAME` - Relying Party name (default: FIDO Server)
- `RP_ORIGIN` - Relying Party origin (default: http://localhost:8080)

## Security Features

- **Challenge-based Authentication**: Cryptographically secure challenges prevent replay attacks
- **Rate Limiting**: Configurable rate limits prevent brute force attacks
- **CORS Protection**: Proper cross-origin validation
- **Security Headers**: HSTS, CSP, X-Frame-Options, etc.
- **Input Validation**: Comprehensive validation of all inputs
- **Error Sanitization**: Prevents information leakage through error messages

## Database Schema

The server uses PostgreSQL with the following main tables:

- `users` - User information
- `credentials` - WebAuthn credentials
- `challenges` - Temporary challenges with TTL

## Getting Started

### Prerequisites

- Rust 1.70+
- PostgreSQL 12+
- Diesel CLI

### Installation

1. Clone the repository
2. Set up the database:
   ```bash
   createdb fido_server
   diesel setup
   diesel migration run
   ```
3. Configure environment variables
4. Run the server:
   ```bash
   cargo run
   ```

## Development

### Running Tests

```bash
cargo test
```

### Code Quality

The project uses strict linting:
```bash
cargo clippy -- -D warnings
cargo fmt --check
```

## Security Considerations

This implementation follows FIDO2 security guidelines:

- **RP ID Validation**: Proper validation of relying party identifiers
- **Origin Validation**: Ensures requests come from allowed origins
- **Challenge Expiration**: Challenges have limited lifetime
- **Counter Tracking**: Monitors credential usage counters
- **Secure Storage**: Credentials stored securely in database

## Compliance

The server aims to be compliant with:
- FIDO2 Specification
- WebAuthn Level 1+
- NIST Digital Identity Guidelines

## License

MIT License - see LICENSE file for details.

## Contributing

Please follow the contribution guidelines and ensure all tests pass before submitting pull requests.