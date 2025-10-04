# FIDO2/WebAuthn Server Architecture

## Project Structure

```
fido-server/
├── src/
│   ├── config/           # Configuration management
│   │   ├── mod.rs
│   │   └── webauthn.rs   # WebAuthn configuration
│   ├── controllers/      # HTTP request handlers
│   │   ├── mod.rs
│   │   ├── auth.rs       # Authentication endpoints
│   │   ├── registration.rs # Registration endpoints
│   │   └── health.rs     # Health check endpoints
│   ├── db/              # Database layer
│   │   ├── mod.rs
│   │   ├── connection.rs # Database connection pool
│   │   ├── models.rs     # Diesel models
│   │   └── repository.rs # Data access layer
│   ├── services/        # Business logic
│   │   ├── mod.rs
│   │   ├── webauthn.rs   # WebAuthn service
│   │   ├── user.rs       # User management
│   │   └── challenge.rs  # Challenge management
│   ├── middleware/      # Custom middleware
│   │   ├── mod.rs
│   │   ├── auth.rs       # Authentication middleware
│   │   └── rate_limit.rs # Rate limiting
│   ├── routes/          # Route definitions
│   │   ├── mod.rs
│   │   ├── api.rs        # API routes
│   │   └── health.rs     # Health routes
│   ├── schema/          # Request/Response DTOs
│   │   ├── mod.rs
│   │   ├── auth.rs       # Authentication schemas
│   │   ├── registration.rs # Registration schemas
│   │   └── common.rs     # Common schemas
│   ├── error/           # Error handling
│   │   ├── mod.rs
│   │   └── webauthn.rs   # WebAuthn-specific errors
│   ├── utils/           # Utility functions
│   │   ├── mod.rs
│   │   ├── crypto.rs     # Cryptographic utilities
│   │   └── validation.rs # Input validation
│   ├── lib.rs           # Library entry point
│   └── main.rs          # Application entry point
├── migrations/          # Database migrations
├── tests/              # Integration tests
└── Cargo.toml
```

## Core Components

### 1. WebAuthn Service
- Challenge generation and validation
- Credential creation and verification
- Attestation statement validation
- User verification handling

### 2. Database Layer
- User management
- Credential storage
- Challenge tracking
- Session management

### 3. API Layer
- RESTful endpoints
- Request/response validation
- Error handling
- Security middleware

## Security Architecture

### 1. Challenge Management
- Cryptographically secure random challenges
- Time-based expiration (5 minutes)
- One-time use enforcement
- Database-backed persistence

### 2. Credential Storage
- Encrypted credential storage
- User-credential binding
- Metadata tracking
- Backup/restore support

### 3. Authentication Flow
- Multi-factor authentication support
- User verification levels
- Device attestation
- Replay attack prevention

## Compliance Requirements

### FIDO2/WebAuthn Level 2+
- Full specification compliance
- Attestation format support
- User verification implementation
- RP ID validation
- Origin checking

### Security Standards
- OWASP Top 10 compliance
- Secure coding practices
- Input validation
- Error handling
- Logging and monitoring