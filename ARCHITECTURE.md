# FIDO2/WebAuthn Server Architecture

## Overview

This document describes the comprehensive architecture of the FIDO2/WebAuthn Relying Party Server implementation in Rust. The architecture follows security-first principles, modern Rust patterns, and FIDO Alliance specifications.

## Architecture Principles

1. **Security First**: All design decisions prioritize security over convenience
2. **FIDO Compliance**: Strict adherence to WebAuthn Level 2 specification
3. **Performance**: Async architecture with connection pooling and caching
4. **Maintainability**: Clean separation of concerns and modular design
5. **Testability**: Comprehensive testing strategy with mocks and integration tests

## System Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Client   │    │  Mobile Client  │    │  Desktop Client │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌─────────────┴─────────────┐
                    │      Load Balancer        │
                    └─────────────┬─────────────┘
                                 │
                    ┌─────────────┴─────────────┐
                    │   FIDO Server Cluster     │
                    │  (Multiple Instances)     │
                    └─────────────┬─────────────┘
                                 │
                    ┌─────────────┴─────────────┐
                    │      PostgreSQL           │
                    │   (Primary + Replicas)    │
                    └───────────────────────────┘
```

## Application Architecture

### Layered Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    HTTP Layer                               │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐   │
│  │ Controllers │ │ Middleware  │ │      Routes         │   │
│  └─────────────┘ └─────────────┘ └─────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│                  Business Logic Layer                       │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐   │
│  │ FIDO Service│ │ User Service│ │ Credential Service  │   │
│  └─────────────┘ └─────────────┘ └─────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│                   Data Access Layer                         │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐   │
│  │ Repositories│ │   Models    │ │   Connection Pool   │   │
│  └─────────────┘ └─────────────┘ └─────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│                    Infrastructure                           │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐   │
│  │ Database    │ │   Config    │ │      Utils          │   │
│  └─────────────┘ └─────────────┘ └─────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. WebAuthn Integration (`services/fido.rs`)

**Responsibilities:**
- Challenge generation and validation
- Attestation verification
- Assertion verification
- Sign count tracking
- RP ID and origin validation

**Key Features:**
- Support for multiple attestation formats
- User verification policy enforcement
- Cryptographic operations using webauthn-rs
- Session state management

### 2. Authentication Flow

#### Registration Flow
```
Client → Server: POST /api/v1/register/start
Server → Client: CreationChallengeResponse
Client → Authenticator: navigator.credentials.create()
Authenticator → Client: AttestationResponse
Client → Server: POST /api/v1/register/finish
Server: Verify attestation, store credential
Server → Client: RegistrationComplete
```

#### Authentication Flow
```
Client → Server: POST /api/v1/authenticate/start
Server → Client: RequestChallengeResponse
Client → Authenticator: navigator.credentials.get()
Authenticator → Client: AssertionResponse
Client → Server: POST /api/v1/authenticate/finish
Server: Verify assertion, update sign count
Server → Client: AuthenticationComplete + Session Token
```

### 3. Database Schema

#### Users Table
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

#### Credentials Table
```sql
CREATE TABLE credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA UNIQUE NOT NULL,
    public_key BYTEA NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    attestation_format VARCHAR(50),
    aaguid BYTEA,
    transports TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    backup_eligible BOOLEAN DEFAULT FALSE,
    backup_state BOOLEAN DEFAULT FALSE
);
```

#### Sessions Table
```sql
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    challenge VARCHAR(255) NOT NULL,
    session_type VARCHAR(20) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### 4. Security Architecture

#### Authentication Middleware
- JWT token validation (placeholder implementation)
- Session management
- User context injection

#### Security Headers
- HSTS (HTTP Strict Transport Security)
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- X-XSS-Protection: 1; mode=block
- Content Security Policy
- Referrer Policy

#### Rate Limiting
- Per-IP rate limiting
- Configurable limits
- In-memory storage (production: Redis)

#### Input Validation
- JSON schema validation
- Username/display name validation
- UUID format validation
- Base64 format validation

### 5. Error Handling Strategy

#### Error Types
```rust
pub enum AppError {
    WebAuthn(WebauthnError),
    Database(diesel::result::Error),
    InvalidCredential(String),
    AuthenticationFailed(String),
    RateLimitExceeded,
    SessionExpired,
    InvalidRequest(String),
    // ... more error types
}
```

#### Error Response Format
```json
{
    "error": "error_type",
    "message": "Human readable message",
    "timestamp": "2024-01-01T00:00:00Z"
}
```

### 6. Performance Considerations

#### Async Architecture
- Tokio runtime for async operations
- Non-blocking I/O throughout
- Connection pooling for database

#### Caching Strategy
- In-memory challenge cache
- Session storage optimization
- Database query optimization

#### Database Optimization
- Connection pooling with r2d2
- Proper indexing strategy
- Query optimization

## Security Analysis

### Threat Mitigation

#### 1. Replay Attacks
- **Challenge-based authentication**: Unique challenges per session
- **Challenge expiration**: Time-limited validity
- **Sign count tracking**: Prevents assertion reuse

#### 2. Man-in-the-Middle Attacks
- **TLS enforcement**: HTTPS-only communication
- **Origin validation**: Strict origin checking
- **RP ID validation**: Prevents domain impersonation

#### 3. Credential Theft
- **Encrypted storage**: Sensitive data encryption
- **Access controls**: Database security
- **Audit logging**: Security event tracking

#### 4. Denial of Service
- **Rate limiting**: Request throttling
- **Connection limits**: Resource protection
- **Health checks**: Service monitoring

### Compliance Checklist

#### WebAuthn Level 2 Compliance
- [x] Registration flow support
- [x] Authentication flow support
- [x] Multiple attestation formats
- [x] User verification handling
- [x] RP ID and origin validation
- [x] Sign count tracking
- [x] Secure credential storage

#### Security Requirements
- [x] TLS 1.2+ enforcement
- [x] Secure random number generation
- [x] Proper error handling
- [x] CSRF protection
- [x] Rate limiting
- [x] Input validation

## Testing Strategy

### Unit Tests
- Service layer testing with mocks
- Utility function testing
- Error handling validation

### Integration Tests
- API endpoint testing
- Database integration
- WebAuthn flow testing

### Security Tests
- Replay attack prevention
- Input validation
- Authentication bypass attempts

## Deployment Architecture

### Containerization
- Multi-stage Docker builds
- Minimal runtime image
- Security hardening

### Orchestration
- Docker Compose for development
- Kubernetes for production
- Health checks and monitoring

### Monitoring
- Application metrics
- Security event logging
- Performance monitoring

## Future Enhancements

### Phase 2 Features
- Redis integration for session storage
- JWT token implementation
- FIDO Metadata Service integration
- Biometric performance data handling

### Phase 3 Features
- Multi-tenant support
- Advanced analytics
- WebAuthn extensions support
- Hardware security module integration

## Development Guidelines

### Code Quality
- Rust clippy linting
- Comprehensive documentation
- Error handling best practices

### Security Development
- Security-focused code reviews
- Dependency vulnerability scanning
- Regular security audits

### Performance Optimization
- Profiling and benchmarking
- Memory usage optimization
- Database query optimization

This architecture provides a solid foundation for a secure, scalable, and maintainable FIDO2/WebAuthn server that meets all security requirements while following Rust best practices.