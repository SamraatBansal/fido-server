# FIDO2/WebAuthn Relying Party Server - Technical Specification

## Executive Summary

This document provides a comprehensive technical specification for implementing a FIDO2/WebAuthn conformant Relying Party Server in Rust using the webauthn-rs library. The specification focuses on security-first design, FIDO Alliance compliance, and comprehensive test-driven development.

## 1. Security Requirements

### 1.1 FIDO Alliance Compliance Requirements

#### Core Security Requirements (Testable Criteria)
- **MUST** Implement WebAuthn Level 2 compliance
- **MUST** Support attestation formats: packed, fido-u2f, none, android-key, android-safetynet
- **MUST** Support user verification: required, preferred, discouraged
- **MUST** Implement proper RP ID validation
- **MUST** Enforce origin validation
- **MUST** Implement timeout controls (minimum 5 minutes, maximum 24 hours)
- **MUST** Support credential exclusion during registration
- **MUST** Implement proper challenge generation (cryptographically secure, 16+ bytes)

#### Cryptographic Requirements
- **MUST** Use cryptographically secure random number generation
- **MUST** Support ES256, RS256, EdDSA algorithms
- **MUST** Validate COSE key parameters
- **MUST** Implement proper signature verification
- **MUST** Support credential protection extensions

#### Session Security
- **MUST** Implement secure session management
- **MUST** Prevent session fixation attacks
- **MUST** Implement proper CSRF protection
- **MUST** Use secure, HttpOnly cookies
- **MUST** Implement proper logout functionality

### 1.2 Data Protection Requirements

#### Credential Storage Security
- **MUST** Encrypt credential data at rest
- **MUST** Implement proper key management
- **MUST** Support credential backup and recovery
- **MUST** Implement credential deletion with proper cleanup
- **MUST** Log all credential operations for audit

#### Privacy Requirements
- **MUST** Implement user consent management
- **MUST** Support user data deletion (GDPR compliance)
- **MUST** Minimize data collection to required fields only
- **MUST** Implement data retention policies

## 2. Technical Scope

### 2.1 Core WebAuthn Operations

#### Registration (Attestation) Flow
**Success Conditions:**
- Valid challenge-response verification
- Proper attestation statement validation
- Successful credential storage
- User mapping established
- Audit log created

**Failure Conditions:**
- Invalid challenge (replay attack prevention)
- Invalid attestation format
- Unsupported algorithm
- RP ID mismatch
- Origin mismatch
- Timeout exceeded
- Duplicate credential ID
- Invalid user verification

#### Authentication (Assertion) Flow
**Success Conditions:**
- Valid challenge-response verification
- Proper signature verification
- Credential exists and is enabled
- User verification matches policy
- Authentication counter updated
- Audit log created

**Failure Conditions:**
- Invalid challenge
- Invalid signature
- Credential not found
- Credential disabled
- User verification failure
- Authentication counter regression (replay attack)
- Timeout exceeded

### 2.2 Edge Cases and Error Handling

#### Registration Edge Cases
- Multiple authenticators per user
- Credential ID collisions
- Attestation statement parsing failures
- Unsupported extensions
- Malformed client data
- Network timeouts during attestation

#### Authentication Edge Cases
- Lost authenticator scenarios
- Backup authenticator usage
- Credential counter overflow
- User verification bypass attempts
- Malicious assertion data
- Concurrent authentication attempts

## 3. Rust Architecture

### 3.1 Project Structure

```
src/
├── lib.rs                    # Library entry point
├── main.rs                   # Binary entry point
├── config/                   # Configuration management
│   ├── mod.rs
│   ├── app.rs               # Application configuration
│   └── database.rs          # Database configuration
├── controllers/              # HTTP request handlers
│   ├── mod.rs
│   ├── registration.rs      # Registration endpoints
│   ├── authentication.rs    # Authentication endpoints
│   ├── user.rs              # User management
│   └── health.rs            # Health check endpoints
├── services/                 # Business logic layer
│   ├── mod.rs
│   ├── webauthn.rs          # WebAuthn service
│   ├── user.rs              # User service
│   ├── credential.rs        # Credential service
│   └── audit.rs             # Audit logging service
├── db/                       # Database layer
│   ├── mod.rs
│   ├── connection.rs        # Database connection management
│   ├── models.rs            # Database models
│   ├── repositories.rs      # Repository pattern implementation
│   └── migrations/          # Database migrations
├── middleware/               # HTTP middleware
│   ├── mod.rs
│   ├── auth.rs              # Authentication middleware
│   ├── cors.rs              # CORS handling
│   ├── logging.rs           # Request logging
│   └── rate_limit.rs        # Rate limiting
├── routes/                   # Route definitions
│   ├── mod.rs
│   ├── webauthn.rs          # WebAuthn routes
│   ├── user.rs              # User routes
│   └── admin.rs             # Admin routes
├── error/                    # Error handling
│   ├── mod.rs
│   ├── types.rs             # Error types
│   └── handlers.rs          # Error handlers
├── utils/                    # Utility functions
│   ├── mod.rs
│   ├── crypto.rs            # Cryptographic utilities
│   ├── validation.rs        # Input validation
│   └── time.rs              # Time utilities
└── schema/                   # Database schema
    ├── mod.rs
    └── generated.rs         # Diesel-generated schema
```

### 3.2 Testing Architecture

```
tests/
├── common/                   # Test utilities and fixtures
│   ├── mod.rs
│   ├── fixtures.rs          # Test data fixtures
│   ├── mock_server.rs       # Mock server setup
│   └── test_helpers.rs      # Common test functions
├── unit/                     # Unit tests
│   ├── services/            # Service layer tests
│   ├── db/                  # Database layer tests
│   └── utils/               # Utility function tests
├── integration/              # Integration tests
│   ├── api/                 # API endpoint tests
│   ├── webauthn/            # WebAuthn flow tests
│   └── security/            # Security tests
├── compliance/               # FIDO compliance tests
│   ├── registration.rs      # Registration compliance
│   ├── authentication.rs    # Authentication compliance
│   └── extensions.rs        # Extension compliance
└── performance/              # Performance tests
    ├── load.rs              # Load testing
    └── concurrent.rs        # Concurrency testing
```

### 3.3 Key Dependencies and Rationale

```toml
# Core WebAuthn Implementation
webauthn-rs = "0.5"           # Primary WebAuthn library
webauthn-rs-proto = "0.5"     # WebAuthn protocol types

# Web Framework
actix-web = "4.9"             # High-performance web framework
actix-cors = "0.7"            # CORS support
actix-rt = "2.10"             # Async runtime

# Database
diesel = { version = "2.1", features = ["postgres", "r2d2", "chrono", "uuid"] }
diesel_migrations = "2.1"     # Database migrations
r2d2 = "0.8"                  # Connection pooling

# Security
base64 = "0.22"               # Base64 encoding/decoding
sha2 = "0.10"                 # SHA-2 hashing
uuid = { version = "1.10", features = ["v4", "serde"] }  # UUID generation

# Testing
mockall = "0.13"              # Mocking framework
actix-test = "0.1"            # Actix testing utilities
```

## 4. API Design

### 4.1 REST Endpoints Specification

#### Registration Endpoints

**POST /webauthn/register/begin**
```json
Request:
{
  "username": "user@example.com",
  "displayName": "John Doe",
  "userVerification": "preferred",
  "attestation": "direct",
  "extensions": {
    "credProps": true
  }
}

Response (200):
{
  "status": "ok",
  "challenge": "base64url-encoded-challenge",
  "user": {
    "id": "base64url-encoded-user-id",
    "name": "user@example.com",
    "displayName": "John Doe"
  },
  "rp": {
    "name": "FIDO Server",
    "id": "example.com"
  },
  "pubKeyCredParams": [
    {
      "type": "public-key",
      "alg": -7
    }
  ],
  "timeout": 60000,
  "excludeCredentials": [],
  "authenticatorSelection": {
    "userVerification": "preferred",
    "residentKey": "preferred"
  },
  "attestation": "direct",
  "extensions": {
    "credProps": true
  }
}

Error Responses:
400: Invalid request format
401: Unauthorized
409: User already exists
500: Internal server error
```

**POST /webauthn/register/finish**
```json
Request:
{
  "credential": {
    "id": "base64url-encoded-credential-id",
    "rawId": "base64url-encoded-raw-id",
    "response": {
      "attestationObject": "base64url-encoded-attestation",
      "clientDataJSON": "base64url-encoded-client-data"
    },
    "type": "public-key"
  },
  "sessionData": {
    "challenge": "base64url-encoded-challenge",
    "userId": "base64url-encoded-user-id"
  }
}

Response (200):
{
  "status": "ok",
  "credentialId": "base64url-encoded-credential-id",
  "user": {
    "id": "base64url-encoded-user-id",
    "name": "user@example.com",
    "displayName": "John Doe"
  },
  "authenticatorInfo": {
    "aaguid": "base64url-encoded-aaguid",
    "signCount": 0,
    "cloneWarning": false
  }
}

Error Responses:
400: Invalid credential data
401: Invalid challenge
409: Credential already exists
422: Unprocessable entity
500: Internal server error
```

#### Authentication Endpoints

**POST /webauthn/authenticate/begin**
```json
Request:
{
  "username": "user@example.com",
  "userVerification": "preferred"
}

Response (200):
{
  "status": "ok",
  "challenge": "base64url-encoded-challenge",
  "rpId": "example.com",
  "allowCredentials": [
    {
      "id": "base64url-encoded-credential-id",
      "type": "public-key",
      "transports": ["usb", "nfc", "ble", "internal"]
    }
  ],
  "userVerification": "preferred",
  "timeout": 60000,
  "extensions": {}
}

Error Responses:
400: Invalid request format
404: User not found
500: Internal server error
```

**POST /webauthn/authenticate/finish**
```json
Request:
{
  "credential": {
    "id": "base64url-encoded-credential-id",
    "rawId": "base64url-encoded-raw-id",
    "response": {
      "authenticatorData": "base64url-encoded-auth-data",
      "clientDataJSON": "base64url-encoded-client-data",
      "signature": "base64url-encoded-signature",
      "userHandle": "base64url-encoded-user-handle"
    },
    "type": "public-key"
  },
  "sessionData": {
    "challenge": "base64url-encoded-challenge",
    "username": "user@example.com"
  }
}

Response (200):
{
  "status": "ok",
  "user": {
    "id": "base64url-encoded-user-id",
    "name": "user@example.com",
    "displayName": "John Doe"
  },
  "credentialId": "base64url-encoded-credential-id",
  "newSignCount": 123,
  "authenticationInfo": {
    "userVerified": true,
    "authenticatorInfo": {
      "aaguid": "base64url-encoded-aaguid",
      "signCount": 123
    }
  }
}

Error Responses:
400: Invalid assertion data
401: Invalid signature or challenge
403: Credential disabled
404: Credential not found
422: Unprocessable entity
500: Internal server error
```

### 4.2 Data Flow Architecture

```
Client Request
    ↓
[Middleware Layer]
    ↓ - CORS, Logging, Rate Limiting
[Controller Layer]
    ↓ - Request Validation, Response Formatting
[Service Layer]
    ↓ - Business Logic, WebAuthn Operations
[Repository Layer]
    ↓ - Data Access, Transaction Management
[Database Layer]
    ↓ - PostgreSQL with Connection Pooling
```

## 5. Storage Requirements

### 5.1 Database Schema Design

#### Users Table
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true,
    email_verified BOOLEAN DEFAULT false
);
```

#### Credentials Table
```sql
CREATE TABLE credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA UNIQUE NOT NULL,
    credential_type VARCHAR(50) NOT NULL DEFAULT 'public-key',
    public_key BYTEA NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    aaguid BYTEA,
    attestation_format VARCHAR(50),
    attestation_statement BYTEA,
    transports TEXT[],
    backup_eligible BOOLEAN DEFAULT false,
    backup_state BOOLEAN DEFAULT false,
    user_verification_policy VARCHAR(20) DEFAULT 'preferred',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true,
    clone_warning BOOLEAN DEFAULT false
);
```

#### Authentication Sessions Table
```sql
CREATE TABLE auth_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    challenge VARCHAR(255) NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    session_type VARCHAR(20) NOT NULL, -- 'registration' or 'authentication'
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_used BOOLEAN DEFAULT false,
    metadata JSONB
);
```

#### Audit Logs Table
```sql
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    credential_id UUID REFERENCES credentials(id) ON DELETE SET NULL,
    action VARCHAR(50) NOT NULL, -- 'register', 'authenticate', 'delete', etc.
    status VARCHAR(20) NOT NULL, -- 'success', 'failure', 'error'
    ip_address INET,
    user_agent TEXT,
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### 5.2 Data Validation Requirements

#### Input Validation
- **Username**: Email format, max 255 characters, unique
- **Display Name**: Max 255 characters, no HTML entities
- **Challenge**: Base64URL encoded, 16+ bytes, unique per session
- **Credential ID**: Base64URL encoded, max 1023 bytes
- **Public Key**: Valid COSE key format
- **Attestation**: Valid CBOR format, supported format

#### Data Integrity
- **Foreign Key Constraints**: Enforce referential integrity
- **Unique Constraints**: Prevent duplicate usernames and credential IDs
- **Check Constraints**: Validate enum values and ranges
- **Triggers**: Update timestamps automatically

#### Encryption Requirements
- **Credentials at Rest**: AES-256 encryption for sensitive fields
- **Session Data**: Encrypted storage with time-based expiration
- **Audit Logs**: Hash sensitive data, encrypt PII

## 6. Compliance Checklist

### 6.1 FIDO2 Specification Compliance Points

#### WebAuthn Level 2 Requirements
- [ ] **RP ID Validation**: Must validate RP ID against effective domain
- [ ] **Origin Validation**: Must validate origin against RP ID
- [ ] **Challenge Generation**: Must use cryptographically secure random values
- [ ] **Challenge Storage**: Must store challenges securely with expiration
- [ ] **Timeout Handling**: Must implement proper timeout mechanisms
- [ ] **User Verification**: Must support all user verification modes
- [ ] **Attestation**: Must support required attestation formats
- [ ] **Extensions**: Must support required extensions (credProps, etc.)

#### Security Requirements
- [ ] **Replay Attack Prevention**: Challenge uniqueness and expiration
- [ ] **Man-in-the-Middle Prevention**: Origin and RP ID validation
- [ ] **Credential Cloning Detection**: Sign counter validation
- [ ] **Secure Storage**: Encryption of sensitive data
- [ ] **Audit Logging**: Comprehensive logging of all operations

#### Privacy Requirements
- [ ] **User Consent**: Explicit consent for credential creation
- [ ] **Data Minimization**: Collect only necessary data
- [ ] **User Control**: Allow credential management and deletion
- [ ] **Transparency**: Clear privacy policies and data usage

### 6.2 Testable Compliance Points

#### Registration Compliance Tests
```rust
#[cfg(test)]
mod registration_compliance {
    use super::*;
    
    #[tokio::test]
    async fn test_rp_id_validation() {
        // Test that RP ID is properly validated
        // Must reject invalid RP IDs
        // Must accept valid RP IDs
    }
    
    #[tokio::test]
    async fn test_challenge_uniqueness() {
        // Test that challenges are unique
        // Test challenge expiration
        // Test challenge replay prevention
    }
    
    #[tokio::test]
    async fn test_attestation_validation() {
        // Test all supported attestation formats
        // Test invalid attestation rejection
        // Test attestation statement parsing
    }
}
```

#### Authentication Compliance Tests
```rust
#[cfg(test)]
mod authentication_compliance {
    use super::*;
    
    #[tokio::test]
    async fn test_signature_verification() {
        // Test valid signature acceptance
        // Test invalid signature rejection
        // Test algorithm support
    }
    
    #[tokio::test]
    async fn test_counter_validation() {
        // Test counter increment validation
        // Test counter regression detection
        // Test counter overflow handling
    }
    
    #[tokio::test]
    async fn test_user_verification() {
        // Test required user verification
        // Test preferred user verification
        // Test discouraged user verification
    }
}
```

## 7. Risk Assessment

### 7.1 Security Vulnerabilities and Mitigations

#### High-Risk Vulnerabilities

**Replay Attacks**
- **Risk**: Attacker reuses valid authentication responses
- **Mitigation**: 
  - One-time challenges with cryptographic randomness
  - Challenge expiration (5-60 minutes)
  - Challenge invalidation after use
  - Secure challenge storage with encryption

**Man-in-the-Middle Attacks**
- **Risk**: Attacker intercepts and modifies WebAuthn data
- **Mitigation**:
  - Strict origin validation
  - RP ID validation against effective domain
  - TLS enforcement for all communications
  - Certificate pinning for high-security applications

**Credential Cloning**
- **Risk**: Attacker copies authenticator credentials
- **Mitigation**:
  - Authentication counter validation
  - Clone warning detection
  - Device binding where supported
  - Regular credential rotation policies

#### Medium-Risk Vulnerabilities

**Session Hijacking**
- **Risk**: Attacker takes over user sessions
- **Mitigation**:
  - Secure, HttpOnly cookies
  - SameSite cookie attributes
  - Short session timeouts
  - Session invalidation on logout

**Database Breaches**
- **Risk**: Credential data exposure
- **Mitigation**:
  - Encryption at rest for sensitive fields
  - Database access controls
  - Regular security audits
  - Backup encryption

#### Low-Risk Vulnerabilities

**Denial of Service**
- **Risk**: Service availability disruption
- **Mitigation**:
  - Rate limiting per IP/user
  - Request size limits
  - Connection pooling
  - Load balancing

**Information Disclosure**
- **Risk**: Sensitive information leakage
- **Mitigation**:
  - Error message sanitization
  - Security headers implementation
  - Audit log protection
  - Minimal error responses

### 7.2 Security Testing Requirements

#### Static Analysis
- **Code Scanning**: Use security-focused linters (clippy with security rules)
- **Dependency Scanning**: Regular vulnerability scans of dependencies
- **Secret Detection**: Scan for hardcoded secrets or credentials

#### Dynamic Testing
- **Penetration Testing**: Regular security assessments
- **Fuzz Testing**: Input validation and parsing robustness
- **Load Testing**: Performance under stress conditions

#### Compliance Testing
- **FIDO Alliance Tools**: Use official conformance test tools
- **Automated Scanning**: Continuous compliance verification
- **Manual Review**: Expert security code reviews

## 8. Implementation Roadmap

### Phase 1: Core Infrastructure (Weeks 1-2)
- [ ] Project structure setup
- [ ] Database schema and migrations
- [ ] Basic WebAuthn service implementation
- [ ] Configuration management
- [ ] Error handling framework

### Phase 2: Registration Flow (Weeks 3-4)
- [ ] Registration begin endpoint
- [ ] Registration finish endpoint
- [ ] Attestation validation
- [ ] User management
- [ ] Unit and integration tests

### Phase 3: Authentication Flow (Weeks 5-6)
- [ ] Authentication begin endpoint
- [ ] Authentication finish endpoint
- [ ] Assertion validation
- [ ] Session management
- [ ] Security tests

### Phase 4: Security & Compliance (Weeks 7-8)
- [ ] Security middleware implementation
- [ ] Audit logging system
- [ ] FIDO compliance testing
- [ ] Performance optimization
- [ ] Documentation completion

### Phase 5: Testing & Deployment (Weeks 9-10)
- [ ] Comprehensive test suite
- [ ] Load testing
- [ ] Security audit
- [ ] Deployment preparation
- [ ] Monitoring and alerting

## 9. Success Metrics

### Technical Metrics
- **Test Coverage**: ≥95% unit test coverage
- **API Performance**: <100ms response time for 95% of requests
- **Security Score**: Zero high-severity vulnerabilities
- **Compliance**: 100% FIDO2 conformance test pass rate

### Operational Metrics
- **Availability**: 99.9% uptime
- **Error Rate**: <0.1% error rate for all operations
- **Security Incidents**: Zero security breaches
- **Audit Trail**: 100% operation logging coverage

This specification provides a comprehensive foundation for implementing a secure, compliant FIDO2/WebAuthn Relying Party Server with extensive testing coverage and security-first design principles.