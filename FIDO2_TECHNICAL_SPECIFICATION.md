# FIDO2/WebAuthn Relying Party Server - Technical Specification

## Executive Summary

This document provides a comprehensive technical specification for implementing a FIDO2/WebAuthn Relying Party Server in Rust using the webauthn-rs library. The specification focuses on security-first design, FIDO Alliance compliance, and comprehensive test-driven development.

## 1. Security Requirements

### 1.1 FIDO Alliance Compliance Requirements

#### Core Security Requirements (Testable Criteria)
- **SR-001**: Server MUST validate attestation statements according to FIDO2 specification
- **SR-002**: Server MUST implement proper challenge generation with minimum 16 bytes of entropy
- **SR-003**: Server MUST enforce user verification requirements based on RP policy
- **SR-004**: Server MUST validate credential parameters (alg, type, transports)
- **SR-005**: Server MUST implement proper origin validation
- **SR-006**: Server MUST prevent replay attacks through challenge uniqueness
- **SR-007**: Server MUST implement rate limiting for registration/authentication attempts
- **SR-008**: Server MUST validate RP ID against allowed origins
- **SR-009**: Server MUST implement secure credential storage with encryption at rest
- **SR-010**: Server MUST support credential backup eligibility flags

#### Cryptographic Requirements
- **CR-001**: Support for ES256, RS256, EdDSA algorithms
- **CR-002**: Minimum 2048-bit RSA keys or equivalent elliptic curve strength
- **CR-003**: Secure random number generation using OS CSPRNG
- **CR-004**: Proper signature validation for all attestation formats
- **CR-005**: Support for Packed, FIDO-U2F, and None attestation formats

### 1.2 Threat Model Mitigation

#### Replay Attack Prevention
- Challenge expiration: 5 minutes maximum lifetime
- One-time use challenges with immediate invalidation
- Cryptographic binding between challenge and session

#### Man-in-the-Middle Protection
- TLS 1.3 enforcement for all endpoints
- Origin validation against configured RP ID
- SameSite cookie attributes for session management

#### Credential Theft Prevention
- Encrypted credential storage using AES-256-GCM
- Key rotation support for storage encryption
- Audit logging for all credential operations

## 2. Technical Scope

### 2.1 Core WebAuthn Operations

#### Registration (Attestation) Flow
**Success Conditions:**
- Valid attestation statement verification
- Proper credential parameter validation
- Successful user verification (if required)
- Secure credential storage completion
- Challenge consumption and invalidation

**Failure Conditions:**
- Invalid attestation format
- Mismatching RP ID or origin
- Expired or already used challenge
- Cryptographic signature verification failure
- User verification failure
- Duplicate credential ID for user

#### Authentication (Assertion) Flow
**Success Conditions:**
- Valid assertion signature verification
- Matching credential ID and user handle
- Proper user verification (if required)
- Authentication counter validation
- Challenge consumption and invalidation

**Failure Conditions:**
- Invalid assertion signature
- Unknown credential ID
- Authentication counter regression
- Expired or used challenge
- User verification failure
- Mismatching user handle

### 2.2 Edge Case Testing Requirements

#### Registration Edge Cases
- Multiple credentials per user
- Credential ID collisions
- Attestation statement parsing errors
- Malformed client data JSON
- Invalid credential parameters
- Timeout scenarios

#### Authentication Edge Cases
- Credential removal during authentication
- Counter overflow scenarios
- Multiple concurrent authentication attempts
- Invalid user handle formats
- Malformed assertion data
- Session expiration during flow

## 3. Rust Architecture

### 3.1 Project Structure

```
src/
├── lib.rs                    # Library entry point
├── main.rs                   # Binary entry point
├── config/
│   ├── mod.rs               # Configuration module
│   ├── webauthn.rs          # WebAuthn configuration
│   └── database.rs          # Database configuration
├── controllers/
│   ├── mod.rs               # Controller module
│   ├── registration.rs      # Registration endpoints
│   ├── authentication.rs    # Authentication endpoints
│   └── health.rs            # Health check endpoints
├── services/
│   ├── mod.rs               # Service module
│   ├── webauthn.rs          # WebAuthn service logic
│   ├── user.rs              # User management service
│   └── credential.rs        # Credential management service
├── db/
│   ├── mod.rs               # Database module
│   ├── connection.rs        # Connection pool management
│   ├── models.rs            # Database models
│   └── repositories.rs      # Repository pattern implementation
├── middleware/
│   ├── mod.rs               # Middleware module
│   ├── auth.rs              # Authentication middleware
│   ├── cors.rs              # CORS middleware
│   └── rate_limit.rs        # Rate limiting middleware
├── routes/
│   ├── mod.rs               # Route definitions
│   ├── v1.rs                # API v1 routes
│   └── health.rs            # Health check routes
├── error/
│   ├── mod.rs               # Error handling module
│   ├── types.rs             # Custom error types
│   └── responses.rs         # Error response formatting
├── utils/
│   ├── mod.rs               # Utility functions
│   ├── crypto.rs            # Cryptographic utilities
│   ├── validation.rs        # Input validation
│   └── logging.rs           # Logging utilities
└── schema/
    └── mod.rs               # Database schema definitions
```

### 3.2 Testing Architecture

#### Unit Testing Structure
```
tests/
├── unit/
│   ├── services/
│   │   ├── webauthn_test.rs
│   │   ├── user_test.rs
│   │   └── credential_test.rs
│   ├── controllers/
│   │   ├── registration_test.rs
│   │   └── authentication_test.rs
│   └── utils/
│       ├── crypto_test.rs
│       └── validation_test.rs
├── integration/
│   ├── api_test.rs          # Full API integration tests
│   ├── database_test.rs     # Database integration tests
│   └── end_to_end_test.rs   # Complete flow tests
├── security/
│   ├── compliance_test.rs   # FIDO2 compliance tests
│   ├── vulnerability_test.rs # Security vulnerability tests
│   └── performance_test.rs  # Performance and load tests
└── fixtures/
    ├── test_data.rs         # Test data generators
    └── mock_responses.rs    # Mock response data
```

### 3.3 Key Dependencies and Testing Tools

```toml
[dependencies]
# Core WebAuthn
webauthn-rs = "0.5"
webauthn-rs-proto = "0.5"

# Web Framework
actix-web = "4.9"
actix-cors = "0.7"

# Database
diesel = { version = "2.1", features = ["postgres", "r2d2", "chrono", "uuid"] }
r2d2 = "0.8"

# Security
ring = "0.17"  # For cryptographic operations
base64 = "0.22"
uuid = { version = "1.10", features = ["v4", "serde"] }

[dev-dependencies]
# Testing Framework
mockall = "0.13"           # Mocking framework
tempfile = "3.10"          # Temporary file testing
proptest = "1.4"           # Property-based testing
criterion = "0.5"          # Benchmarking

# Security Testing
webauthn-rs = { version = "0.5", features = ["danger-allow-insecure"] }
```

## 4. API Design

### 4.1 REST Endpoints Specification

#### Registration Endpoints

**POST /api/v1/registration/challenge**
```json
Request:
{
  "username": "user@example.com",
  "displayName": "User Display Name",
  "userVerification": "required|preferred|discouraged",
  "attestation": "none|direct|enterprise|indirect"
}

Response (200):
{
  "status": "ok",
  "challenge": "base64url-encoded-challenge",
  "rp": {
    "name": "Example RP",
    "id": "example.com"
  },
  "user": {
    "id": "base64url-encoded-user-id",
    "name": "user@example.com",
    "displayName": "User Display Name"
  },
  "pubKeyCredParams": [
    { "type": "public-key", "alg": -7 },
    { "type": "public-key", "alg": -257 }
  ],
  "timeout": 60000,
  "excludeCredentials": [],
  "authenticatorSelection": {
    "authenticatorAttachment": "platform|cross-platform",
    "requireResidentKey": false,
    "userVerification": "required"
  },
  "attestation": "direct"
}

Error Responses:
400: Invalid request parameters
429: Rate limit exceeded
500: Internal server error
```

**POST /api/v1/registration/verify**
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
    "username": "user@example.com"
  }
}

Response (200):
{
  "status": "ok",
  "credentialId": "base64url-encoded-credential-id",
  "userId": "base64url-encoded-user-id",
  "registrationTime": "2024-01-01T00:00:00Z",
  "aaguid": "base64url-encoded-aaguid",
  "signCount": 0,
  "userVerified": true
}

Error Responses:
400: Invalid credential data
401: Invalid attestation
409: Credential already exists
422: Unprocessable entity
500: Internal server error
```

#### Authentication Endpoints

**POST /api/v1/authentication/challenge**
```json
Request:
{
  "username": "user@example.com",
  "userVerification": "required|preferred|discouraged"
}

Response (200):
{
  "status": "ok",
  "challenge": "base64url-encoded-challenge",
  "rpId": "example.com",
  "allowCredentials": [
    {
      "type": "public-key",
      "id": "base64url-encoded-credential-id",
      "transports": ["internal", "usb", "nfc", "ble"]
    }
  ],
  "userVerification": "required",
  "timeout": 60000
}

Error Responses:
400: Invalid request parameters
404: User not found
429: Rate limit exceeded
500: Internal server error
```

**POST /api/v1/authentication/verify**
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
  "credentialId": "base64url-encoded-credential-id",
  "userId": "base64url-encoded-user-id",
  "authenticationTime": "2024-01-01T00:00:00Z",
  "newSignCount": 42,
  "userVerified": true
}

Error Responses:
400: Invalid assertion data
401: Invalid signature
404: Credential not found
422: Unprocessable entity
500: Internal server error
```

### 4.2 Data Flow Specifications

#### Registration Flow
1. Client requests challenge → Server generates cryptographically secure challenge
2. Server stores challenge with expiration timestamp and user context
3. Client creates credential → Authenticator generates key pair and attestation
4. Client submits attestation → Server validates and stores credential
5. Server invalidates challenge and returns success

#### Authentication Flow
1. Client requests challenge → Server retrieves user credentials and generates challenge
2. Server stores challenge with expiration and credential context
3. Client creates assertion → Authenticator signs challenge with private key
4. Client submits assertion → Server validates signature and updates counter
5. Server invalidates challenge and returns success

## 5. Storage Requirements

### 5.1 Database Schema

#### Users Table
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    user_handle BYTEA UNIQUE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true
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
    aaguid BYTEA,
    attestation_format VARCHAR(50),
    attestation_statement BYTEA,
    backup_eligible BOOLEAN DEFAULT false,
    backup_state BOOLEAN DEFAULT false,
    transports JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true
);
```

#### Challenges Table
```sql
CREATE TABLE challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    challenge BYTEA NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    credential_id UUID REFERENCES credentials(id) ON DELETE CASCADE,
    challenge_type VARCHAR(20) NOT NULL, -- 'registration' or 'authentication'
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    metadata JSONB
);
```

### 5.2 Data Validation Requirements

#### Input Validation
- Username: 3-255 characters, valid email format
- Display Name: 1-255 characters, no control characters
- Challenge: Base64URL encoded, minimum 16 bytes when decoded
- Credential ID: Base64URL encoded, maximum 1023 bytes
- Public Key: Valid COSE key format
- Signature: Valid cryptographic signature for algorithm

#### Storage Validation
- All binary data stored as BYTEA with size limits
- JSON fields validated against schemas
- Foreign key constraints enforced
- Unique constraints on credential IDs and user handles
- Check constraints for sign_count (non-negative)

### 5.3 Encryption Requirements

#### At Rest Encryption
- Credential private keys: Not stored (server-side only public keys)
- User handles: Encrypted with AES-256-GCM
- Sensitive metadata: Encrypted with per-record keys
- Database connections: TLS 1.3 with certificate validation

#### Key Management
- Master encryption key: Hardware security module or KMS
- Key rotation: Automated every 90 days
- Key derivation: PBKDF2 with random salt
- Key storage: Secure key vault with access logging

## 6. Compliance Checklist

### 6.1 FIDO2 Specification Compliance Points

#### WebAuthn Level 2 Compliance
- [ ] RP ID validation against effective domain
- [ ] Origin validation for all requests
- [ ] Challenge generation with minimum 16 bytes entropy
- [ ] Client data JSON validation
- [ ] Authenticator data parsing and validation
- [ ] Signature verification for all supported algorithms
- [ ] Attestation statement validation
- [ ] User verification enforcement
- [ ] Credential parameter validation
- [ ] Transport parameter validation

#### FIDO2 Conformance Test Points
- [ ] Registration with different attestation formats
- [ ] Authentication with various user verification requirements
- [ ] Credential management operations
- [ ] Error handling and response codes
- [ ] Timeout handling
- [ ] Concurrent request handling
- [ ] Rate limiting implementation
- [ ] Cross-origin request handling

### 6.2 Security Compliance Verification

#### Cryptographic Compliance
- [ ] Algorithm implementation verification
- [ ] Random number generation quality
- [ ] Key strength requirements
- [ ] Signature format compliance
- [ ] Hash function usage

#### Data Protection Compliance
- [ ] Data encryption at rest
- [ ] Data encryption in transit
- [ ] Access control implementation
- [ ] Audit logging completeness
- [ ] Data retention policies

## 7. Risk Assessment

### 7.1 Security Considerations

#### High Risk Items
1. **Credential Replay Attacks**
   - Risk: Reuse of valid assertions
   - Mitigation: One-time challenges, immediate invalidation
   - Testing: Replay attempt scenarios

2. **Man-in-the-Middle Attacks**
   - Risk: Request/response tampering
   - Mitigation: TLS enforcement, origin validation
   - Testing: TLS downgrade attacks, origin spoofing

3. **Database Compromise**
   - Risk: Credential data exposure
   - Mitigation: Encryption at rest, minimal data storage
   - Testing: Database access simulation

#### Medium Risk Items
1. **Denial of Service**
   - Risk: Resource exhaustion
   - Mitigation: Rate limiting, request validation
   - Testing: Load testing, resource exhaustion

2. **Timing Attacks**
   - Risk: Information disclosure through timing
   - Mitigation: Constant-time operations
   - Testing: Timing analysis

### 7.2 Vulnerability Mitigation Strategies

#### Input Validation
- Strict schema validation for all inputs
- Length limits on all fields
- Character set restrictions
- Format validation with regex

#### Error Handling
- Consistent error responses
- No information leakage in errors
- Proper HTTP status codes
- Error rate limiting

#### Logging and Monitoring
- Comprehensive audit logging
- Security event detection
- Performance monitoring
- Anomaly detection

### 7.3 Testing Strategy for Security

#### Penetration Testing
- OWASP Top 10 vulnerability testing
- FIDO2 specific attack vectors
- Cryptographic implementation testing
- API security testing

#### Compliance Testing
- FIDO Alliance conformance tests
- Automated compliance verification
- Third-party security audits
- Regular security assessments

## Implementation Priority

### Phase 1: Core Functionality (Weeks 1-4)
1. Basic WebAuthn service implementation
2. Registration and authentication flows
3. In-memory credential storage
4. Basic API endpoints
5. Unit test coverage (80%+)

### Phase 2: Database Integration (Weeks 5-6)
1. PostgreSQL integration
2. Credential persistence
3. User management
4. Migration scripts
5. Integration tests

### Phase 3: Security Hardening (Weeks 7-8)
1. TLS enforcement
2. Rate limiting
3. Input validation
4. Error handling
5. Security tests

### Phase 4: Compliance and Performance (Weeks 9-10)
1. FIDO2 compliance testing
2. Performance optimization
3. Load testing
4. Documentation
5. Final testing (95%+ coverage)

## Success Metrics

### Technical Metrics
- Unit test coverage: ≥95%
- Integration test coverage: 100%
- Security test pass rate: 100%
- FIDO2 compliance: 100%
- Performance: <100ms response time (95th percentile)

### Security Metrics
- Zero critical vulnerabilities
- Zero high-risk vulnerabilities
- Complete audit trail coverage
- Successful penetration testing
- Compliance certification achieved

This specification provides a comprehensive foundation for implementing a secure, compliant FIDO2/WebAuthn Relying Party Server with extensive testing coverage and security-first design principles.