# FIDO2/WebAuthn Relying Party Server Technical Specification

## Executive Summary

This document provides a comprehensive technical specification for implementing a FIDO2/WebAuthn conformant Relying Party Server in Rust using the webauthn-rs library. The specification focuses on security-first design, FIDO Alliance compliance, and comprehensive testability.

## 1. Security Requirements

### 1.1 FIDO Alliance Compliance Requirements

#### Core Security Requirements (Testable Criteria)
- **REQ-SEC-001**: Server MUST implement WebAuthn Level 2 compliance
  - Test: Verify all required WebAuthn API endpoints exist
  - Test: Validate response formats match FIDO2 specification
  - Test: Ensure proper error codes and status handling

- **REQ-SEC-002**: Server MUST enforce TLS 1.2+ for all communications
  - Test: Verify HTTPS enforcement in all endpoints
  - Test: Test certificate validation
  - Test: Ensure HSTS headers are present

- **REQ-SEC-003**: Server MUST prevent replay attacks
  - Test: Verify challenge uniqueness and expiration
  - Test: Test replay detection mechanisms
  - Test: Validate timestamp-based challenge validation

- **REQ-SEC-004**: Server MUST implement proper credential binding
  - Test: Verify user-credential association integrity
  - Test: Test credential isolation between users
  - Test: Validate RP ID binding enforcement

#### Cryptographic Requirements
- **REQ-SEC-005**: Server MUST support ES256, RS256, and EdDSA algorithms
  - Test: Verify attestation format support
  - Test: Test signature validation for each algorithm
  - Test: Validate key parameter constraints

- **REQ-SEC-006**: Server MUST implement secure random challenge generation
  - Test: Verify challenge entropy (minimum 128 bits)
  - Test: Test challenge uniqueness across requests
  - Test: Validate challenge format compliance

### 1.2 Data Protection Requirements

#### Credential Storage Security
- **REQ-SEC-007**: Server MUST encrypt credential data at rest
  - Test: Verify database encryption implementation
  - Test: Test key management procedures
  - Test: Validate credential data confidentiality

- **REQ-SEC-008**: Server MUST implement secure credential deletion
  - Test: Verify complete credential removal
  - Test: Test audit trail for credential operations
  - Test: Validate secure memory clearing

#### Privacy Requirements
- **REQ-SEC-009**: Server MUST minimize data collection
  - Test: Verify only required data is stored
  - Test: Test data retention policies
  - Test: Validate user consent mechanisms

## 2. Technical Scope

### 2.1 Core WebAuthn Operations

#### Registration (Attestation) Flow
**Success Conditions:**
- User authentication successful
- Valid attestation statement received
- Credential properly stored and bound to user
- Response format matches FIDO2 specification

**Failure Conditions:**
- Invalid attestation format
- Malformed credential data
- Duplicate credential ID
- Unsupported attestation type
- Challenge mismatch or expiration
- Cryptographic validation failure

**Test Scenarios:**
- Valid registration with supported attestation formats
- Registration with unsupported algorithms (should fail)
- Registration with expired challenges (should fail)
- Registration with malformed client data (should fail)
- Concurrent registration attempts (race condition testing)

#### Authentication (Assertion) Flow
**Success Conditions:**
- Valid assertion signature
- Correct credential ID and user mapping
- Challenge verification successful
- User authentication completed

**Failure Conditions:**
- Invalid signature
- Unknown credential ID
- Challenge mismatch
- Counter manipulation detected
- User verification failure

**Test Scenarios:**
- Valid authentication with user verification
- Authentication without user verification (when allowed)
- Authentication with invalid signatures
- Authentication with replayed assertions
- Authentication with revoked credentials

### 2.2 Edge Cases and Error Handling

#### Network and Timing Issues
- Timeout handling for long-running operations
- Partial request handling
- Concurrent request management
- Rate limiting implementation

#### Data Validation Edge Cases
- Maximum credential limits per user
- Large payload handling
- Unicode and internationalization support
- Malformed JSON handling

## 3. Rust Architecture

### 3.1 Project Structure

```
src/
├── lib.rs                    # Library entry point
├── main.rs                   # Binary entry point
├── config/                   # Configuration management
│   ├── mod.rs
│   ├── database.rs           # Database configuration
│   ├── webauthn.rs           # WebAuthn configuration
│   └── security.rs           # Security settings
├── controllers/              # HTTP request handlers
│   ├── mod.rs
│   ├── registration.rs       # Registration endpoints
│   ├── authentication.rs     # Authentication endpoints
│   ├── user.rs              # User management endpoints
│   └── health.rs            # Health check endpoints
├── services/                 # Business logic layer
│   ├── mod.rs
│   ├── webauthn_service.rs   # Core WebAuthn operations
│   ├── user_service.rs       # User management
│   ├── credential_service.rs # Credential operations
│   └── security_service.rs   # Security utilities
├── db/                       # Database layer
│   ├── mod.rs
│   ├── connection.rs         # Database connection management
│   ├── models/               # Diesel models
│   │   ├── mod.rs
│   │   ├── user.rs
│   │   ├── credential.rs
│   │   └── challenge.rs
│   └── repositories/         # Data access layer
│       ├── mod.rs
│       ├── user_repository.rs
│       ├── credential_repository.rs
│       └── challenge_repository.rs
├── middleware/               # HTTP middleware
│   ├── mod.rs
│   ├── auth.rs              # Authentication middleware
│   ├── cors.rs              # CORS handling
│   ├── rate_limit.rs        # Rate limiting
│   └── security.rs          # Security headers
├── routes/                   # Route definitions
│   ├── mod.rs
│   ├── webauthn.rs          # WebAuthn routes
│   ├── user.rs              # User routes
│   └── admin.rs             # Admin routes
├── error/                    # Error handling
│   ├── mod.rs
│   ├── app_error.rs         # Application error types
│   └── webauthn_error.rs    # WebAuthn-specific errors
├── utils/                    # Utility functions
│   ├── mod.rs
│   ├── crypto.rs            # Cryptographic utilities
│   ├── validation.rs        # Input validation
│   └── time.rs              # Time utilities
└── schema/                   # Diesel schema files
    ├── mod.rs
    ├── users.rs
    ├── credentials.rs
    └── challenges.rs
```

### 3.2 Testing Architecture

#### Unit Tests (95%+ Coverage Target)
- Service layer business logic tests
- Repository layer data access tests
- Utility function tests
- Error handling tests

#### Integration Tests
- API endpoint contract tests
- Database integration tests
- WebAuthn flow end-to-end tests
- Security boundary tests

#### Security Tests
- FIDO2 compliance tests
- Cryptographic validation tests
- Attack simulation tests
- Performance security tests

## 4. API Design

### 4.1 REST Endpoints Specification

#### Registration Endpoints

**POST /webauthn/register/begin**
```json
Request:
{
  "username": "user@example.com",
  "displayName": "User Name",
  "userVerification": "required|preferred|discouraged",
  "attestation": "none|indirect|direct|enterprise"
}

Response (200):
{
  "status": "ok",
  "challenge": "base64url-encoded-challenge",
  "user": {
    "id": "base64url-encoded-user-id",
    "name": "user@example.com",
    "displayName": "User Name"
  },
  "rp": {
    "id": "example.com",
    "name": "Example Application"
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
    "authenticatorAttachment": "platform|cross-platform",
    "userVerification": "required",
    "residentKey": "required|preferred|discouraged"
  },
  "attestation": "direct"
}

Error Responses:
400: Invalid request format
401: User not authenticated
429: Rate limit exceeded
500: Internal server error
```

**POST /webauthn/register/finish**
```json
Request:
{
  "credential": {
    "id": "base64url-encoded-credential-id",
    "rawId": "base64url-encoded-raw-id",
    "type": "public-key",
    "response": {
      "attestationObject": "base64url-encoded-attestation",
      "clientDataJSON": "base64url-encoded-client-data"
    }
  },
  "user": {
    "id": "base64url-encoded-user-id",
    "name": "user@example.com"
  }
}

Response (200):
{
  "status": "ok",
  "credentialId": "base64url-encoded-credential-id",
  "user": {
    "id": "base64url-encoded-user-id",
    "name": "user@example.com"
  }
}

Error Responses:
400: Invalid credential format
401: Invalid attestation
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
      "transports": ["usb", "nfc", "ble", "internal"]
    }
  ],
  "userVerification": "required",
  "timeout": 60000
}

Error Responses:
400: Invalid request format
404: User not found
429: Rate limit exceeded
500: Internal server error
```

**POST /webauthn/authenticate/finish**
```json
Request:
{
  "credential": {
    "id": "base64url-encoded-credential-id",
    "rawId": "base64url-encoded-raw-id",
    "type": "public-key",
    "response": {
      "authenticatorData": "base64url-encoded-auth-data",
      "clientDataJSON": "base64url-encoded-client-data",
      "signature": "base64url-encoded-signature",
      "userHandle": "base64url-encoded-user-handle"
    }
  }
}

Response (200):
{
  "status": "ok",
  "user": {
    "id": "base64url-encoded-user-id",
    "name": "user@example.com"
  },
  "credentialId": "base64url-encoded-credential-id",
  "signCount": 123
}

Error Responses:
400: Invalid assertion format
401: Invalid signature
403: Credential revoked
422: Unprocessable entity
500: Internal server error
```

### 4.2 Data Flow Specifications

#### Registration Flow
1. Client requests registration challenge
2. Server generates unique challenge (128-bit random)
3. Server stores challenge with expiration timestamp
4. Server returns WebAuthn options to client
5. Client creates credential with authenticator
6. Client sends attestation response
7. Server validates challenge and attestation
8. Server stores credential bound to user
9. Server returns success response

#### Authentication Flow
1. Client requests authentication challenge
2. Server retrieves user credentials
3. Server generates unique challenge
4. Server stores challenge with expiration
5. Server returns WebAuthn options to client
6. Client authenticates with authenticator
7. Client sends assertion response
8. Server validates challenge and signature
9. Server updates credential counter
10. Server returns authentication success

## 5. Storage Requirements

### 5.1 Database Schema

#### Users Table
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
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
    credential_public_key BYTEA NOT NULL,
    attestation_type VARCHAR(50) NOT NULL,
    aaguid BYTEA,
    sign_count BIGINT NOT NULL DEFAULT 0,
    transports JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used TIMESTAMP WITH TIME ZONE,
    is_backup_eligible BOOLEAN DEFAULT false,
    is_backed_up BOOLEAN DEFAULT false,
    user_verification BOOLEAN DEFAULT false,
    is_active BOOLEAN DEFAULT true
);
```

#### Challenges Table
```sql
CREATE TABLE challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    challenge_id BYTEA UNIQUE NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    challenge_type VARCHAR(20) NOT NULL, -- 'registration' or 'authentication'
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_used BOOLEAN DEFAULT false
);
```

### 5.2 Data Validation Requirements

#### Input Validation
- Username: 3-255 characters, email format or alphanumeric
- Display Name: 1-255 characters, Unicode support
- Credential ID: Base64URL encoded, max 1024 bytes
- Challenge: Base64URL encoded, exactly 16 bytes decoded
- Timestamps: ISO 8601 format, UTC timezone

#### Data Integrity
- Foreign key constraints enforcement
- Unique constraint on credential IDs
- Check constraints for sign_count (non-negative)
- Transaction isolation for concurrent operations

#### Security Validation
- Credential ID uniqueness across all users
- Challenge expiration enforcement (5 minutes default)
- Rate limiting per user and IP address
- Input sanitization against injection attacks

## 6. Compliance Checklist

### 6.1 FIDO2 Specification Compliance Points

#### WebAuthn API Compliance
- [ ] All required endpoints implemented
- [ ] Correct HTTP status codes
- [ ] Proper JSON response formats
- [ ] Error handling per specification
- [ ] CORS headers properly configured

#### Cryptographic Compliance
- [ ] Supported algorithms: ES256, RS256, EdDSA
- [ ] Proper signature validation
- [ ] Secure random number generation
- [ ] Key parameter validation
- [ ] Attestation statement verification

#### Security Compliance
- [ ] TLS 1.2+ enforcement
- [ ] Challenge uniqueness and expiration
- [ ] Replay attack prevention
- [ ] Rate limiting implementation
- [ ] Secure credential storage

#### Privacy Compliance
- [ ] Data minimization principles
- [ ] User consent mechanisms
- [ ] Data retention policies
- [ ] Secure data deletion
- [ ] Privacy policy compliance

### 6.2 Testable Compliance Points

#### Functional Tests
- Registration flow with all attestation formats
- Authentication flow with user verification variations
- Error handling for all failure scenarios
- Edge cases and boundary conditions

#### Security Tests
- Cryptographic validation tests
- Attack simulation (replay, tampering, injection)
- Access control tests
- Data protection verification

#### Performance Tests
- Concurrent user authentication
- Large credential database handling
- Memory usage optimization
- Response time requirements

#### Interoperability Tests
- Multiple authenticator types
- Different browser implementations
- Mobile platform compatibility
- Cross-platform testing

## 7. Risk Assessment

### 7.1 Security Risks and Mitigations

#### High Risk: Credential Compromise
**Risk**: Stolen credentials allow unauthorized access
**Mitigation**:
- Implement hardware-backed authenticator requirements
- Enforce user verification for sensitive operations
- Monitor for anomalous authentication patterns
- Implement credential revocation mechanisms

**Testing**:
- Simulate credential theft scenarios
- Test revocation flow effectiveness
- Verify anomaly detection accuracy

#### High Risk: Replay Attacks
**Risk**: Replayed authentication attempts
**Mitigation**:
- Unique challenge per authentication attempt
- Challenge expiration (5 minutes maximum)
- Cryptographic binding to origin
- Timestamp validation

**Testing**:
- Replay captured authentication attempts
- Test challenge uniqueness enforcement
- Verify expiration handling

#### Medium Risk: Database Compromise
**Risk**: Credential data exposure
**Mitigation**:
- Encrypt sensitive data at rest
- Implement database access controls
- Regular security audits
- Backup encryption

**Testing**:
- Database access control tests
- Encryption verification tests
- Backup security validation

#### Medium Risk: Denial of Service
**Risk**: Service availability impact
**Mitigation**:
- Rate limiting per user/IP
- Request size limitations
- Resource usage monitoring
- Load balancing

**Testing**:
- Load testing with high concurrency
- Rate limiting effectiveness tests
- Resource exhaustion scenarios

### 7.2 Implementation Risks

#### Medium Risk: WebAuthn Library Compatibility
**Risk**: webauthn-rs version compatibility issues
**Mitigation**:
- Pin dependency versions
- Regular security updates
- Compatibility testing matrix
- Fallback mechanisms

**Testing**:
- Library version compatibility tests
- API contract maintenance tests
- Regression testing suite

#### Low Risk: Performance Bottlenecks
**Risk**: Slow response times under load
**Mitigation**:
- Database query optimization
- Caching strategies
- Connection pooling
- Performance monitoring

**Testing**:
- Load testing with realistic scenarios
- Database performance profiling
- Memory usage analysis

### 7.3 Compliance Risks

#### Medium Risk: FIDO2 Specification Changes
**Risk**: Non-compliance with updated specifications
**Mitigation**:
- Regular specification review
- Automated compliance testing
- Version compatibility matrix
- Update deployment procedures

**Testing**:
- Specification compliance test suite
- Version compatibility verification
- Regression testing for updates

## 8. Implementation Roadmap

### Phase 1: Core Infrastructure (Weeks 1-2)
- Database schema implementation
- Basic WebAuthn service setup
- Configuration management
- Error handling framework

### Phase 2: Registration Flow (Weeks 3-4)
- Registration endpoints implementation
- Attestation validation
- Credential storage
- Unit and integration tests

### Phase 3: Authentication Flow (Weeks 5-6)
- Authentication endpoints implementation
- Assertion validation
- User session management
- Security testing

### Phase 4: Security Hardening (Weeks 7-8)
- Rate limiting implementation
- Security headers configuration
- Attack surface analysis
- Penetration testing

### Phase 5: Compliance Testing (Weeks 9-10)
- FIDO2 compliance test suite
- Interoperability testing
- Performance optimization
- Documentation completion

## 9. Success Metrics

### Technical Metrics
- 95%+ unit test coverage
- 100% API endpoint test coverage
- <100ms average response time
- 99.9% uptime availability
- Zero critical security vulnerabilities

### Compliance Metrics
- 100% FIDO2 specification compliance
- Successful interoperability testing
- Complete security audit clearance
- Full documentation coverage

### Performance Metrics
- Support for 1000+ concurrent users
- <500MB memory usage under load
- <1 second credential lookup time
- 99th percentile response time <200ms

This specification provides a comprehensive foundation for implementing a secure, compliant, and thoroughly tested FIDO2/WebAuthn Relying Party Server in Rust.