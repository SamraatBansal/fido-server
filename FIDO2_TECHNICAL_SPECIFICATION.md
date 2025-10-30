# FIDO2/WebAuthn Relying Party Server Technical Specification

## Executive Summary

This document provides a comprehensive technical specification for implementing a FIDO2/WebAuthn conformant Relying Party Server in Rust using the webauthn-rs library. The specification focuses on security-first design, FIDO Alliance compliance, and comprehensive test-driven development.

## 1. Security Requirements

### 1.1 FIDO Alliance Compliance Requirements

#### Core Security Requirements (Testable Criteria)

| Requirement | Test Criteria | Security Level |
|-------------|---------------|----------------|
| **RP ID Validation** | Must validate RP ID against origin, prevent cross-origin attacks | Critical |
| **Challenge Uniqueness** | Each challenge must be cryptographically random and single-use | Critical |
| **Origin Validation** | Must validate request origin against configured allowed origins | Critical |
| **Timeout Enforcement** | Registration/authentication must enforce configurable timeouts | High |
| **Credential Binding** | Credentials must be bound to specific user accounts | Critical |
| **Replay Attack Prevention** | Challenges must be invalidated after use or expiration | Critical |
| **Attestation Verification** | Must verify attestation statements when required | High |
| **User Verification** | Must enforce user verification levels as configured | High |

#### Cryptographic Requirements

| Algorithm | Support Required | Test Validation |
|-----------|------------------|-----------------|
| ES256 (P-256) | Required | Verify signature validation |
| ES384 (P-384) | Required | Verify signature validation |
| ES512 (P-521) | Optional | Verify signature validation |
| RS256 (RSA-2048) | Required | Verify signature validation |
| EdDSA (Ed25519) | Optional | Verify signature validation |

### 1.2 Security Test Scenarios

#### Registration Security Tests
```rust
// Test Cases to Implement:
1. Invalid RP ID rejection
2. Challenge reuse prevention
3. Origin validation bypass attempts
4. Malformed attestation statement handling
5. Unsupported algorithm rejection
6. Timeout enforcement
7. User verification enforcement
8. Credential binding validation
```

#### Authentication Security Tests
```rust
// Test Cases to Implement:
1. Invalid credential ID handling
2. Challenge reuse prevention
3. Origin validation bypass attempts
4. Malformed assertion statement handling
5. Counter validation (cloning detection)
6. User verification enforcement
7. Timeout enforcement
8. Revoked credential rejection
```

## 2. Technical Scope

### 2.1 Core WebAuthn Operations

#### Registration (Attestation) Flow

**Success Conditions:**
- Valid challenge-response cycle
- Proper RP ID and origin validation
- Successful attestation verification
- Secure credential storage
- User-credential binding established

**Failure Conditions:**
- Invalid or expired challenge
- Mismatched RP ID or origin
- Unsupported attestation format
- Cryptographic validation failures
- Storage failures
- User verification failures

#### Authentication (Assertion) Flow

**Success Conditions:**
- Valid challenge-response cycle
- Proper credential authentication
- Counter validation (no cloning)
- User verification success
- Session establishment

**Failure Conditions:**
- Invalid or expired challenge
- Unknown credential ID
- Cryptographic signature failures
- Counter rollback detection
- User verification failures
- Revoked credentials

### 2.2 Edge Case Testing Requirements

#### Network and Timing Edge Cases
- Network timeouts during registration/authentication
- Concurrent registration attempts for same user
- Challenge expiration edge cases
- High-load scenarios with concurrent users

#### Data Validation Edge Cases
- Malformed JSON payloads
- Oversized credential data
- Invalid base64 encoding
- Unicode handling in user data
- SQL injection attempts

## 3. Rust Architecture

### 3.1 Project Structure

```
src/
├── lib.rs                    # Library entry point
├── main.rs                   # Binary entry point
├── config/                   # Configuration management
│   ├── mod.rs
│   ├── webauthn.rs          # WebAuthn configuration
│   └── database.rs          # Database configuration
├── controllers/              # HTTP request handlers
│   ├── mod.rs
│   ├── registration.rs      # Registration endpoints
│   ├── authentication.rs    # Authentication endpoints
│   └── health.rs            # Health check endpoints
├── services/                 # Business logic layer
│   ├── mod.rs
│   ├── webauthn_service.rs  # Core WebAuthn operations
│   ├── user_service.rs      # User management
│   └── credential_service.rs # Credential management
├── db/                       # Database layer
│   ├── mod.rs
│   ├── connection.rs        # Database connection management
│   ├── models.rs            # Database models
│   └── repositories.rs      # Data access layer
├── middleware/               # HTTP middleware
│   ├── mod.rs
│   ├── auth.rs              # Authentication middleware
│   ├── cors.rs              # CORS handling
│   └── rate_limit.rs        # Rate limiting
├── routes/                   # Route definitions
│   ├── mod.rs
│   └── webauthn.rs          # WebAuthn routes
├── error/                    # Error handling
│   ├── mod.rs
│   └── types.rs             # Error types
├── utils/                    # Utilities
│   ├── mod.rs
│   ├── crypto.rs            # Cryptographic utilities
│   └── validation.rs        # Input validation
└── schema/                   # Database schema
    ├── mod.rs
    └── migrations/          # Database migrations
```

### 3.2 Testing Architecture

```
tests/
├── common/                   # Test utilities and fixtures
│   ├── mod.rs
│   ├── fixtures.rs          # Test data fixtures
│   ├── mock_server.rs       # Mock server for testing
│   └── test_utils.rs        # Common test utilities
├── unit/                     # Unit tests
│   ├── services/            # Service layer tests
│   ├── controllers/         # Controller tests
│   └── utils/               # Utility tests
├── integration/              # Integration tests
│   ├── api_tests.rs         # API endpoint tests
│   ├── webauthn_flow.rs     # End-to-end WebAuthn tests
│   └── security_tests.rs    # Security-focused tests
├── compliance/               # FIDO compliance tests
│   ├── registration_tests.rs
│   ├── authentication_tests.rs
│   └── attestation_tests.rs
└── performance/              # Performance tests
    ├── load_tests.rs        # Load testing
    └── concurrent_tests.rs  # Concurrency testing
```

## 4. API Design

### 4.1 REST Endpoints Specification

Based on FIDO Alliance Conformance Test API specification:

#### Registration Endpoints

**POST /attestation/options**
```json
Request:
{
  "username": "user@example.com",
  "displayName": "User Display Name",
  "attestation": "direct",
  "authenticatorSelection": {
    "authenticatorAttachment": "platform",
    "requireResidentKey": false,
    "userVerification": "required"
  }
}

Response:
{
  "status": "ok",
  "errorMessage": "",
  "challenge": "base64url-encoded-challenge",
  "rp": {
    "name": "FIDO Server",
    "id": "example.com"
  },
  "user": {
    "id": "base64url-encoded-user-id",
    "name": "user@example.com",
    "displayName": "User Display Name"
  },
  "pubKeyCredParams": [
    {
      "type": "public-key",
      "alg": -7
    }
  ],
  "timeout": 60000,
  "attestation": "direct",
  "authenticatorSelection": {
    "authenticatorAttachment": "platform",
    "requireResidentKey": false,
    "userVerification": "required"
  }
}
```

**POST /attestation/result**
```json
Request:
{
  "credentialId": "base64url-encoded-credential-id",
  "clientDataJSON": "base64url-encoded-client-data",
  "attestationObject": "base64url-encoded-attestation-object"
}

Response:
{
  "status": "ok",
  "errorMessage": "",
  "credentialId": "base64url-encoded-credential-id",
  "newIdentity": {
    "username": "user@example.com",
    "displayName": "User Display Name"
  }
}
```

#### Authentication Endpoints

**POST /assertion/options**
```json
Request:
{
  "username": "user@example.com",
  "userVerification": "required"
}

Response:
{
  "status": "ok",
  "errorMessage": "",
  "challenge": "base64url-encoded-challenge",
  "rpId": "example.com",
  "allowCredentials": [
    {
      "type": "public-key",
      "id": "base64url-encoded-credential-id",
      "transports": ["internal", "usb"]
    }
  ],
  "userVerification": "required",
  "timeout": 60000
}
```

**POST /assertion/result**
```json
Request:
{
  "credentialId": "base64url-encoded-credential-id",
  "clientDataJSON": "base64url-encoded-client-data",
  "authenticatorData": "base64url-encoded-authenticator-data",
  "signature": "base64url-encoded-signature",
  "userHandle": "base64url-encoded-user-handle"
}

Response:
{
  "status": "ok",
  "errorMessage": "",
  "newIdentity": {
    "username": "user@example.com",
    "displayName": "User Display Name"
  }
}
```

### 4.2 Data Flow Specifications

#### Registration Flow
1. Client requests attestation options
2. Server generates cryptographically random challenge
3. Server returns credential creation options
4. Client creates credential with authenticator
5. Client submits attestation result
6. Server validates attestation and stores credential

#### Authentication Flow
1. Client requests assertion options
2. Server generates cryptographically random challenge
3. Server returns credential request options
4. Client authenticates with authenticator
5. Client submits assertion result
6. Server validates assertion and establishes session

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
    aaguid UUID NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true,
    user_verification_policy VARCHAR(20) NOT NULL DEFAULT 'required'
);
```

#### Challenges Table
```sql
CREATE TABLE challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    challenge_base64 VARCHAR(255) UNIQUE NOT NULL,
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
- Display Name: 1-255 characters, no control characters
- Credential ID: Base64URL encoded, max 1024 bytes
- Challenge: Base64URL encoded, exactly 32 bytes when decoded
- Timestamps: ISO 8601 format, within reasonable ranges

#### Storage Validation
- All binary data stored as BYTEA with size limits
- Sensitive data encrypted at rest
- Audit logging for all credential operations
- Regular cleanup of expired challenges

## 6. Compliance Checklist

### 6.1 FIDO2 Specification Compliance Points

#### Core Specification Compliance
- [ ] RP ID validation per §5.1.1
- [ ] Origin validation per §5.1.2
- [ ] Challenge generation per §5.1.3
- [ ] Credential storage per §5.1.4
- [ ] User verification per §5.1.5
- [ ] Attestation verification per §5.1.6

#### WebAuthn API Compliance
- [ ] navigator.credentials.create() support
- [ ] navigator.credentials.get() support
- [ ] PublicKeyCredential interface
- [ ] AuthenticatorAttestationResponse
- [ ] AuthenticatorAssertionResponse

#### Security Compliance
- [ ] TLS 1.2+ enforcement
- [ ] Secure challenge generation
- [ ] Replay attack prevention
- [ ] Credential cloning detection
- [ ] Rate limiting implementation

### 6.2 Testable Compliance Points

#### Registration Compliance Tests
```rust
#[cfg(test)]
mod compliance_tests {
    // Test RP ID validation
    #[test]
    fn test_rp_id_validation() {
        // Verify RP ID matches origin
        // Reject invalid RP IDs
        // Test subdomain handling
    }
    
    // Test challenge requirements
    #[test]
    fn test_challenge_requirements() {
        // Verify challenge is cryptographically random
        // Verify challenge is single-use
        // Verify challenge expiration
    }
    
    // Test attestation verification
    #[test]
    fn test_attestation_verification() {
        // Verify Packed attestation format
        // Verify FIDO-U2F attestation format
        // Verify None attestation format
        // Verify invalid attestation rejection
    }
}
```

#### Authentication Compliance Tests
```rust
#[cfg(test)]
mod authentication_compliance {
    // Test assertion verification
    #[test]
    fn test_assertion_verification() {
        // Verify signature validation
        // Verify authenticator data validation
        // Verify client data JSON validation
        // Verify counter validation
    }
    
    // Test user verification
    #[test]
    fn test_user_verification() {
        // Test required user verification
        // Test preferred user verification
        // Test discouraged user verification
    }
}
```

## 7. Risk Assessment

### 7.1 Security Considerations

#### High-Risk Vulnerabilities

| Vulnerability | Impact | Likelihood | Mitigation |
|---------------|--------|------------|------------|
| **Challenge Replay** | Account takeover | Medium | Single-use challenges, expiration |
| **RP ID Bypass** | Cross-origin attacks | Low | Strict origin validation |
| **Credential Cloning** | Unauthorized access | Low | Counter validation, monitoring |
| **Attestation Forgery** | Fake credentials | Low | Comprehensive attestation verification |
| **Database Compromise** | Credential theft | Medium | Encryption at rest, access controls |

#### Medium-Risk Vulnerabilities

| Vulnerability | Impact | Likelihood | Mitigation |
|---------------|--------|------------|------------|
| **Timing Attacks** | Information disclosure | Medium | Constant-time operations |
| **Side-Channel Attacks** | Key extraction | Low | Secure coding practices |
| **Denial of Service** | Service unavailability | High | Rate limiting, monitoring |
| **Information Leakage** | Privacy violation | Medium | Error message sanitization |

### 7.2 Mitigation Strategies

#### Preventive Measures
1. **Input Validation**: Comprehensive validation of all inputs
2. **Rate Limiting**: Prevent brute force and DoS attacks
3. **Monitoring**: Real-time security monitoring and alerting
4. **Encryption**: Encryption of sensitive data at rest and in transit
5. **Access Controls**: Principle of least privilege implementation

#### Detective Measures
1. **Audit Logging**: Comprehensive logging of all security events
2. **Anomaly Detection**: Machine learning-based anomaly detection
3. **Security Testing**: Regular penetration testing and code reviews
4. **Compliance Monitoring**: Continuous compliance verification

#### Corrective Measures
1. **Incident Response**: Established incident response procedures
2. **Credential Revocation**: Ability to revoke compromised credentials
3. **Backup and Recovery**: Secure backup and recovery procedures
4. **Patch Management**: Regular security patching

### 7.3 Security Testing Requirements

#### Static Analysis
- Rust security lints (clippy security rules)
- Dependency vulnerability scanning
- Code security review

#### Dynamic Analysis
- Penetration testing
- Fuzz testing of API endpoints
- Load testing under security conditions

#### Compliance Testing
- FIDO Alliance conformance testing
- OWASP security testing
- Regulatory compliance verification

## Implementation Priority

### Phase 1: Core Functionality (Weeks 1-4)
1. Basic WebAuthn registration and authentication
2. In-memory credential storage
3. Basic API endpoints
4. Unit test coverage >80%

### Phase 2: Security Hardening (Weeks 5-8)
1. Database integration with PostgreSQL
2. Comprehensive security testing
3. FIDO compliance verification
4. Integration test coverage >90%

### Phase 3: Production Readiness (Weeks 9-12)
1. Performance optimization
2. Monitoring and logging
3. Documentation completion
4. Full compliance testing

## Success Metrics

### Security Metrics
- Zero critical vulnerabilities in security testing
- 100% FIDO Alliance conformance test pass rate
- <100ms average response time for operations
- 99.9% uptime under normal load

### Testing Metrics
- 95%+ unit test coverage
- 90%+ integration test coverage
- 100% security test case pass rate
- Performance benchmarks met

This specification provides a comprehensive foundation for implementing a secure, FIDO2-compliant WebAuthn server with extensive testing coverage and security-first design principles.