# FIDO2/WebAuthn Relying Party Server - Technical Specification

## Executive Summary

This document provides a comprehensive technical specification for implementing a FIDO2/WebAuthn Relying Party Server in Rust using the webauthn-rs library. The specification focuses on security-first design, FIDO Alliance compliance, and comprehensive test-driven development.

## 1. Security Requirements

### 1.1 FIDO Alliance Compliance Requirements

#### Core Security Requirements (Testable Criteria)
- **SR-001**: Server MUST validate attestation statements according to FIDO2 specification
- **SR-002**: Server MUST implement proper user verification (UV) flag handling
- **SR-003**: Server MUST enforce RP ID validation for all operations
- **SR-004**: Server MUST implement secure challenge generation with minimum 16 bytes entropy
- **SR-005**: Server MUST prevent credential cloning through proper credential ID binding
- **SR-006**: Server MUST implement timeout enforcement for all ceremonies (≤ 5 minutes)
- **SR-007**: Server MUST validate origin against configured allowed origins
- **SR-008**: Server MUST implement proper signature verification for all algorithms

#### Cryptographic Requirements
- **CR-001**: Support for ES256, RS256, EdDSA algorithms
- **CR-002**: Minimum 2048-bit RSA keys, 256-bit EC keys
- **CR-003**: Secure random number generation using OS CSPRNG
- **CR-004**: Proper hash algorithm validation (SHA-256 minimum)

#### Transport Security
- **TS-001**: TLS 1.2+ enforcement for all endpoints
- **TS-002**: HSTS header implementation
- **TS-003**: CORS policy enforcement
- **TS-004**: Rate limiting implementation (100 requests/minute per IP)

### 1.2 Data Protection Requirements

#### Credential Storage Security
- **DS-001**: Credential private keys MUST be stored encrypted at rest
- **DS-002**: User credential mapping MUST be isolated per user
- **DS-003**: Credential metadata MUST include creation timestamp and last used timestamp
- **DS-004**: Implement credential backup and recovery mechanisms

#### Session Management
- **SM-001**: Challenge MUST be single-use and expire after 5 minutes
- **SM-002**: Session tokens MUST be cryptographically signed
- **SM-003**: Implement proper session invalidation on logout

## 2. Technical Scope

### 2.1 Core WebAuthn Operations

#### Registration (Attestation) Flow
**Success Conditions:**
- Valid attestation statement verification
- Proper user verification (if required)
- Credential storage successful
- Response includes registration completion status

**Failure Conditions:**
- Invalid attestation format
- Mismatching RP ID
- Expired challenge
- Duplicate credential ID
- Invalid user verification

**Test Scenarios:**
```rust
// Test Case: REG-001 - Successful Registration
#[test]
fn test_successful_registration() {
    // Arrange: Valid attestation object
    // Act: Process registration
    // Assert: Credential stored, success response
}

// Test Case: REG-002 - Invalid RP ID
#[test]
fn test_invalid_rp_id() {
    // Arrange: Attestation with wrong RP ID
    // Act: Process registration
    // Assert: Registration rejected with proper error
}
```

#### Authentication (Assertion) Flow
**Success Conditions:**
- Valid assertion signature verification
- Matching credential ID found
- Proper user verification (if required)
- Authentication counter updated

**Failure Conditions:**
- Invalid signature
- Unknown credential ID
- Expired challenge
- Counter replay attack detected
- Invalid user verification

**Test Scenarios:**
```rust
// Test Case: AUTH-001 - Successful Authentication
#[test]
fn test_successful_authentication() {
    // Arrange: Valid assertion object
    // Act: Process authentication
    // Assert: Authentication successful, counter updated
}

// Test Case: AUTH-002 - Replay Attack Prevention
#[test]
fn test_replay_attack_prevention() {
    // Arrange: Reused assertion signature
    // Act: Process authentication
    // Assert: Authentication rejected
}
```

### 2.2 Edge Cases and Error Handling

#### Network and Timeout Scenarios
- Network interruption during ceremony
- Challenge expiration handling
- Concurrent registration attempts
- Database connection failures

#### Malicious Input Handling
- Oversized attestation objects (> 1MB)
- Invalid JSON structures
- SQL injection attempts
- XSS prevention in error messages

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
│   ├── registration.rs      # Registration controller
│   ├── authentication.rs    # Authentication controller
│   └── user.rs              # User management controller
├── services/
│   ├── mod.rs               # Service module
│   ├── webauthn.rs          # WebAuthn service
│   ├── credential.rs        # Credential management
│   └── user.rs              # User service
├── db/
│   ├── mod.rs               # Database module
│   ├── connection.rs        # Connection pool
│   ├── models.rs            # Database models
│   └── repositories.rs      # Repository pattern
├── middleware/
│   ├── mod.rs               # Middleware module
│   ├── auth.rs              # Authentication middleware
│   ├── cors.rs              # CORS middleware
│   └── rate_limit.rs        # Rate limiting
├── routes/
│   ├── mod.rs               # Route definitions
│   ├── webauthn.rs          # WebAuthn routes
│   └── api.rs               # API routes
├── error/
│   ├── mod.rs               # Error handling
│   └── types.rs             # Error types
├── utils/
│   ├── mod.rs               # Utilities
│   ├── crypto.rs            # Cryptographic utilities
│   └── validation.rs        # Input validation
└── schema/                  # Diesel schema files
    └── migrations/          # Database migrations
```

### 3.2 Testing Architecture

#### Unit Tests (95%+ Coverage Target)
```rust
// src/services/webauthn.rs
#[cfg(test)]
mod tests {
    use super::*;
    use mockall::predicate::*;
    
    #[test]
    fn test_challenge_generation() {
        // Test challenge generation entropy and length
    }
    
    #[test]
    fn test_attestation_verification() {
        // Test various attestation formats
    }
}
```

#### Integration Tests
```rust
// tests/integration/registration_tests.rs
#[actix_rt::test]
async fn test_registration_flow() {
    // End-to-end registration test
}

#[actix_rt::test]
async fn test_authentication_flow() {
    // End-to-end authentication test
}
```

#### Security Tests
```rust
// tests/security/compliance_tests.rs
#[actix_rt::test]
async fn test_fido2_compliance() {
    // FIDO2 specification compliance tests
}

#[actix_rt::test]
async fn test_attack_vectors() {
    // Security attack vector tests
}
```

## 4. API Design

### 4.1 REST Endpoints

#### Registration Endpoints

**POST /webauthn/register/challenge**
```json
// Request
{
  "username": "user@example.com",
  "displayName": "User Display Name",
  "userVerification": "required"
}

// Response
{
  "status": "ok",
  "challenge": "base64url-challenge",
  "rp": {
    "name": "FIDO Server",
    "id": "example.com"
  },
  "user": {
    "id": "base64url-user-id",
    "name": "user@example.com",
    "displayName": "User Display Name"
  },
  "pubKeyCredParams": [
    {
      "type": "public-key",
      "alg": -7
    }
  ],
  "timeout": 300000,
  "attestation": "direct"
}
```

**POST /webauthn/register/verify**
```json
// Request
{
  "credential": "base64url-attestation-object",
  "clientDataJSON": "base64url-client-data",
  "challenge": "base64url-challenge"
}

// Response
{
  "status": "ok",
  "credentialId": "base64url-credential-id",
  "counter": 0
}
```

#### Authentication Endpoints

**POST /webauthn/authenticate/challenge**
```json
// Request
{
  "username": "user@example.com",
  "userVerification": "required"
}

// Response
{
  "status": "ok",
  "challenge": "base64url-challenge",
  "allowCredentials": [
    {
      "type": "public-key",
      "id": "base64url-credential-id"
    }
  ],
  "userVerification": "required",
  "timeout": 300000
}
```

**POST /webauthn/authenticate/verify**
```json
// Request
{
  "credentialId": "base64url-credential-id",
  "authenticatorData": "base64url-auth-data",
  "clientDataJSON": "base64url-client-data",
  "signature": "base64url-signature",
  "userHandle": "base64url-user-handle",
  "challenge": "base64url-challenge"
}

// Response
{
  "status": "ok",
  "counter": 42
}
```

### 4.2 Error Response Format

```json
{
  "status": "error",
  "error": {
    "code": "INVALID_ATTESTATION",
    "message": "Invalid attestation format",
    "details": "Attestation statement could not be verified"
  }
}
```

### 4.3 Data Flow Specifications

#### Registration Flow
1. Client requests challenge
2. Server generates cryptographically secure challenge
3. Server stores challenge with expiration
4. Client creates credential with attestation
5. Client sends attestation to server
6. Server validates attestation and challenge
7. Server stores credential if valid
8. Server returns success/failure status

#### Authentication Flow
1. Client requests challenge
2. Server retrieves user credentials
3. Server generates challenge
4. Client creates assertion
5. Client sends assertion to server
6. Server validates assertion and challenge
7. Server updates credential counter
8. Server returns authentication result

## 5. Storage Requirements

### 5.1 Database Schema

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
    attestation_type VARCHAR(50) NOT NULL,
    aaguid BYTEA NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    user_verification BOOLEAN NOT NULL DEFAULT false,
    backup_eligible BOOLEAN NOT NULL DEFAULT false,
    backup_state BOOLEAN NOT NULL DEFAULT false,
    transports TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

#### Challenges Table
```sql
CREATE TABLE challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    challenge BYTEA NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    challenge_type VARCHAR(20) NOT NULL, -- 'registration' or 'authentication'
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### 5.2 Data Validation Requirements

#### Input Validation
- Username: 3-255 characters, email format or alphanumeric
- Display Name: 1-255 characters, no control characters
- Challenge: Base64URL encoded, minimum 16 bytes when decoded
- Credential ID: Base64URL encoded, maximum 1023 bytes

#### Output Validation
- All responses must be valid JSON
- Base64URL encoding for all binary data
- Timestamps in ISO 8601 format
- Proper HTTP status codes

### 5.3 Security Considerations

#### Credential Storage
- Private keys never stored (only public keys)
- Credential IDs encrypted at rest
- Database connection encryption
- Regular credential cleanup for unused accounts

#### Data Integrity
- Foreign key constraints enforced
- Unique constraints on credential IDs
- Transaction isolation for concurrent operations
- Audit logging for all credential operations

## 6. Compliance Checklist

### 6.1 FIDO2 Specification Compliance Points

#### WebAuthn Level 2 Compliance
- [ ] RP ID validation (§5.1.2)
- [ ] Origin validation (§5.1.3)
- [ ] Challenge generation (§5.1.4)
- [ ] User verification handling (§5.1.5)
- [ ] Attestation statement verification (§5.2)
- [ ] Assertion verification (§5.3)
- [ ] Credential storage requirements (§6.1)
- [ ] Metadata statement support (§6.4)

#### Security Requirements
- [ ] TLS 1.2+ enforcement
- [ ] Secure random number generation
- [ ] Proper timeout handling
- [ ] Replay attack prevention
- [ ] Rate limiting implementation
- [ ] Input validation and sanitization

#### Privacy Requirements
- [ ] User consent mechanisms
- [ ] Data minimization principles
- [ ] Secure credential deletion
- [ ] Privacy-preserving attestation

### 6.2 Testable Compliance Points

#### Automated Tests
```rust
// tests/compliance/fido2_compliance.rs
#[actix_rt::test]
async fn test_rp_id_validation() {
    // Test RP ID validation against specification
}

#[actix_rt::test]
async fn test_origin_validation() {
    // Test origin validation requirements
}

#[actix_rt::test]
async fn test_challenge_security() {
    // Test challenge entropy and uniqueness
}
```

#### Manual Verification Points
- [ ] FIDO Alliance conformance testing tools
- [ ] Third-party security audit
- [ ] Penetration testing results
- [ ] Performance benchmarking

## 7. Risk Assessment

### 7.1 Security Risks and Mitigation

#### High Risk Items

**Replay Attacks**
- Risk: Reuse of valid assertions
- Mitigation: Challenge uniqueness, counter tracking, timeout enforcement
- Testing: Replay attack simulation tests

**Credential Cloning**
- Risk: Duplicate credential IDs across users
- Mitigation: Unique constraints, proper credential binding
- Testing: Credential duplication prevention tests

**Man-in-the-Middle Attacks**
- Risk: Interception of WebAuthn ceremonies
- Mitigation: TLS enforcement, origin validation
- Testing: TLS certificate validation tests

#### Medium Risk Items

**Denial of Service**
- Risk: Resource exhaustion through repeated requests
- Mitigation: Rate limiting, request size limits
- Testing: Load testing and rate limit validation

**Database Compromise**
- Risk: Credential data exposure
- Mitigation: Encryption at rest, access controls
- Testing: Database security audit

#### Low Risk Items

**Information Disclosure**
- Risk: Error messages revealing sensitive information
- Mitigation: Generic error messages, proper logging
- Testing: Information disclosure tests

### 7.2 Operational Risks

#### Performance Risks
- Risk: High latency under load
- Mitigation: Connection pooling, caching, horizontal scaling
- Testing: Performance benchmarking

#### Availability Risks
- Risk: Service downtime
- Mitigation: Health checks, graceful degradation
- Testing: Failover testing

### 7.3 Compliance Risks

#### Specification Drift
- Risk: FIDO2 specification updates
- Mitigation: Regular specification review, automated compliance tests
- Testing: Specification change impact analysis

#### Certification Requirements
- Risk: FIDO Alliance certification failure
- Mitigation: Early conformance testing, third-party audit
- Testing: Conformance test suite execution

## 8. Implementation Roadmap

### Phase 1: Core Infrastructure (Weeks 1-2)
- [ ] Project structure setup
- [ ] Database schema and migrations
- [ ] Basic WebAuthn service implementation
- [ ] Unit test framework setup

### Phase 2: Registration Flow (Weeks 3-4)
- [ ] Registration challenge endpoint
- [ ] Registration verification endpoint
- [ ] Attestation statement validation
- [ ] Integration tests for registration

### Phase 3: Authentication Flow (Weeks 5-6)
- [ ] Authentication challenge endpoint
- [ ] Authentication verification endpoint
- [ ] Assertion validation
- [ ] Integration tests for authentication

### Phase 4: Security Hardening (Weeks 7-8)
- [ ] Rate limiting implementation
- [ ] CORS and security headers
- [ ] Input validation and sanitization
- [ ] Security test suite

### Phase 5: Compliance and Testing (Weeks 9-10)
- [ ] FIDO2 conformance testing
- [ ] Performance testing
- [ ] Security audit preparation
- [ ] Documentation completion

## 9. Success Metrics

### Technical Metrics
- Unit test coverage: ≥95%
- Integration test coverage: 100% of API endpoints
- Security test coverage: All identified attack vectors
- Performance: <100ms response time for 95% of requests
- Availability: 99.9% uptime

### Compliance Metrics
- FIDO2 specification compliance: 100%
- Security audit findings: 0 high/critical
- Conformance test suite: 100% pass rate

### Quality Metrics
- Code coverage: ≥95%
- Documentation coverage: 100% of public APIs
- Performance benchmarks: Meet or exceed targets
- Security scan results: 0 vulnerabilities

This specification provides a comprehensive foundation for implementing a secure, compliant FIDO2/WebAuthn Relying Party Server with extensive testing coverage and security-first design principles.