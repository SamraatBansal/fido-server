# FIDO2/WebAuthn Relying Party Server - Technical Specification

## Executive Summary

This document provides a comprehensive technical specification for implementing a FIDO2/WebAuthn Relying Party Server in Rust using the webauthn-rs library. The specification focuses on security-first design, FIDO Alliance compliance, and comprehensive test-driven development.

## 1. Security Requirements

### 1.1 FIDO Alliance Compliance Requirements

#### Core Security Requirements (Testable Criteria)
- **SR-001**: Server MUST validate attestation statements according to FIDO2 specification
- **SR-002**: Server MUST implement proper credential binding to user accounts
- **SR-003**: Server MUST prevent credential replay attacks using challenge-response mechanism
- **SR-004**: Server MUST enforce RP ID validation for cross-origin protection
- **SR-005**: Server MUST implement secure random challenge generation (≥16 bytes)
- **SR-006**: Server MUST validate user verification requirements (UV flag)
- **SR-007**: Server MUST implement proper timeout handling for ceremonies
- **SR-008**: Server MUST validate credential parameters (alg, type, transports)

#### Cryptographic Requirements
- **CR-001**: Support for ES256, RS256, EdDSA algorithms
- **CR-002**: Proper signature verification for all supported algorithms
- **CR-003**: Secure random number generation using CSPRNG
- **CR-004**: Proper handling of attestation formats (packed, fido-u2f, none, etc.)

#### Transport Security
- **TS-001**: TLS 1.2+ enforcement for all endpoints
- **TS-002**: HSTS header implementation
- **TS-003**: CORS policy enforcement for WebAuthn API
- **TS-004**: Rate limiting for authentication attempts

### 1.2 Data Protection Requirements

#### Credential Storage Security
- **DS-001**: Credentials stored with encrypted private keys
- **DS-002**: User credential mapping with proper isolation
- **DS-003**: Audit logging for all credential operations
- **DS-004**: Secure credential deletion with proper cleanup

#### Session Management
- **SM-001**: Secure session token generation and validation
- **SM-002**: Proper session expiration handling
- **SM-003**: Session fixation prevention
- **SM-004**: Concurrent session management

## 2. Technical Scope

### 2.1 Core WebAuthn Operations

#### Registration (Attestation) Flow
**Success Conditions:**
- Valid attestation statement verification
- Proper credential binding to user
- Challenge consumption and validation
- User verification completion
- Credential storage success

**Failure Conditions:**
- Invalid attestation format
- Challenge mismatch or replay
- RP ID validation failure
- User verification failure
- Cryptographic verification failure
- Storage operation failure

**Test Scenarios:**
- Valid registration with different attestation formats
- Invalid attestation statement handling
- Challenge replay attempts
- RP ID mismatch scenarios
- User verification bypass attempts
- Concurrent registration attempts

#### Authentication (Assertion) Flow
**Success Conditions:**
- Valid assertion signature verification
- Credential existence and ownership validation
- Challenge consumption and validation
- User verification completion
- Authentication session establishment

**Failure Conditions:**
- Invalid assertion signature
- Non-existent credential
- Challenge mismatch or replay
- User verification failure
- Credential disabled/revoked
- Rate limit exceeded

**Test Scenarios:**
- Valid authentication with various algorithms
- Invalid signature handling
- Non-existent credential attempts
- Challenge replay protection
- User verification bypass
- Credential revocation scenarios

### 2.2 Edge Case Testing Requirements

#### Boundary Conditions
- Maximum credential count per user
- Challenge expiration edge cases
- Large payload handling
- Concurrent operation handling
- Network timeout scenarios

#### Error Handling
- Malformed request validation
- Invalid JSON handling
- Missing required fields
- Type validation errors
- Database connection failures

## 3. Rust Architecture

### 3.1 Project Structure

```
src/
├── lib.rs                    # Library entry point
├── main.rs                   # Application entry point
├── config/
│   ├── mod.rs               # Configuration module
│   ├── database.rs          # Database configuration
│   └── webauthn.rs          # WebAuthn configuration
├── controllers/
│   ├── mod.rs               # Controllers module
│   ├── registration.rs      # Registration controller
│   ├── authentication.rs    # Authentication controller
│   └── user.rs              # User management controller
├── services/
│   ├── mod.rs               # Services module
│   ├── webauthn.rs          # WebAuthn service
│   ├── credential.rs        # Credential management
│   └── user.rs              # User service
├── db/
│   ├── mod.rs               # Database module
│   ├── connection.rs        # Connection management
│   ├── models.rs            # Database models
│   └── repositories.rs      # Repository pattern
├── middleware/
│   ├── mod.rs               # Middleware module
│   ├── auth.rs              # Authentication middleware
│   ├── cors.rs              # CORS middleware
│   └── rate_limit.rs        # Rate limiting
├── routes/
│   ├── mod.rs               # Routes module
│   ├── webauthn.rs          # WebAuthn routes
│   └── api.rs               # API routes
├── error/
│   ├── mod.rs               # Error handling
│   └── types.rs             # Error types
├── utils/
│   ├── mod.rs               # Utilities
│   ├── crypto.rs            # Cryptographic utilities
│   └── validation.rs        # Validation utilities
└── schema/                  # Diesel schema files
```

### 3.2 Testing Architecture

```
tests/
├── common/
│   ├── mod.rs               # Common test utilities
│   ├── fixtures.rs          # Test fixtures
│   └── mock_server.rs       # Mock server setup
├── integration/
│   ├── mod.rs               # Integration tests
│   ├── registration_tests.rs # Registration flow tests
│   ├── authentication_tests.rs # Authentication flow tests
│   └── compliance_tests.rs  # FIDO compliance tests
└── unit/                    # Unit tests (in src/)
```

### 3.3 Key Dependencies and Testing Considerations

#### Core Dependencies
- `webauthn-rs`: WebAuthn implementation
- `actix-web`: Web framework
- `diesel`: Database ORM
- `uuid`: Unique identifiers
- `chrono`: Time handling
- `serde`: Serialization

#### Testing Dependencies
- `mockall`: Mocking framework
- `actix-test`: HTTP testing
- `tempfile`: Temporary file testing
- `proptest`: Property-based testing

## 4. API Design

### 4.1 REST Endpoints

#### Registration Endpoints

**POST /api/webauthn/registration/challenge**
```json
Request:
{
  "username": "user@example.com",
  "displayName": "User Name",
  "userVerification": "required|preferred|discouraged",
  "attestation": "none|direct|enterprise|indirect"
}

Response:
{
  "status": "ok",
  "challenge": "base64url-encoded-challenge",
  "rp": {
    "name": "FIDO Server",
    "id": "example.com"
  },
  "user": {
    "id": "base64url-encoded-user-id",
    "name": "user@example.com",
    "displayName": "User Name"
  },
  "pubKeyCredParams": [
    {"type": "public-key", "alg": -7},
    {"type": "public-key", "alg": -257}
  ],
  "timeout": 60000,
  "excludeCredentials": [],
  "authenticatorSelection": {
    "authenticatorAttachment": "platform|cross-platform",
    "userVerification": "required",
    "residentKey": "preferred"
  },
  "attestation": "none"
}
```

**POST /api/webauthn/registration/verify**
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
  "username": "user@example.com",
  "challenge": "base64url-encoded-challenge"
}

Response:
{
  "status": "ok",
  "credentialId": "base64url-encoded-credential-id",
  "user": {
    "id": "user-uuid",
    "username": "user@example.com"
  }
}
```

#### Authentication Endpoints

**POST /api/webauthn/authentication/challenge**
```json
Request:
{
  "username": "user@example.com",
  "userVerification": "required|preferred|discouraged"
}

Response:
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
```

**POST /api/webauthn/authentication/verify**
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
  },
  "username": "user@example.com",
  "challenge": "base64url-encoded-challenge"
}

Response:
{
  "status": "ok",
  "user": {
    "id": "user-uuid",
    "username": "user@example.com"
  },
  "sessionToken": "jwt-session-token"
}
```

### 4.2 Data Flow Specifications

#### Registration Flow
1. Client requests challenge → Server generates secure challenge
2. Client creates credential → Server validates attestation
3. Server stores credential → Returns success response

#### Authentication Flow
1. Client requests challenge → Server generates challenge with user credentials
2. Client creates assertion → Server validates assertion
3. Server creates session → Returns session token

### 4.3 Error Response Format

```json
{
  "status": "error",
  "error": {
    "code": "INVALID_ATTESTATION",
    "message": "Attestation verification failed",
    "details": {
      "reason": "Invalid signature format"
    }
  }
}
```

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
    public_key BYTEA NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    attestation_type VARCHAR(50) NOT NULL,
    aaguid BYTEA,
    transports JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true
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
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_used BOOLEAN DEFAULT false
);
```

#### Sessions Table
```sql
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_accessed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### 5.2 Data Validation Requirements

#### Input Validation
- Username: Email format, max 255 characters
- Display Name: 1-255 characters, no control characters
- Challenge: Base64URL encoded, 16+ bytes
- Credential ID: Base64URL encoded, max 1023 bytes
- Public Key: Valid COSE key format

#### Data Integrity
- Foreign key constraints enforcement
- Unique constraint on credential IDs
- Check constraints for valid values
- Transaction isolation for concurrent operations

#### Security Validation
- SQL injection prevention
- XSS prevention in display names
- Proper data sanitization
- Size limits enforcement

## 6. Compliance Checklist

### 6.1 FIDO2 Specification Compliance Points

#### Core Specification (§5-§8)
- [ ] **5.1.1**: Client data JSON structure validation
- [ ] **5.1.2**: Collected client data verification
- [ ] **5.2**: Attestation statement validation
- [ ] **5.3**: Attestation object validation
- [ ] **6.1**: Assertion request generation
- [ ] **6.2**: Assertion response validation
- [ ] **7**: Credential storage and management
- [ ] **8**: User verification handling

#### WebAuthn Specification (§5-§7)
- [ ] **5.1**: Registration ceremony implementation
- [ ] **5.2**: Authentication ceremony implementation
- [ ] **6.1**: Credential parameters validation
- [ ] **6.2**: Authenticator selection criteria
- [ ] **7**: Extension support (optional)

#### Security Requirements
- [ ] **RP ID validation**: Cross-origin protection
- [ ] **Challenge generation**: Cryptographically secure
- [ ] **Replay protection**: Challenge consumption
- [ ] **Rate limiting**: Brute force prevention
- [ ] **TLS enforcement**: Transport security

### 6.2 Testable Compliance Points

#### Registration Compliance Tests
```rust
#[cfg(test)]
mod registration_compliance {
    use super::*;
    
    #[test]
    fn test_attestation_format_validation() {
        // Test various attestation formats
        // Verify compliance with §5.2
    }
    
    #[test]
    fn test_client_data_validation() {
        // Test client data JSON structure
        // Verify compliance with §5.1.1
    }
    
    #[test]
    fn test_challenge_replay_protection() {
        // Test challenge reuse prevention
        // Verify compliance with security requirements
    }
}
```

#### Authentication Compliance Tests
```rust
#[cfg(test)]
mod authentication_compliance {
    use super::*;
    
    #[test]
    fn test_assertion_signature_validation() {
        // Test signature verification
        // Verify compliance with §6.2
    }
    
    #[test]
    fn test_authenticator_data_validation() {
        // Test authenticator data structure
        // Verify compliance with §6.2.1
    }
    
    #[test]
    fn test_user_verification_enforcement() {
        // Test UV flag validation
        // Verify compliance with §6.1
    }
}
```

## 7. Risk Assessment

### 7.1 Security Considerations

#### High Risk Items
1. **Credential Replay Attacks**
   - Risk: Challenge reuse leading to unauthorized access
   - Mitigation: One-time challenges with proper expiration
   - Testing: Challenge replay test scenarios

2. **Attestation Bypass**
   - Risk: Invalid attestation acceptance
   - Mitigation: Comprehensive attestation validation
   - Testing: Various attestation format tests

3. **RP ID Manipulation**
   - Risk: Cross-origin credential theft
   - Mitigation: Strict RP ID validation
   - Testing: RP ID mismatch scenarios

#### Medium Risk Items
1. **Database Injection**
   - Risk: SQL injection through user inputs
   - Mitigation: Parameterized queries, input validation
   - Testing: SQL injection test cases

2. **Session Hijacking**
   - Risk: Session token theft
   - Mitigation: Secure session management, HTTPS enforcement
   - Testing: Session security tests

3. **Denial of Service**
   - Risk: Resource exhaustion attacks
   - Mitigation: Rate limiting, resource quotas
   - Testing: Load testing, rate limit tests

#### Low Risk Items
1. **Information Disclosure**
   - Risk: Sensitive data leakage
   - Mitigation: Proper error handling, logging controls
   - Testing: Information disclosure tests

2. **Weak Cryptography**
   - Risk: Inadequate cryptographic strength
   - Mitigation: Algorithm validation, key size requirements
   - Testing: Cryptographic validation tests

### 7.2 Vulnerability Mitigation Strategies

#### Preventive Measures
- Input validation and sanitization
- Secure coding practices
- Regular security audits
- Dependency vulnerability scanning
- Code review processes

#### Detective Measures
- Comprehensive logging and monitoring
- Anomaly detection systems
- Security event correlation
- Regular penetration testing
- Compliance monitoring

#### Corrective Measures
- Incident response procedures
- Security patch management
- Credential revocation mechanisms
- Backup and recovery procedures
- Post-incident analysis

### 7.3 Testing Strategy for Security

#### Security Test Categories
1. **Unit Security Tests**
   - Input validation tests
   - Cryptographic function tests
   - Authorization logic tests

2. **Integration Security Tests**
   - End-to-end flow security tests
   - API security tests
   - Database security tests

3. **Compliance Tests**
   - FIDO2 specification compliance
   - Regulatory requirement tests
   - Industry standard compliance

4. **Penetration Tests**
   - External attack simulation
   - Internal threat assessment
   - Social engineering tests

#### Test Automation
- Continuous security testing in CI/CD
- Automated vulnerability scanning
- Compliance test automation
- Performance security testing

## 8. Implementation Roadmap

### Phase 1: Core Infrastructure (Weeks 1-2)
- Project structure setup
- Database schema implementation
- Basic WebAuthn service foundation
- Configuration management
- Logging and error handling

### Phase 2: Registration Flow (Weeks 3-4)
- Challenge generation endpoint
- Attestation verification service
- Credential storage implementation
- Registration API endpoints
- Unit and integration tests

### Phase 3: Authentication Flow (Weeks 5-6)
- Authentication challenge endpoint
- Assertion verification service
- Session management
- Authentication API endpoints
- Security testing

### Phase 4: Security Hardening (Weeks 7-8)
- Rate limiting implementation
- CORS and security headers
- Input validation enhancement
- Error handling improvements
- Security test suite

### Phase 5: Compliance and Testing (Weeks 9-10)
- FIDO2 compliance verification
- Performance testing
- Load testing
- Security audit preparation
- Documentation completion

## 9. Success Metrics

### Technical Metrics
- Test coverage: ≥95% unit, ≥90% integration
- Performance: <100ms response time for 95% of requests
- Security: Zero critical vulnerabilities in security audit
- Compliance: 100% FIDO2 specification compliance

### Quality Metrics
- Code quality: Pass all clippy lints
- Documentation: 100% public API documentation
- Reliability: 99.9% uptime in production
- Maintainability: <10% code duplication

This specification provides a comprehensive foundation for implementing a secure, compliant FIDO2/WebAuthn Relying Party Server with extensive testing coverage and security-first design principles.