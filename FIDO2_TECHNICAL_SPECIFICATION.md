# FIDO2/WebAuthn Relying Party Server - Technical Specification

## Executive Summary

This document provides a comprehensive technical specification for implementing a FIDO2/WebAuthn Relying Party Server in Rust using the webauthn-rs library. The specification focuses on security-first design, FIDO Alliance compliance, and comprehensive test-driven development.

## 1. Security Requirements

### 1.1 FIDO Alliance Compliance Requirements

#### Core Security Requirements (Testable Criteria)
- **SR-001**: Server MUST validate attestation statements according to FIDO2 specification
- **SR-002**: Server MUST implement proper origin validation for all WebAuthn operations
- **SR-003**: Server MUST enforce TLS 1.2+ for all communications
- **SR-004**: Server MUST implement replay attack prevention using challenges
- **SR-005**: Server MUST validate user presence and user verification flags
- **SR-006**: Server MUST implement proper credential binding to user accounts
- **SR-007**: Server MUST support resident key (discoverable credentials) functionality
- **SR-008**: Server MUST implement proper timeout handling for ceremonies

#### Cryptographic Requirements
- **CR-001**: Support for ES256, RS256, and EdDSA algorithms
- **CR-002**: Proper random challenge generation (minimum 16 bytes)
- **CR-003**: Secure storage of credential IDs and public keys
- **CR-004**: Implementation of proper signature verification
- **CR-005**: Support for attestation formats: packed, fido-u2f, none, android-key, android-safetynet

#### Authentication Security
- **AS-001**: Multi-factor authentication support
- **AS-002**: Rate limiting for authentication attempts
- **AS-003**: Account lockout after failed attempts
- **AS-004**: Secure session management
- **AS-005**: Proper logout and session invalidation

### 1.2 Testable Security Criteria

#### Registration Flow Security Tests
```rust
// Test cases to implement:
- test_registration_with_invalid_attestation()
- test_registration_with_malformed_client_data()
- test_registration_with_replayed_challenge()
- test_registration_with_untrusted_origin()
- test_registration_user_verification_required()
- test_registration_resident_key_support()
```

#### Authentication Flow Security Tests
```rust
// Test cases to implement:
- test_authentication_with_invalid_assertion()
- test_authentication_with_expired_challenge()
- test_authentication_with_wrong_user_handle()
- test_authentication_user_presence_verification()
- test_authentication_concurrent_sessions()
```

## 2. Technical Scope

### 2.1 Core WebAuthn Operations

#### Registration (Attestation) Flow
**Success Conditions:**
- Valid attestation statement verification
- Proper challenge-response validation
- Successful credential storage
- User binding established
- Attestation metadata processed

**Failure Conditions:**
- Invalid attestation format
- Challenge mismatch or expired
- Origin validation failure
- Cryptographic verification failure
- Duplicate credential ID
- User not found or inactive

#### Authentication (Assertion) Flow
**Success Conditions:**
- Valid assertion signature verification
- Challenge validation
- User presence confirmed
- User verification (if required)
- Credential found and active
- Authentication context established

**Failure Conditions:**
- Invalid signature
- Challenge mismatch
- Credential not found
- User verification failure
- Counter replay detected
- Credential disabled

### 2.2 Edge Cases and Error Handling

#### Registration Edge Cases
- Multiple authenticators per user
- Credential ID collisions
- Attestation statement parsing errors
- Unsupported attestation formats
- Timeout during ceremony
- Network interruptions

#### Authentication Edge Cases
- Lost authenticator scenarios
- Credential backup and restore
- Multiple credentials selection
- Biometric failure fallback
- Device battery depletion
- Cross-origin authentication attempts

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
│   ├── user.rs              # User service
│   └── credential.rs        # Credential service
├── models/
│   ├── mod.rs               # Models module
│   ├── user.rs              # User model
│   ├── credential.rs        # Credential model
│   └── session.rs           # Session model
├── db/
│   ├── mod.rs               # Database module
│   ├── connection.rs        # Database connection
│   └── migrations/          # Database migrations
├── middleware/
│   ├── mod.rs               # Middleware module
│   ├── auth.rs              # Authentication middleware
│   ├── cors.rs              # CORS middleware
│   └── rate_limit.rs        # Rate limiting middleware
├── routes/
│   ├── mod.rs               # Routes module
│   ├── webauthn.rs          # WebAuthn routes
│   └── api.rs               # API routes
├── error/
│   ├── mod.rs               # Error module
│   └── types.rs             # Error types
└── utils/
    ├── mod.rs               # Utilities module
    ├── crypto.rs            # Cryptographic utilities
    └── validation.rs        # Validation utilities
```

### 3.2 Testing Architecture

```
tests/
├── common/
│   ├── mod.rs               # Common test utilities
│   ├── fixtures.rs          # Test fixtures
│   └── mock_server.rs       # Mock server setup
├── unit/
│   ├── services/            # Unit tests for services
│   ├── controllers/         # Unit tests for controllers
│   └── models/              # Unit tests for models
├── integration/
│   ├── api/                 # API integration tests
│   ├── webauthn/            # WebAuthn flow tests
│   └── security/            # Security tests
├── compliance/
│   ├── fido2/               # FIDO2 compliance tests
│   └── webauthn/            # WebAuthn spec tests
└── performance/
    ├── load/                # Load testing
    └── concurrent/          # Concurrency testing
```

### 3.3 Key Dependencies and Testing Considerations

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

# Testing
[dev-dependencies]
actix-test = "0.1"
mockall = "0.13"
tokio-test = "0.4"
wiremock = "0.6"
criterion = "0.5"
proptest = "1.4"
```

## 4. API Design

### 4.1 REST Endpoints Specification

#### Registration Endpoints

**POST /api/v1/webauthn/registration/challenge**
```json
// Request
{
  "username": "user@example.com",
  "displayName": "John Doe",
  "userVerification": "required",
  "authenticatorSelection": {
    "authenticatorAttachment": "platform",
    "requireResidentKey": true,
    "userVerification": "required"
  },
  "attestation": "direct"
}

// Response
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
    "authenticatorAttachment": "platform",
    "requireResidentKey": true,
    "userVerification": "required"
  },
  "attestation": "direct",
  "extensions": {}
}
```

**POST /api/v1/webauthn/registration/verify**
```json
// Request
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
  "sessionToken": "jwt-session-token"
}

// Response
{
  "status": "ok",
  "credentialId": "base64url-encoded-credential-id",
  "userId": "user-uuid",
  "registrationTime": "2024-01-01T00:00:00Z",
  "authenticatorInfo": {
    "aaguid": "base64url-encoded-aaguid",
    "signCount": 0,
    "cloneWarning": false
  }
}
```

#### Authentication Endpoints

**POST /api/v1/webauthn/authentication/challenge**
```json
// Request
{
  "username": "user@example.com",
  "userVerification": "required"
}

// Response
{
  "status": "ok",
  "challenge": "base64url-encoded-challenge",
  "allowCredentials": [
    {
      "type": "public-key",
      "id": "base64url-encoded-credential-id",
      "transports": ["internal", "usb", "nfc", "ble"]
    }
  ],
  "userVerification": "required",
  "timeout": 60000,
  "extensions": {}
}
```

**POST /api/v1/webauthn/authentication/verify**
```json
// Request
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
  "sessionToken": "jwt-session-token"
}

// Response
{
  "status": "ok",
  "userId": "user-uuid",
  "credentialId": "base64url-encoded-credential-id",
  "newSignCount": 42,
  "authenticationTime": "2024-01-01T00:00:00Z",
  "sessionToken": "new-jwt-session-token"
}
```

### 4.2 Data Flow Specifications

#### Registration Flow
1. Client requests registration challenge
2. Server generates cryptographically secure challenge
3. Server stores challenge with expiration
4. Client creates credential with authenticator
5. Client submits attestation response
6. Server validates attestation and challenge
7. Server stores credential metadata
8. Server returns success response

#### Authentication Flow
1. Client requests authentication challenge
2. Server retrieves user credentials
3. Server generates challenge for specific credentials
4. Server stores challenge with expiration
5. Client signs challenge with authenticator
6. Client submits assertion response
7. Server validates signature and challenge
8. Server updates sign counter
9. Server establishes authenticated session

## 5. Storage Requirements

### 5.1 Database Schema

#### Users Table
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT true,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE
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
    transports JSONB,
    flags JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true,
    backup_eligible BOOLEAN DEFAULT false,
    backup_state BOOLEAN DEFAULT false
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
    used_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB
);
```

#### Sessions Table
```sql
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ip_address INET,
    user_agent TEXT,
    is_active BOOLEAN DEFAULT true
);
```

### 5.2 Data Validation Requirements

#### Input Validation
- Username: 3-255 characters, alphanumeric + @._-
- Email: Valid RFC 5322 email format
- Display Name: 1-255 characters, no control characters
- Challenge: Minimum 16 bytes, cryptographically random
- Credential ID: Maximum 1023 bytes
- Public Key: Valid COSE key format

#### Output Validation
- All responses must be valid JSON
- Base64URL encoding for binary data
- Timestamps in ISO 8601 format
- Proper HTTP status codes
- Consistent error response format

#### Security Validation
- SQL injection prevention
- XSS prevention in responses
- CSRF protection for state-changing operations
- Rate limiting per user/IP
- Input size limits
- Character encoding validation

## 6. Compliance Checklist

### 6.1 FIDO2 Specification Compliance Points

#### Core Specification (Testable)
- [ ] **FIDO-001**: Implement WebAuthn API Level 2
- [ ] **FIDO-002**: Support for CTAP2 protocol
- [ ] **FIDO-003**: Proper RP ID validation
- [ ] **FIDO-004**: Origin validation implementation
- [ ] **FIDO-005**: Challenge generation and validation
- [ ] **FIDO-006**: Client data JSON validation
- [ ] **FIDO-007**: Authenticator data validation
- [ ] **FIDO-008**: Signature verification algorithms

#### Attestation Compliance
- [ ] **ATT-001**: Packed attestation format support
- [ ] **ATT-002**: FIDO-U2F attestation format support
- [ ] **ATT-003**: None attestation format support
- [ ] **ATT-004**: Android-key attestation support
- [ ] **ATT-005**: Android-safetynet attestation support
- [ ] **ATT-006**: Attestation statement validation
- [ ] **ATT-007**: AAGUID extraction and validation
- [ ] **ATT-008**: Attestation trust anchor validation

#### User Verification Compliance
- [ ] **UV-001**: User presence flag validation
- [ ] **UV-002**: User verification flag validation
- [ ] **UV-003**: User verification methods support
- [ ] **UV-004**: Biometric authentication support
- [ ] **UV-005**: PIN authentication support
- [ ] **UV-006**: User verification requirement handling

#### Extensions Compliance
- [ ] **EXT-001**: Credential protection extension
- [ ] **EXT-002**: Large blob key extension
- [ ] **EXT-003**: Minimum PIN length extension
- [ ] **EXT-004**: User verification method extension
- [ ] **EXT-005**: CredBlob extension support

### 6.2 WebAuthn Specification Compliance

#### Registration Ceremony
- [ ] **REG-001**: PublicKeyCredentialCreationOptions validation
- [ ] **REG-002**: AuthenticatorSelectionCriteria enforcement
- [ ] **REG-003**: CredentialParameters validation
- [ ] **REG-004**: ExcludeCredentials handling
- [ ] **REG-005**: Extensions support in registration
- [ ] **REG-006**: Attestation conveyance preference
- [ ] **REG-007**: Client data JSON structure validation
- [ ] **REG-008**: Attestation object validation

#### Authentication Ceremony
- [ ] **AUTH-001**: PublicKeyCredentialRequestOptions validation
- [ ] **AUTH-002**: AllowCredentials filtering
- [ ] **AUTH-003**: User verification requirement handling
- [ ] **AUTH-004**: Extensions support in authentication
- [ ] **AUTH-005**: Client data JSON validation
- [ ] **AUTH-006**: Authenticator data validation
- [ ] **AUTH-007**: Signature validation
- [ ] **AUTH-008**: Sign counter validation

#### Security Requirements
- [ ] **SEC-001**: Same-origin policy enforcement
- [ ] **SEC-002**: HTTPS requirement enforcement
- [ ] **SEC-003**: Replay attack prevention
- [ ] **SEC-004**: Cloning detection
- [ ] **SEC-005**: Physical attack resistance
- [ ] **SEC-006**: Malicious software protection

## 7. Risk Assessment

### 7.1 Security Considerations

#### High Risk Vulnerabilities
1. **Replay Attacks**
   - Risk: Challenge reuse leading to unauthorized access
   - Mitigation: Single-use challenges with short expiration
   - Testing: Challenge replay detection tests

2. **Man-in-the-Middle Attacks**
   - Risk: Credential interception during registration
   - Mitigation: TLS enforcement, origin validation
   - Testing: TLS certificate validation tests

3. **Credential Cloning**
   - Risk: Duplicate credentials across devices
   - Mitigation: Sign counter tracking, clone detection
   - Testing: Sign counter validation tests

4. **Database Compromise**
   - Risk: Credential data exposure
   - Mitigation: Encryption at rest, access controls
   - Testing: Database encryption tests

#### Medium Risk Vulnerabilities
1. **Brute Force Attacks**
   - Risk: Credential guessing
   - Mitigation: Rate limiting, account lockout
   - Testing: Rate limiting effectiveness tests

2. **Session Hijacking**
   - Risk: Unauthorized session access
   - Mitigation: Secure session management, IP binding
   - Testing: Session security tests

3. **Cross-Site Scripting (XSS)**
   - Risk: Client-side script injection
   - Mitigation: Input sanitization, CSP headers
   - Testing: XSS prevention tests

#### Low Risk Vulnerabilities
1. **Information Disclosure**
   - Risk: Sensitive information leakage
   - Mitigation: Error message sanitization
   - Testing: Information disclosure tests

2. **Denial of Service**
   - Risk: Service unavailability
   - Mitigation: Resource limits, monitoring
   - Testing: DoS resistance tests

### 7.2 Mitigation Strategies

#### Technical Mitigations
- **Cryptographic Security**: Use vetted cryptographic libraries
- **Input Validation**: Comprehensive input sanitization
- **Output Encoding**: Proper encoding for all outputs
- **Authentication**: Multi-factor authentication where possible
- **Authorization**: Principle of least privilege
- **Logging**: Comprehensive security logging
- **Monitoring**: Real-time threat detection

#### Operational Mitigations
- **Regular Updates**: Keep dependencies updated
- **Security Audits**: Regular security assessments
- **Penetration Testing**: Regular security testing
- **Incident Response**: Security incident procedures
- **Training**: Security awareness training
- **Backup**: Regular secure backups
- **Disaster Recovery**: Business continuity planning

### 7.3 Testing Strategy for Security

#### Security Test Categories
1. **Unit Security Tests**
   - Input validation tests
   - Cryptographic function tests
   - Authorization logic tests

2. **Integration Security Tests**
   - API security tests
   - Database security tests
   - Session management tests

3. **End-to-End Security Tests**
   - Full WebAuthn flow tests
   - Attack scenario simulations
   - Compliance validation tests

4. **Performance Security Tests**
   - Load testing under attack
   - Resource exhaustion tests
   - Memory leak detection

#### Security Test Automation
- **Static Analysis**: Automated code security scanning
- **Dynamic Analysis**: Runtime security testing
- **Dependency Scanning**: Vulnerability scanning
- **Compliance Testing**: Automated compliance checks
- **Penetration Testing**: Automated security testing

## Conclusion

This technical specification provides a comprehensive foundation for implementing a secure, FIDO2-compliant WebAuthn Relying Party Server in Rust. The focus on testable security requirements, comprehensive API design, and thorough compliance checking ensures that the implementation will meet both security standards and functional requirements.

The specification emphasizes security-first design principles while maintaining practical implementation considerations. The detailed testing strategy ensures that all security requirements can be verified through automated testing, providing confidence in the system's security posture.

Next steps should include:
1. Implementation of the core WebAuthn service
2. Database schema creation and migration
3. API endpoint implementation
4. Comprehensive test suite development
5. Security audit and penetration testing
6. FIDO Alliance compliance validation