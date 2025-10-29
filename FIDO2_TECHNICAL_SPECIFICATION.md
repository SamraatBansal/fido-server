# FIDO2/WebAuthn Relying Party Server - Technical Specification

## Executive Summary

This document provides a comprehensive technical specification for implementing a FIDO2/WebAuthn Relying Party Server in Rust using the webauthn-rs library. The specification focuses on security-first design, FIDO Alliance compliance, and comprehensive test-driven development.

## 1. Security Requirements

### 1.1 FIDO Alliance Compliance Requirements

#### Core Security Requirements (Testable Criteria)
- **RP ID Validation**: MUST validate RP ID against origin with exact string matching
- **Origin Validation**: MUST verify request origin matches configured allowed origins
- **Challenge Uniqueness**: MUST generate cryptographically random challenges (minimum 16 bytes)
- **Challenge Expiration**: MUST expire challenges within 5 minutes (configurable)
- **Replay Attack Prevention**: MUST prevent challenge reuse with one-time use enforcement
- **TLS Enforcement**: MUST enforce HTTPS in production environments
- **Credential Binding**: MUST bind credentials to specific user accounts
- **Attestation Validation**: MUST validate attestation statements according to FIDO2 spec
- **User Verification**: MUST support user verification levels (required, preferred, discouraged)

#### Security Test Cases
```rust
// Testable security requirements
#[test]
fn test_rp_id_validation() {
    // Verify RP ID matches origin exactly
    // Test cases: valid RP ID, invalid RP ID, malformed RP ID
}

#[test]
fn test_challenge_uniqueness() {
    // Verify challenges are cryptographically random
    // Verify no duplicate challenges within timeframe
}

#[test]
fn test_replay_attack_prevention() {
    // Verify challenges cannot be reused
    // Verify challenge expiration enforcement
}
```

### 1.2 Cryptographic Requirements

#### Supported Algorithms
- **ECDSA**: P-256, P-384, P-521 curves
- **RSA**: RS256, RS384, RS512 with minimum 2048-bit keys
- **EdDSA**: Ed25519, Ed448
- **Attestation Formats**: Packed, FIDO-U2F, None, Android Key, Android SafetyNet

#### Key Storage Security
- Private keys MUST be stored encrypted at rest
- Key rotation support with versioning
- Secure key generation using CSPRNG
- Memory protection for sensitive operations

## 2. Technical Scope

### 2.1 Core WebAuthn Operations

#### Registration (Attestation) Flow
```
1. Client → Server: POST /attestation/options
   Input: { username, displayName, userVerification }
   Output: { challenge, user, rp, pubKeyCredParams, timeout }

2. Client → Server: POST /attestation/result
   Input: { id, rawId, response: { attestationObject, clientDataJSON }, type }
   Output: { status, errorMessage? }
```

**Success Conditions:**
- Valid attestation object format
- Proper challenge verification
- Valid client data JSON
- Successful credential storage
- User binding established

**Failure Conditions:**
- Invalid or expired challenge
- Malformed attestation object
- Unsupported attestation format
- Duplicate credential ID
- Invalid user verification

#### Authentication (Assertion) Flow
```
1. Client → Server: POST /assertion/options
   Input: { username?, userVerification, allowCredentials? }
   Output: { challenge, allowCredentials, userVerification, timeout }

2. Client → Server: POST /assertion/result
   Input: { id, rawId, response: { authenticatorData, clientDataJSON, signature, userHandle }, type }
   Output: { status, errorMessage? }
```

**Success Conditions:**
- Valid assertion signature
- Proper challenge verification
- Valid authenticator data
- User verification matches requirements
- Credential exists and is not disabled

**Failure Conditions:**
- Invalid or expired challenge
- Invalid signature
- Credential not found or disabled
- User verification failure
- Counter replay attack

### 2.2 Edge Case Testing Requirements

#### Registration Edge Cases
- Concurrent registration attempts for same user
- Registration with existing credential ID
- Invalid attestation formats
- Malformed client data JSON
- Timeout scenarios
- Network interruption handling

#### Authentication Edge Cases
- Authentication with disabled credentials
- Invalid user handle
- Signature verification failures
- Counter manipulation attempts
- Cross-origin request attempts

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
│   ├── mod.rs               # Controllers module
│   ├── attestation.rs       # Registration controller
│   ├── assertion.rs         # Authentication controller
│   └── health.rs            # Health check controller
├── services/
│   ├── mod.rs               # Services module
│   ├── webauthn.rs          # WebAuthn service
│   ├── user.rs              # User management service
│   └── credential.rs        # Credential service
├── models/
│   ├── mod.rs               # Models module
│   ├── user.rs              # User model
│   ├── credential.rs        # Credential model
│   └── challenge.rs         # Challenge model
├── db/
│   ├── mod.rs               # Database module
│   ├── connection.rs        # Connection pool
│   ├── migrations/          # Database migrations
│   └── queries.rs           # Database queries
├── middleware/
│   ├── mod.rs               # Middleware module
│   ├── cors.rs              # CORS middleware
│   ├── security.rs          # Security headers
│   └── rate_limit.rs        # Rate limiting
├── routes/
│   ├── mod.rs               # Routes module
│   ├── webauthn.rs          # WebAuthn routes
│   └── api.rs               # API routes
├── error/
│   ├── mod.rs               # Error module
│   ├── types.rs             # Error types
│   └── handlers.rs          # Error handlers
└── utils/
    ├── mod.rs               # Utilities module
    ├── crypto.rs            # Cryptographic utilities
    ├── validation.rs        # Input validation
    └── logging.rs           # Logging utilities
```

### 3.2 Testing Architecture
```
tests/
├── integration/             # Integration tests
│   ├── api_tests.rs         # API endpoint tests
│   ├── webauthn_tests.rs    # WebAuthn flow tests
│   └── security_tests.rs    # Security tests
├── unit/                    # Unit tests
│   ├── services/            # Service unit tests
│   ├── models/              # Model unit tests
│   └── utils/               # Utility unit tests
├── compliance/              # FIDO compliance tests
│   ├── registration_tests.rs
│   ├── authentication_tests.rs
│   └── attestation_tests.rs
└── fixtures/                # Test fixtures
    ├── test_data.rs         # Test data
    └── mock_responses.rs    # Mock responses
```

### 3.3 Key Dependencies and Testing Considerations

#### Core Dependencies
```toml
[dependencies]
webauthn-rs = "0.5"           # Core WebAuthn implementation
actix-web = "4.9"             # Web framework
diesel = { version = "2.1", features = ["postgres"] }  # Database
uuid = { version = "1.10", features = ["v4", "serde"] }  # UUID generation
chrono = { version = "0.4", features = ["serde"] }     # Time handling
serde = { version = "1.0", features = ["derive"] }     # Serialization
```

#### Testing Dependencies
```toml
[dev-dependencies]
actix-test = "0.1"           # HTTP testing
mockall = "0.13"             # Mocking framework
tokio-test = "0.4"           # Async testing
tempfile = "3.8"             # Temporary files for testing
wiremock = "0.6"             # HTTP mocking
```

## 4. API Design

### 4.1 REST Endpoints Specification

#### Registration Endpoints

**POST /attestation/options**
```json
Request:
{
  "username": "string",
  "displayName": "string",
  "userVerification": "required|preferred|discouraged",
  "attestation": "none|direct|enterprise",
  "extensions": {}
}

Response (200):
{
  "status": "ok",
  "errorMessage": "",
  "challenge": "base64url-encoded-challenge",
  "rp": {
    "name": "string",
    "id": "string"
  },
  "user": {
    "id": "base64url-encoded-user-id",
    "name": "string",
    "displayName": "string"
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
    "requireResidentKey": false,
    "userVerification": "required|preferred|discouraged"
  },
  "extensions": {}
}

Error Response (400):
{
  "status": "error",
  "errorMessage": "Invalid username format"
}
```

**POST /attestation/result**
```json
Request:
{
  "id": "base64url-encoded-credential-id",
  "rawId": "base64url-encoded-raw-credential-id",
  "type": "public-key",
  "response": {
    "attestationObject": "base64url-encoded",
    "clientDataJSON": "base64url-encoded",
    "transports": ["usb", "nfc", "ble", "internal"]
  },
  "clientExtensionResults": {}
}

Response (200):
{
  "status": "ok",
  "errorMessage": "",
  "credentialId": "base64url-encoded-credential-id",
  "newUser": false
}

Error Response (400):
{
  "status": "error",
  "errorMessage": "Invalid attestation format"
}
```

#### Authentication Endpoints

**POST /assertion/options**
```json
Request:
{
  "username": "string",
  "userVerification": "required|preferred|discouraged",
  "allowCredentials": [
    {
      "type": "public-key",
      "id": "base64url-encoded-credential-id",
      "transports": ["usb", "nfc", "ble", "internal"]
    }
  ],
  "extensions": {}
}

Response (200):
{
  "status": "ok",
  "errorMessage": "",
  "challenge": "base64url-encoded-challenge",
  "allowCredentials": [],
  "userVerification": "required|preferred|discouraged",
  "timeout": 60000,
  "rpId": "string",
  "extensions": {}
}
```

**POST /assertion/result**
```json
Request:
{
  "id": "base64url-encoded-credential-id",
  "rawId": "base64url-encoded-raw-credential-id",
  "type": "public-key",
  "response": {
    "authenticatorData": "base64url-encoded",
    "clientDataJSON": "base64url-encoded",
    "signature": "base64url-encoded",
    "userHandle": "base64url-encoded-user-id"
  },
  "clientExtensionResults": {}
}

Response (200):
{
  "status": "ok",
  "errorMessage": "",
  "credentialId": "base64url-encoded-credential-id",
  "user": {
    "id": "base64url-encoded-user-id",
    "name": "string",
    "displayName": "string"
  },
  "counter": 12345
}
```

### 4.2 Data Flow Specifications

#### Registration Flow
```
Client Request → Validation → Challenge Generation → Response
Client Response → Challenge Verification → Attestation Validation → Credential Storage → User Binding → Success Response
```

#### Authentication Flow
```
Client Request → User Lookup → Challenge Generation → Credential Selection → Response
Client Response → Challenge Verification → Signature Verification → Counter Update → Session Creation → Success Response
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
    attestation_format VARCHAR(50) NOT NULL,
    aaguid BYTEA,
    sign_count BIGINT DEFAULT 0,
    user_verified BOOLEAN DEFAULT false,
    backup_eligible BOOLEAN DEFAULT false,
    backup_state BOOLEAN DEFAULT false,
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
    used_at TIMESTAMP WITH TIME ZONE,
    is_used BOOLEAN DEFAULT false
);
```

### 5.2 Data Validation Requirements

#### Input Validation
- Username: 3-64 characters, alphanumeric + @._-
- Display Name: 1-128 characters, UTF-8
- Challenge: Base64URL encoded, minimum 16 bytes when decoded
- Credential ID: Base64URL encoded, maximum 1023 bytes when decoded

#### Data Integrity
- All sensitive data stored encrypted at rest
- Database constraints enforce uniqueness
- Audit logging for all credential operations
- Regular data integrity checks

#### Performance Requirements
- Challenge lookup: < 10ms
- Credential verification: < 50ms
- User lookup: < 5ms
- Concurrent user support: 1000+ active sessions

## 6. Compliance Checklist

### 6.1 FIDO2 Specification Compliance Points

#### Core Requirements (Testable)
- [ ] RP ID validation against origin
- [ ] Challenge generation with CSPRNG
- [ ] Challenge expiration enforcement
- [ ] One-time challenge use
- [ ] TLS enforcement in production
- [ ] Proper error responses
- [ ] Credential binding to users
- [ ] Support for required algorithms
- [ ] Attestation validation
- [ ] User verification support

#### WebAuthn Level 1 Compliance
- [ ] PublicKeyCredential creation options
- [ ] PublicKeyCredential request options
- [ ] Client data JSON validation
- [ ] Authenticator data validation
- [ ] Signature verification
- [ ] Counter tracking
- [ ] Credential management
- [ ] User account management

#### WebAuthn Level 2 Compliance
- [ ] Extension support
- [ ] Multiple credential handling
- [ ] Credential properties
- [ ] Attestation conveyance
- [ ] Resident key support
- [ ] User verification methods
- [ ] Authenticator selection

### 6.2 Security Compliance Testing

#### Cryptographic Compliance
```rust
#[cfg(test)]
mod compliance_tests {
    use super::*;
    
    #[test]
    fn test_fido2_algorithm_support() {
        // Test support for required algorithms
        // P-256, P-384, P-521, RSA-2048+
    }
    
    #[test]
    fn test_attestation_validation() {
        // Test attestation format validation
        // Packed, FIDO-U2F, None formats
    }
    
    #[test]
    fn test_challenge_security() {
        // Test challenge randomness
        // Test challenge uniqueness
        // Test challenge expiration
    }
}
```

#### API Compliance Testing
```rust
#[actix_web::test]
async fn test_api_compliance() {
    // Test request/response formats
    // Test error handling
    // Test status codes
    // Test content types
}
```

## 7. Risk Assessment

### 7.1 Security Considerations

#### High Risk Items
1. **Replay Attacks**
   - Risk: Challenge reuse leading to unauthorized access
   - Mitigation: One-time challenges, immediate invalidation, short expiration

2. **Man-in-the-Middle Attacks**
   - Risk: Request/response tampering
   - Mitigation: TLS enforcement, origin validation, message signing

3. **Credential Theft**
   - Risk: Database compromise exposing credentials
   - Mitigation: Encryption at rest, key rotation, access controls

4. **Denial of Service**
   - Risk: Resource exhaustion attacks
   - Mitigation: Rate limiting, request validation, resource monitoring

#### Medium Risk Items
1. **Side-Channel Attacks**
   - Risk: Timing attacks on cryptographic operations
   - Mitigation: Constant-time operations, input masking

2. **Cross-Site Request Forgery**
   - Risk: Unauthorized actions on behalf of users
   - Mitigation: CSRF tokens, same-site cookies, origin validation

3. **Information Disclosure**
   - Risk: Sensitive information in error messages
   - Mitigation: Generic error messages, audit logging

### 7.2 Vulnerability Mitigation Strategies

#### Preventive Measures
- Input validation and sanitization
- Secure coding practices
- Regular security audits
- Dependency vulnerability scanning
- Penetration testing

#### Detective Measures
- Comprehensive logging and monitoring
- Anomaly detection
- Security event correlation
- Regular compliance checks

#### Corrective Measures
- Incident response procedures
- Rapid patch deployment
- Credential revocation mechanisms
- Backup and recovery procedures

### 7.3 Testing for Security Vulnerabilities

#### Security Test Suite
```rust
#[cfg(test)]
mod security_tests {
    use super::*;
    
    #[test]
    fn test_sql_injection_prevention() {
        // Test SQL injection resistance
    }
    
    #[test]
    fn test_xss_prevention() {
        // Test XSS prevention in responses
    }
    
    #[test]
    fn test_csrf_protection() {
        // Test CSRF token validation
    }
    
    #[test]
    fn test_rate_limiting() {
        // Test rate limiting effectiveness
    }
    
    #[test]
    fn test_input_validation() {
        // Test malicious input handling
    }
}
```

## 8. Implementation Roadmap

### Phase 1: Core Infrastructure (Weeks 1-2)
- [ ] Project structure setup
- [ ] Database schema and migrations
- [ ] Basic WebAuthn service implementation
- [ ] Configuration management
- [ ] Error handling framework

### Phase 2: Registration Flow (Weeks 3-4)
- [ ] Attestation options endpoint
- [ ] Attestation result endpoint
- [ ] Challenge management
- [ ] Credential storage
- [ ] User management

### Phase 3: Authentication Flow (Weeks 5-6)
- [ ] Assertion options endpoint
- [ ] Assertion result endpoint
- [ ] Signature verification
- [ ] Counter tracking
- [ ] Session management

### Phase 4: Security & Compliance (Weeks 7-8)
- [ ] Security middleware
- [ ] Rate limiting
- [ ] CORS configuration
- [ ] TLS enforcement
- [ ] Security headers

### Phase 5: Testing & Documentation (Weeks 9-10)
- [ ] Unit test suite (95%+ coverage)
- [ ] Integration test suite
- [ ] Security test suite
- [ ] Compliance test suite
- [ ] Performance testing
- [ ] API documentation

## 9. Success Metrics

### Technical Metrics
- Unit test coverage: ≥95%
- Integration test coverage: 100%
- Security test coverage: 100%
- API response time: <100ms (95th percentile)
- Concurrent user support: 1000+
- Zero critical vulnerabilities

### Compliance Metrics
- FIDO2 specification compliance: 100%
- WebAuthn conformance test pass rate: 100%
- Security audit findings: 0 critical, 0 high
- Penetration test findings: 0 critical

### Performance Metrics
- Registration flow: <500ms end-to-end
- Authentication flow: <300ms end-to-end
- Database query performance: <10ms average
- Memory usage: <512MB under load
- CPU usage: <50% under normal load

This specification provides a comprehensive foundation for implementing a secure, compliant FIDO2/WebAuthn Relying Party Server with extensive testing coverage and security-first design principles.