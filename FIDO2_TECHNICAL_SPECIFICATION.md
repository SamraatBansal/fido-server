# FIDO2/WebAuthn Relying Party Server - Technical Specification

## Executive Summary

This document provides a comprehensive technical specification for implementing a FIDO2/WebAuthn Relying Party Server in Rust using the webauthn-rs library. The specification focuses on security-first design, FIDO Alliance compliance, and comprehensive test-driven development.

## 1. Security Requirements

### 1.1 FIDO Alliance Compliance Requirements

#### Core Security Requirements (Testable Criteria)
- **SR-001**: Server MUST validate attestation statements according to FIDO2 specification
- **SR-002**: Server MUST implement proper challenge generation with minimum 16 bytes of entropy
- **SR-003**: Server MUST enforce origin validation for all WebAuthn operations
- **SR-004**: Server MUST implement proper user verification policies
- **SR-005**: Server MUST prevent credential cloning and replay attacks
- **SR-006**: Server MUST validate credential parameters (alg, type, transports)
- **SR-007**: Server MUST implement proper timeout handling for ceremonies
- **SR-008**: Server MUST enforce RP ID validation according to specification

#### Cryptographic Requirements
- **CR-001**: Support for ES256, RS256, EdDSA algorithms
- **CR-002**: Proper random number generation using cryptographically secure RNG
- **CR-003**: Secure storage of credential secrets with encryption at rest
- **CR-004**: Implementation of proper key derivation for credential IDs

#### Transport Security
- **TS-001**: TLS 1.2+ enforcement for all API endpoints
- **TS-002**: HSTS header implementation
- **TS-003**: CORS policy enforcement for WebAuthn APIs
- **TS-004**: Rate limiting implementation for authentication endpoints

### 1.2 Data Protection Requirements

#### Credential Storage Security
- **DS-001**: Credential private keys MUST be encrypted at rest
- **DS-002**: User-credential mapping MUST be isolated per user
- **DS-003**: Credential metadata MUST include creation timestamp and last used timestamp
- **DS-004**: Implement credential backup and recovery mechanisms

#### Privacy Requirements
- **PR-001**: Minimal data collection principle
- **PR-002**: User consent management for credential operations
- **PR-003**: Data retention policies compliant with GDPR/CCPA
- **PR-004**: Audit logging for all credential operations

## 2. Technical Scope

### 2.1 Core WebAuthn Operations

#### Registration (Attestation) Flow
**Success Conditions:**
- Valid challenge-response verification
- Proper attestation statement validation
- User verification completion
- Credential storage success
- Response format compliance

**Failure Conditions:**
- Invalid challenge
- Malformed attestation statement
- User verification failure
- Duplicate credential ID
- Storage failure
- Timeout exceeded

**Test Scenarios:**
- Valid registration with different attestation formats (packed, fido-u2f, none)
- Invalid challenge scenarios
- Malformed credential data
- User verification bypass attempts
- Concurrent registration attempts
- Network interruption handling

#### Authentication (Assertion) Flow
**Success Conditions:**
- Valid assertion signature verification
- Proper user authentication
- Credential existence validation
- Counter verification for replay protection
- Session establishment

**Failure Conditions:**
- Invalid signature
- Non-existent credential
- Counter replay detection
- User verification failure
- Expired assertion
- Malformed assertion data

**Test Scenarios:**
- Valid authentication with various algorithms
- Invalid signature scenarios
- Replay attack attempts
- Credential not found scenarios
- User verification failures
- Counter manipulation attempts

### 2.2 Edge Cases and Error Handling

#### Network and Timing Issues
- Network timeout during ceremony
- Partial request/response handling
- Concurrent request handling
- Resource exhaustion scenarios

#### Data Integrity Issues
- Corrupted credential data
- Database connection failures
- Inconsistent state recovery
- Data migration scenarios

#### Security Edge Cases
- Malformed WebAuthn data structures
- Algorithm downgrade attacks
- Origin spoofing attempts
- Credential enumeration attacks

## 3. Rust Architecture

### 3.1 Project Structure

```
src/
├── lib.rs                    # Library entry point
├── main.rs                   # Binary entry point
├── config/                   # Configuration management
│   ├── mod.rs
│   ├── app_config.rs
│   └── webauthn_config.rs
├── controllers/              # HTTP request handlers
│   ├── mod.rs
│   ├── webauthn_controller.rs
│   └── health_controller.rs
├── services/                 # Business logic
│   ├── mod.rs
│   ├── webauthn_service.rs
│   ├── credential_service.rs
│   └── user_service.rs
├── db/                       # Database layer
│   ├── mod.rs
│   ├── connection.rs
│   ├── models/
│   │   ├── mod.rs
│   │   ├── user.rs
│   │   └── credential.rs
│   └── repositories/
│       ├── mod.rs
│       ├── user_repository.rs
│       └── credential_repository.rs
├── middleware/               # HTTP middleware
│   ├── mod.rs
│   ├── auth_middleware.rs
│   ├── cors_middleware.rs
│   └── rate_limit_middleware.rs
├── routes/                   # Route definitions
│   ├── mod.rs
│   └── webauthn_routes.rs
├── error/                    # Error handling
│   ├── mod.rs
│   ├── app_error.rs
│   └── webauthn_error.rs
├── utils/                    # Utilities
│   ├── mod.rs
│   ├── crypto.rs
│   └── validation.rs
└── schema/                   # Database schema
    ├── mod.rs
    ├── users.rs
    └── credentials.rs
```

### 3.2 Core Components

#### WebAuthn Service Layer
```rust
pub struct WebAuthnService {
    webauthn: WebAuthn<WebauthnConfig>,
    credential_service: Arc<CredentialService>,
    user_service: Arc<UserService>,
}

impl WebAuthnService {
    // Registration ceremony
    pub async fn start_registration(&self, user: &User) -> Result<CreationChallengeResponse, WebAuthnError>;
    pub async fn finish_registration(&self, user: &User, response: PublicKeyCredential) -> Result<(), WebAuthnError>;
    
    // Authentication ceremony
    pub async fn start_authentication(&self, user: &User) -> Result<RequestChallengeResponse, WebAuthnError>;
    pub async fn finish_authentication(&self, user: &User, response: PublicKeyCredential) -> Result<AuthResult, WebAuthnError>;
}
```

#### Credential Management
```rust
pub struct CredentialService {
    repository: Arc<CredentialRepository>,
    crypto: Arc<CryptoService>,
}

impl CredentialService {
    pub async fn store_credential(&self, user_id: Uuid, credential: Passkey) -> Result<(), CredentialError>;
    pub async fn get_credential(&self, credential_id: &str) -> Result<Option<StoredPasskey>, CredentialError>;
    pub async fn update_credential_usage(&self, credential_id: &str, counter: u32) -> Result<(), CredentialError>;
    pub async fn delete_credential(&self, user_id: Uuid, credential_id: &str) -> Result<(), CredentialError>;
}
```

### 3.3 Testing Architecture

#### Unit Test Structure
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use mockall::predicate::*;
    
    #[tokio::test]
    async fn test_registration_challenge_generation() {
        // Test challenge generation with proper entropy
    }
    
    #[tokio::test]
    async fn test_attestation_validation() {
        // Test various attestation formats
    }
    
    #[tokio::test]
    async fn test_credential_storage_security() {
        // Test encryption at rest
    }
}
```

#### Integration Test Structure
```rust
#[cfg(test)]
mod integration_tests {
    use actix_test::TestServer;
    
    #[tokio::test]
    async fn test_full_registration_flow() {
        // End-to-end registration test
    }
    
    #[tokio::test]
    async fn test_full_authentication_flow() {
        // End-to-end authentication test
    }
}
```

## 4. API Design

### 4.1 REST Endpoints

#### Registration Endpoints

**POST /webauthn/register/challenge**
```json
Request:
{
  "username": "user@example.com",
  "displayName": "John Doe",
  "userVerification": "required"
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
    "displayName": "John Doe"
  },
  "pubKeyCredParams": [
    {"type": "public-key", "alg": -7},
    {"type": "public-key", "alg": -257}
  ],
  "timeout": 60000,
  "attestation": "direct"
}
```

**POST /webauthn/register/verify**
```json
Request:
{
  "username": "user@example.com",
  "credential": {
    "id": "base64url-encoded-credential-id",
    "rawId": "base64url-encoded-raw-id",
    "response": {
      "attestationObject": "base64url-encoded-attestation",
      "clientDataJSON": "base64url-encoded-client-data"
    },
    "type": "public-key"
  }
}

Response:
{
  "status": "ok",
  "credentialId": "base64url-encoded-credential-id",
  "signCount": 0
}
```

#### Authentication Endpoints

**POST /webauthn/authenticate/challenge**
```json
Request:
{
  "username": "user@example.com",
  "userVerification": "required"
}

Response:
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
  "timeout": 60000
}
```

**POST /webauthn/authenticate/verify**
```json
Request:
{
  "username": "user@example.com",
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
  }
}

Response:
{
  "status": "ok",
  "credentialId": "base64url-encoded-credential-id",
  "signCount": 42,
  "userVerified": true
}
```

### 4.2 Data Flow Specifications

#### Registration Flow
1. Client requests registration challenge
2. Server generates cryptographically secure challenge
3. Server stores challenge with timestamp and user context
4. Client creates credential with authenticator
5. Client submits attestation response
6. Server validates challenge, attestation, and user verification
7. Server stores credential securely
8. Server returns success response

#### Authentication Flow
1. Client requests authentication challenge
2. Server retrieves user's credentials
3. Server generates challenge and returns allowed credentials
4. Client creates assertion with authenticator
5. Client submits assertion response
6. Server validates signature, challenge, and counter
7. Server updates credential usage data
8. Server establishes authenticated session

### 4.3 Error Response Format

```json
{
  "status": "error",
  "error": {
    "code": "INVALID_CHALLENGE",
    "message": "The provided challenge is invalid or expired",
    "details": {
      "challengeId": "challenge-123",
      "expiredAt": "2024-01-01T12:00:00Z"
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
    last_login TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true
);
```

#### Credentials Table
```sql
CREATE TABLE credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id VARCHAR(255) UNIQUE NOT NULL,
    credential_data BYTEA NOT NULL, -- Encrypted Passkey data
    sign_count BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used TIMESTAMP WITH TIME ZONE,
    is_backup BOOLEAN DEFAULT false,
    transports TEXT[], -- ["internal", "usb", "nfc", "ble"]
    attestation_type VARCHAR(50),
    aaguid UUID
);

CREATE INDEX idx_credentials_user_id ON credentials(user_id);
CREATE INDEX idx_credentials_credential_id ON credentials(credential_id);
```

#### Challenges Table (for security)
```sql
CREATE TABLE challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    challenge_hash VARCHAR(255) NOT NULL,
    challenge_type VARCHAR(20) NOT NULL, -- 'registration' or 'authentication'
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used BOOLEAN DEFAULT false
);

CREATE INDEX idx_challenges_user_id ON challenges(user_id);
CREATE INDEX idx_challenges_expires_at ON challenges(expires_at);
```

### 5.2 Data Validation Requirements

#### Input Validation
- Username: 3-255 characters, email format or alphanumeric
- Display Name: 1-255 characters, no control characters
- Credential ID: Base64URL encoded, max 1024 bytes
- Challenge: Base64URL encoded, exactly 32 bytes when decoded

#### Data Integrity
- All timestamps must be in UTC
- Credential data must be encrypted before storage
- Challenge expiration must be enforced (5 minutes default)
- Sign counter must be monotonic increasing

#### Access Control
- Users can only access their own credentials
- Admin access requires separate authentication
- Audit logging for all credential operations
- Rate limiting per user and per IP

## 6. Compliance Checklist

### 6.1 FIDO2 Specification Compliance Points

#### Core Specification (Testable)
- [ ] **CT-001**: Implement WebAuthn API according to W3C Recommendation
- [ ] **CT-002**: Support for PublicKeyCredential interface
- [ ] **CT-003**: Proper implementation of CredentialCreationOptions
- [ ] **CT-004**: Proper implementation of CredentialRequestOptions
- [ ] **CT-005**: Client data JSON validation
- [ ] **CT-006**: Authenticator data structure validation
- [ ] **CT-007**: Attestation statement format validation
- [ ] **CT-008**: Assertion signature validation

#### Security Requirements (Testable)
- [ ] **SR-001**: Challenge uniqueness and randomness verification
- [ ] **SR-002**: Origin validation enforcement
- [ ] **SR-003**: RP ID validation according to effective domain
- [ ] **SR-004**: User verification policy enforcement
- [ ] **SR-005**: Counter-based replay attack prevention
- [ ] **SR-006**: Attestation trust path validation
- [ ] **SR-007**: Credential parameter validation
- [ ] **SR-008**: Timeout enforcement for ceremonies

#### Privacy Requirements (Testable)
- [ ] **PR-001**: User consent verification
- [ ] **PR-002**: Minimal data collection compliance
- [ ] **PR-003**: Data retention policy enforcement
- [ ] **PR-004**: User data deletion capability

### 6.2 FIDO Alliance Conformance Testing

#### Test Categories
1. **Server Registration Tests**
   - Valid registration scenarios
   - Invalid attestation handling
   - User verification requirements
   - Timeout handling

2. **Server Authentication Tests**
   - Valid authentication scenarios
   - Invalid assertion handling
   - Counter verification
   - Credential discovery

3. **Security Tests**
   - Replay attack prevention
   - Origin validation
   - Challenge manipulation
   - Credential enumeration

4. **Interoperability Tests**
   - Multiple authenticator types
   - Different attestation formats
   - Various algorithms
   - Cross-browser compatibility

## 7. Risk Assessment

### 7.1 Security Considerations

#### High Risk Items
1. **Credential Storage Compromise**
   - **Risk**: Unauthorized access to stored credentials
   - **Impact**: Complete account takeover
   - **Mitigation**: Encryption at rest, key rotation, access controls

2. **Challenge Replay Attacks**
   - **Risk**: Reuse of valid challenges
   - **Impact**: Authentication bypass
   - **Mitigation**: Single-use challenges, short expiration, secure storage

3. **Origin Validation Bypass**
   - **Risk**: Malicious origin acceptance
   - **Impact**: Cross-site request forgery
   - **Mitigation**: Strict origin checking, HSTS, CORS policies

#### Medium Risk Items
1. **Side-Channel Attacks**
   - **Risk**: Timing or power analysis
   - **Impact**: Partial key recovery
   - **Mitigation**: Constant-time operations, proper error handling

2. **Denial of Service**
   - **Risk**: Resource exhaustion
   - **Impact**: Service unavailability
   - **Mitigation**: Rate limiting, resource quotas, monitoring

3. **Database Injection**
   - **Risk**: SQL injection attacks
   - **Impact**: Data compromise
   - **Mitigation**: Parameterized queries, input validation

#### Low Risk Items
1. **Information Disclosure**
   - **Risk**: Sensitive data leakage
   - **Impact**: Privacy violation
   - **Mitigation**: Proper error messages, logging controls

2. **Session Hijacking**
   - **Risk**: Session token theft
   - **Impact**: Account compromise
   - **Mitigation**: Secure cookies, session rotation

### 7.2 Vulnerability Mitigation Strategies

#### Preventive Measures
1. **Secure Development Practices**
   - Code review requirements
   - Static analysis integration
   - Dependency vulnerability scanning
   - Security testing in CI/CD

2. **Operational Security**
   - Regular security audits
   - Penetration testing
   - Incident response planning
   - Security monitoring

3. **Compliance Monitoring**
   - Automated compliance checks
   - Regular specification updates
   - Third-party security assessments
   - Continuous compliance validation

#### Detective Measures
1. **Logging and Monitoring**
   - Comprehensive audit trails
   - Anomaly detection
   - Security event correlation
   - Real-time alerting

2. **Testing and Validation**
   - Automated security testing
   - FIDO conformance testing
   - Performance testing
   - Load testing

#### Corrective Measures
1. **Incident Response**
   - Rapid response procedures
   - Credential revocation
   - System recovery
   - Post-incident analysis

2. **Patch Management**
   - Regular security updates
   - Vulnerability remediation
   - Configuration management
   - Change control procedures

## 8. Implementation Roadmap

### Phase 1: Core Infrastructure (Weeks 1-2)
- Project setup and configuration
- Database schema implementation
- Basic WebAuthn service structure
- Unit test framework setup

### Phase 2: Registration Flow (Weeks 3-4)
- Challenge generation API
- Attestation validation
- Credential storage
- Registration flow testing

### Phase 3: Authentication Flow (Weeks 5-6)
- Authentication challenge API
- Assertion validation
- Session management
- Authentication flow testing

### Phase 4: Security Hardening (Weeks 7-8)
- Rate limiting implementation
- CORS and security headers
- Input validation hardening
- Security testing suite

### Phase 5: Compliance and Testing (Weeks 9-10)
- FIDO conformance testing
- Performance optimization
- Documentation completion
- Production readiness review

## 9. Success Metrics

### Technical Metrics
- Unit test coverage: ≥95%
- Integration test coverage: 100% of API endpoints
- Security test coverage: All FIDO2 requirements
- Performance: <100ms response time for 95% of requests
- Availability: 99.9% uptime

### Compliance Metrics
- FIDO Alliance conformance: 100% pass rate
- Security audit: Zero high-severity findings
- Penetration test: No critical vulnerabilities
- Code quality: Zero security warnings from static analysis

### Operational Metrics
- Mean Time to Detection (MTTD): <5 minutes
- Mean Time to Resolution (MTTR): <30 minutes
- False positive rate: <1%
- User satisfaction: >95% positive feedback

This specification provides a comprehensive foundation for implementing a secure, compliant FIDO2/WebAuthn Relying Party Server with extensive testing coverage and security-first design principles.