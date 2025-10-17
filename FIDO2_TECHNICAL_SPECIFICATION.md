# FIDO2/WebAuthn Relying Party Server - Technical Specification

## Executive Summary

This document provides a comprehensive technical specification for implementing a FIDO2/WebAuthn Relying Party Server in Rust using the webauthn-rs library. The specification focuses on security-first design, FIDO Alliance compliance, and comprehensive test-driven development.

## 1. Security Requirements

### 1.1 FIDO Alliance Compliance Requirements

#### 1.1.1 Core Security Requirements
- **MUST**: Implement WebAuthn Level 2 compliance (W3C Recommendation)
- **MUST**: Support FIDO2 Conformance Testing Tools v1.6+
- **MUST**: Validate all WebAuthn extensions (credProps, hmac-secret, etc.)
- **MUST**: Implement proper attestation verification
- **MUST**: Support user verification (UV) requirements

#### 1.1.2 Testable Security Criteria

| Requirement | Test Method | Success Criteria |
|-------------|-------------|------------------|
| **Attestation Verification** | Unit/Integration Tests | All attestation formats (packed, fido-u2f, none) validated |
| **Challenge Uniqueness** | Statistical Tests | No duplicate challenges in 1M operations |
| **Origin Validation** | Integration Tests | Rejects invalid origins with 100% accuracy |
| **User Verification** | Conformance Tests | Supports UVRequired, UVPreferred, UVDiscouraged |
| **Replay Attack Prevention** | Security Tests | Challenges expire within 5 minutes |
| **Credential Binding** | Database Tests | User-credential mapping integrity maintained |

### 1.2 Cryptographic Requirements

#### 1.2.1 Supported Algorithms
- **MUST**: ES256 (ECDSA with SHA-256)
- **MUST**: RS256 (RSASSA-PKCS1-v1_5 with SHA-256)
- **SHOULD**: EdDSA (Ed25519)
- **MUST**: COSE key validation per RFC8152

#### 1.2.2 Key Storage Security
- **MUST**: Private keys never stored (only public keys)
- **MUST**: Credential IDs encrypted at rest
- **MUST**: Secure random number generation (CSPRNG)
- **MUST**: Memory zeroization for sensitive data

### 1.3 Transport Security

#### 1.3.1 TLS Requirements
- **MUST**: TLS 1.2+ with strong cipher suites
- **MUST**: HSTS enforcement
- **MUST**: Certificate pinning for production
- **MUST**: Perfect Forward Secrecy (ECDHE)

#### 1.3.2 API Security
- **MUST**: CSRF protection for state-changing operations
- **MUST**: Rate limiting (100 req/min per IP)
- **MUST**: Request size limits (1MB max)
- **MUST**: Input validation and sanitization

## 2. Technical Scope

### 2.1 Core WebAuthn Operations

#### 2.1.1 Registration (Attestation) Flow

**Success Conditions:**
- Valid challenge-response verification
- Proper attestation format validation
- User verification meets requirements
- Credential stored securely with user binding
- Returns registration completion response

**Failure Conditions:**
- Invalid or expired challenge
- Mismatched origin or RP ID
- Unsupported attestation format
- User verification failure
- Duplicate credential ID
- Database storage errors

**Test Scenarios:**
```rust
// Test matrix for registration
#[test]
fn test_registration_success_scenarios() {
    // Valid ES256 attestation
    // Valid RS256 attestation
    // Valid FIDO-U2F attestation
    // Valid none attestation
}

#[test]
fn test_registration_failure_scenarios() {
    // Invalid challenge
    // Expired challenge
    // Wrong origin
    // Invalid signature
    // Duplicate credential
}
```

#### 2.1.2 Authentication (Assertion) Flow

**Success Conditions:**
- Valid assertion signature verification
- Credential exists and is not disabled
- User verification meets requirements
- Authentication counter increments
- Returns authentication success response

**Failure Conditions:**
- Invalid assertion signature
- Credential not found or disabled
- Authentication counter regression
- User verification failure
- Replay attack detected

**Test Scenarios:**
```rust
#[test]
fn test_authentication_success_scenarios() {
    // Valid ES256 assertion
    // Valid RS256 assertion
    // User verified assertion
    // User not verified assertion (if allowed)
}

#[test]
fn test_authentication_failure_scenarios() {
    // Invalid signature
    // Wrong credential ID
    // Counter regression
    // Replay attack
    // Disabled credential
}
```

### 2.2 Edge Cases and Error Handling

#### 2.2.1 Network and Timeout Scenarios
- Challenge expiration handling
- Concurrent registration attempts
- Database connection failures
- Memory pressure scenarios

#### 2.2.2 Malicious Input Handling
- Oversized requests
- Invalid JSON structures
- Malformed CBOR data
- Injection attempts

## 3. Rust Architecture

### 3.1 Project Structure

```
src/
├── lib.rs                    # Library entry point
├── main.rs                   # Binary entry point
├── config/
│   ├── mod.rs               # Configuration module
│   ├── database.rs          # Database configuration
│   └── webauthn.rs          # WebAuthn configuration
├── controllers/
│   ├── mod.rs               # Controller module
│   ├── registration.rs      # Registration endpoints
│   ├── authentication.rs    # Authentication endpoints
│   └── health.rs            # Health check endpoints
├── services/
│   ├── mod.rs               # Service module
│   ├── webauthn.rs          # WebAuthn core service
│   ├── user.rs              # User management service
│   └── credential.rs        # Credential management service
├── db/
│   ├── mod.rs               # Database module
│   ├── connection.rs        # Connection pool
│   ├── models.rs            # Database models
│   └── repositories.rs      # Repository pattern
├── middleware/
│   ├── mod.rs               # Middleware module
│   ├── auth.rs              # Authentication middleware
│   ├── cors.rs              # CORS middleware
│   └── rate_limit.rs        # Rate limiting middleware
├── routes/
│   ├── mod.rs               # Route definitions
│   └── api.rs               # API routes
├── error/
│   ├── mod.rs               # Error handling
│   └── types.rs             # Error types
└── utils/
    ├── mod.rs               # Utility functions
    ├── crypto.rs            # Cryptographic utilities
    └── validation.rs        # Input validation
```

### 3.2 Core Components

#### 3.2.1 WebAuthn Service
```rust
pub struct WebAuthnService {
    webauthn: WebAuthn<WebauthnConfig>,
    challenge_store: Arc<dyn ChallengeStore>,
    credential_repo: Arc<dyn CredentialRepository>,
}

impl WebAuthnService {
    pub async fn start_registration(&self, user: &User) -> Result<CreationChallengeResponse, WebAuthnError>;
    pub async fn finish_registration(&self, user: &User, response: PublicKeyCredential) -> Result<RegistrationResult, WebAuthnError>;
    pub async fn start_authentication(&self, user: &User) -> Result<RequestChallengeResponse, WebAuthnError>;
    pub async fn finish_authentication(&self, response: PublicKeyCredential) -> Result<AuthenticationResult, WebAuthnError>;
}
```

#### 3.2.2 Challenge Store
```rust
#[async_trait]
pub trait ChallengeStore: Send + Sync {
    async fn store_challenge(&self, challenge: &Challenge) -> Result<(), ChallengeError>;
    async fn get_and_remove_challenge(&self, challenge_id: &str) -> Result<Option<Challenge>, ChallengeError>;
    async fn cleanup_expired_challenges(&self) -> Result<usize, ChallengeError>;
}
```

#### 3.2.3 Credential Repository
```rust
#[async_trait]
pub trait CredentialRepository: Send + Sync {
    async fn store_credential(&self, credential: &StoredCredential) -> Result<(), CredentialError>;
    async fn get_credential(&self, credential_id: &str) -> Result<Option<StoredCredential>, CredentialError>;
    async fn get_user_credentials(&self, user_id: &str) -> Result<Vec<StoredCredential>, CredentialError>;
    async fn update_credential(&self, credential: &StoredCredential) -> Result<(), CredentialError>;
    async fn delete_credential(&self, credential_id: &str) -> Result<(), CredentialError>;
}
```

### 3.3 Testing Architecture

#### 3.3.1 Unit Test Structure
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use mockall::predicate::*;
    use mockall::mock;

    mock! {
        ChallengeStore {}

        #[async_trait]
        impl ChallengeStore for ChallengeStore {
            async fn store_challenge(&self, challenge: &Challenge) -> Result<(), ChallengeError>;
            async fn get_and_remove_challenge(&self, challenge_id: &str) -> Result<Option<Challenge>, ChallengeError>;
            async fn cleanup_expired_challenges(&self) -> Result<usize, ChallengeError>;
        }
    }

    #[tokio::test]
    async fn test_registration_challenge_generation() {
        // Test implementation
    }
}
```

#### 3.3.2 Integration Test Structure
```rust
#[cfg(test)]
mod integration_tests {
    use actix_web::{test, App};
    use super::*;

    #[actix_web::test]
    async fn test_registration_flow_integration() {
        // Full registration flow test
    }

    #[actix_web::test]
    async fn test_authentication_flow_integration() {
        // Full authentication flow test
    }
}
```

## 4. API Design

### 4.1 REST Endpoints

#### 4.1.1 Registration Endpoints

**POST /api/v1/registration/challenge**
```json
Request:
{
  "username": "user@example.com",
  "displayName": "User Name",
  "userVerification": "required|preferred|discouraged",
  "attestation": "none|direct|enterprise"
}

Response (200):
{
  "status": "ok",
  "challenge": "base64url-challenge",
  "user": {
    "id": "base64url-user-id",
    "name": "user@example.com",
    "displayName": "User Name"
  },
  "rp": {
    "id": "example.com",
    "name": "Example Service"
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

Response (400):
{
  "status": "error",
  "error": "INVALID_REQUEST",
  "message": "Invalid username format"
}
```

**POST /api/v1/registration/verify**
```json
Request:
{
  "credential": {
    "id": "base64url-credential-id",
    "rawId": "base64url-raw-id",
    "response": {
      "attestationObject": "base64url-attestation",
      "clientDataJSON": "base64url-client-data"
    },
    "type": "public-key"
  },
  "username": "user@example.com"
}

Response (200):
{
  "status": "ok",
  "credentialId": "base64url-credential-id",
  "userVerified": true,
  "authenticatorInfo": {
    "aaguid": "base64url-aaguid",
    "signCount": 0
  }
}

Response (400):
{
  "status": "error",
  "error": "INVALID_ATTESTATION",
  "message": "Attestation verification failed"
}
```

#### 4.1.2 Authentication Endpoints

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
  "challenge": "base64url-challenge",
  "allowCredentials": [
    {
      "type": "public-key",
      "id": "base64url-credential-id",
      "transports": ["internal", "usb", "nfc", "ble"]
    }
  ],
  "userVerification": "required",
  "timeout": 60000,
  "rpId": "example.com"
}
```

**POST /api/v1/authentication/verify**
```json
Request:
{
  "credential": {
    "id": "base64url-credential-id",
    "rawId": "base64url-raw-id",
    "response": {
      "authenticatorData": "base64url-auth-data",
      "clientDataJSON": "base64url-client-data",
      "signature": "base64url-signature",
      "userHandle": "base64url-user-handle"
    },
    "type": "public-key"
  }
}

Response (200):
{
  "status": "ok",
  "credentialId": "base64url-credential-id",
  "userVerified": true,
  "newSignCount": 42,
  "username": "user@example.com"
}
```

### 4.2 Data Flow Specifications

#### 4.2.1 Registration Flow
1. Client requests registration challenge
2. Server generates cryptographically secure challenge
3. Server stores challenge with expiration (5 minutes)
4. Server returns WebAuthn creation options
5. Client creates credential with authenticator
6. Client sends attestation response
7. Server validates challenge, signature, and attestation
8. Server stores credential with user binding
9. Server returns registration success

#### 4.2.2 Authentication Flow
1. Client requests authentication challenge
2. Server retrieves user's credentials
3. Server generates challenge and returns assertion options
4. Client signs challenge with authenticator
5. Client sends assertion response
6. Server validates challenge and signature
7. Server updates authentication counter
8. Server returns authentication success

## 5. Storage Requirements

### 5.1 Database Schema

#### 5.1.1 Users Table
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT true
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_active ON users(is_active);
```

#### 5.1.2 Credentials Table
```sql
CREATE TABLE credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA UNIQUE NOT NULL,
    credential_public_key BYTEA NOT NULL,
    aaguid BYTEA NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    user_verification_method VARCHAR(50),
    backup_eligible BOOLEAN DEFAULT false,
    backup_state BOOLEAN DEFAULT false,
    attestation_type VARCHAR(50) NOT NULL,
    transports TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true
);

CREATE INDEX idx_credentials_user_id ON credentials(user_id);
CREATE INDEX idx_credentials_credential_id ON credentials(credential_id);
CREATE INDEX idx_credentials_active ON credentials(is_active);
CREATE INDEX idx_credentials_last_used ON credentials(last_used_at);
```

#### 5.1.3 Challenges Table
```sql
CREATE TABLE challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    challenge_id VARCHAR(255) UNIQUE NOT NULL,
    challenge_data BYTEA NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    challenge_type VARCHAR(20) NOT NULL, -- 'registration' or 'authentication'
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    used_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_challenges_id ON challenges(challenge_id);
CREATE INDEX idx_challenges_expires ON challenges(expires_at);
CREATE INDEX idx_challenges_user ON challenges(user_id);
```

### 5.2 Data Validation Requirements

#### 5.2.1 Input Validation
```rust
pub struct RegistrationRequest {
    #[validate(length(min = 1, max = 255))]
    #[validate(email)]
    pub username: String,
    
    #[validate(length(min = 1, max = 255))]
    pub display_name: String,
    
    #[validate(custom = "validate_user_verification")]
    pub user_verification: Option<String>,
    
    #[validate(custom = "validate_attestation")]
    pub attestation: Option<String>,
}

pub struct CredentialResponse {
    #[validate(length(min = 1, max = 1024))]
    pub id: String,
    
    #[validate(custom = "validate_base64url")]
    pub raw_id: String,
    
    #[validate(custom = "validate_attestation_response")]
    pub response: AttestationResponse,
    
    #[validate(custom = "validate_credential_type")]
    pub r#type: String,
}
```

#### 5.2.2 Data Integrity Checks
- Credential ID uniqueness enforcement
- User-credential relationship integrity
- Challenge expiration validation
- Authentication counter monotonicity
- Transport protocol validation

### 5.3 Security Considerations

#### 5.3.1 Encryption at Rest
- Credential IDs encrypted using AES-256-GCM
- Database connection encryption (TLS)
- Backup encryption with separate keys

#### 5.3.2 Access Control
- Database user with least privileges
- Connection pooling with authentication
- Audit logging for all data access

## 6. Compliance Checklist

### 6.1 FIDO2 Specification Compliance

#### 6.1.1 WebAuthn Level 2 Requirements
- [ ] **Client Data Processing**: Proper parsing and validation of clientDataJSON
- [ ] **Authenticator Data**: Correct parsing of authenticatorData structure
- [ ] **Attestation Statement**: Support for all required attestation formats
- [ ] **Extensions**: Implement credProps and other required extensions
- [ ] **User Verification**: Proper handling of UV flags and requirements
- [ ] **Signature Verification**: Correct implementation for all COSE algorithms

#### 6.1.2 FIDO2 Conformance Testing
- [ ] **Server Registration**: Pass all server registration test cases
- [ ] **Server Authentication**: Pass all server authentication test cases
- [ ] **Metadata Service**: Integration with FIDO Metadata Service
- [ ] **Error Handling**: Proper error responses per specification
- [ ] **Edge Cases**: Handle all specification-defined edge cases

### 6.2 Security Compliance

#### 6.2.1 Cryptographic Standards
- [ ] **Random Number Generation**: Use CSPRNG for all random values
- [ ] **Key Storage**: Secure storage of public keys only
- [ ] **Hash Functions**: Use SHA-256 for all hashing operations
- [ ] **Signature Verification**: Proper implementation of signature algorithms

#### 6.2.2 Transport Security
- [ ] **TLS Configuration**: Strong cipher suites and proper configuration
- [ ] **HSTS**: HTTP Strict Transport Security enforcement
- [ ] **Certificate Validation**: Proper certificate chain validation
- [ ] **Forward Secrecy**: Ephemeral key exchange support

### 6.3 Data Protection Compliance

#### 6.3.1 Privacy Requirements
- [ ] **Data Minimization**: Store only necessary credential data
- [ ] **User Consent**: Clear consent for credential storage
- [ ] **Data Retention**: Implement credential deletion on request
- [ ] **Audit Logging**: Comprehensive audit trail for all operations

#### 6.3.2 GDPR Considerations
- [ ] **Right to Erasure**: Complete credential deletion capability
- [ ] **Data Portability**: Export user credential data
- [ ] **Consent Management**: Track and manage user consent
- [ ] **Breach Notification**: Security incident response procedures

## 7. Risk Assessment

### 7.1 Security Risks and Mitigations

#### 7.1.1 High-Risk Vulnerabilities

| Risk | Impact | Likelihood | Mitigation Strategy |
|------|--------|------------|-------------------|
| **Replay Attacks** | High | Medium | Challenge expiration, one-time use, secure random generation |
| **Credential Theft** | High | Low | Server-side storage only, encrypted at rest, access controls |
| **Man-in-the-Middle** | High | Medium | TLS enforcement, certificate pinning, origin validation |
| **Database Compromise** | High | Low | Encryption at rest, minimal data storage, access controls |
| **Side-Channel Attacks** | Medium | Low | Constant-time operations, memory zeroization |

#### 7.1.2 Implementation Risks

| Risk | Impact | Likelihood | Mitigation Strategy |
|------|--------|------------|-------------------|
| **Incorrect Signature Verification** | High | Medium | Comprehensive test suite, code review, formal verification |
| **Challenge Reuse** | High | Low | Secure challenge generation, proper cleanup, expiration |
| **Origin Validation Bypass** | High | Medium | Strict origin checking, allowlist configuration |
| **Memory Leaks** | Medium | Medium | Memory profiling, proper resource cleanup |
| **Race Conditions** | Medium | Medium | Atomic operations, proper locking, concurrent testing |

### 7.2 Operational Risks

#### 7.2.1 Availability Risks
- **Database Failover**: Implement connection pooling and failover
- **Rate Limiting**: Prevent DoS attacks while allowing legitimate use
- **Resource Exhaustion**: Monitor and limit resource usage
- **Network Partitions**: Implement proper timeout and retry logic

#### 7.2.2 Performance Risks
- **High Load**: Implement horizontal scaling capabilities
- **Large Credential Sets**: Optimize database queries and indexing
- **Memory Usage**: Monitor and optimize memory consumption
- **Response Times**: Implement performance monitoring and alerts

### 7.3 Compliance Risks

#### 7.3.1 Specification Compliance
- **Interpretation Errors**: Regular review of FIDO specifications
- **Test Coverage**: Comprehensive test suite for all requirements
- **Version Compatibility**: Support for multiple WebAuthn versions
- **Extension Support**: Proper implementation of optional extensions

#### 7.3.2 Regulatory Compliance
- **Data Protection**: Regular privacy impact assessments
- **Audit Requirements**: Comprehensive logging and monitoring
- **Incident Response**: Security incident response procedures
- **Documentation**: Maintain comprehensive technical documentation

## 8. Testing Strategy

### 8.1 Test Coverage Requirements

#### 8.1.1 Unit Testing (95%+ Coverage)
- All service methods
- Error handling paths
- Input validation
- Cryptographic operations
- Data transformation functions

#### 8.1.2 Integration Testing
- Full registration flow
- Full authentication flow
- Database operations
- API endpoint contracts
- Error propagation

#### 8.1.3 Security Testing
- FIDO2 conformance tests
- Penetration testing
- Vulnerability scanning
- Cryptographic validation
- Input fuzzing

#### 8.1.4 Performance Testing
- Load testing (1000+ concurrent users)
- Stress testing (resource limits)
- Memory leak detection
- Response time benchmarks
- Database performance

### 8.2 Test Automation

#### 8.2.1 Continuous Integration
- Automated test execution on all commits
- Code coverage reporting
- Security scanning integration
- Performance regression testing
- Compliance validation

#### 8.2.2 Test Data Management
- Automated test data generation
- Test database isolation
- Credential test vectors
- Mock authenticator responses
- Edge case data sets

## 9. Implementation Timeline

### 9.1 Phase 1: Core Infrastructure (Weeks 1-2)
- Project structure setup
- Database schema implementation
- Basic WebAuthn service
- Configuration management
- Logging and monitoring

### 9.2 Phase 2: Registration Flow (Weeks 3-4)
- Registration challenge endpoint
- Attestation verification
- Credential storage
- Unit and integration tests
- Error handling

### 9.3 Phase 3: Authentication Flow (Weeks 5-6)
- Authentication challenge endpoint
- Assertion verification
- Counter management
- Security tests
- Performance optimization

### 9.4 Phase 4: Security & Compliance (Weeks 7-8)
- FIDO2 conformance testing
- Security hardening
- Documentation
- Performance testing
- Production readiness

## 10. Success Metrics

### 10.1 Technical Metrics
- **Test Coverage**: ≥95% unit, 100% integration
- **Performance**: <100ms response time, 1000+ concurrent users
- **Security**: Zero critical vulnerabilities, FIDO2 conformance pass
- **Reliability**: 99.9% uptime, <0.1% error rate

### 10.2 Compliance Metrics
- **FIDO2 Conformance**: 100% test case pass rate
- **Security Standards**: Full compliance with OWASP guidelines
- **Data Protection**: GDPR and privacy regulation compliance
- **Audit Readiness**: Complete audit trail and documentation

This specification provides a comprehensive foundation for implementing a secure, compliant, and thoroughly tested FIDO2/WebAuthn Relying Party Server in Rust.