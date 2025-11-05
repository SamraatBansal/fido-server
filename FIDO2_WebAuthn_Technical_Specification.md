# FIDO2/WebAuthn Relying Party Server - Technical Specification

## Executive Summary

This document provides a comprehensive technical analysis for implementing a FIDO2/WebAuthn Relying Party Server in Rust, focusing on security-first design, FIDO Alliance specification compliance, and test-driven development practices.

## 1. Security Requirements & Testable Criteria

### 1.1 FIDO Alliance Compliance Requirements

#### Authentication Requirements
- **Requirement**: Support FIDO2 Level 1 and Level 2 authenticators
- **Test Criteria**: Verify authenticator capabilities during registration
- **Implementation**: Parse and validate authenticator metadata statements

#### Origin Validation
- **Requirement**: Strict origin validation for all WebAuthn operations
- **Test Criteria**: Reject requests from unauthorized origins
- **Implementation**: Validate `origin` field matches configured allowed origins

#### Challenge Entropy
- **Requirement**: Generate cryptographically secure random challenges (≥32 bytes)
- **Test Criteria**: Verify challenge uniqueness and entropy
- **Implementation**: Use `rand::thread_rng()` for challenge generation

#### Replay Attack Prevention
- **Requirement**: Prevent replay attacks using challenge-response mechanism
- **Test Criteria**: Reject reused challenges and responses
- **Implementation**: Store used challenges with TTL (5 minutes)

#### Attestation Verification
- **Requirement**: Verify attestation statements according to FIDO2 spec
- **Test Criteria**: Validate attestation format, certificate chain, and signature
- **Implementation**: Use webauthn-rs attestation verification

### 1.2 Cryptographic Requirements

#### Signature Verification
- **Requirement**: Verify ECDSA/RSA signatures using stored public keys
- **Test Criteria**: Reject invalid signatures, accept valid ones
- **Implementation**: webauthn-rs handles signature verification

#### Certificate Chain Validation
- **Requirement**: Validate full certificate chain to trusted root
- **Test Criteria**: Reject expired, revoked, or untrusted certificates
- **Implementation**: Configure trusted attestation root certificates

## 2. Technical Scope & Success/Failure Conditions

### 2.1 Core WebAuthn Operations

#### Registration Flow (/attestation)
```
GET /webauthn/attestation/options/{user_id}
POST /webauthn/attestation/result/{user_id}
```

**Success Conditions:**
- Valid challenge generation (>= 32 bytes entropy)
- Proper credential creation options
- Successful attestation verification
- Credential storage with user binding

**Failure Conditions:**
- Invalid user ID format
- Challenge generation failure
- Attestation verification failure
- Database storage errors

#### Authentication Flow (/assertion)
```
GET /webauthn/assertion/options/{user_id}
POST /webauthn/assertion/result/{user_id}
```

**Success Conditions:**
- Valid authentication options generation
- Successful assertion verification
- Counter validation (anti-cloning protection)
- User presence/verification checks

**Failure Conditions:**
- No registered credentials found
- Invalid assertion signature
- Counter rollback detected
- User verification requirements not met

### 2.2 Additional Operations

#### Credential Management
```
GET /webauthn/credentials/{user_id}
DELETE /webauthn/credentials/{credential_id}
```

#### Health Check
```
GET /health
```

## 3. Rust Architecture & Project Structure

### 3.1 Recommended Project Structure

```
fido2-relying-party/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── config/
│   │   ├── mod.rs
│   │   └── settings.rs
│   ├── handlers/
│   │   ├── mod.rs
│   │   ├── attestation.rs
│   │   ├── assertion.rs
│   │   └── credentials.rs
│   ├── models/
│   │   ├── mod.rs
│   │   ├── user.rs
│   │   ├── credential.rs
│   │   └── challenge.rs
│   ├── storage/
│   │   ├── mod.rs
│   │   ├── memory.rs
│   │   ├── postgres.rs
│   │   └── traits.rs
│   ├── services/
│   │   ├── mod.rs
│   │   ├── webauthn.rs
│   │   ├── challenge.rs
│   │   └── user.rs
│   ├── middleware/
│   │   ├── mod.rs
│   │   ├── security.rs
│   │   └── cors.rs
│   └── errors/
│       ├── mod.rs
│       └── webauthn.rs
├── tests/
│   ├── integration/
│   │   ├── mod.rs
│   │   ├── attestation_tests.rs
│   │   ├── assertion_tests.rs
│   │   └── security_tests.rs
│   └── unit/
│       ├── mod.rs
│       ├── storage_tests.rs
│       └── service_tests.rs
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
└── migrations/
    └── postgres/
        ├── 001_initial.sql
        └── 002_credentials.sql
```

### 3.2 Key Dependencies (Cargo.toml)

```toml
[dependencies]
webauthn-rs = "0.5"
tokio = { version = "1.0", features = ["full"] }
axum = "0.7"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
uuid = { version = "1.0", features = ["v4", "serde"] }
sqlx = { version = "0.7", features = ["postgres", "runtime-tokio-rustls", "uuid", "time"] }
tower = "0.4"
tower-http = { version = "0.5", features = ["cors", "trace"] }
tracing = "0.1"
tracing-subscriber = "0.3"
config = "0.13"
anyhow = "1.0"
thiserror = "1.0"
base64 = "0.21"
rand = "0.8"
time = "0.3"

[dev-dependencies]
tokio-test = "0.4"
reqwest = { version = "0.11", features = ["json"] }
testcontainers = "0.15"
```

### 3.3 Testing Architecture

#### Unit Testing Strategy
- Mock storage implementations for isolated testing
- Property-based testing for cryptographic operations
- Error path validation for all failure scenarios

#### Integration Testing Strategy
- Full request/response cycle testing
- Database integration with test containers
- Cross-browser compatibility testing
- Performance and load testing

## 4. API Design & Data Flow Specifications

### 4.1 Attestation (Registration) Endpoints

#### GET /webauthn/attestation/options/{user_id}

**Request:**
```http
GET /webauthn/attestation/options/user123 HTTP/1.1
Host: relying-party.example.com
Content-Type: application/json
```

**Response (Success - 200):**
```json
{
  "status": "ok",
  "errorMessage": "",
  "rp": {
    "name": "FIDO2 Demo",
    "id": "relying-party.example.com"
  },
  "user": {
    "id": "dXNlcjEyMw==",
    "name": "user123",
    "displayName": "User 123"
  },
  "challenge": "Y2hhbGxlbmdlMTIzNDU2Nzg5MA==",
  "pubKeyCredParams": [
    {"alg": -7, "type": "public-key"},
    {"alg": -257, "type": "public-key"}
  ],
  "timeout": 300000,
  "excludeCredentials": [],
  "authenticatorSelection": {
    "authenticatorAttachment": "platform",
    "userVerification": "required",
    "residentKey": "preferred"
  },
  "attestation": "direct",
  "extensions": {}
}
```

**Response (Error - 400):**
```json
{
  "status": "failed",
  "errorMessage": "Invalid user ID format"
}
```

#### POST /webauthn/attestation/result/{user_id}

**Request:**
```json
{
  "id": "credential-id-base64",
  "rawId": "credential-id-base64",
  "response": {
    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIi...",
    "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVik..."
  },
  "type": "public-key"
}
```

**Response (Success - 200):**
```json
{
  "status": "ok",
  "errorMessage": ""
}
```

### 4.2 Assertion (Authentication) Endpoints

#### GET /webauthn/assertion/options/{user_id}

**Response (Success - 200):**
```json
{
  "status": "ok",
  "errorMessage": "",
  "challenge": "YXNzZXJ0aW9uLWNoYWxsZW5nZQ==",
  "timeout": 300000,
  "rpId": "relying-party.example.com",
  "allowCredentials": [
    {
      "id": "credential-id-base64",
      "type": "public-key",
      "transports": ["usb", "nfc", "ble", "internal"]
    }
  ],
  "userVerification": "required",
  "extensions": {}
}
```

#### POST /webauthn/assertion/result/{user_id}

**Request:**
```json
{
  "id": "credential-id-base64",
  "rawId": "credential-id-base64",
  "response": {
    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0Ii...",
    "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2M...",
    "signature": "MEUCIQDTGVqaWg_TfKT1xtZNjfVcNCbfDZqn...",
    "userHandle": "dXNlcjEyMw=="
  },
  "type": "public-key"
}
```

### 4.3 Data Flow Architecture

```
Client Browser                 Relying Party Server              Database
     |                               |                              |
     |-- GET /attestation/options ---|                              |
     |                               |-- Generate Challenge --------|
     |                               |-- Store Challenge ---------->|
     |<-- Return Options ------------|                              |
     |                               |                              |
     |-- User Gesture ---------------|                              |
     |-- Authenticator Creation -----|                              |
     |                               |                              |
     |-- POST /attestation/result ---|                              |
     |                               |-- Verify Attestation -------|
     |                               |-- Store Credential -------->|
     |<-- Registration Complete -----|                              |
```

## 5. Storage Requirements & Data Validation

### 5.1 Database Schema (PostgreSQL)

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
    attestation_object BYTEA,
    counter BIGINT NOT NULL DEFAULT 0,
    aaguid UUID,
    transports TEXT[],
    user_verified BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_credentials_user_id ON credentials(user_id);
CREATE INDEX idx_credentials_credential_id ON credentials(credential_id);
```

#### Challenges Table
```sql
CREATE TABLE challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    challenge BYTEA NOT NULL,
    challenge_type VARCHAR(20) NOT NULL CHECK (challenge_type IN ('attestation', 'assertion')),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_challenges_user_id ON challenges(user_id);
CREATE INDEX idx_challenges_expires_at ON challenges(expires_at);
```

### 5.2 Data Validation Requirements

#### Input Validation
- **User ID**: UUID format validation
- **Challenge**: Base64URL encoding, minimum 32 bytes
- **Credential ID**: Base64URL encoding, maximum 1024 bytes
- **Public Key**: Valid COSE key format
- **Origin**: Exact match against allowlist

#### Data Integrity
- **Credential Uniqueness**: Prevent duplicate credential IDs
- **Counter Validation**: Ensure monotonic increase (anti-cloning)
- **Timestamp Validation**: Verify reasonable timestamp ranges
- **Challenge Expiry**: Enforce 5-minute TTL

### 5.3 Storage Interface Design

```rust
#[async_trait]
pub trait CredentialStorage: Send + Sync {
    async fn store_user(&self, user: &User) -> Result<(), StorageError>;
    async fn get_user(&self, user_id: &Uuid) -> Result<Option<User>, StorageError>;
    async fn store_credential(&self, credential: &Credential) -> Result<(), StorageError>;
    async fn get_credentials(&self, user_id: &Uuid) -> Result<Vec<Credential>, StorageError>;
    async fn get_credential(&self, credential_id: &[u8]) -> Result<Option<Credential>, StorageError>;
    async fn update_credential_counter(&self, credential_id: &[u8], counter: u32) -> Result<(), StorageError>;
    async fn store_challenge(&self, challenge: &Challenge) -> Result<(), StorageError>;
    async fn get_challenge(&self, user_id: &Uuid, challenge_type: ChallengeType) -> Result<Option<Challenge>, StorageError>;
    async fn mark_challenge_used(&self, challenge_id: &Uuid) -> Result<(), StorageError>;
    async fn cleanup_expired_challenges(&self) -> Result<u64, StorageError>;
}
```

## 6. FIDO2 Specification Compliance Checklist

### 6.1 WebAuthn Level 1 Compliance

- [ ] **Credential Creation (navigator.credentials.create)**
  - [ ] Support publicKeyCredentialCreationOptions
  - [ ] Validate rp, user, challenge, pubKeyCredParams
  - [ ] Handle excludeCredentials list
  - [ ] Support authenticatorSelection criteria
  - [ ] Process attestation parameter

- [ ] **Credential Request (navigator.credentials.get)**
  - [ ] Support publicKeyCredentialRequestOptions
  - [ ] Validate challenge, rpId, allowCredentials
  - [ ] Handle userVerification requirements
  - [ ] Support timeout parameter

- [ ] **Attestation Verification**
  - [ ] Support packed attestation format
  - [ ] Support fido-u2f attestation format
  - [ ] Support none attestation format
  - [ ] Verify attestation statement signatures
  - [ ] Validate certificate chains

- [ ] **Assertion Verification**
  - [ ] Verify authenticator data structure
  - [ ] Validate signature over client data and authenticator data
  - [ ] Check user presence (UP) flag
  - [ ] Verify counter value increase
  - [ ] Handle user verification (UV) flag

### 6.2 WebAuthn Level 2 Compliance

- [ ] **Large Blob Extension**
  - [ ] Support largeBlob extension during registration
  - [ ] Support largeBlob extension during authentication
  - [ ] Handle blob storage and retrieval

- [ ] **Credential Properties Extension**
  - [ ] Support credProps extension
  - [ ] Report discoverable credential properties

- [ ] **Authenticator Selection Criteria**
  - [ ] Support residentKey parameter
  - [ ] Handle requireResidentKey deprecation
  - [ ] Support authenticatorAttachment filtering

### 6.3 FIDO2 CTAP2 Support

- [ ] **Platform Authenticators**
  - [ ] Support Windows Hello integration
  - [ ] Support Touch ID/Face ID integration
  - [ ] Support Android biometric authenticators

- [ ] **Roaming Authenticators**
  - [ ] Support FIDO2 security keys
  - [ ] Support USB, NFC, and BLE transports
  - [ ] Handle multiple transport mechanisms

### 6.4 Security Requirements

- [ ] **Origin Validation**
  - [ ] Verify origin matches RP ID
  - [ ] Prevent subdomain attacks
  - [ ] Handle effective domain validation

- [ ] **Challenge Security**
  - [ ] Generate cryptographically random challenges
  - [ ] Ensure challenge uniqueness
  - [ ] Implement challenge replay prevention

- [ ] **TLS Requirements**
  - [ ] Enforce HTTPS for all operations
  - [ ] Validate certificate chains
  - [ ] Support modern TLS versions (1.2+)

## 7. Risk Assessment & Mitigation Strategies

### 7.1 Security Risks

#### High-Risk Vulnerabilities

**1. Challenge Reuse Attack**
- **Risk**: Attackers replay captured challenges
- **Impact**: Authentication bypass
- **Mitigation**: Store used challenges with TTL, verify uniqueness
- **Test**: Attempt challenge reuse, verify rejection

**2. Origin Spoofing**
- **Risk**: Malicious sites impersonate legitimate RP
- **Impact**: Credential theft
- **Mitigation**: Strict origin validation, HTTPS enforcement
- **Test**: Test cross-origin requests, verify rejection

**3. Credential ID Enumeration**
- **Risk**: Attackers enumerate valid credential IDs
- **Impact**: User presence disclosure
- **Mitigation**: Consistent error responses, rate limiting
- **Test**: Enumerate credential IDs, verify no information leakage

#### Medium-Risk Vulnerabilities

**4. Counter Rollback**
- **Risk**: Cloned authenticators with reset counters
- **Impact**: Device cloning detection bypass
- **Mitigation**: Monitor counter values, alert on rollback
- **Test**: Simulate counter rollback, verify detection

**5. Timing Attacks**
- **Risk**: Information disclosure through response timing
- **Impact**: User enumeration, credential discovery
- **Mitigation**: Constant-time operations, response padding
- **Test**: Measure response times, verify consistency

**6. Database Injection**
- **Risk**: SQL injection through user inputs
- **Impact**: Data breach, system compromise
- **Mitigation**: Parameterized queries, input validation
- **Test**: Inject SQL payloads, verify sanitization

### 7.2 Operational Risks

#### Database Security
- **Risk**: Credential database compromise
- **Mitigation**: Encryption at rest, access controls, audit logging
- **Monitoring**: Failed authentication attempts, unusual patterns

#### Key Management
- **Risk**: Private key compromise
- **Mitigation**: Hardware security modules, key rotation
- **Monitoring**: Key usage patterns, unauthorized access

#### Availability
- **Risk**: DoS attacks, resource exhaustion
- **Mitigation**: Rate limiting, request validation, monitoring
- **Monitoring**: Request patterns, error rates, response times

### 7.3 Compliance Risks

#### FIDO2 Specification Violations
- **Risk**: Non-compliant implementation
- **Mitigation**: Comprehensive testing, spec validation
- **Monitoring**: Conformance test results

#### Privacy Violations
- **Risk**: Biometric data handling issues
- **Mitigation**: Local biometric processing, minimal data collection
- **Monitoring**: Data access patterns, retention compliance

## 8. Implementation Recommendations

### 8.1 Development Phases

#### Phase 1: Core Infrastructure
1. Project setup and dependency management
2. Basic HTTP server with security middleware
3. Database schema and migrations
4. Configuration management

#### Phase 2: WebAuthn Integration
1. webauthn-rs integration and configuration
2. Challenge generation and storage
3. Basic attestation flow implementation
4. Basic assertion flow implementation

#### Phase 3: Security Hardening
1. Origin validation implementation
2. Replay attack prevention
3. Rate limiting and monitoring
4. Error handling standardization

#### Phase 4: Testing & Compliance
1. Unit test suite completion
2. Integration test implementation
3. FIDO Alliance conformance testing
4. Security testing and penetration testing

### 8.2 Quality Assurance

#### Code Quality
- Rust clippy linting with strict rules
- Code coverage minimum 90%
- Documentation coverage for public APIs
- Regular dependency updates and security scanning

#### Security Testing
- Static analysis with cargo-audit
- Dynamic analysis with fuzzing
- Penetration testing for common vulnerabilities
- Third-party security audit

#### Performance Testing
- Load testing for concurrent users
- Memory usage profiling
- Database query optimization
- Response time monitoring

## 9. Conclusion

This specification provides a comprehensive foundation for implementing a secure, compliant FIDO2/WebAuthn Relying Party Server in Rust. The focus on security-first design, detailed testing criteria, and FIDO Alliance specification compliance ensures a robust implementation suitable for production environments.

Key success factors:
1. Strict adherence to FIDO2/WebAuthn specifications
2. Comprehensive security controls and monitoring
3. Robust testing strategy with high coverage
4. Clear separation of concerns in architecture
5. Detailed documentation and compliance tracking

The implementation should prioritize security over convenience and maintain strict compliance with FIDO Alliance specifications throughout the development process.