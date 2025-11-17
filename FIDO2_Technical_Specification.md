# FIDO2/WebAuthn Relying Party Server - Technical Specification

## Executive Summary
This document provides a comprehensive technical analysis for implementing a FIDO2/WebAuthn Relying Party Server in Rust, focusing on security-first design and full FIDO Alliance specification compliance.

## 1. Security Requirements

### 1.1 FIDO Alliance Compliance Requirements
**Testable Criteria:**
- ✅ WebAuthn Level 2 specification compliance (W3C Recommendation)
- ✅ FIDO2 Client to Authenticator Protocol (CTAP2) support
- ✅ Attestation verification according to FIDO Metadata Service
- ✅ Origin validation and Relying Party ID verification
- ✅ Challenge entropy requirements (minimum 64 bytes)
- ✅ Timeout enforcement (30 seconds for registration, 60 seconds for authentication)

### 1.2 Cryptographic Requirements
**Testable Security Controls:**
```rust
// Required algorithms support
- ES256 (ECDSA w/ P-256 & SHA-256) - REQUIRED
- ES384 (ECDSA w/ P-384 & SHA-384) - OPTIONAL
- ES512 (ECDSA w/ P-521 & SHA-512) - OPTIONAL
- PS256 (RSASSA-PSS w/ SHA-256) - OPTIONAL
- EdDSA (Ed25519) - OPTIONAL
```

### 1.3 Security Headers and TLS
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
```

## 2. Technical Scope

### 2.1 Core WebAuthn Operations

#### 2.1.1 Registration Flow
**Success Conditions:**
- Valid attestation object verification
- Credential ID uniqueness validation
- User verification flag compliance
- Public key extraction and storage

**Failure Conditions:**
- Invalid attestation format
- Duplicate credential ID
- Invalid origin/RP ID
- Timeout exceeded
- User verification failed

#### 2.1.2 Authentication Flow  
**Success Conditions:**
- Valid assertion signature verification
- Counter value progression
- User presence verification
- Credential lookup success

**Failure Conditions:**
- Invalid signature
- Counter regression attack
- Unknown credential ID
- User verification mismatch

### 2.2 Supported Authenticator Types
```rust
pub enum AuthenticatorAttachment {
    Platform,     // Platform authenticators (TouchID, FaceID, Windows Hello)
    CrossPlatform, // Roaming authenticators (YubiKey, etc.)
    Both,         // Allow both types
}
```

## 3. Rust Architecture

### 3.1 Project Structure
```
fido2-rp-server/
├── src/
│   ├── main.rs                 # Application entry point
│   ├── lib.rs                  # Library root
│   ├── api/                    # REST API layer
│   │   ├── mod.rs
│   │   ├── registration.rs     # Registration endpoints
│   │   ├── authentication.rs   # Authentication endpoints
│   │   └── middleware.rs       # Security middleware
│   ├── core/                   # Core WebAuthn logic
│   │   ├── mod.rs
│   │   ├── webauthn.rs        # WebAuthn service wrapper
│   │   ├── challenge.rs       # Challenge management
│   │   └── verification.rs    # Verification logic
│   ├── storage/               # Storage layer
│   │   ├── mod.rs
│   │   ├── memory.rs          # In-memory storage
│   │   ├── postgres.rs        # PostgreSQL storage
│   │   └── traits.rs          # Storage abstractions
│   ├── models/                # Data models
│   │   ├── mod.rs
│   │   ├── user.rs            # User models
│   │   ├── credential.rs      # Credential models
│   │   └── challenge.rs       # Challenge models
│   ├── config/                # Configuration
│   │   ├── mod.rs
│   │   └── settings.rs        # Application settings
│   └── error/                 # Error handling
│       ├── mod.rs
│       └── types.rs           # Custom error types
├── tests/                     # Integration tests
│   ├── integration/
│   │   ├── registration_test.rs
│   │   ├── authentication_test.rs
│   │   └── security_test.rs
│   └── conformance/           # FIDO Alliance conformance tests
├── migrations/                # Database migrations
├── docker/                    # Docker configuration
├── Cargo.toml
└── README.md
```

### 3.2 Key Dependencies
```toml
[dependencies]
webauthn-rs = "0.5"
tokio = { version = "1.0", features = ["full"] }
axum = "0.7"
sqlx = { version = "0.7", features = ["postgres", "runtime-tokio-rustls", "uuid", "chrono"] }
serde = { version = "1.0", features = ["derive"] }
uuid = { version = "1.0", features = ["v4"] }
chrono = { version = "0.4", features = ["serde"] }
tracing = "0.1"
tower = "0.4"
tower-http = { version = "0.5", features = ["cors", "trace"] }

[dev-dependencies]
reqwest = { version = "0.11", features = ["json"] }
tokio-test = "0.4"
```

## 4. API Design

### 4.1 Registration Endpoints

#### 4.1.1 POST /webauthn/register/begin
**Request:**
```json
{
    "username": "alice@example.com",
    "display_name": "Alice Smith",
    "user_verification": "required", // "required", "preferred", "discouraged"
    "authenticator_selection": {
        "authenticator_attachment": "cross-platform", // "platform", "cross-platform"
        "require_resident_key": false,
        "user_verification": "required"
    },
    "attestation": "direct" // "none", "indirect", "direct", "enterprise"
}
```

**Response (Success - 200):**
```json
{
    "status": "ok",
    "errorMessage": "",
    "challenge": "base64url-encoded-challenge",
    "rp": {
        "id": "example.com",
        "name": "Example Corp"
    },
    "user": {
        "id": "base64url-encoded-user-id",
        "name": "alice@example.com",
        "displayName": "Alice Smith"
    },
    "pubKeyCredParams": [
        {"type": "public-key", "alg": -7},
        {"type": "public-key", "alg": -257}
    ],
    "timeout": 30000,
    "excludeCredentials": [],
    "authenticatorSelection": {
        "authenticatorAttachment": "cross-platform",
        "requireResidentKey": false,
        "userVerification": "required"
    },
    "attestation": "direct"
}
```

#### 4.1.2 POST /webauthn/register/complete
**Request:**
```json
{
    "id": "credential-id",
    "rawId": "base64url-credential-id",
    "response": {
        "clientDataJSON": "base64url-client-data",
        "attestationObject": "base64url-attestation-object"
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

### 4.2 Authentication Endpoints

#### 4.2.1 POST /webauthn/authenticate/begin
**Request:**
```json
{
    "username": "alice@example.com",
    "user_verification": "required"
}
```

**Response (Success - 200):**
```json
{
    "status": "ok",
    "errorMessage": "",
    "challenge": "base64url-encoded-challenge",
    "timeout": 60000,
    "rpId": "example.com",
    "allowCredentials": [
        {
            "type": "public-key",
            "id": "base64url-credential-id",
            "transports": ["usb", "nfc", "ble"]
        }
    ],
    "userVerification": "required"
}
```

#### 4.2.2 POST /webauthn/authenticate/complete
**Request:**
```json
{
    "id": "credential-id",
    "rawId": "base64url-credential-id",
    "response": {
        "clientDataJSON": "base64url-client-data",
        "authenticatorData": "base64url-authenticator-data",
        "signature": "base64url-signature",
        "userHandle": "base64url-user-handle"
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

### 4.3 Error Response Format
```json
{
    "status": "failed",
    "errorMessage": "Detailed error description",
    "errorCode": "INVALID_CHALLENGE" // Standardized error codes
}
```

## 5. Storage Requirements

### 5.1 Database Schema

#### 5.1.1 Users Table
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    user_handle BYTEA UNIQUE NOT NULL, -- WebAuthn user.id
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

#### 5.1.2 Credentials Table
```sql
CREATE TABLE credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA UNIQUE NOT NULL,
    public_key BYTEA NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    credential_type VARCHAR(50) NOT NULL, -- 'public-key'
    attestation_type VARCHAR(50) NOT NULL, -- 'basic', 'self', 'attca', 'ecdaa'
    transports TEXT[], -- ['usb', 'nfc', 'ble', 'internal']
    aaguid UUID, -- Authenticator AAGUID
    backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,
    backup_state BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ
);
```

#### 5.1.3 Challenges Table
```sql
CREATE TABLE challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    challenge BYTEA UNIQUE NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    challenge_type VARCHAR(20) NOT NULL, -- 'registration', 'authentication'
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### 5.2 Data Validation Requirements
```rust
// Credential validation rules
pub struct CredentialValidator;

impl CredentialValidator {
    pub fn validate_credential_id(id: &[u8]) -> Result<(), ValidationError> {
        if id.len() < 16 || id.len() > 1024 {
            return Err(ValidationError::InvalidCredentialIdLength);
        }
        Ok(())
    }
    
    pub fn validate_sign_count(current: u32, stored: u32) -> Result<(), ValidationError> {
        if current < stored && current != 0 {
            return Err(ValidationError::CounterRegression);
        }
        Ok(())
    }
}
```

### 5.3 In-Memory Storage for Testing
```rust
use std::collections::HashMap;
use tokio::sync::RwLock;

pub struct InMemoryStorage {
    users: RwLock<HashMap<String, User>>,
    credentials: RwLock<HashMap<Vec<u8>, Credential>>,
    challenges: RwLock<HashMap<Vec<u8>, Challenge>>,
}
```

## 6. Compliance Checklist

### 6.1 FIDO2 Specification Compliance
- [ ] **WebAuthn API Compliance**
  - [ ] PublicKeyCredentialCreationOptions structure
  - [ ] PublicKeyCredentialRequestOptions structure
  - [ ] Attestation object parsing and verification
  - [ ] Assertion response verification

- [ ] **Security Requirements**
  - [ ] Challenge randomness (minimum 64 bytes entropy)
  - [ ] Origin validation against RP ID
  - [ ] Signature verification using stored public key
  - [ ] Counter value progression validation

- [ ] **Attestation Support**
  - [ ] None attestation
  - [ ] Self attestation
  - [ ] Basic attestation
  - [ ] AttCA attestation (optional)

- [ ] **User Verification Levels**
  - [ ] Required user verification
  - [ ] Preferred user verification
  - [ ] Discouraged user verification

### 6.2 FIDO Alliance Conformance Tests
Reference: [FIDO Alliance Conformance Test API](https://github.com/fido-alliance/conformance-test-tools-resources/blob/main/docs/FIDO2/Server/Conformance-Test-API.md)

**Required Test Categories:**
- [ ] Registration conformance tests
- [ ] Authentication conformance tests
- [ ] Negative testing scenarios
- [ ] Edge case handling

## 7. Risk Assessment

### 7.1 Security Considerations

#### 7.1.1 High-Risk Areas
1. **Challenge Management**
   - **Risk**: Challenge reuse attacks
   - **Mitigation**: Single-use challenges with short TTL (30-60 seconds)
   - **Test**: Verify challenge uniqueness and expiration

2. **Credential Storage**
   - **Risk**: Credential theft from database
   - **Mitigation**: No private keys stored, only public keys
   - **Test**: Verify no sensitive data in storage

3. **Origin Validation**
   - **Risk**: Cross-origin attacks
   - **Mitigation**: Strict origin and RP ID validation
   - **Test**: Verify rejection of invalid origins

#### 7.1.2 Potential Vulnerabilities

1. **Replay Attacks**
   ```rust
   // Mitigation: Challenge-response with nonce
   pub fn verify_challenge_freshness(&self, challenge: &[u8]) -> Result<bool, Error> {
       // Implementation ensures challenge is recent and unused
   }
   ```

2. **Counter Regression Attacks**
   ```rust
   // Mitigation: Monotonic counter verification
   pub fn verify_sign_count(&self, current: u32, stored: u32) -> Result<(), Error> {
       if current < stored && current != 0 {
           return Err(Error::CounterRegression);
       }
       Ok(())
   }
   ```

3. **Session Fixation**
   - **Risk**: Challenge prediction
   - **Mitigation**: Cryptographically secure random challenge generation
   - **Test**: Verify challenge entropy and unpredictability

### 7.2 Mitigation Strategies

#### 7.2.1 Rate Limiting
```rust
// Per-endpoint rate limits
pub struct RateLimiter {
    registration_limit: u32,  // 5 attempts per minute
    authentication_limit: u32, // 10 attempts per minute
}
```

#### 7.2.2 Logging and Monitoring
```rust
// Security event logging
pub enum SecurityEvent {
    SuccessfulRegistration(UserId),
    FailedRegistration(String, String), // username, reason
    SuccessfulAuthentication(UserId),
    FailedAuthentication(String, String),
    SuspiciousActivity(String), // description
}
```

## 8. Implementation Priority

### 8.1 Phase 1: Core Implementation
1. Basic WebAuthn integration with webauthn-rs
2. In-memory storage implementation
3. Registration and authentication flows
4. Basic error handling

### 8.2 Phase 2: Production Readiness
1. PostgreSQL storage implementation
2. Comprehensive error handling
3. Security middleware
4. Rate limiting

### 8.3 Phase 3: Advanced Features
1. FIDO Metadata Service integration
2. Advanced attestation verification
3. Comprehensive logging and monitoring
4. Performance optimization

## 9. Testing Strategy

### 9.1 Unit Tests
- Individual function validation
- Error case coverage
- Edge case handling

### 9.2 Integration Tests
- Complete registration flow
- Complete authentication flow
- Database integration
- API endpoint testing

### 9.3 Security Tests
- Challenge uniqueness
- Origin validation
- Replay attack prevention
- Counter regression detection

### 9.4 Conformance Tests
- FIDO Alliance test suite compliance
- WebAuthn specification compliance
- Cross-browser compatibility

## 10. Configuration Management

```rust
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub rp_id: String,
    pub rp_name: String,
    pub rp_origin: String,
    pub database_url: String,
    pub tls_cert_path: String,
    pub tls_key_path: String,
    pub challenge_timeout: Duration,
    pub max_credentials_per_user: usize,
}
```

This specification provides the foundation for implementing a secure, compliant FIDO2/WebAuthn Relying Party Server with comprehensive testing coverage and security-first design principles.