# FIDO2/WebAuthn Relying Party Server Technical Specification

## Executive Summary

This document provides a comprehensive technical specification for implementing a FIDO2/WebAuthn Relying Party Server in Rust using the webauthn-rs library. The specification focuses on security-first design, FIDO Alliance compliance, and comprehensive test-driven development.

## 1. Security Requirements

### 1.1 FIDO Alliance Compliance Requirements

#### Core Security Requirements (Testable Criteria)

| Requirement | Test Criteria | Security Level |
|-------------|---------------|----------------|
| **Attestation Verification** | Verify attestation statements against FIDO2 metadata | Critical |
| **User Verification** | Enforce UV flag for high-value operations | Critical |
| **RP ID Validation** | Strict RP ID matching with allowed origins | Critical |
| **Challenge Uniqueness** | Cryptographically random challenges, single-use | Critical |
| **Timeout Enforcement** | Challenge expiration within 5 minutes | High |
| **Origin Validation** | Validate against allowed origins list | Critical |
| **Credential Binding** | User-credential mapping with integrity checks | High |
| **Replay Attack Prevention** | Nonce-based challenge tracking | Critical |

#### Cryptographic Requirements

- **Algorithm Support**: ES256, RS256, EdDSA (P-256, P-384, P-521 curves)
- **Key Storage**: Encrypted at rest with AES-256-GCM
- **Random Number Generation**: CSPRNG with entropy validation
- **Hash Functions**: SHA-256, SHA-384, SHA-512
- **Signature Verification**: Full WebAuthn signature validation

### 1.2 Security Test Cases

```rust
// Security Test Matrix
#[cfg(test)]
mod security_tests {
    // Test: Challenge uniqueness and randomness
    fn test_challenge_uniqueness() {
        // Generate 1000 challenges, verify no duplicates
        // Verify entropy quality using statistical tests
    }
    
    // Test: RP ID validation
    fn test_rp_id_validation() {
        // Test valid RP IDs
        // Test malformed RP IDs
        // Test cross-origin attacks
    }
    
    // Test: Attestation verification
    fn test_attestation_verification() {
        // Test Packed attestation
        // Test FIDO-U2F attestation
        // Test None attestation
        // Test invalid attestation formats
    }
}
```

## 2. Technical Scope

### 2.1 Core WebAuthn Operations

#### Registration (Attestation) Flow

**Success Conditions:**
- Valid attestation statement format
- Proper challenge verification
- User verification completed (if required)
- Credential ID uniqueness within RP
- AAGUID validation against metadata
- Proper origin and RP ID validation

**Failure Conditions:**
- Invalid attestation format
- Challenge mismatch or expired
- User verification failed
- Duplicate credential ID
- Invalid origin/RP ID
- Cryptographic verification failure

#### Authentication (Assertion) Flow

**Success Conditions:**
- Valid assertion signature
- Challenge verification
- User presence verification
- User verification (if required)
- Credential exists and is not disabled
- Proper authentication counter validation

**Failure Conditions:**
- Invalid signature
- Challenge mismatch or expired
- Counter replay detected
- Credential not found or disabled
- User verification failed
- Invalid origin/RP ID

### 2.2 Edge Case Testing Requirements

```rust
// Edge Case Test Scenarios
#[cfg(test)]
mod edge_cases {
    // Concurrent registration attempts
    fn test_concurrent_registrations() {
        // Multiple users registering simultaneously
        // Race condition handling
    }
    
    // Credential overflow scenarios
    fn test_credential_limits() {
        // Maximum credentials per user
        // Storage capacity limits
    }
    
    // Network failure scenarios
    fn test_network_failures() {
        // Timeout during registration
        // Partial request handling
    }
    
    // Malformed request handling
    fn test_malformed_requests() {
        // Invalid JSON structures
        // Oversized payloads
        // Missing required fields
    }
}
```

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
│   └── user.rs              # User management
├── services/
│   ├── mod.rs               # Service module
│   ├── webauthn.rs          # WebAuthn core service
│   ├── credential.rs        # Credential management
│   └── user.rs              # User service
├── db/
│   ├── mod.rs               # Database module
│   ├── connection.rs        # Connection pool
│   ├── models.rs            # Database models
│   └── repositories.rs      # Data access layer
├── middleware/
│   ├── mod.rs               # Middleware module
│   ├── auth.rs              # Authentication middleware
│   ├── cors.rs              # CORS handling
│   └── rate_limit.rs        # Rate limiting
├── routes/
│   ├── mod.rs               # Route definitions
│   ├── webauthn.rs          # WebAuthn routes
│   └── health.rs            # Health check routes
├── error/
│   ├── mod.rs               # Error handling
│   └── types.rs             # Error types
├── utils/
│   ├── mod.rs               # Utility functions
│   ├── crypto.rs            # Cryptographic utilities
│   └── validation.rs        # Input validation
└── schema/                  # Diesel schema files
    └── migrations/          # Database migrations
```

### 3.2 Testing Architecture

```
tests/
├── integration/             # Integration tests
│   ├── registration_tests.rs
│   ├── authentication_tests.rs
│   └── api_contract_tests.rs
├── security/               # Security tests
│   ├── attestation_tests.rs
│   ├── replay_attack_tests.rs
│   └── compliance_tests.rs
├── performance/            # Performance tests
│   ├── load_tests.rs
│   └── concurrency_tests.rs
└── fixtures/               # Test fixtures
    ├── test_data.rs
    └── mock_data.rs
```

### 3.3 Core Dependencies

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
r2d2 = "0.8"

# Security
base64 = "0.22"
uuid = { version = "1.10", features = ["v4", "serde"] }
sha2 = "0.10"

# Testing
mockall = "0.13"
actix-test = "0.1"
```

## 4. API Design

### 4.1 REST Endpoints Specification

Based on FIDO Alliance Conformance Test API:

#### Registration Endpoints

```http
POST /webauthn/register/begin
Content-Type: application/json

Request:
{
  "username": "user@example.com",
  "displayName": "User Name",
  "attestation": "direct",
  "authenticatorSelection": {
    "authenticatorAttachment": "platform",
    "requireResidentKey": false,
    "userVerification": "required"
  },
  "extensions": {
    "credProps": true
  }
}

Response:
{
  "status": "ok",
  "errorMessage": "",
  "challenge": "base64url-challenge",
  "rp": {
    "name": "FIDO Server",
    "id": "example.com"
  },
  "user": {
    "id": "base64url-user-id",
    "name": "user@example.com",
    "displayName": "User Name"
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
  },
  "extensions": {
    "credProps": true
  }
}
```

```http
POST /webauthn/register/complete
Content-Type: application/json

Request:
{
  "credential": {
    "id": "base64url-credential-id",
    "rawId": "base64url-raw-id",
    "type": "public-key",
    "response": {
      "attestationObject": "base64url-attestation",
      "clientDataJSON": "base64url-client-data"
    }
  },
  "username": "user@example.com",
  "sessionData": {
    "challenge": "base64url-challenge",
    "timestamp": 1234567890
  }
}

Response:
{
  "status": "ok",
  "errorMessage": "",
  "credentialId": "base64url-credential-id",
  "newUser": false
}
```

#### Authentication Endpoints

```http
POST /webauthn/authenticate/begin
Content-Type: application/json

Request:
{
  "username": "user@example.com",
  "userVerification": "required"
}

Response:
{
  "status": "ok",
  "errorMessage": "",
  "challenge": "base64url-challenge",
  "rpId": "example.com",
  "allowCredentials": [
    {
      "type": "public-key",
      "id": "base64url-credential-id",
      "transports": ["internal", "usb"]
    }
  ],
  "userVerification": "required",
  "timeout": 60000
}
```

```http
POST /webauthn/authenticate/complete
Content-Type: application/json

Request:
{
  "credential": {
    "id": "base64url-credential-id",
    "rawId": "base64url-raw-id",
    "type": "public-key",
    "response": {
      "authenticatorData": "base64url-auth-data",
      "clientDataJSON": "base64url-client-data",
      "signature": "base64url-signature",
      "userHandle": "base64url-user-handle"
    }
  },
  "username": "user@example.com",
  "sessionData": {
    "challenge": "base64url-challenge",
    "timestamp": 1234567890
  }
}

Response:
{
  "status": "ok",
  "errorMessage": "",
  "credentialId": "base64url-credential-id",
  "user": {
    "id": "base64url-user-id",
    "name": "user@example.com",
    "displayName": "User Name"
  }
}
```

### 4.2 Data Flow Specifications

#### Registration Flow
1. Client requests registration challenge
2. Server generates cryptographically random challenge
3. Server stores challenge with timestamp and user context
4. Client creates credential with attestation
5. Server verifies attestation and challenge
6. Server stores credential with user binding

#### Authentication Flow
1. Client requests authentication challenge
2. Server retrieves user's credentials
3. Server generates challenge for specific credentials
4. Client creates assertion with credential
5. Server verifies assertion and challenge
6. Server updates authentication counter

## 5. Storage Requirements

### 5.1 Database Schema

```sql
-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT true
);

-- Credentials table
CREATE TABLE credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA UNIQUE NOT NULL,
    credential_type VARCHAR(50) NOT NULL DEFAULT 'public-key',
    public_key BYTEA NOT NULL,
    attestation_type VARCHAR(50) NOT NULL,
    aaguid BYTEA,
    sign_count BIGINT NOT NULL DEFAULT 0,
    transports JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    is_backup_eligible BOOLEAN DEFAULT false,
    is_backed_up BOOLEAN DEFAULT false,
    is_resident BOOLEAN DEFAULT false,
    user_verification_required BOOLEAN DEFAULT false,
    is_active BOOLEAN DEFAULT true
);

-- Challenges table (for replay protection)
CREATE TABLE challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    challenge_hash BYTEA NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    challenge_type VARCHAR(20) NOT NULL, -- 'registration' or 'authentication'
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    used_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(challenge_hash, challenge_type)
);

-- Session data table
CREATE TABLE session_data (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id VARCHAR(255) UNIQUE NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    challenge_hash BYTEA NOT NULL,
    data JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);
```

### 5.2 Data Validation Requirements

```rust
// Input validation schemas
use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct RegistrationBeginRequest {
    #[validate(email)]
    pub username: String,
    
    #[validate(length(min = 1, max = 255))]
    pub display_name: String,
    
    #[validate(custom = "validate_attestation_format")]
    pub attestation: Option<String>,
    
    pub authenticator_selection: Option<AuthenticatorSelection>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct RegistrationCompleteRequest {
    #[validate(custom = "validate_credential")]
    pub credential: PublicKeyCredential,
    
    #[validate(email)]
    pub username: String,
    
    #[validate(custom = "validate_session_data")]
    pub session_data: SessionData,
}

// Validation functions
fn validate_attestation_format(attestation: &str) -> Result<(), validator::ValidationError> {
    match attestation {
        "none" | "indirect" | "direct" | "enterprise" => Ok(()),
        _ => Err(validator::ValidationError::new("invalid_attestation")),
    }
}

fn validate_credential(credential: &PublicKeyCredential) -> Result<(), validator::ValidationError> {
    // Validate credential ID format
    // Validate response structure
    // Validate base64url encoding
    Ok(())
}
```

### 5.3 Storage Security Requirements

- **Encryption at Rest**: All sensitive data encrypted with AES-256-GCM
- **Key Management**: Separate key management service for encryption keys
- **Access Control**: Database-level access controls with least privilege
- **Audit Logging**: All credential operations logged with timestamps
- **Backup Security**: Encrypted backups with secure key rotation

## 6. Compliance Checklist

### 6.1 FIDO2 Specification Compliance Points

#### Core Specification (Level 1)
- [ ] **§5.1.1** RP ID validation
- [ ] **§5.1.2** Origin validation
- [ ] **§5.2** Challenge generation and management
- [ ] **§5.3** User verification requirements
- [ ] **§5.4** Credential storage and binding
- [ ] **§5.5** Attestation verification
- [ ] **§5.6** Authentication counter validation

#### WebAuthn Specification (Level 2)
- [ ] **§6.1** Registration ceremony
- [ ] **§6.2** Authentication ceremony
- [ ] **§6.3** Credential management
- [ ] **§6.4** Extension support
- [ ] **§6.5** Error handling
- [ ] **§6.6** Metadata service integration

#### Security Requirements
- [ ] **§7.1** Cryptographic algorithm support
- [ ] **§7.2** Random number generation
- [ ] **§7.3** Replay attack prevention
- [ ] **§7.4** Man-in-the-middle protection
- [ ] **§7.5** Phishing resistance

### 6.2 Testable Compliance Points

```rust
#[cfg(test)]
mod compliance_tests {
    use webauthn_rs::prelude::*;
    
    // Test: RP ID validation compliance
    #[test]
    fn test_rp_id_compliance() {
        // Test valid RP ID formats
        // Test invalid RP ID formats
        // Test subdomain handling
        // Test port handling
    }
    
    // Test: Challenge compliance
    #[test]
    fn test_challenge_compliance() {
        // Test challenge length (minimum 16 bytes)
        // Test challenge randomness
        // Test challenge expiration
        // Test challenge single-use
    }
    
    // Test: Attestation compliance
    #[test]
    fn test_attestation_compliance() {
        // Test Packed attestation format
        // Test FIDO-U2F attestation format
        // Test None attestation format
        // Test invalid attestation rejection
    }
    
    // Test: Authentication counter compliance
    #[test]
    fn test_counter_compliance() {
        // Test counter increment
        // Test counter replay detection
        // Test counter overflow handling
    }
}
```

## 7. Risk Assessment

### 7.1 Security Considerations

#### High Risk Items

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| **Replay Attacks** | Critical | Medium | Challenge tracking, timestamp validation |
| **Credential Theft** | Critical | Low | Encrypted storage, secure key management |
| **Man-in-the-Middle** | Critical | Medium | TLS enforcement, origin validation |
| **Phishing** | High | High | RP ID validation, user verification |
| **Denial of Service** | Medium | High | Rate limiting, resource quotas |

#### Medium Risk Items

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| **Credential Enumeration** | Medium | Medium | Generic error messages |
| **Session Hijacking** | Medium | Low | Secure session management |
| **Database Compromise** | High | Low | Encryption at rest, access controls |
| **Side-Channel Attacks** | Medium | Low | Constant-time operations |

### 7.2 Vulnerability Mitigation Strategies

#### Replay Attack Prevention
```rust
pub struct ChallengeManager {
    challenges: Arc<RwLock<HashMap<String, ChallengeData>>>,
    cleanup_interval: Duration,
}

impl ChallengeManager {
    pub async fn verify_challenge(
        &self,
        challenge: &str,
        challenge_type: ChallengeType,
    ) -> Result<(), WebAuthnError> {
        let challenges = self.challenges.read().await;
        
        match challenges.get(challenge) {
            Some(data) if data.challenge_type == challenge_type => {
                if data.used_at.is_some() {
                    return Err(WebAuthnError::ChallengeAlreadyUsed);
                }
                if data.expires_at < Utc::now() {
                    return Err(WebAuthnError::ChallengeExpired);
                }
                Ok(())
            }
            _ => Err(WebAuthnError::InvalidChallenge),
        }
    }
}
```

#### Secure Credential Storage
```rust
pub struct CredentialStorage {
    encryption_key: Vec<u8>,
    db_pool: PgPool,
}

impl CredentialStorage {
    pub async fn store_credential(
        &self,
        credential: &WebAuthnCredential,
    ) -> Result<(), StorageError> {
        let encrypted_key = self.encrypt_credential_key(&credential.public_key)?;
        let encrypted_data = self.encrypt_credential_data(credential)?;
        
        sqlx::query!(
            r#"
            INSERT INTO credentials (
                user_id, credential_id, public_key, credential_data
            ) VALUES ($1, $2, $3, $4)
            "#,
            credential.user_id,
            credential.credential_id,
            encrypted_key,
            encrypted_data
        )
        .execute(&self.db_pool)
        .await?;
        
        Ok(())
    }
}
```

### 7.3 Security Testing Requirements

```rust
#[cfg(test)]
mod security_tests {
    // Test: Replay attack prevention
    #[tokio::test]
    async fn test_replay_attack_prevention() {
        // Use same challenge twice
        // Verify second attempt fails
    }
    
    // Test: Credential enumeration prevention
    #[tokio::test]
    async fn test_credential_enumeration_prevention() {
        // Request authentication for non-existent user
        // Verify response doesn't reveal user existence
    }
    
    // Test: Origin validation
    #[tokio::test]
    async fn test_origin_validation() {
        // Test with invalid origin
        // Test with malformed origin
        // Test with cross-origin attempts
    }
    
    // Test: Rate limiting
    #[tokio::test]
    async fn test_rate_limiting() {
        // Send rapid requests
        // Verify rate limiting enforcement
    }
}
```

## 8. Implementation Roadmap

### Phase 1: Core Infrastructure (Weeks 1-2)
- [ ] Project structure setup
- [ ] Database schema and migrations
- [ ] Basic WebAuthn configuration
- [ ] Error handling framework
- [ ] Logging and monitoring

### Phase 2: Registration Flow (Weeks 3-4)
- [ ] Registration begin endpoint
- [ ] Registration complete endpoint
- [ ] Attestation verification
- [ ] Credential storage
- [ ] Unit and integration tests

### Phase 3: Authentication Flow (Weeks 5-6)
- [ ] Authentication begin endpoint
- [ ] Authentication complete endpoint
- [ ] Assertion verification
- [ ] Counter management
- [ ] Security tests

### Phase 4: Security Hardening (Weeks 7-8)
- [ ] Rate limiting implementation
- [ ] Input validation
- [ ] Encryption at rest
- [ ] Security audit
- [ ] Compliance testing

### Phase 5: Performance & Compliance (Weeks 9-10)
- [ ] Performance optimization
- [ ] Load testing
- [ ] FIDO compliance testing
- [ ] Documentation
- [ ] Production deployment

## 9. Success Metrics

### Security Metrics
- Zero critical vulnerabilities in security audit
- 100% FIDO2 compliance test pass rate
- <100ms average response time for operations
- 99.9% uptime under normal load

### Testing Metrics
- 95%+ unit test coverage
- 100% API endpoint integration test coverage
- All security test scenarios passing
- Performance benchmarks meeting requirements

### Compliance Metrics
- Full FIDO Alliance specification compliance
- Successful conformance test tool execution
- Proper attestation verification for all formats
- Complete metadata service integration

This specification provides a comprehensive foundation for implementing a secure, compliant FIDO2/WebAuthn Relying Party Server with extensive testing coverage and security-first design principles.