# FIDO2/WebAuthn Relying Party Server - Technical Specification

## Executive Summary

This document provides a comprehensive technical specification for implementing a FIDO2/WebAuthn conformant Relying Party Server in Rust using the webauthn-rs library. The specification focuses on security-first design, FIDO Alliance compliance, and comprehensive test-driven development.

## 1. Security Requirements

### 1.1 FIDO Alliance Compliance Requirements

#### Core Security Requirements (Testable Criteria)
- **RP ID Validation**: MUST validate RP ID against origin with exact string matching
- **Origin Validation**: MUST verify request origin against configured allowed origins
- **Challenge Uniqueness**: MUST generate cryptographically random challenges (minimum 16 bytes)
- **Challenge Expiration**: MUST enforce challenge expiration (maximum 10 minutes)
- **Replay Attack Prevention**: MUST prevent challenge reuse with one-time use policy
- **TLS Enforcement**: MUST enforce HTTPS in production environments
- **Credential Binding**: MUST bind credentials to specific user accounts
- **Attestation Validation**: MUST validate attestation statements when required
- **User Verification**: MUST support user verification levels (required, preferred, discouraged)

#### Testable Security Metrics
```rust
// Security test criteria
const MIN_CHALLENGE_LENGTH: usize = 16;
const MAX_CHALLENGE_AGE_SECS: u64 = 600; // 10 minutes
const MAX_CREDENTIALS_PER_USER: u32 = 10;
const ATTESTATION_TIMEOUT_MS: u64 = 30000;
```

### 1.2 Cryptographic Requirements

#### Supported Algorithms
- **ECDSA**: P-256, P-384, P-521 curves
- **RSA**: RS256, RS384, RS512 with minimum 2048-bit keys
- **EdDSA**: Ed25519, Ed448
- **COSE Key Types**: OKP, EC2, RSA

#### Key Storage Security
- Private keys MUST be stored encrypted at rest
- Key rotation support with versioning
- Secure key deletion with memory zeroization

## 2. Technical Scope

### 2.1 Core WebAuthn Operations

#### Registration (Attestation) Flow
```
1. Client → Server: POST /attestation/options
   Input: { username, displayName, userVerification }
   Output: { challenge, rp, user, pubKeyCredParams }

2. Client → Server: POST /attestation/result
   Input: { id, rawId, response: { attestationObject, clientDataJSON } }
   Output: { status, credentialId }
```

**Success Conditions:**
- Valid attestation object format
- Proper client data JSON structure
- Challenge verification success
- RP ID and origin validation
- User verification level met
- Credential not already registered

**Failure Conditions:**
- Invalid challenge or expired
- RP ID/origin mismatch
- Unsupported attestation format
- Duplicate credential registration
- Cryptographic validation failure

#### Authentication (Assertion) Flow
```
1. Client → Server: POST /assertion/options
   Input: { username, userVerification }
   Output: { challenge, allowCredentials, userVerification }

2. Client → Server: POST /assertion/result
   Input: { id, rawId, response: { authenticatorData, clientDataJSON, signature } }
   Output: { status, authenticationTime }
```

**Success Conditions:**
- Valid assertion signature
- Authenticator data integrity
- Challenge verification success
- User presence verified
- User verification level met (if required)

**Failure Conditions:**
- Invalid signature
- Challenge expired or reused
- User verification not met
- Credential not found or disabled
- Counter replay detected

### 2.2 Edge Case Testing Requirements

#### Registration Edge Cases
- Multiple credentials per user
- Attestation statement variations
- User verification level changes
- Timeout scenarios
- Network interruption handling
- Malformed request payloads

#### Authentication Edge Cases
- Lost/stolen authenticator scenarios
- Credential backup/restore
- Multiple authenticators per user
- Biometric failure fallbacks
- Device battery depletion
- Concurrent authentication attempts

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
│   ├── attestation.rs       # Registration endpoints
│   ├── assertion.rs         # Authentication endpoints
│   └── health.rs            # Health check endpoints
├── services/                 # Business logic layer
│   ├── mod.rs
│   ├── webauthn.rs          # WebAuthn service
│   ├── user.rs              # User management
│   └── credential.rs        # Credential management
├── db/                       # Database layer
│   ├── mod.rs
│   ├── connection.rs        # Connection pool
│   ├── models.rs            # Data models
│   └── repositories.rs      # Repository pattern
├── middleware/               # HTTP middleware
│   ├── mod.rs
│   ├── cors.rs              # CORS handling
│   ├── security.rs          # Security headers
│   └── rate_limit.rs        # Rate limiting
├── routes/                   # Route definitions
│   ├── mod.rs
│   └── api.rs               # API routes
├── error/                    # Error handling
│   ├── mod.rs
│   └── types.rs             # Error types
├── utils/                    # Utilities
│   ├── mod.rs
│   ├── crypto.rs            # Cryptographic utilities
│   └── validation.rs        # Input validation
└── schema/                   # Database schema
    └── mod.rs
```

### 3.2 Core Dependencies

```toml
[dependencies]
# Web Framework
actix-web = "4.9"
actix-cors = "0.7"

# FIDO/WebAuthn
webauthn-rs = "0.5"
webauthn-rs-proto = "0.5"

# Database
diesel = { version = "2.1", features = ["postgres", "r2d2", "chrono", "uuid"] }
r2d2 = "0.8"

# Security
ring = "0.17"  # For cryptographic operations
base64 = "0.22"
uuid = { version = "1.10", features = ["v4", "serde"] }

# Testing
mockall = "0.13"
actix-test = "0.1"
```

### 3.3 Testing Architecture

#### Unit Tests (95%+ Coverage Target)
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use mockall::predicate::*;
    
    #[test]
    fn test_challenge_generation() {
        // Test challenge uniqueness and length
    }
    
    #[test]
    fn test_rp_id_validation() {
        // Test RP ID validation logic
    }
    
    #[test]
    fn test_credential_storage() {
        // Test credential storage and retrieval
    }
}
```

#### Integration Tests
```rust
#[actix_rt::test]
async fn test_registration_flow() {
    // Test complete registration flow
}

#[actix_rt::test]
async fn test_authentication_flow() {
    // Test complete authentication flow
}
```

## 4. API Design

### 4.1 REST Endpoints Specification

#### Registration Endpoints

**POST /attestation/options**
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
    "id": "example.com",
    "name": "Example Service"
  },
  "user": {
    "id": "base64url-encoded-user-id",
    "name": "user@example.com",
    "displayName": "User Name"
  },
  "pubKeyCredParams": [
    { "type": "public-key", "alg": -7 },
    { "type": "public-key", "alg": -257 }
  ],
  "timeout": 60000,
  "excludeCredentials": []
}
```

**POST /attestation/result**
```json
Request:
{
  "id": "base64url-encoded-credential-id",
  "rawId": "base64url-encoded-credential-id",
  "response": {
    "attestationObject": "base64url-encoded",
    "clientDataJSON": "base64url-encoded"
  },
  "type": "public-key"
}

Response:
{
  "status": "ok",
  "credentialId": "base64url-encoded-credential-id",
  "registrationTime": "2024-01-01T00:00:00Z"
}
```

#### Authentication Endpoints

**POST /assertion/options**
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
  "allowCredentials": [
    {
      "type": "public-key",
      "id": "base64url-encoded-credential-id",
      "transports": ["usb", "nfc", "ble", "internal"]
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
  "id": "base64url-encoded-credential-id",
  "rawId": "base64url-encoded-credential-id",
  "response": {
    "authenticatorData": "base64url-encoded",
    "clientDataJSON": "base64url-encoded",
    "signature": "base64url-encoded",
    "userHandle": "base64url-encoded"
  },
  "type": "public-key"
}

Response:
{
  "status": "ok",
  "authenticationTime": "2024-01-01T00:00:00Z",
  "credentialId": "base64url-encoded-credential-id"
}
```

### 4.2 Data Flow Architecture

```
Client Request
    ↓
[Middleware Layer]
    ↓ (Security Headers, CORS, Rate Limiting)
[Controller Layer]
    ↓ (Request Validation)
[Service Layer]
    ↓ (Business Logic, WebAuthn Operations)
[Repository Layer]
    ↓ (Data Access)
[Database Layer]
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
    credential_public_key BYTEA NOT NULL,
    attestation_type VARCHAR(50) NOT NULL,
    aaguid UUID NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    is_backup_eligible BOOLEAN DEFAULT false,
    is_backed_up BOOLEAN DEFAULT false,
    transports JSONB,
    user_verification_policy VARCHAR(20) DEFAULT 'preferred'
);
```

#### Challenges Table
```sql
CREATE TABLE challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    challenge_value BYTEA NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    challenge_type VARCHAR(20) NOT NULL, -- 'attestation' or 'assertion'
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### 5.2 Data Validation Requirements

#### Input Validation
- Username: 3-255 characters, email format or alphanumeric
- Display Name: 1-255 characters, no control characters
- Challenge: Base64URL encoded, minimum 16 bytes when decoded
- Credential ID: Base64URL encoded, maximum 1023 bytes when decoded

#### Output Validation
- All timestamps in ISO 8601 format
- All binary data Base64URL encoded
- JSON responses follow strict schema validation
- Error messages sanitized for security

### 5.3 Security Storage Requirements

#### Encryption at Rest
- Credential private keys encrypted using AES-256-GCM
- Database connection encrypted (TLS)
- Backup encryption with separate key management

#### Access Control
- Database user with least privileges
- Connection pooling with authentication
- Audit logging for all data access

## 6. Compliance Checklist

### 6.1 FIDO2 Specification Compliance Points

#### Core Specification (Testable)
- [ ] RP ID validation against origin
- [ ] Challenge generation with cryptographic randomness
- [ ] Challenge expiration enforcement
- [ ] One-time challenge use enforcement
- [ ] Client data JSON validation
- [ ] Authenticator data validation
- [ ] Signature verification
- [ ] User presence verification
- [ ] User verification level enforcement
- [ ] Credential binding to user accounts

#### Attestation Compliance
- [ ] Packed attestation format support
- [ ] FIDO-U2F attestation format support
- [ ] None attestation format support
- [ ] Attestation statement validation
- [ ] AAGUID extraction and validation
- [ ] Counter value tracking

#### Metadata Compliance
- [ ] Metadata statement processing
- [ ] Trust anchor validation
- [ ] Attestation certificate chain validation
- [ ] Authenticator status checking

### 6.2 Security Compliance Testing

#### Cryptographic Tests
```rust
#[test]
fn test_signature_verification() {
    // Test ECDSA P-256 signature verification
}

#[test]
fn test_challenge_randomness() {
    // Test statistical randomness of challenges
}

#[test]
fn test_rp_id_validation() {
    // Test RP ID against various origins
}
```

#### Protocol Compliance Tests
```rust
#[test]
fn test_registration_flow_compliance() {
    // Test complete registration against FIDO2 spec
}

#[test]
fn test_authentication_flow_compliance() {
    // Test complete authentication against FIDO2 spec
}
```

## 7. Risk Assessment

### 7.1 Security Considerations

#### High Risk Items
1. **Replay Attacks**
   - Risk: Challenge reuse leading to unauthorized access
   - Mitigation: One-time challenges with immediate invalidation
   - Test: Challenge reuse attempt detection

2. **Man-in-the-Middle Attacks**
   - Risk: Request/response tampering
   - Mitigation: TLS enforcement, origin validation
   - Test: Origin validation with malicious origins

3. **Credential Theft**
   - Risk: Database compromise exposing credentials
   - Mitigation: Encryption at rest, access controls
   - Test: Database encryption verification

#### Medium Risk Items
1. **Denial of Service**
   - Risk: Resource exhaustion
   - Mitigation: Rate limiting, request validation
   - Test: Load testing with concurrent requests

2. **Side-Channel Attacks**
   - Risk: Timing attacks on cryptographic operations
   - Mitigation: Constant-time operations
   - Test: Timing analysis of critical operations

### 7.2 Vulnerability Mitigation Strategies

#### Input Validation
- Strict JSON schema validation
- Length limits on all inputs
- Character set restrictions
- SQL injection prevention

#### Error Handling
- Generic error messages for security
- Detailed logging for debugging
- Rate limiting on error responses
- Secure error reporting

#### Monitoring and Auditing
- Failed authentication attempt logging
- Anomaly detection for unusual patterns
- Security event correlation
- Regular security scanning

### 7.3 Performance Considerations

#### Scalability Requirements
- Support 1000+ concurrent users
- Sub-100ms response times for API calls
- Database connection pooling
- Efficient credential lookup

#### Performance Testing
```rust
#[tokio::test]
async fn test_concurrent_registrations() {
    // Test 100 concurrent registration attempts
}

#[tokio::test]
async fn test_authentication_performance() {
    // Test authentication under load
}
```

## 8. Implementation Roadmap

### Phase 1: Core Infrastructure (Weeks 1-2)
- [ ] Project structure setup
- [ ] Database schema implementation
- [ ] Basic WebAuthn service
- [ ] Configuration management
- [ ] Error handling framework

### Phase 2: Registration Flow (Weeks 3-4)
- [ ] Attestation options endpoint
- [ ] Attestation result endpoint
- [ ] Credential storage
- [ ] User management
- [ ] Comprehensive testing

### Phase 3: Authentication Flow (Weeks 5-6)
- [ ] Assertion options endpoint
- [ ] Assertion result endpoint
- [ ] Credential lookup
- [ ] Authentication tracking
- [ ] Security testing

### Phase 4: Security & Compliance (Weeks 7-8)
- [ ] FIDO2 compliance testing
- [ ] Security audit
- [ ] Performance optimization
- [ ] Documentation completion
- [ ] Production readiness

## 9. Testing Strategy

### 9.1 Test Coverage Requirements
- Unit Tests: 95%+ line coverage
- Integration Tests: All API endpoints
- Security Tests: FIDO2 compliance scenarios
- Performance Tests: Load and stress testing
- Compliance Tests: FIDO Alliance conformance

### 9.2 Test Categories

#### Functional Tests
- Registration flow success scenarios
- Authentication flow success scenarios
- Error handling and edge cases
- Input validation tests

#### Security Tests
- Replay attack prevention
- Origin validation
- Challenge security
- Cryptographic validation

#### Compliance Tests
- FIDO2 specification adherence
- Interoperability testing
- Metadata compliance
- Attestation validation

#### Performance Tests
- Concurrent user handling
- Response time benchmarks
- Memory usage profiling
- Database performance

This specification provides a comprehensive foundation for implementing a secure, compliant FIDO2/WebAuthn Relying Party Server with extensive testing coverage and security-first design principles.