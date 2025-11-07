# FIDO2/WebAuthn Relying Party Server - Technical Specification

## Executive Summary

This specification defines a FIDO2/WebAuthn Relying Party Server implementation in Rust, focusing on security-first design, FIDO Alliance specification compliance, and comprehensive test coverage.

## 1. Security Requirements & Testable Criteria

### 1.1 FIDO Alliance Compliance Requirements

| Requirement | Test Criteria | Priority |
|-------------|---------------|----------|
| **FIDO2 Level 1 Compliance** | All CTAP2 and WebAuthn operations pass FIDO conformance tests | Critical |
| **Attestation Verification** | Properly validate attestation statements per FIDO metadata | Critical |
| **Origin Validation** | Reject requests from unauthorized origins | Critical |
| **Challenge Entropy** | Generate cryptographically secure random challenges (≥128 bits) | Critical |
| **Replay Attack Prevention** | Reject duplicate challenges and assertions | Critical |
| **User Verification** | Support UV=required, preferred, discouraged modes | High |
| **Resident Key Support** | Handle discoverable credentials correctly | High |
| **Algorithm Support** | Support FIDO-approved algorithms (ES256, RS256, EdDSA) | High |

### 1.2 Security Validation Points

```rust
// Test Categories for Security Validation
pub enum SecurityTestCategory {
    ChallengeGeneration,
    OriginValidation,
    AttestationVerification,
    ReplayProtection,
    UserVerification,
    CredentialBinding,
    SessionManagement,
    RateLimiting,
}
```

## 2. Technical Scope & Operations

### 2.1 Core WebAuthn Operations

#### Registration Flow
```
Client → POST /webauthn/register/begin
     ← PublicKeyCredentialCreationOptions + challenge

Client → POST /webauthn/register/complete
     ← Registration success/failure + credential_id
```

#### Authentication Flow
```
Client → POST /webauthn/authenticate/begin  
     ← PublicKeyCredentialRequestOptions + challenge

Client → POST /webauthn/authenticate/complete
     ← Authentication success/failure + session_token
```

### 2.2 Success/Failure Conditions

#### Registration Success Criteria
- [ ] Valid attestation statement verification
- [ ] Unique credential ID generation
- [ ] Proper user binding
- [ ] Challenge consumption (one-time use)
- [ ] Origin validation passed
- [ ] AAGUID validation (if required)

#### Authentication Success Criteria
- [ ] Valid assertion signature verification
- [ ] Credential exists and is active
- [ ] Challenge consumption (one-time use)
- [ ] User verification requirements met
- [ ] Counter validation (anti-cloning)
- [ ] Origin validation passed

## 3. Rust Architecture & Project Structure

### 3.1 Recommended Project Structure

```
fido2-webauthn-server/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── config/
│   │   ├── mod.rs
│   │   └── settings.rs
│   ├── handlers/
│   │   ├── mod.rs
│   │   ├── registration.rs
│   │   └── authentication.rs
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
│   ├── security/
│   │   ├── mod.rs
│   │   ├── validation.rs
│   │   ├── rate_limit.rs
│   │   └── session.rs
│   ├── error/
│   │   ├── mod.rs
│   │   └── types.rs
│   └── utils/
│       ├── mod.rs
│       └── crypto.rs
├── tests/
│   ├── integration/
│   │   ├── mod.rs
│   │   ├── registration_flow.rs
│   │   ├── authentication_flow.rs
│   │   └── security_tests.rs
│   ├── conformance/
│   │   ├── mod.rs
│   │   └── fido_compliance.rs
│   └── unit/
│       ├── mod.rs
│       ├── handlers_test.rs
│       ├── storage_test.rs
│       └── security_test.rs
├── migrations/
│   └── postgres/
└── docs/
    ├── api.md
    └── security.md
```

### 3.2 Core Dependencies

```toml
[dependencies]
webauthn-rs = "0.5"
tokio = { version = "1.0", features = ["full"] }
axum = "0.7"
sqlx = { version = "0.7", features = ["postgres", "runtime-tokio-rustls"] }
serde = { version = "1.0", features = ["derive"] }
uuid = { version = "1.0", features = ["v4", "serde"] }
base64 = "0.21"
sha2 = "0.10"
rand = "0.8"
tracing = "0.1"
tracing-subscriber = "0.3"
tower = "0.4"
tower-http = { version = "0.5", features = ["cors", "trace"] }

[dev-dependencies]
reqwest = { version = "0.11", features = ["json"] }
tokio-test = "0.4"
testcontainers = "0.15"
```

## 4. API Design & Data Flow

### 4.1 REST Endpoints Specification

#### 4.1.1 Registration Begin Endpoint

**POST** `/webauthn/register/begin`

**Request Body:**
```json
{
  "username": "string",
  "displayName": "string",
  "authenticatorSelection": {
    "authenticatorAttachment": "platform|cross-platform",
    "userVerification": "required|preferred|discouraged",
    "residentKey": "required|preferred|discouraged"
  },
  "attestation": "none|indirect|direct|enterprise"
}
```

**Response:**
```json
{
  "challenge": "base64url",
  "rp": {
    "id": "example.com",
    "name": "Example Corp"
  },
  "user": {
    "id": "base64url",
    "name": "username",
    "displayName": "User Display Name"
  },
  "pubKeyCredParams": [
    {"type": "public-key", "alg": -7},
    {"type": "public-key", "alg": -257}
  ],
  "timeout": 60000,
  "authenticatorSelection": {},
  "attestation": "none",
  "excludeCredentials": []
}
```

#### 4.1.2 Registration Complete Endpoint

**POST** `/webauthn/register/complete`

**Request Body:**
```json
{
  "id": "credential_id_base64url",
  "rawId": "credential_id_base64url", 
  "response": {
    "clientDataJSON": "base64url",
    "attestationObject": "base64url"
  },
  "type": "public-key"
}
```

**Response:**
```json
{
  "verified": true,
  "credentialId": "base64url",
  "credentialPublicKey": "base64url",
  "counter": 0,
  "aaguid": "uuid",
  "fmt": "attestation_format"
}
```

#### 4.1.3 Authentication Begin Endpoint

**POST** `/webauthn/authenticate/begin`

**Request Body:**
```json
{
  "username": "string"
}
```

**Response:**
```json
{
  "challenge": "base64url",
  "timeout": 60000,
  "rpId": "example.com",
  "allowCredentials": [
    {
      "type": "public-key",
      "id": "credential_id_base64url",
      "transports": ["usb", "nfc", "ble", "internal"]
    }
  ],
  "userVerification": "preferred"
}
```

#### 4.1.4 Authentication Complete Endpoint

**POST** `/webauthn/authenticate/complete`

**Request Body:**
```json
{
  "id": "credential_id_base64url",
  "rawId": "credential_id_base64url",
  "response": {
    "clientDataJSON": "base64url",
    "authenticatorData": "base64url", 
    "signature": "base64url",
    "userHandle": "base64url"
  },
  "type": "public-key"
}
```

**Response:**
```json
{
  "verified": true,
  "counter": 1,
  "sessionToken": "jwt_token",
  "expiresAt": "2024-01-01T00:00:00Z"
}
```

### 4.2 Error Response Format

```json
{
  "error": "error_code",
  "message": "Human readable error message",
  "details": {
    "field": "specific_error_info"
  },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

## 5. Storage Requirements & Data Models

### 5.1 Database Schema (PostgreSQL)

```sql
-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Credentials table
CREATE TABLE credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA UNIQUE NOT NULL,
    public_key BYTEA NOT NULL,
    counter BIGINT NOT NULL DEFAULT 0,
    aaguid UUID,
    attestation_format VARCHAR(50),
    transports TEXT[], -- Array of transport methods
    user_verified BOOLEAN NOT NULL DEFAULT false,
    backup_eligible BOOLEAN NOT NULL DEFAULT false,
    backup_state BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true
);

-- Challenges table (for replay protection)
CREATE TABLE challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    challenge BYTEA UNIQUE NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    challenge_type VARCHAR(20) NOT NULL, -- 'registration' or 'authentication'
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Sessions table
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(512) UNIQUE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Rate limiting table
CREATE TABLE rate_limits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identifier VARCHAR(255) NOT NULL, -- IP address or user ID
    endpoint VARCHAR(100) NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 1,
    window_start TIMESTAMP WITH TIME ZONE NOT NULL,
    blocked_until TIMESTAMP WITH TIME ZONE
);

-- Indexes for performance
CREATE INDEX idx_credentials_user_id ON credentials(user_id);
CREATE INDEX idx_credentials_credential_id ON credentials(credential_id);
CREATE INDEX idx_challenges_expires_at ON challenges(expires_at);
CREATE INDEX idx_challenges_user_id ON challenges(user_id);
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_rate_limits_identifier_endpoint ON rate_limits(identifier, endpoint);
```

### 5.2 Data Validation Requirements

```rust
// Validation Rules
pub struct ValidationRules {
    pub username: UsernameRules,
    pub challenge: ChallengeRules,
    pub credential: CredentialRules,
    pub session: SessionRules,
}

pub struct UsernameRules {
    pub min_length: usize,      // 3
    pub max_length: usize,      // 255
    pub allowed_chars: String,  // alphanumeric + specific symbols
    pub reserved_names: Vec<String>, // admin, root, etc.
}

pub struct ChallengeRules {
    pub entropy_bits: usize,    // 128 minimum
    pub expiry_seconds: u64,    // 300 (5 minutes) 
    pub max_active_per_user: usize, // 5
}

pub struct CredentialRules {
    pub max_per_user: usize,    // 10
    pub min_counter_increment: u32, // 0
    pub max_counter_value: u32, // u32::MAX
}
```

## 6. FIDO2 Compliance Checklist

### 6.1 WebAuthn Specification Compliance

- [ ] **FIDO2 CTAP2 Support**
  - [ ] Platform authenticators (TouchID, FaceID, Windows Hello)
  - [ ] Cross-platform authenticators (USB security keys)
  - [ ] Hybrid transport (QR code + smartphone)

- [ ] **Attestation Support**
  - [ ] None attestation (privacy-focused)
  - [ ] Self attestation
  - [ ] Basic attestation
  - [ ] AttCA (Attestation CA) attestation
  - [ ] ECDAA (Elliptic Curve Direct Anonymous Attestation)

- [ ] **Algorithm Support**
  - [ ] ES256 (ECDSA with SHA-256)
  - [ ] RS256 (RSASSA-PKCS1-v1_5 with SHA-256)
  - [ ] EdDSA (Ed25519)
  - [ ] PS256 (RSASSA-PSS with SHA-256)

- [ ] **User Verification Levels**
  - [ ] Required (UV=true mandatory)
  - [ ] Preferred (UV=true preferred but not mandatory)
  - [ ] Discouraged (UV=false)

- [ ] **Resident Key Support**
  - [ ] Server-side credential storage
  - [ ] Client-side discoverable credentials
  - [ ] Hybrid approaches

### 6.2 Security Features Compliance

- [ ] **Challenge Management**
  - [ ] Cryptographically secure random generation
  - [ ] One-time use enforcement
  - [ ] Appropriate expiration times
  - [ ] Rate limiting for challenge requests

- [ ] **Origin Validation**
  - [ ] Strict origin checking
  - [ ] HTTPS enforcement
  - [ ] Subdomain policy handling
  - [ ] Port-specific validation

- [ ] **Anti-Replay Protection**
  - [ ] Challenge uniqueness enforcement
  - [ ] Timestamp validation
  - [ ] Signature counter verification
  - [ ] Duplicate credential detection

- [ ] **Session Management**
  - [ ] Secure session token generation
  - [ ] Appropriate session timeouts
  - [ ] Session invalidation
  - [ ] Concurrent session handling

## 7. Risk Assessment & Security Considerations

### 7.1 Threat Model

| Threat | Impact | Likelihood | Mitigation Strategy |
|--------|---------|------------|-------------------|
| **Replay Attacks** | High | Medium | Challenge-based nonce system, timestamp validation |
| **Man-in-the-Middle** | High | Low | TLS enforcement, certificate pinning |
| **Credential Stuffing** | Medium | High | Rate limiting, account lockout policies |
| **Session Hijacking** | High | Medium | Secure session tokens, HTTP-only cookies |
| **Origin Confusion** | High | Medium | Strict origin validation, same-site policies |
| **Database Compromise** | High | Low | Encryption at rest, minimal data storage |
| **Side-Channel Attacks** | Medium | Low | Constant-time operations, secure memory handling |
| **Denial of Service** | Medium | High | Rate limiting, resource quotas |

### 7.2 Security Controls Implementation

#### 7.2.1 Input Validation
```rust
pub struct SecurityValidator {
    max_request_size: usize,
    allowed_origins: HashSet<String>,
    rate_limiter: RateLimiter,
    challenge_store: ChallengeStore,
}

impl SecurityValidator {
    pub fn validate_registration_request(&self, req: &RegistrationRequest) -> Result<(), SecurityError> {
        // Origin validation
        self.validate_origin(&req.origin)?;
        
        // Rate limiting
        self.rate_limiter.check(&req.client_ip)?;
        
        // Input sanitization
        self.validate_username(&req.username)?;
        
        // Request size limits
        self.validate_request_size(&req)?;
        
        Ok(())
    }
}
```

#### 7.2.2 Rate Limiting Strategy
```rust
pub struct RateLimitConfig {
    pub registration_begin: RateLimit,    // 5 requests per minute
    pub registration_complete: RateLimit, // 10 requests per minute
    pub auth_begin: RateLimit,           // 10 requests per minute  
    pub auth_complete: RateLimit,        // 20 requests per minute
    pub global_per_ip: RateLimit,        // 100 requests per minute
}

pub struct RateLimit {
    pub requests: u32,
    pub window_seconds: u64,
    pub burst_allowance: u32,
}
```

#### 7.2.3 Security Headers
```rust
pub fn security_middleware() -> impl Filter<Extract = (), Error = Rejection> + Copy {
    warp::reply::with::headers([
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("X-XSS-Protection", "1; mode=block"),
        ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
        ("Content-Security-Policy", "default-src 'self'"),
        ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ])
}
```

### 7.3 Vulnerability Mitigation

#### 7.3.1 Common WebAuthn Vulnerabilities
1. **Challenge Fixation**: Mitigated by cryptographically secure random challenge generation
2. **Origin Bypass**: Mitigated by strict origin validation and HTTPS enforcement
3. **Credential Cloning**: Mitigated by signature counter verification
4. **Registration Confusion**: Mitigated by proper user binding and credential uniqueness
5. **Session Fixation**: Mitigated by session token regeneration and secure cookie handling

#### 7.3.2 Monitoring & Alerting
```rust
pub struct SecurityMonitor {
    pub failed_auth_threshold: u32,      // 5 failures per hour
    pub suspicious_patterns: Vec<Pattern>,
    pub alert_channels: Vec<AlertChannel>,
}

pub enum SecurityAlert {
    RepeatedFailures(String),           // IP or user
    UnknownOrigin(String),              // Origin
    RateLimitExceeded(String),          // Endpoint
    DatabaseError(String),              // Error type
    InvalidCredential(String),          // Credential ID
}
```

## 8. Implementation Phases

### Phase 1: Core Infrastructure (Week 1-2)
- [ ] Project setup and dependencies
- [ ] Database schema and migrations
- [ ] Basic HTTP server with security middleware
- [ ] Configuration management
- [ ] Logging and monitoring setup

### Phase 2: WebAuthn Core (Week 3-4)
- [ ] Registration flow implementation
- [ ] Authentication flow implementation
- [ ] Challenge management
- [ ] Credential storage and retrieval
- [ ] Basic security validations

### Phase 3: Security Hardening (Week 5-6)
- [ ] Rate limiting implementation
- [ ] Advanced input validation
- [ ] Session management
- [ ] Security headers and CORS
- [ ] Error handling and logging

### Phase 4: Testing & Compliance (Week 7-8)
- [ ] Unit test suite
- [ ] Integration test suite
- [ ] Security test suite
- [ ] FIDO conformance testing
- [ ] Performance testing

### Phase 5: Production Readiness (Week 9-10)
- [ ] Documentation completion
- [ ] Deployment configurations
- [ ] Monitoring and alerting setup
- [ ] Security audit and penetration testing
- [ ] Performance optimization

## 9. Testing Strategy

### 9.1 Test Categories
1. **Unit Tests**: Individual component functionality
2. **Integration Tests**: End-to-end flow testing
3. **Security Tests**: Vulnerability and attack simulation
4. **Conformance Tests**: FIDO Alliance specification compliance
5. **Performance Tests**: Load and stress testing
6. **Compatibility Tests**: Cross-browser and device testing

### 9.2 Test Data Management
```rust
pub struct TestDataManager {
    pub test_users: Vec<TestUser>,
    pub test_credentials: Vec<TestCredential>,
    pub test_challenges: Vec<TestChallenge>,
    pub attack_vectors: Vec<AttackVector>,
}
```

This specification provides a comprehensive foundation for implementing a secure, compliant FIDO2/WebAuthn Relying Party Server with extensive test coverage and security-first design principles.