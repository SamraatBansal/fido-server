# FIDO2/WebAuthn Relying Party Server Technical Specification

## Executive Summary

This document provides a comprehensive technical specification for implementing a FIDO2/WebAuthn conformant Relying Party Server in Rust using the webauthn-rs library. The specification focuses on security-first design, FIDO Alliance compliance, and comprehensive testability.

## 1. Security Requirements

### 1.1 FIDO Alliance Compliance Requirements

#### Core Security Requirements (Testable Criteria)
- **REQ-SEC-001**: Server MUST implement WebAuthn Level 2 compliance
  - Test: Verify against FIDO2 Conformance Test Suite
  - Success: All conformance tests pass
  - Failure: Any test failure indicates non-compliance

- **REQ-SEC-002**: Server MUST enforce TLS 1.2+ for all endpoints
  - Test: TLS version validation test
  - Success: Only TLS 1.2+ connections accepted
  - Failure: TLS 1.0/1.1 connections accepted

- **REQ-SEC-003**: Server MUST implement proper origin validation
  - Test: Cross-origin request validation
  - Success: Invalid origins rejected with proper error codes
  - Failure: Invalid origins processed

- **REQ-SEC-004**: Server MUST prevent replay attacks
  - Test: Challenge reuse prevention
  - Success: Duplicate challenges rejected
  - Failure: Same challenge accepted multiple times

- **REQ-SEC-005**: Server MUST implement proper credential binding
  - Test: User-credential binding verification
  - Success: Credentials bound to correct user
  - Failure: Cross-user credential access possible

#### Cryptographic Requirements
- **REQ-CRYPTO-001**: Support for ES256, RS256, EdDSA algorithms
- **REQ-CRYPTO-002**: Proper random challenge generation (≥16 bytes)
- **REQ-CRYPTO-003**: Secure storage of private keys and secrets
- **REQ-CRYPTO-004**: Implementation of attestation verification

### 1.2 Data Protection Requirements

#### Privacy Requirements
- **REQ-PRIV-001**: Minimal data collection (only required WebAuthn fields)
- **REQ-PRIV-002**: No storage of biometric data
- **REQ-PRIV-003**: User consent for credential storage
- **REQ-PRIV-004**: Data retention policies implementation

#### Integrity Requirements
- **REQ-INTEGRITY-001**: Database transaction consistency
- **REQ-INTEGRITY-002**: Atomic credential operations
- **REQ-INTEGRITY-003**: Audit logging for all operations

## 2. Technical Scope

### 2.1 Core WebAuthn Operations

#### Registration (Attestation) Flow
```
1. Client → Server: POST /attestation/options
   Input: { username, displayName, userVerification }
   Output: { challenge, user, rp, pubKeyCredParams }

2. Client → Server: POST /attestation/result
   Input: { id, rawId, response: { attestationObject, clientDataJSON } }
   Output: { status, errorMessage? }
```

**Success Conditions:**
- Valid attestation format verification
- Proper challenge verification
- User existence validation
- Credential storage success

**Failure Conditions:**
- Invalid attestation format
- Challenge mismatch
- User already exists with same credential
- Cryptographic verification failure

#### Authentication (Assertion) Flow
```
1. Client → Server: POST /assertion/options
   Input: { username?, userVerification? }
   Output: { challenge, allowCredentials, userVerification }

2. Client → Server: POST /assertion/result
   Input: { id, rawId, response: { authenticatorData, clientDataJSON, signature } }
   Output: { status, errorMessage? }
```

**Success Conditions:**
- Valid signature verification
- Proper challenge verification
- Credential existence validation
- User authentication success

**Failure Conditions:**
- Invalid signature
- Challenge mismatch
- Credential not found
- User verification failure

### 2.2 Edge Cases and Error Handling

#### Registration Edge Cases
- Duplicate credential ID handling
- Invalid attestation formats
- Malformed client data
- Timeout scenarios
- Concurrent registration attempts

#### Authentication Edge Cases
- Credential revocation scenarios
- Lost authenticator handling
- Multiple credentials per user
- User verification bypass attempts
- Rate limiting scenarios

## 3. Rust Architecture

### 3.1 Project Structure
```
src/
├── lib.rs                    # Library entry point
├── main.rs                   # Binary entry point
├── config/                   # Configuration management
│   ├── mod.rs
│   └── settings.rs
├── controllers/              # HTTP request handlers
│   ├── mod.rs
│   ├── attestation.rs
│   ├── assertion.rs
│   └── health.rs
├── services/                 # Business logic
│   ├── mod.rs
│   ├── webauthn_service.rs
│   ├── user_service.rs
│   └── credential_service.rs
├── db/                       # Database layer
│   ├── mod.rs
│   ├── connection.rs
│   ├── models.rs
│   └── repositories/
│       ├── mod.rs
│       ├── user_repository.rs
│       └── credential_repository.rs
├── middleware/               # HTTP middleware
│   ├── mod.rs
│   ├── auth.rs
│   ├── cors.rs
│   └── rate_limit.rs
├── routes/                   # Route definitions
│   ├── mod.rs
│   └── webauthn.rs
├── error/                    # Error handling
│   ├── mod.rs
│   └── types.rs
├── utils/                    # Utilities
│   ├── mod.rs
│   ├── crypto.rs
│   └── validation.rs
└── schema/                   # Database schema
    ├── mod.rs
    └── migrations/
```

### 3.2 Core Dependencies and Testing Strategy

#### Production Dependencies
```toml
webauthn-rs = "0.5"           # Core WebAuthn implementation
actix-web = "4.9"             # Web framework
diesel = { version = "2.1", features = ["postgres"] }  # ORM
uuid = { version = "1.10", features = ["v4", "serde"] }  # UUID generation
serde = { version = "1.0", features = ["derive"] }     # Serialization
```

#### Testing Dependencies
```toml
[dev-dependencies]
actix-test = "0.1"           # HTTP testing
mockall = "0.13"             # Mocking framework
tokio-test = "0.4"           # Async testing
tempfile = "3.8"             # Temporary files for testing
wiremock = "0.5"             # HTTP mocking
```

### 3.3 Testing Architecture

#### Unit Testing Strategy
- **Service Layer**: Mock database dependencies
- **Repository Layer**: In-memory test databases
- **Controller Layer**: Mock service dependencies
- **Utility Functions**: Pure function testing

#### Integration Testing Strategy
- **API Endpoints**: Full HTTP request/response testing
- **Database Operations**: Real PostgreSQL test database
- **WebAuthn Flow**: End-to-end credential lifecycle testing
- **Security Scenarios**: Attack simulation testing

## 4. API Design

### 4.1 REST Endpoints Specification

#### Registration Endpoints

##### POST /attestation/options
**Purpose**: Generate attestation challenge options
**Authentication**: Optional (user identification)
**Request Body**:
```json
{
  "username": "string (required)",
  "displayName": "string (required)",
  "userVerification": "required|preferred|discouraged (optional)",
  "attestation": "none|direct|enterprise (optional)",
  "extensions": "object (optional)"
}
```

**Response Body**:
```json
{
  "status": "ok",
  "errorMessage": "string (optional)",
  "challenge": "string (base64url)",
  "rp": {
    "name": "string",
    "id": "string"
  },
  "user": {
    "id": "string (base64url)",
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
  "attestation": "none|direct|enterprise",
  "extensions": {}
}
```

**Error Responses**:
- 400: Invalid request parameters
- 429: Rate limit exceeded
- 500: Internal server error

##### POST /attestation/result
**Purpose**: Process attestation response
**Authentication**: None (challenge-based)
**Request Body**:
```json
{
  "id": "string (base64url)",
  "rawId": "string (base64url)",
  "response": {
    "attestationObject": "string (base64url)",
    "clientDataJSON": "string (base64url)"
  },
  "type": "public-key",
  "clientExtensionResults": {},
  "transports": ["usb", "nfc", "ble", "internal"]
}
```

**Response Body**:
```json
{
  "status": "ok|failed",
  "errorMessage": "string (optional)",
  "registrationInfo": {
    "credentialId": "string",
    "userId": "string",
    "nickname": "string (optional)"
  }
}
```

#### Authentication Endpoints

##### POST /assertion/options
**Purpose**: Generate assertion challenge options
**Authentication**: Optional (user identification)
**Request Body**:
```json
{
  "username": "string (optional)",
  "userVerification": "required|preferred|discouraged (optional)",
  "extensions": "object (optional)"
}
```

**Response Body**:
```json
{
  "status": "ok",
  "errorMessage": "string (optional)",
  "challenge": "string (base64url)",
  "allowCredentials": [
    {
      "type": "public-key",
      "id": "string (base64url)",
      "transports": ["usb", "nfc", "ble", "internal"]
    }
  ],
  "userVerification": "required|preferred|discouraged",
  "timeout": 60000,
  "rpId": "string",
  "extensions": {}
}
```

##### POST /assertion/result
**Purpose**: Process assertion response
**Authentication**: None (challenge-based)
**Request Body**:
```json
{
  "id": "string (base64url)",
  "rawId": "string (base64url)",
  "response": {
    "authenticatorData": "string (base64url)",
    "clientDataJSON": "string (base64url)",
    "signature": "string (base64url)",
    "userHandle": "string (base64url, optional)"
  },
  "type": "public-key",
  "clientExtensionResults": {}
}
```

**Response Body**:
```json
{
  "status": "ok|failed",
  "errorMessage": "string (optional)",
  "authenticationInfo": {
    "credentialId": "string",
    "userId": "string",
    "userVerified": boolean,
    "authenticatorInfo": {
      "rpIdHash": "string",
      "flags": {
        "userPresent": boolean,
        "userVerified": boolean,
        "backupEligible": boolean,
        "backupState": boolean
      },
      "signCount": number
    }
  }
}
```

### 4.2 Data Flow Architecture

#### Registration Flow
```
Client Request → Middleware (CORS, Rate Limit) → Controller → Service → Repository → Database
                ← Response ← Service ← Repository ← Database
```

#### Authentication Flow
```
Client Request → Middleware (CORS, Rate Limit) → Controller → Service → Repository → Database
                ← Response ← Service ← Repository ← Database
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
    deleted_at TIMESTAMP WITH TIME ZONE NULL
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
    aaguid BYTEA,
    sign_count BIGINT NOT NULL DEFAULT 0,
    backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,
    backup_state BOOLEAN NOT NULL DEFAULT FALSE,
    user_verified BOOLEAN NOT NULL DEFAULT FALSE,
    transports JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE NULL,
    deleted_at TIMESTAMP WITH TIME ZONE NULL
);
```

#### Challenges Table (for replay protection)
```sql
CREATE TABLE challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    challenge_value VARCHAR(255) UNIQUE NOT NULL,
    challenge_type VARCHAR(20) NOT NULL, -- 'attestation' or 'assertion'
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### 5.2 Data Validation Requirements

#### Input Validation
- **Username**: 3-64 characters, alphanumeric + @._-
- **Display Name**: 1-128 characters, UTF-8
- **Challenge**: Base64URL encoded, ≥16 bytes
- **Credential ID**: Base64URL encoded, ≤1023 bytes
- **Attestation Object**: Valid CBOR, ≤4096 bytes
- **Client Data JSON**: Valid JSON, ≤1024 bytes

#### Output Validation
- All responses must be valid JSON
- Base64URL encoding for binary data
- Proper HTTP status codes
- Consistent error message format

### 5.3 Security Storage Requirements

#### Sensitive Data Protection
- Private keys stored encrypted at rest
- Database connections encrypted (TLS)
- Challenge values hashed before storage
- Audit logs immutable and tamper-evident

#### Data Retention
- Challenges: Expire after 5 minutes
- Session data: Expire after 24 hours
- Audit logs: Retain 1 year
- User data: Retain per privacy policy

## 6. Compliance Checklist

### 6.1 FIDO2 Specification Compliance Points

#### WebAuthn Level 2 Requirements
- [ ] **RP-1**: Implement WebAuthn API correctly
- [ ] **RP-2**: Support required cryptographic algorithms
- [ ] **RP-3**: Proper origin validation
- [ ] **RP-4**: Challenge generation and verification
- [ ] **RP-5**: Credential storage and retrieval
- [ ] **RP-6**: User verification handling
- [ ] **RP-7**: Attestation verification
- [ ] **RP-8**: Extension support
- [ ] **RP-9**: Error handling per specification
- [ ] **RP-10**: Metadata statement support

#### Security Requirements
- [ ] **SEC-1**: TLS enforcement
- [ ] **SEC-2**: CSRF protection
- [ ] **SEC-3**: Rate limiting
- [ ] **SEC-4**: Input validation
- [ ] **SEC-5**: Output encoding
- [ ] **SEC-6**: Secure random generation
- [ ] **SEC-7**: Replay attack prevention
- [ ] **SEC-8**: Credential binding

#### Privacy Requirements
- [ ] **PRIV-1**: Minimal data collection
- [ ] **PRIV-2**: User consent
- [ ] **PRIV-3**: Data minimization
- [ ] **PRIV-4**: Right to deletion
- [ ] **PRIV-5**: Transparency

### 6.2 Testing Compliance Matrix

| Requirement | Test Type | Test Coverage | Success Criteria |
|-------------|-----------|---------------|------------------|
| RP-1 | Unit/Integration | 100% | All API calls conform to spec |
| RP-2 | Unit | 100% | All algorithms supported |
| RP-3 | Integration | 100% | Invalid origins rejected |
| RP-4 | Unit/Integration | 100% | Challenge lifecycle correct |
| RP-5 | Integration | 100% | CRUD operations work |
| RP-6 | Unit | 100% | UV flags handled correctly |
| RP-7 | Unit | 100% | Attestation formats verified |
| SEC-1 | Integration | 100% | TLS only connections |
| SEC-2 | Integration | 100% | CSRF tokens validated |
| SEC-3 | Integration | 100% | Rate limits enforced |
| PRIV-1 | Unit | 100% | Only required data stored |

## 7. Risk Assessment

### 7.1 Security Risks and Mitigation

#### High Risk Items

**Risk 1: Credential Theft**
- **Threat**: Unauthorized access to stored credentials
- **Impact**: Complete account compromise
- **Likelihood**: Medium
- **Mitigation**: 
  - Encrypt credential data at rest
  - Implement proper access controls
  - Regular security audits
  - Database connection encryption

**Risk 2: Replay Attacks**
- **Threat**: Reuse of valid authentication responses
- **Impact**: Unauthorized access
- **Likelihood**: High
- **Mitigation**:
  - Single-use challenges
  - Challenge expiration
  - Timestamp validation
  - Cryptographic nonces

**Risk 3: Man-in-the-Middle Attacks**
- **Threat**: Interception of WebAuthn communications
- **Impact**: Credential compromise
- **Likelihood**: Medium
- **Mitigation**:
  - TLS enforcement
  - Certificate pinning
  - Origin validation
  - HSTS headers

#### Medium Risk Items

**Risk 4: Denial of Service**
- **Threat**: Resource exhaustion attacks
- **Impact**: Service unavailability
- **Likelihood**: High
- **Mitigation**:
  - Rate limiting
  - Request size limits
  - Connection throttling
  - Load balancing

**Risk 5: Data Privacy Violations**
- **Threat**: Unauthorized data access or leakage
- **Impact**: Privacy violations, regulatory penalties
- **Likelihood**: Medium
- **Mitigation**:
  - Data minimization
  - Access logging
  - Privacy by design
  - Regular privacy audits

### 7.2 Implementation Risks

#### Technical Risks

**Risk 6: WebAuthn Library Compatibility**
- **Threat**: Library bugs or compatibility issues
- **Impact**: Functionality failures
- **Likelihood**: Medium
- **Mitigation**:
  - Comprehensive testing
  - Library version pinning
  - Fallback mechanisms
  - Regular updates

**Risk 7: Database Performance**
- **Threat**: Slow credential operations
- **Impact**: Poor user experience
- **Likelihood**: Medium
- **Mitigation**:
  - Proper indexing
  - Connection pooling
  - Query optimization
  - Performance monitoring

### 7.3 Compliance Risks

**Risk 8: FIDO2 Non-Compliance**
- **Threat**: Failure to meet specification requirements
- **Impact**: Interoperability issues
- **Likelihood**: Medium
- **Mitigation**:
  - Regular conformance testing
  - Specification review
  - Third-party audits
  - Continuous integration testing

## 8. Implementation Roadmap

### Phase 1: Core Infrastructure (Weeks 1-2)
- [ ] Project structure setup
- [ ] Database schema implementation
- [ ] Basic WebAuthn service integration
- [ ] Configuration management
- [ ] Error handling framework

### Phase 2: Registration Flow (Weeks 3-4)
- [ ] Attestation options endpoint
- [ ] Attestation result processing
- [ ] User management
- [ ] Credential storage
- [ ] Unit and integration tests

### Phase 3: Authentication Flow (Weeks 5-6)
- [ ] Assertion options endpoint
- [ ] Assertion result processing
- [ ] Credential retrieval
- [ ] User verification
- [ ] Security testing

### Phase 4: Security Hardening (Weeks 7-8)
- [ ] TLS enforcement
- [ ] Rate limiting
- [ ] Input validation
- [ ] Error handling
- [ ] Security audit

### Phase 5: Compliance Testing (Weeks 9-10)
- [ ] FIDO2 conformance testing
- [ ] Performance testing
- [ ] Load testing
- [ ] Security penetration testing
- [ ] Documentation completion

## 9. Success Metrics

### Technical Metrics
- **Test Coverage**: ≥95% unit, ≥90% integration
- **Performance**: <100ms response time for 95% of requests
- **Availability**: 99.9% uptime
- **Security**: Zero critical vulnerabilities in scans

### Compliance Metrics
- **FIDO2 Conformance**: 100% test suite pass rate
- **Security Audit**: Zero high-risk findings
- **Privacy Audit**: Full compliance with data protection regulations

### Quality Metrics
- **Code Quality**: Zero clippy warnings
- **Documentation**: 100% public API documented
- **Error Handling**: All error paths tested

This specification provides a comprehensive foundation for implementing a secure, compliant, and thoroughly tested FIDO2/WebAuthn Relying Party Server in Rust.