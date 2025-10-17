# FIDO2/WebAuthn Relying Party Server Technical Specification

## Executive Summary

This document provides a comprehensive technical specification for implementing a FIDO2/WebAuthn Relying Party Server in Rust with focus on security-first design, FIDO Alliance compliance, and comprehensive test-driven development.

## 1. Security Requirements

### 1.1 FIDO Alliance Compliance Requirements

#### Core Security Requirements (Testable Criteria)
- **SR-001**: Server MUST validate attestation statements according to FIDO2 specification
- **SR-002**: Server MUST implement proper origin validation for all WebAuthn operations
- **SR-003**: Server MUST enforce TLS 1.2+ for all communications
- **SR-004**: Server MUST implement replay attack prevention using challenge uniqueness
- **SR-005**: Server MUST validate user presence and user verification flags
- **SR-006**: Server MUST implement proper credential binding to user accounts
- **SR-007**: Server MUST support resident key (discoverable credentials) functionality
- **SR-008**: Server MUST implement proper timeout handling for all operations

#### Cryptographic Requirements
- **CR-001**: Support for ES256, RS256, and EdDSA algorithms
- **CR-002**: Proper random challenge generation (minimum 16 bytes)
- **CR-003**: Secure storage of credential private keys (never stored)
- **CR-004**: Implementation of proper signature verification
- **CR-005**: Support for attestation formats: packed, fido-u2f, none, android-key, android-safetynet

#### Data Protection Requirements
- **DR-001**: Credential IDs MUST be treated as sensitive data
- **DR-002**: User handles MUST be random and not guessable
- **DR-003**: All sensitive data MUST be encrypted at rest
- **DR-004**: Audit logging for all authentication events
- **DR-005**: Rate limiting for authentication attempts

### 1.2 Testable Security Criteria

| Requirement | Test Method | Success Criteria |
|-------------|-------------|------------------|
| SR-001 | Unit tests with known attestation formats | 100% format validation accuracy |
| SR-002 | Integration tests with various origins | Proper rejection of invalid origins |
| SR-003 | TLS configuration tests | Only TLS 1.2+ accepted |
| SR-004 | Replay attack simulation | 100% replay detection |
| SR-005 | Flag validation tests | Proper UP/UV flag handling |
| SR-006 | Credential binding tests | Secure user-credential mapping |

## 2. Technical Scope

### 2.1 Core WebAuthn Operations

#### Registration (Attestation) Flow
```
1. Client → Server: POST /attestation/options
   Input: { username, displayName, attestation, userVerification }
   Output: { challenge, user, pubKeyCredParams, timeout, attestation }

2. Client → Server: POST /attestation/result
   Input: { id, rawId, response: { attestationObject, clientDataJSON }, type }
   Output: { status, errorMessage? }
```

**Success Conditions:**
- Valid attestation object format
- Proper challenge verification
- Valid client data JSON
- Successful credential storage
- Proper user binding

**Failure Conditions:**
- Invalid challenge
- Malformed attestation object
- Unsupported attestation format
- Duplicate credential ID
- Invalid user verification

#### Authentication (Assertion) Flow
```
1. Client → Server: POST /assertion/options
   Input: { username?, userVerification, userHandle? }
   Output: { challenge, allowCredentials, timeout, userVerification }

2. Client → Server: POST /assertion/result
   Input: { id, rawId, response: { authenticatorData, clientDataJSON, signature, userHandle }, type }
   Output: { status, errorMessage? }
```

**Success Conditions:**
- Valid assertion signature
- Proper challenge verification
- Valid authenticator data
- Successful user authentication
- Proper credential usage tracking

**Failure Conditions:**
- Invalid signature
- Expired challenge
- Invalid user handle
- Credential not found
- User verification failure

### 2.2 Edge Case Testing Requirements

#### Registration Edge Cases
- EC-001: Multiple credentials for same user
- EC-002: Duplicate credential ID detection
- EC-003: Invalid attestation formats
- EC-004: Timeout scenarios
- EC-005: Concurrent registration attempts
- EC-006: Large credential IDs (>1024 bytes)
- EC-007: Malformed client data JSON

#### Authentication Edge Cases
- EC-008: Non-existent credential authentication
- EC-009: Expired challenge usage
- EC-010: Invalid signature formats
- EC-011: User verification bypass attempts
- EC-012: Credential counter manipulation
- EC-013: Cross-origin authentication attempts
- EC-014: Replay attack scenarios

## 3. Rust Architecture

### 3.1 Project Structure
```
src/
├── lib.rs                    # Library entry point
├── main.rs                   # Binary entry point
├── config/
│   ├── mod.rs               # Configuration module
│   └── settings.rs          # Application settings
├── controllers/
│   ├── mod.rs               # Controller module
│   ├── attestation.rs       # Registration controller
│   └── assertion.rs         # Authentication controller
├── services/
│   ├── mod.rs               # Service module
│   ├── webauthn.rs          # WebAuthn service
│   ├── user.rs              # User management service
│   └── credential.rs        # Credential service
├── db/
│   ├── mod.rs               # Database module
│   ├── connection.rs        # Database connection
│   ├── models.rs            # Database models
│   └── repositories.rs      # Data access layer
├── middleware/
│   ├── mod.rs               # Middleware module
│   ├── auth.rs              # Authentication middleware
│   ├── cors.rs              # CORS middleware
│   └── rate_limit.rs        # Rate limiting middleware
├── routes/
│   ├── mod.rs               # Routes module
│   ├── webauthn.rs          # WebAuthn routes
│   └── health.rs            # Health check routes
├── error/
│   ├── mod.rs               # Error module
│   └── types.rs             # Error types
├── utils/
│   ├── mod.rs               # Utilities module
│   ├── crypto.rs            # Cryptographic utilities
│   └── validation.rs        # Validation utilities
└── schema/                  # Diesel schema files
    └── migrations/          # Database migrations
```

### 3.2 Testing Architecture
```
tests/
├── unit/                    # Unit tests
│   ├── services/            # Service layer tests
│   ├── controllers/         # Controller tests
│   └── utils/               # Utility tests
├── integration/             # Integration tests
│   ├── api/                 # API endpoint tests
│   ├── database/            # Database tests
│   └── webauthn/            # WebAuthn flow tests
├── security/                # Security tests
│   ├── compliance/          # FIDO compliance tests
│   ├── vulnerability/       # Vulnerability tests
│   └── penetration/         # Penetration tests
├── performance/             # Performance tests
│   ├── load/                # Load tests
│   └── stress/              # Stress tests
└── fixtures/                # Test fixtures
    ├── credentials/         # Test credentials
    └── users/               # Test users
```

### 3.3 Key Dependencies and Testing Considerations

#### Core Dependencies
```toml
webauthn-rs = "0.5"          # WebAuthn implementation
actix-web = "4.9"            # Web framework
diesel = { version = "2.1", features = ["postgres"] }  # Database
uuid = { version = "1.10", features = ["v4", "serde"] }  # UUID generation
```

#### Testing Dependencies
```toml
[dev-dependencies]
actix-test = "0.1"           # HTTP testing
mockall = "0.13"             # Mocking framework
tempfile = "3.10"            # Temporary files
tokio-test = "0.4"           # Async testing
proptest = "1.5"             # Property-based testing
criterion = "0.5"            # Benchmarking
```

## 4. API Design

### 4.1 REST Endpoints Specification

#### Registration Endpoints

##### POST /attestation/options
**Purpose**: Generate attestation challenge options

**Request**:
```json
{
  "username": "string",
  "displayName": "string",
  "attestation": "none|direct|enterprise|indirect",
  "authenticatorSelection": {
    "authenticatorAttachment": "platform|cross-platform",
    "requireResidentKey": false,
    "userVerification": "required|preferred|discouraged"
  },
  "extensions": {}
}
```

**Response**:
```json
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
  "attestation": "none|direct|enterprise|indirect",
  "authenticatorSelection": {
    "authenticatorAttachment": "platform|cross-platform",
    "requireResidentKey": false,
    "userVerification": "required|preferred|discouraged"
  },
  "extensions": {}
}
```

**Error Responses**:
- 400: Invalid request format
- 409: User already exists
- 500: Internal server error

##### POST /attestation/result
**Purpose**: Process attestation result

**Request**:
```json
{
  "id": "base64url-encoded-credential-id",
  "rawId": "base64url-encoded-credential-id",
  "type": "public-key",
  "response": {
    "attestationObject": "base64url-encoded",
    "clientDataJSON": "base64url-encoded"
  },
  "clientExtensionResults": {}
}
```

**Response**:
```json
{
  "status": "ok|failed",
  "errorMessage": "string",
  "credentialId": "base64url-encoded-credential-id"
}
```

#### Authentication Endpoints

##### POST /assertion/options
**Purpose**: Generate assertion challenge options

**Request**:
```json
{
  "username": "string",
  "userVerification": "required|preferred|discouraged",
  "userHandle": "base64url-encoded-user-id"
}
```

**Response**:
```json
{
  "status": "ok",
  "errorMessage": "",
  "challenge": "base64url-encoded-challenge",
  "allowCredentials": [
    {
      "type": "public-key",
      "id": "base64url-encoded-credential-id",
      "transports": ["usb", "nfc", "ble", "internal"]
    }
  ],
  "userVerification": "required|preferred|discouraged",
  "timeout": 60000,
  "extensions": {}
}
```

##### POST /assertion/result
**Purpose**: Process assertion result

**Request**:
```json
{
  "id": "base64url-encoded-credential-id",
  "rawId": "base64url-encoded-credential-id",
  "type": "public-key",
  "response": {
    "authenticatorData": "base64url-encoded",
    "clientDataJSON": "base64url-encoded",
    "signature": "base64url-encoded",
    "userHandle": "base64url-encoded-user-id"
  },
  "clientExtensionResults": {}
}
```

**Response**:
```json
{
  "status": "ok|failed",
  "errorMessage": "string",
  "userHandle": "base64url-encoded-user-id"
}
```

### 4.2 Data Flow Specifications

#### Registration Flow
```
Client Request → Validation → Challenge Generation → Response Storage → Client Response
Client Response → Challenge Verification → Attestation Validation → Credential Storage → Success Response
```

#### Authentication Flow
```
Client Request → User Lookup → Challenge Generation → Credential Selection → Response Storage → Client Response
Client Response → Challenge Verification → Signature Validation → User Authentication → Success Response
```

## 5. Storage Requirements

### 5.1 Database Schema

#### Users Table
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    user_handle BYTEA UNIQUE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login TIMESTAMP WITH TIME ZONE
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
    user_verified BOOLEAN NOT NULL DEFAULT false,
    backup_eligible BOOLEAN NOT NULL DEFAULT false,
    backup_state BOOLEAN NOT NULL DEFAULT false,
    transports JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used TIMESTAMP WITH TIME ZONE
);
```

#### Challenges Table
```sql
CREATE TABLE challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    challenge BYTEA NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    challenge_type VARCHAR(20) NOT NULL, -- 'attestation' or 'assertion'
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    used BOOLEAN NOT NULL DEFAULT false
);
```

#### Audit Log Table
```sql
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    credential_id UUID REFERENCES credentials(id),
    event_type VARCHAR(50) NOT NULL, -- 'registration', 'authentication', 'failure'
    event_data JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### 5.2 Data Validation Requirements

#### Input Validation
- **Username**: 3-64 characters, alphanumeric + @._-
- **Display Name**: 1-128 characters, UTF-8
- **Challenge**: Base64URL encoded, minimum 16 bytes
- **Credential ID**: Base64URL encoded, maximum 1024 bytes
- **User Handle**: Base64URL encoded, exactly 64 bytes

#### Data Integrity
- All timestamps in UTC
- UUID v4 for primary keys
- Binary data stored as BYTEA
- JSON validation for structured fields
- Foreign key constraints enforced

#### Security Validation
- Challenge uniqueness verification
- Credential ID collision detection
- User handle randomness verification
- Rate limiting per user/IP
- Audit trail for all operations

## 6. Compliance Checklist

### 6.1 FIDO2 Specification Compliance Points

#### Core Specification (Level 1)
- [ ] **CT-001**: Server implements WebAuthn API correctly
- [ ] **CT-002**: Proper challenge generation and validation
- [ ] **CT-003**: Correct attestation statement processing
- [ ] **CT-004**: Proper assertion verification
- [ ] **CT-005**: User verification handling
- [ ] **CT-006**: Credential binding to user accounts
- [ ] **CT-007**: Proper error handling and responses

#### Security Requirements
- [ ] **SR-001**: TLS enforcement for all communications
- [ ] **SR-002**: Origin validation implementation
- [ ] **SR-003**: Replay attack prevention
- [ ] **SR-004**: Secure credential storage
- [ ] **SR-005**: Proper random number generation
- [ ] **SR-006**: Cryptographic algorithm support
- [ ] **SR-007**: Attestation format support

#### Privacy Requirements
- [ ] **PR-001**: User consent for credential creation
- [ ] **PR-002**: Minimal data collection
- [ ] **PR-003**: Data retention policies
- [ ] **PR-004**: User data deletion capabilities
- [ ] **PR-005**: Privacy policy compliance

#### Performance Requirements
- [ ] **PF-001**: Response time < 100ms for challenge generation
- [ ] **PF-002**: Response time < 200ms for verification
- [ ] **PF-003**: Support for 1000+ concurrent users
- [ ] **PF-004**: Database query optimization
- [ ] **PF-005**: Memory usage optimization

### 6.2 Testing Compliance Matrix

| Compliance Point | Test Type | Test Coverage | Success Criteria |
|------------------|-----------|---------------|------------------|
| CT-001 | Unit/Integration | 100% | All API endpoints functional |
| CT-002 | Security | 100% | Challenge uniqueness verified |
| CT-003 | Integration | 95% | All attestation formats supported |
| CT-004 | Integration | 95% | Signature verification accurate |
| CT-005 | Security | 100% | User verification enforced |
| SR-001 | Security | 100% | TLS only connections |
| SR-002 | Security | 100% | Origin validation working |
| PF-001 | Performance | 100% | <100ms response time |

## 7. Risk Assessment

### 7.1 Security Vulnerabilities and Mitigation

#### High Risk Vulnerabilities

##### RV-001: Replay Attacks
**Risk**: Attacker replays captured authentication responses
**Impact**: Account compromise
**Mitigation**: 
- Unique challenge per request
- Challenge expiration (5 minutes)
- Challenge single-use enforcement
- Cryptographic binding to session

**Testing**: Replay attack simulation with captured responses

##### RV-002: Man-in-the-Middle Attacks
**Risk**: Attacker intercepts and modifies WebAuthn communications
**Impact**: Credential theft, authentication bypass
**Mitigation**:
- TLS 1.2+ enforcement
- Certificate pinning
- Origin validation
- HSTS headers

**Testing**: MITM simulation with invalid certificates

##### RV-003: Credential Enumeration
**Risk**: Attacker discovers valid credential IDs
**Impact**: Targeted attacks, privacy breach
**Mitigation**:
- Random credential IDs
- No credential ID leakage in error messages
- Rate limiting on credential lookups
- Generic error messages

**Testing**: Credential enumeration attack simulation

#### Medium Risk Vulnerabilities

##### RV-004: Timing Attacks
**Risk**: Attacker extracts information through response timing
**Impact**: Partial credential discovery
**Mitigation**:
- Constant-time operations
- Response time normalization
- Random delays for failed attempts

**Testing**: Timing analysis with statistical significance

##### RV-005: Database Injection
**Risk**: SQL injection through user inputs
**Impact**: Data breach, system compromise
**Mitigation**:
- Parameterized queries
- Input validation
- ORM usage (Diesel)
- Database user privilege limitation

**Testing**: SQL injection payload testing

#### Low Risk Vulnerabilities

##### RV-006: Information Disclosure
**Risk**: Sensitive information in error messages
**Impact**: System reconnaissance
**Mitigation**:
- Generic error messages
- Detailed logging only server-side
- Proper error handling

**Testing**: Error message analysis

### 7.2 Operational Risks

##### OR-001: Service Availability
**Risk**: Denial of service attacks
**Impact**: Authentication service unavailability
**Mitigation**:
- Rate limiting
- Load balancing
- Circuit breakers
- Monitoring and alerting

##### OR-002: Data Loss
**Risk**: Credential database corruption/loss
**Impact**: User authentication failure
**Mitigation**:
- Regular backups
- Database replication
- Point-in-time recovery
- Data integrity checks

### 7.3 Compliance Risks

##### CR-001: FIDO Alliance Non-Compliance
**Risk**: Implementation fails FIDO certification
**Impact**: Market rejection, legal issues
**Mitigation**:
- Regular compliance testing
- FIDO conformance test suite
- Third-party security audits
- Specification adherence

## 8. Implementation Roadmap

### Phase 1: Core Infrastructure (Weeks 1-2)
- [ ] Project setup and CI/CD pipeline
- [ ] Database schema and migrations
- [ ] Basic WebAuthn service implementation
- [ ] Unit test framework setup

### Phase 2: Registration Flow (Weeks 3-4)
- [ ] Attestation options endpoint
- [ ] Attestation result processing
- [ ] Credential storage implementation
- [ ] Registration flow testing

### Phase 3: Authentication Flow (Weeks 5-6)
- [ ] Assertion options endpoint
- [ ] Assertion result processing
- [ ] User authentication logic
- [ ] Authentication flow testing

### Phase 4: Security Hardening (Weeks 7-8)
- [ ] TLS enforcement
- [ ] Rate limiting implementation
- [ ] Audit logging
- [ ] Security testing suite

### Phase 5: Compliance and Performance (Weeks 9-10)
- [ ] FIDO compliance testing
- [ ] Performance optimization
- [ ] Load testing
- [ ] Documentation completion

## 9. Success Metrics

### 9.1 Technical Metrics
- **Code Coverage**: ≥95% unit test coverage
- **API Coverage**: 100% endpoint integration testing
- **Security**: Zero critical vulnerabilities in security audit
- **Performance**: <100ms response time for 95th percentile
- **Compliance**: 100% FIDO2 specification compliance

### 9.2 Quality Metrics
- **Bug Density**: <1 critical bug per 1000 lines of code
- **Test Pass Rate**: 100% automated test pass rate
- **Documentation**: 100% API documentation coverage
- **Code Quality**: Zero clippy warnings, 100% documentation coverage

This specification provides a comprehensive foundation for implementing a secure, compliant, and thoroughly tested FIDO2/WebAuthn Relying Party Server in Rust.