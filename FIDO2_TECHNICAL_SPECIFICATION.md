# FIDO2/WebAuthn Relying Party Server - Technical Specification

## Executive Summary

This document provides a comprehensive technical specification for implementing a FIDO2/WebAuthn Relying Party Server in Rust using the webauthn-rs library. The specification focuses on security-first design, FIDO Alliance compliance, and comprehensive test-driven development.

## 1. Security Requirements

### 1.1 FIDO Alliance Compliance Requirements

#### Core Security Requirements (Testable Criteria)
- **SR-001**: Server MUST implement WebAuthn Level 2 compliance
- **SR-002**: Server MUST support attestation formats: packed, fido-u2f, none
- **SR-003**: Server MUST validate attestation statements according to FIDO2 specification
- **SR-004**: Server MUST enforce user verification requirements based on RP policy
- **SR-005**: Server MUST implement proper credential binding to user accounts
- **SR-006**: Server MUST prevent credential replay attacks using challenge-response
- **SR-007**: Server MUST validate origin against configured RP ID
- **SR-008**: Server MUST implement proper timeout handling for ceremonies

#### Cryptographic Requirements
- **CR-001**: Server MUST use cryptographically secure random challenge generation (≥128 bits)
- **CR-002**: Server MUST validate COSE key parameters and algorithms
- **CR-003**: Server MUST support ES256, RS256, and EdDSA algorithms
- **CR-004**: Server MUST validate signature formats and padding
- **CR-005**: Server MUST implement proper certificate chain validation for attestation

#### Session Security
- **SS-001**: Server MUST enforce HTTPS/TLS 1.2+ for all endpoints
- **SS-002**: Server MUST implement secure session management
- **SS-003**: Server MUST protect against CSRF attacks
- **SS-004**: Server MUST implement rate limiting for authentication attempts
- **SS-005**: Server MUST log security-relevant events with proper audit trails

### 1.2 Data Protection Requirements

#### Credential Storage Security
- **DS-001**: Server MUST encrypt credential private keys at rest
- **DS-002**: Server MUST implement secure credential backup and recovery
- **DS-003**: Server MUST enforce credential uniqueness per user
- **DS-004**: Server MUST implement credential revocation mechanisms
- **DS-005**: Server MUST validate credential metadata integrity

#### User Data Protection
- **UD-001**: Server MUST implement proper user authentication before credential operations
- **UD-002**: Server MUST enforce least privilege access to credential data
- **UD-003**: Server MUST implement data retention policies
- **UD-004**: Server MUST provide credential export functionality with proper authorization

## 2. Technical Scope

### 2.1 Core WebAuthn Operations

#### Registration (Attestation) Flow
**Success Conditions:**
- Valid challenge-response exchange completed
- Attestation statement validated successfully
- Credential properly bound to user account
- Metadata stored securely
- Response includes registration completion status

**Failure Conditions:**
- Invalid or expired challenge
- Malformed attestation statement
- Unsupported attestation format
- User verification requirements not met
- Origin validation failure
- Cryptographic validation failure
- Duplicate credential detection

#### Authentication (Assertion) Flow
**Success Conditions:**
- Valid challenge-response exchange completed
- Assertion signature validated successfully
- User verification requirements satisfied
- Credential found and active
- Authentication context established

**Failure Conditions:**
- Invalid or expired challenge
- Invalid assertion signature
- Credential not found or inactive
- User verification failure
- Origin validation failure
- Counter replay detection triggered

### 2.2 Edge Case Testing Requirements

#### Registration Edge Cases
- EC-REG-001: Multiple simultaneous registration attempts
- EC-REG-002: Registration with expired challenge
- EC-REG-003: Registration with malformed attestation
- EC-REG-004: Registration with unsupported algorithms
- EC-REG-005: Registration during network interruption
- EC-REG-006: Registration with duplicate credential ID
- EC-REG-007: Registration with invalid user verification

#### Authentication Edge Cases
- EC-AUTH-001: Authentication with revoked credential
- EC-AUTH-002: Authentication with invalid counter
- EC-AUTH-003: Authentication during session timeout
- EC-AUTH-004: Authentication with malformed assertion
- EC-AUTH-005: Authentication with multiple credentials
- EC-AUTH-006: Authentication replay attack attempts
- EC-AUTH-007: Authentication with compromised credentials

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
│   ├── mod.rs               # Controller module
│   ├── registration.rs      # Registration endpoints
│   ├── authentication.rs    # Authentication endpoints
│   └── user.rs              # User management endpoints
├── services/
│   ├── mod.rs               # Service module
│   ├── webauthn.rs          # WebAuthn service layer
│   ├── credential.rs        # Credential management
│   ├── user.rs              # User service
│   └── attestation.rs       # Attestation validation
├── db/
│   ├── mod.rs               # Database module
│   ├── connection.rs        # Connection management
│   ├── models.rs            # Database models
│   └── repositories.rs      # Repository pattern
├── middleware/
│   ├── mod.rs               # Middleware module
│   ├── auth.rs              # Authentication middleware
│   ├── cors.rs              # CORS middleware
│   ├── rate_limit.rs        # Rate limiting
│   └── logging.rs           # Request logging
├── routes/
│   ├── mod.rs               # Route definitions
│   ├── webauthn.rs          # WebAuthn routes
│   └── health.rs            # Health check routes
├── error/
│   ├── mod.rs               # Error handling
│   ├── types.rs             # Error types
│   └── responses.rs         # Error responses
├── utils/
│   ├── mod.rs               # Utility functions
│   ├── crypto.rs            # Cryptographic utilities
│   ├── validation.rs        # Input validation
│   └── time.rs              # Time utilities
└── schema/
    ├── mod.rs               # Database schema
    ├── credentials.rs       # Credential schema
    └── users.rs             # User schema
```

### 3.2 Testing Architecture

#### Unit Test Structure
```
tests/unit/
├── services/
│   ├── webauthn_test.rs     # WebAuthn service tests
│   ├── credential_test.rs   # Credential service tests
│   └── attestation_test.rs  # Attestation validation tests
├── controllers/
│   ├── registration_test.rs # Registration controller tests
│   └── authentication_test.rs # Authentication controller tests
├── utils/
│   ├── crypto_test.rs       # Cryptographic utility tests
│   └── validation_test.rs   # Validation tests
└── error/
    └── error_test.rs        # Error handling tests
```

#### Integration Test Structure
```
tests/integration/
├── api/
│   ├── registration_test.rs # Registration API tests
│   ├── authentication_test.rs # Authentication API tests
│   └── user_test.rs         # User management API tests
├── security/
│   ├── compliance_test.rs   # FIDO2 compliance tests
│   ├── replay_test.rs       # Replay attack tests
│   └── crypto_test.rs       # Cryptographic security tests
└── performance/
    ├── load_test.rs         # Load testing
    └── concurrent_test.rs   # Concurrency tests
```

### 3.3 Key Dependencies and Testing Considerations

#### Core Dependencies
- `webauthn-rs`: Primary WebAuthn implementation
- `actix-web`: Web framework with testing support
- `diesel`: Database ORM with transaction testing
- `tokio-test`: Async testing utilities
- `mockall`: Mocking framework for unit tests

#### Testing Dependencies
- `actix-test`: HTTP testing utilities
- `tempfile`: Temporary file/database testing
- `wiremock`: HTTP service mocking
- `proptest`: Property-based testing
- `criterion`: Performance benchmarking

## 4. API Design

### 4.1 REST Endpoints Specification

#### Registration Endpoints

**POST /webauthn/register/begin**
```json
Request:
{
  "username": "user@example.com",
  "displayName": "User Display Name",
  "userVerification": "preferred",
  "attestation": "direct"
}

Response (200):
{
  "status": "ok",
  "challenge": "base64url-encoded-challenge",
  "rp": {
    "name": "Example RP",
    "id": "example.com"
  },
  "user": {
    "id": "base64url-encoded-user-id",
    "name": "user@example.com",
    "displayName": "User Display Name"
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
    "userVerification": "preferred"
  }
}

Error Responses:
400: Invalid request format
401: User not authenticated
429: Rate limit exceeded
500: Internal server error
```

**POST /webauthn/register/finish**
```json
Request:
{
  "credential": {
    "id": "base64url-encoded-credential-id",
    "rawId": "base64url-encoded-raw-id",
    "type": "public-key",
    "response": {
      "attestationObject": "base64url-encoded-attestation",
      "clientDataJSON": "base64url-encoded-client-data"
    }
  },
  "sessionToken": "session-token"
}

Response (200):
{
  "status": "ok",
  "credentialId": "base64url-encoded-credential-id",
  "userVerified": true,
  "attestationType": "packed",
  "aaguid": "base64url-encoded-aaguid"
}

Error Responses:
400: Invalid credential format
401: Invalid session
403: Attestation verification failed
409: Duplicate credential
422: Unprocessable entity
500: Internal server error
```

#### Authentication Endpoints

**POST /webauthn/authenticate/begin**
```json
Request:
{
  "username": "user@example.com",
  "userVerification": "preferred"
}

Response (200):
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
  "userVerification": "preferred",
  "timeout": 60000,
  "rpId": "example.com"
}

Error Responses:
400: Invalid request format
401: User not found
429: Rate limit exceeded
500: Internal server error
```

**POST /webauthn/authenticate/finish**
```json
Request:
{
  "credential": {
    "id": "base64url-encoded-credential-id",
    "rawId": "base64url-encoded-raw-id",
    "type": "public-key",
    "response": {
      "authenticatorData": "base64url-encoded-auth-data",
      "clientDataJSON": "base64url-encoded-client-data",
      "signature": "base64url-encoded-signature",
      "userHandle": "base64url-encoded-user-handle"
    }
  },
  "sessionToken": "session-token"
}

Response (200):
{
  "status": "ok",
  "credentialId": "base64url-encoded-credential-id",
  "userVerified": true,
  "counter": 12345,
  "sessionToken": "new-session-token"
}

Error Responses:
400: Invalid assertion format
401: Invalid credentials
403: Signature verification failed
422: Unprocessable entity
500: Internal server error
```

### 4.2 Data Flow Specifications

#### Registration Flow
1. Client requests registration challenge
2. Server generates cryptographically secure challenge
3. Server stores challenge with expiration
4. Client creates credential with attestation
5. Server validates attestation statement
6. Server verifies credential binding
7. Server stores credential securely
8. Server returns registration success

#### Authentication Flow
1. Client requests authentication challenge
2. Server retrieves user credentials
3. Server generates challenge for specific credentials
4. Client creates assertion with credential
5. Server validates assertion signature
6. Server verifies counter and replay protection
7. Server updates credential metadata
8. Server establishes authenticated session

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
    credential_id BYTEA UNIQUE NOT NULL,
    credential_public_key BYTEA NOT NULL,
    attestation_type VARCHAR(50) NOT NULL,
    aaguid BYTEA,
    sign_count BIGINT DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true,
    backup_eligible BOOLEAN DEFAULT false,
    backup_state BOOLEAN DEFAULT false,
    transports JSONB,
    user_verification VARCHAR(20) DEFAULT 'preferred'
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
    used BOOLEAN DEFAULT false,
    metadata JSONB
);
```

#### Sessions Table
```sql
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT true,
    metadata JSONB
);
```

### 5.2 Data Validation Requirements

#### Input Validation
- **IV-001**: Username must be valid email format (RFC 5322)
- **IV-002**: Display name must be 1-255 characters, no control characters
- **IV-003**: Credential ID must be base64url-encoded, max 1023 bytes
- **IV-004**: Challenge must be base64url-encoded, exactly 16 bytes
- **IV-005**: Session tokens must be UUID v4 format
- **IV-006**: All timestamps must be ISO 8601 format

#### Data Integrity
- **DI-001**: All foreign key constraints must be enforced
- **DI-002**: Unique constraints on credential IDs and usernames
- **DI-003**: Check constraints for valid enum values
- **DI-004**: Not null constraints on critical fields
- **DI-005**: Proper indexing for performance and uniqueness

#### Encryption Requirements
- **ER-001**: Credential private keys encrypted at rest using AES-256-GCM
- **ER-002**: Session tokens signed using HMAC-SHA256
- **ER-003**: Database connections encrypted (TLS)
- **ER-004**: Backup encryption with customer-managed keys
- **ER-005**: Audit log integrity protection

## 6. Compliance Checklist

### 6.1 FIDO2 Specification Compliance Points

#### WebAuthn Level 2 Compliance
- [ ] **WC-001**: Implement all required WebAuthn API endpoints
- [ ] **WC-002**: Support all required attestation formats
- [ ] **WC-003**: Implement proper challenge generation and validation
- [ ] **WC-004**: Support user verification requirements
- [ ] **WC-005**: Implement proper origin validation
- [ ] **WC-006**: Support credential discovery and management
- [ ] **WC-007**: Implement proper error handling and status codes

#### Attestation Compliance
- [ ] **AC-001**: Validate Packed attestation format
- [ ] **AC-002**: Validate FIDO-U2F attestation format
- [ ] **AC-003**: Handle None attestation format
- [ ] **AC-004**: Validate attestation certificate chains
- [ ] **AC-005**: Verify AAGUID validity
- [ ] **AC-006**: Implement attestation trust anchors

#### Security Compliance
- [ ] **SC-001**: Implement replay attack protection
- [ ] **SC-002**: Enforce proper timeout handling
- [ ] **SC-003**: Implement rate limiting
- [ ] **SC-004**: Secure credential storage
- [ ] **SC-005**: Proper audit logging
- [ ] **SC-006**: TLS enforcement for all communications

### 6.2 Testing Compliance Verification

#### Automated Compliance Tests
- **CT-001**: FIDO2 conformance test suite integration
- **CT-002**: Automated attestation format validation
- **CT-003**: Cryptographic implementation verification
- **CT-004**: API contract compliance testing
- **CT-005**: Security vulnerability scanning

#### Manual Compliance Verification
- **CM-001**: FIDO Alliance certification process
- **CM-002**: Third-party security audit
- **CM-003**: Penetration testing
- **CM-004**: Code review for security best practices

## 7. Risk Assessment

### 7.1 Security Considerations

#### High-Risk Vulnerabilities
- **RV-001**: **Replay Attacks** - Mitigation: Challenge-response with unique, time-bound challenges
- **RV-002**: **Credential Theft** - Mitigation: Encrypted storage, secure backup, user verification
- **RV-003**: **Man-in-the-Middle** - Mitigation: TLS enforcement, origin validation
- **RV-004**: **Attestation Forgery** - Mitigation: Certificate validation, trust anchors
- **RV-005**: **Database Compromise** - Mitigation: Encryption at rest, access controls

#### Medium-Risk Vulnerabilities
- **RV-006**: **Session Hijacking** - Mitigation: Secure session management, token rotation
- **RV-007**: **Denial of Service** - Mitigation: Rate limiting, resource quotas
- **RV-008**: **Information Disclosure** - Mitigation: Proper error handling, audit logging
- **RV-009**: **Weak Cryptography** - Mitigation: Algorithm validation, key strength requirements

#### Low-Risk Vulnerabilities
- **RV-010**: **Timing Attacks** - Mitigation: Constant-time comparisons
- **RV-011**: **Log Injection** - Mitigation: Input sanitization, structured logging
- **RV-012**: **Resource Exhaustion** - Mitigation: Memory limits, connection pooling

### 7.2 Mitigation Strategies

#### Preventive Controls
- **PC-001**: Input validation and sanitization
- **PC-002**: Output encoding and escaping
- **PC-003**: Secure configuration management
- **PC-004**: Regular security updates
- **PC-005**: Security code reviews

#### Detective Controls
- **DC-001**: Comprehensive audit logging
- **DC-002**: Intrusion detection systems
- **DC-003**: Anomaly detection
- **DC-004**: Security monitoring and alerting
- **DC-005**: Regular vulnerability scanning

#### Corrective Controls
- **CC-001**: Incident response procedures
- **CC-002**: Credential revocation mechanisms
- **CC-003**: Backup and recovery procedures
- **CC-004**: Security patch management
- **CC-005**: Forensic analysis capabilities

### 7.3 Compliance Risk Mitigation

#### FIDO2 Compliance Risks
- **FC-001**: **Specification Drift** - Mitigation: Regular specification review, automated testing
- **FC-002**: **Attestation Format Changes** - Mitigation: Flexible attestation handling, version management
- **FC-003**: **Security Requirement Updates** - Mitigation: Continuous monitoring, adaptive security

#### Testing Coverage Risks
- **TC-001**: **Incomplete Test Coverage** - Mitigation: Code coverage analysis, test-driven development
- **TC-002**: **Test Environment Drift** - Mitigation: Infrastructure as code, automated provisioning
- **TC-003**: **Performance Regression** - Mitigation: Continuous performance testing, benchmarking

## Conclusion

This technical specification provides a comprehensive foundation for implementing a secure, compliant FIDO2/WebAuthn Relying Party Server. The specification emphasizes:

1. **Security-First Design**: All requirements prioritize security and FIDO2 compliance
2. **Testability**: Every requirement includes specific testable criteria
3. **Comprehensive Coverage**: Addresses all aspects from API design to storage security
4. **Risk Mitigation**: Proactive identification and mitigation of security risks
5. **Maintainability**: Clear architecture and testing strategies for long-term maintenance

The implementation should follow this specification closely, with regular reviews to ensure continued compliance with evolving FIDO2 standards and security best practices.