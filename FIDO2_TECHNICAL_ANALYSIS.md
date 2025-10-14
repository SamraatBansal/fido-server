# FIDO2/WebAuthn Relying Party Server - Technical Analysis

## 1. Security Requirements: FIDO2 Alliance Compliance

### 1.1 Core Security Requirements

#### **Authentication Security**
- **Zero-Knowledge Proof**: Server never stores user passwords, only public keys
- **Phishing Resistance**: Origin-bound credentials prevent credential harvesting
- **Replay Attack Prevention**: Unique challenges for each authentication ceremony
- **Man-in-the-Middle Protection**: TLS enforcement and origin validation

#### **Cryptographic Requirements**
- **Algorithm Support**: ES256 (P-256), EdDSA (Ed25519), RS256 (RSA-2048+)
- **Attestation Formats**: Packed, FIDO-U2F, None, TPM, Android Key, Android SafetyNet
- **Key Protection**: Private keys never leave authenticator device
- **Random Number Generation**: Cryptographically secure challenge generation

#### **Session Security**
- **Challenge Expiration**: 5-10 minute timeout for registration/authentication
- **One-Time Use**: Challenges must be single-use only
- **Secure Storage**: Challenges stored securely with expiration tracking
- **CSRF Protection**: Anti-CSRF tokens for state-changing operations

### 1.2 FIDO2 Specification Compliance

#### **WebAuthn Level 2 Compliance**
- **Registration Ceremony**: Complete attestation flow with verification
- **Authentication Ceremony**: Full assertion verification process
- **Credential Management**: Add, remove, update user credentials
- **User Verification**: Support for UV (User Verification) flags

#### **Metadata Service (MDS) Compliance**
- **FIDO Metadata Service**: Authenticator metadata validation
- **Attestation Statement Verification**: Format-specific validation
- **Trust Anchor Management**: Root certificate validation
- **Compliance Status**: FIDO Certified status tracking

## 2. Technical Scope: Core WebAuthn Operations

### 2.1 Registration (Attestation) Flow

#### **Step 1: Registration Challenge Generation**
```rust
// Generate registration options
let registration_options = webauthn
    .start_registration(&user, &auth_selection_criteria)
    .await?;
```

**Requirements:**
- Generate cryptographically random challenge (16+ bytes)
- Include user information (ID, name, display name)
- Specify authenticator selection criteria
- Set timeout (5-10 minutes)
- Include attestation preference

#### **Step 2: Registration Response Processing**
```rust
// Process registration response
let credential = webauthn
    .finish_registration(&registration_response, &state)
    .await?;
```

**Requirements:**
- Verify attestation statement format
- Validate authenticator data
- Verify client data JSON
- Check origin and challenge
- Store credential securely

### 2.2 Authentication (Assertion) Flow

#### **Step 1: Authentication Challenge Generation**
```rust
// Generate authentication options
let authentication_options = webauthn
    .start_authentication(&user)
    .await?;
```

**Requirements:**
- Generate unique challenge per authentication
- Include allowed credentials list
- Set user verification requirements
- Specify timeout period

#### **Step 2: Authentication Response Processing**
```rust
// Process authentication response
let auth_result = webauthn
    .finish_authentication(&authentication_response, &state)
    .await?;
```

**Requirements:**
- Verify assertion signature
- Validate authenticator data
- Check user presence/verification flags
- Verify challenge and origin
- Update credential counter

### 2.3 Credential Management

#### **Operations Required**
- **List Credentials**: Retrieve all user credentials
- **Delete Credential**: Remove specific credential
- **Update Credential**: Update credential metadata
- **Credential Discovery**: Find credentials by user ID

## 3. Rust Architecture: Recommended Project Structure

### 3.1 Core Architecture Components

```
src/
├── lib.rs                    # Library entry point
├── main.rs                   # Application entry point
├── config/                   # Configuration management
│   ├── mod.rs
│   ├── database.rs
│   └── webauthn.rs
├── controllers/              # HTTP request handlers
│   ├── mod.rs
│   ├── registration.rs
│   ├── authentication.rs
│   └── credential.rs
├── services/                 # Business logic
│   ├── mod.rs
│   ├── webauthn_service.rs
│   ├── user_service.rs
│   └── credential_service.rs
├── models/                   # Data models
│   ├── mod.rs
│   ├── user.rs
│   ├── credential.rs
│   └── webauthn.rs
├── db/                       # Database layer
│   ├── mod.rs
│   ├── connection.rs
│   ├── repositories/
│   │   ├── mod.rs
│   │   ├── user_repository.rs
│   │   └── credential_repository.rs
│   └── migrations/
├── middleware/               # HTTP middleware
│   ├── mod.rs
│   ├── auth.rs
│   ├── cors.rs
│   └── security.rs
├── routes/                   # Route definitions
│   ├── mod.rs
│   ├── webauthn.rs
│   └── health.rs
├── error/                    # Error handling
│   ├── mod.rs
│   └── types.rs
└── utils/                    # Utilities
    ├── mod.rs
    ├── crypto.rs
    └── validation.rs
```

### 3.2 Key Dependencies Analysis

#### **webauthn-rs Integration**
```rust
// Core WebAuthn configuration
use webauthn_rs::prelude::*;

pub struct WebAuthnService {
    webauthn: WebAuthn<WebauthnConfig>,
    challenge_store: Arc<dyn ChallengeStore>,
}

impl WebAuthnService {
    pub fn new(config: WebauthnConfig) -> Self {
        Self {
            webauthn: WebAuthn::new(config),
            challenge_store: Arc::new(InMemoryChallengeStore::new()),
        }
    }
}
```

#### **Database Integration**
```rust
// Diesel ORM models
#[derive(Queryable, Identifiable, Serialize)]
#[diesel(table_name = users)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
}

#[derive(Queryable, Identifiable, Associations, Serialize)]
#[diesel(belongs_to(User))]
#[diesel(table_name = credentials)]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub sign_count: u32,
    pub attestation_format: String,
    pub created_at: NaiveDateTime,
    pub last_used_at: Option<NaiveDateTime>,
}
```

## 4. API Design: REST Endpoints and Data Flow

### 4.1 Registration Endpoints

#### **POST /api/v1/registration/challenge**
```json
// Request
{
  "username": "user@example.com",
  "displayName": "John Doe",
  "attestation": "direct",
  "authenticatorSelection": {
    "authenticatorAttachment": "platform",
    "requireResidentKey": false,
    "userVerification": "preferred"
  }
}

// Response
{
  "challenge": "Y2hhbGxlbmdlXzEyMzQ1Njc4OTA=",
  "rp": {
    "name": "FIDO Server",
    "id": "example.com"
  },
  "user": {
    "id": "dXNlcl9pZF8xMjM0",
    "name": "user@example.com",
    "displayName": "John Doe"
  },
  "pubKeyCredParams": [
    {"type": "public-key", "alg": -7},
    {"type": "public-key", "alg": -257}
  ],
  "timeout": 600000,
  "attestation": "direct"
}
```

#### **POST /api/v1/registration/verify**
```json
// Request
{
  "credential": {
    "id": "credential_id_base64",
    "rawId": "credential_id_base64",
    "response": {
      "attestationObject": "attestation_object_base64",
      "clientDataJSON": "client_data_json_base64"
    },
    "type": "public-key"
  },
  "sessionData": {
    "challenge": "Y2hhbGxlbmdlXzEyMzQ1Njc4OTA=",
    "userId": "dXNlcl9pZF8xMjM0"
  }
}

// Response
{
  "credentialId": "credential_id_base64",
  "status": "success",
  "errorMessage": null
}
```

### 4.2 Authentication Endpoints

#### **POST /api/v1/authentication/challenge**
```json
// Request
{
  "username": "user@example.com",
  "userVerification": "preferred"
}

// Response
{
  "challenge": "Y2hhbGxlbmdlXzg3NjU0MzIxMA==",
  "allowCredentials": [
    {
      "type": "public-key",
      "id": "credential_id_base64",
      "transports": ["internal", "usb", "nfc", "ble"]
    }
  ],
  "userVerification": "preferred",
  "timeout": 600000
}
```

#### **POST /api/v1/authentication/verify**
```json
// Request
{
  "credential": {
    "id": "credential_id_base64",
    "rawId": "credential_id_base64",
    "response": {
      "authenticatorData": "authenticator_data_base64",
      "clientDataJSON": "client_data_json_base64",
      "signature": "signature_base64",
      "userHandle": "user_id_base64"
    },
    "type": "public-key"
  },
  "sessionData": {
    "challenge": "Y2hhbGxlbmdlXzg3NjU0MzIxMA==",
    "username": "user@example.com"
  }
}

// Response
{
  "status": "success",
  "errorMessage": null,
  "newSignCount": 42
}
```

### 4.3 Credential Management Endpoints

#### **GET /api/v1/credentials**
```json
// Response
{
  "credentials": [
    {
      "id": "credential_id_base64",
      "name": "My Security Key",
      "createdAt": "2023-01-01T00:00:00Z",
      "lastUsedAt": "2023-01-15T10:30:00Z",
      "transports": ["usb", "nfc"]
    }
  ]
}
```

#### **DELETE /api/v1/credentials/{credentialId}**
```json
// Response
{
  "status": "success",
  "message": "Credential deleted successfully"
}
```

## 5. Storage Requirements: Credential Storage and User Mapping

### 5.1 Database Schema Design

#### **Users Table**
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

#### **Credentials Table**
```sql
CREATE TABLE credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA UNIQUE NOT NULL,
    public_key BYTEA NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    attestation_format VARCHAR(50) NOT NULL,
    aaguid BYTEA,
    transports JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    backup_eligible BOOLEAN DEFAULT FALSE,
    backup_state BOOLEAN DEFAULT FALSE
);

CREATE INDEX idx_credentials_user_id ON credentials(user_id);
CREATE INDEX idx_credentials_credential_id ON credentials(credential_id);
```

#### **Challenges Table (for replay protection)**
```sql
CREATE TABLE challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    challenge BYTEA NOT NULL,
    user_id UUID REFERENCES users(id),
    challenge_type VARCHAR(20) NOT NULL, -- 'registration' or 'authentication'
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    used BOOLEAN DEFAULT FALSE
);

CREATE INDEX idx_challenges_expires_at ON challenges(expires_at);
CREATE INDEX idx_challenges_user_id ON challenges(user_id);
```

### 5.2 Data Security Requirements

#### **Encryption at Rest**
- **Public Keys**: Stored as-is (public information)
- **Credential IDs**: Base64 encoded for storage
- **Challenges**: Stored with expiration, automatically cleaned
- **User Data**: PII encrypted if required by compliance

#### **Access Control**
- **Row-Level Security**: Users can only access their own credentials
- **Database Encryption**: Transparent Data Encryption (TDE)
- **Audit Logging**: All credential operations logged
- **Backup Security**: Encrypted backups with access controls

## 6. Compliance Checklist: FIDO2 Specification Compliance

### 6.1 WebAuthn Level 2 Requirements

#### **✅ Registration Ceremony**
- [ ] Generate proper registration options
- [ ] Support multiple attestation formats
- [ ] Verify attestation statements
- [ ] Store credentials securely
- [ ] Handle user verification requirements

#### **✅ Authentication Ceremony**
- [ ] Generate authentication challenges
- [ ] Verify assertion signatures
- [ ] Update sign counters
- [ ] Handle user verification
- [ ] Support multiple transports

#### **✅ Credential Management**
- [ ] List user credentials
- [ ] Delete credentials
- [ ] Update credential metadata
- [ ] Handle credential discovery

### 6.2 Security Requirements

#### **✅ Cryptographic Security**
- [ ] Use cryptographically secure random numbers
- [ ] Support required algorithms (ES256, RS256, EdDSA)
- [ ] Verify certificate chains for attestation
- [ ] Implement proper key validation

#### **✅ Protocol Security**
- [ ] Enforce HTTPS/TLS 1.3
- [ ] Validate origins properly
- [ ] Prevent replay attacks
- [ ] Implement proper session management

#### **✅ Data Protection**
- [ ] Encrypt sensitive data at rest
- [ ] Implement proper access controls
- [ ] Log security events
- [ ] Handle data retention requirements

### 6.3 FIDO Alliance Test Requirements

#### **✅ Conformance Test Coverage**
- [ ] Registration flow tests
- [ ] Authentication flow tests
- [ ] Error handling tests
- [ ] Edge case handling
- [ ] Performance requirements

#### **✅ Interoperability**
- [ ] Support major browsers
- [ ] Support various authenticators
- [ ] Handle different platforms
- [ ] Test with FIDO conformance tools

## 7. Risk Assessment: Security Considerations and Vulnerabilities

### 7.1 High-Risk Areas

#### **🔴 Replay Attacks**
**Risk**: Reuse of captured authentication responses
**Mitigation**:
- Single-use challenges with expiration
- Challenge storage with automatic cleanup
- Cryptographic binding to user session

#### **🔴 Man-in-the-Middle Attacks**
**Risk**: Interception of WebAuthn communications
**Mitigation**:
- Enforce TLS 1.3 with strong cipher suites
- Origin validation in client data
- Certificate pinning for critical operations

#### **🔴 Credential Theft**
**Risk**: Unauthorized access to stored credentials
**Mitigation**:
- Database encryption at rest
- Row-level security for user data
- Audit logging for all credential operations

### 7.2 Medium-Risk Areas

#### **🟡 Attestation Bypass**
**Risk**: Fake attestation statements
**Mitigation**:
- Verify attestation certificate chains
- Use FIDO Metadata Service
- Implement trust anchor validation

#### **🟡 User Enumeration**
**Risk**: Discovering valid usernames
**Mitigation**:
- Consistent error responses
- Rate limiting on challenge requests
- Generic error messages

#### **🟡 Denial of Service**
**Risk**: Resource exhaustion attacks
**Mitigation**:
- Rate limiting on all endpoints
- Challenge expiration and cleanup
- Resource usage monitoring

### 7.3 Low-Risk Areas

#### **🟢 Configuration Errors**
**Risk**: Misconfigured WebAuthn parameters
**Mitigation**:
- Configuration validation
- Default secure settings
- Comprehensive testing

#### **🟢 Logging Issues**
**Risk**: Insufficient security logging
**Mitigation**:
- Structured logging format
- Log retention policies
- Security event correlation

### 7.4 Security Monitoring Requirements

#### **Real-time Monitoring**
- Failed authentication attempts
- Unusual credential usage patterns
- Challenge generation anomalies
- Database access patterns

#### **Alerting Thresholds**
- Multiple failed authentications (>5 in 5 minutes)
- Credential usage from new locations
- Challenge generation spikes
- Database access anomalies

#### **Incident Response**
- Credential compromise procedures
- User notification processes
- Forensic data collection
- Recovery procedures

## Implementation Priority

### **Phase 1: Core Functionality**
1. Basic registration/authentication flow
2. In-memory credential storage
3. Basic API endpoints
4. Security middleware

### **Phase 2: Production Readiness**
1. PostgreSQL integration
2. Comprehensive error handling
3. Security monitoring
4. Performance optimization

### **Phase 3: Advanced Features**
1. FIDO Metadata Service integration
2. Advanced attestation verification
3. Multi-factor authentication
4. Compliance certification

This analysis provides a comprehensive foundation for implementing a secure, FIDO2-compliant WebAuthn server in Rust with the webauthn-rs library.