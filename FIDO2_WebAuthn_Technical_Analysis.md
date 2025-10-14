# FIDO2/WebAuthn Relying Party Server - Technical Analysis

## 1. Security Requirements: FIDO2 Alliance Compliance Requirements

### 1.1 Core Security Requirements

#### **Authentication Security**
- **Challenge-Based Authentication**: Each WebAuthn operation must use cryptographically random challenges (minimum 16 bytes)
- **Origin Validation**: Strict validation of requesting origins against configured RP origins
- **Timeout Enforcement**: Configurable timeouts for all WebAuthn operations (default: 5-10 minutes)
- **Replay Attack Prevention**: One-time use challenges with secure storage and expiration

#### **Cryptographic Requirements**
- **Algorithm Support**: ES256 (-7), RS256 (-257), EdDSA (-8) as per FIDO2 specification
- **Key Storage**: Secure storage of credential public keys with proper access controls
- **Signature Verification**: Full verification of authenticator signatures against stored public keys
- **Attestation Validation**: Support for Packed, FIDO-U2F, and None attestation formats

#### **Transport Security**
- **TLS Enforcement**: HTTPS-only for all WebAuthn endpoints (TLS 1.2+ minimum)
- **CORS Configuration**: Proper Cross-Origin Resource Sharing for WebAuthn API
- **CSRF Protection**: Anti-CSRF tokens for state-changing operations
- **Rate Limiting**: Protection against brute force and enumeration attacks

### 1.2 FIDO2 Specification Compliance

#### **WebAuthn Level 2 Compliance**
- **Credential Creation**: Full support for navigator.credentials.create()
- **Credential Assertion**: Full support for navigator.credentials.get()
- **User Verification**: Support for required, preferred, and discouraged UV
- **Resident Keys**: Support for client-side discoverable credentials
- **Extensions**: Support for credProps, hmac-secret, and largeBlob extensions

#### **Metadata Service Compliance**
- **FIDO Metadata Service (MDS)**: Integration with FIDO Alliance MDS
- **Attestation Statement Validation**: Verification against trusted metadata
- **Authenticator Status Checking**: Revocation and compromise status validation
- **TOC (Table of Contents)**: Regular updates and validation

## 2. Technical Scope: Core WebAuthn Operations

### 2.1 Registration (Attestation) Flow

#### **Phase 1: Credential Creation Options**
```
POST /attestation/options
Request: ServerPublicKeyCredentialCreationOptionsRequest
Response: ServerPublicKeyCredentialCreationOptionsResponse
```

**Key Operations:**
- Generate cryptographically random challenge
- Create user entity with unique ID
- Configure authenticator selection criteria
- Set attestation conveyance preference
- Return PublicKeyCredentialCreationOptions

#### **Phase 2: Attestation Verification**
```
POST /attestation/result
Request: ServerAuthenticatorAttestationResponse
Response: ServerResponse
```

**Key Operations:**
- Verify attestation statement format
- Validate challenge and origin
- Verify authenticator data
- Store credential with metadata
- Return registration status

### 2.2 Authentication (Assertion) Flow

#### **Phase 1: Assertion Options**
```
POST /assertion/options
Request: ServerPublicKeyCredentialGetOptionsRequest
Response: ServerPublicKeyCredentialGetOptionsResponse
```

**Key Operations:**
- Generate cryptographically random challenge
- Retrieve user's allowed credentials
- Configure user verification requirements
- Return PublicKeyCredentialRequestOptions

#### **Phase 2: Assertion Verification**
```
POST /assertion/result
Request: ServerAuthenticatorAssertionResponse
Response: ServerResponse
```

**Key Operations:**
- Verify assertion signature
- Validate challenge and origin
- Check authenticator data
- Update credential usage count
- Return authentication status

### 2.3 Credential Management Operations

#### **Credential Listing**
```
GET /credentials/{username}
Response: Array of ServerPublicKeyCredentialDescriptor
```

#### **Credential Deletion**
```
DELETE /credentials/{credential_id}
Response: ServerResponse
```

#### **User Management**
```
POST /users/create
PUT /users/{username}
DELETE /users/{username}
```

## 3. Rust Architecture: Recommended Project Structure

### 3.1 Core Architecture Components

```
src/
├── lib.rs                    # Library entry point
├── main.rs                   # Binary entry point
├── config/                   # Configuration management
│   ├── mod.rs
│   ├── app_config.rs         # Application configuration
│   └── webauthn_config.rs    # WebAuthn-specific config
├── controllers/              # HTTP request handlers
│   ├── mod.rs
│   ├── attestation.rs        # Registration endpoints
│   ├── assertion.rs          # Authentication endpoints
│   ├── credential.rs         # Credential management
│   └── user.rs               # User management
├── services/                 # Business logic layer
│   ├── mod.rs
│   ├── webauthn_service.rs   # Core WebAuthn operations
│   ├── credential_service.rs # Credential management
│   ├── user_service.rs       # User management
│   └── attestation_service.rs # Attestation validation
├── db/                       # Database layer
│   ├── mod.rs
│   ├── connection.rs         # Database connection pool
│   ├── models.rs             # Diesel models
│   ├── repositories/         # Repository pattern
│   │   ├── mod.rs
│   │   ├── credential_repo.rs
│   │   ├── user_repo.rs
│   │   └── attestation_repo.rs
├── middleware/               # HTTP middleware
│   ├── mod.rs
│   ├── auth.rs               # Authentication middleware
│   ├── cors.rs               # CORS configuration
│   ├── rate_limit.rs         # Rate limiting
│   └── logging.rs            # Request logging
├── routes/                   # Route definitions
│   ├── mod.rs
│   ├── webauthn.rs           # WebAuthn routes
│   └── admin.rs              # Administrative routes
├── error/                    # Error handling
│   ├── mod.rs
│   ├── app_error.rs          # Application error types
│   └── webauthn_error.rs     # WebAuthn-specific errors
├── utils/                    # Utility functions
│   ├── mod.rs
│   ├── crypto.rs             # Cryptographic utilities
│   ├── validation.rs         # Input validation
│   └── time.rs               # Time utilities
└── schema/                   # Diesel schema
    ├── mod.rs
    └── migrations/           # Database migrations
```

### 3.2 Key Dependencies and Their Roles

```toml
# Core WebAuthn
webauthn-rs = "0.5"           # Main WebAuthn implementation
webauthn-rs-proto = "0.5"     # WebAuthn protocol types

# Web Framework
actix-web = "4.9"             # HTTP server and routing
actix-cors = "0.7"            # CORS middleware
actix-rt = "2.10"             # Async runtime

# Database
diesel = { version = "2.1", features = ["postgres", "r2d2", "chrono", "uuid"] }
diesel_migrations = "2.1"     # Database migrations
r2d2 = "0.8"                  # Connection pooling

# Security & Crypto
base64 = "0.22"               # Base64 encoding/decoding
uuid = { version = "1.10", features = ["v4", "serde"] }
rand = "0.8"                  # Cryptographically random numbers
sha2 = "0.10"                 # SHA-2 hashing

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# Configuration & Logging
config = "0.14"               # Configuration management
dotenv = "0.15"               # Environment variables
log = "0.4"                   # Logging facade
env_logger = "0.11"           # Logger implementation
```

### 3.3 Core Service Architecture

#### **WebAuthnService**
```rust
pub struct WebAuthnService {
    webauthn: Webauthn,
    credential_service: Arc<CredentialService>,
    user_service: Arc<UserService>,
}

impl WebAuthnService {
    // Registration operations
    pub async fn generate_attestation_options(
        &self, 
        request: AttestationOptionsRequest
    ) -> Result<PublicKeyCredentialCreationOptions>;
    
    pub async fn verify_attestation_response(
        &self,
        response: AttestationResponse,
        state: AttestationState
    ) -> Result<RegistrationResult>;
    
    // Authentication operations
    pub async fn generate_assertion_options(
        &self,
        request: AssertionOptionsRequest
    ) -> Result<PublicKeyCredentialRequestOptions>;
    
    pub async fn verify_assertion_response(
        &self,
        response: AssertionResponse,
        state: AssertionState
    ) -> Result<AuthenticationResult>;
}
```

## 4. API Design: REST Endpoints and Data Flow

### 4.1 FIDO2 Conformance Test API Endpoints

#### **Registration Endpoints**

```http
POST /attestation/options
Content-Type: application/json

{
    "username": "johndoe@example.com",
    "displayName": "John Doe",
    "authenticatorSelection": {
        "requireResidentKey": false,
        "authenticatorAttachment": "cross-platform",
        "userVerification": "preferred"
    },
    "attestation": "direct"
}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
    "status": "ok",
    "errorMessage": "",
    "rp": {
        "name": "FIDO Server",
        "id": "localhost"
    },
    "user": {
        "id": "S3932ee31vKEC0JtJMIQ",
        "name": "johndoe@example.com",
        "displayName": "John Doe"
    },
    "challenge": "uhUjPNlZfvn7onwuhNdsLPkkE5Fv-lUN",
    "pubKeyCredParams": [
        {
            "type": "public-key",
            "alg": -7
        }
    ],
    "timeout": 60000,
    "excludeCredentials": [],
    "authenticatorSelection": {
        "requireResidentKey": false,
        "authenticatorAttachment": "cross-platform",
        "userVerification": "preferred"
    },
    "attestation": "direct"
}
```

```http
POST /attestation/result
Content-Type: application/json

{
    "id": "lTqW8uw...",
    "rawId": "lTqW8uw...",
    "response": {
        "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAEGdhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAEGZ1YmxpY1B1Ym...",
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidWhValBOWlpmdm43b253dWhOZHNMUGtrRTVGdi1sVU4iLCJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdDo4NDQzIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ"
    },
    "type": "public-key"
}
```

#### **Authentication Endpoints**

```http
POST /assertion/options
Content-Type: application/json

{
    "username": "johndoe@example.com",
    "userVerification": "preferred"
}
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
    "status": "ok",
    "errorMessage": "",
    "challenge": "R2R6tpV3hGhC9v8yJ9mB",
    "timeout": 60000,
    "rpId": "localhost",
    "allowCredentials": [
        {
            "type": "public-key",
            "id": "lTqW8uw...",
            "transports": ["internal", "usb", "nfc", "ble"]
        }
    ],
    "userVerification": "preferred"
}
```

```http
POST /assertion/result
Content-Type: application/json

{
    "id": "lTqW8uw...",
    "rawId": "lTqW8uw...",
    "response": {
        "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAQ",
        "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiUjJSNnRwVjNoR2hDOXY4eUo5bUIiLCJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdDo4NDQzIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ",
        "signature": "MEUCIQCdwBCrPzZy_8Y2LgKdZjHJh5f9h8f9h8f9h8f9h8f9h8f9h8f9h8f9h8f9h8f9",
        "userHandle": "S3932ee31vKEC0JtJMIQ"
    },
    "type": "public-key"
}
```

### 4.2 Data Flow Architecture

```
Client Browser
    ↓ (HTTPS/WebAuthn API)
Load Balancer / TLS Termination
    ↓
Actix-Web Server
    ├── Middleware Layer
    │   ├── CORS
    │   ├── Rate Limiting
    │   ├── Request Logging
    │   └── Error Handling
    ├── Route Layer
    │   ├── /attestation/options
    │   ├── /attestation/result
    │   ├── /assertion/options
    │   └── /assertion/result
    ├── Controller Layer
    │   ├── Request Validation
    │   ├── Response Formatting
    │   └── Error Mapping
    ├── Service Layer
    │   ├── WebAuthn Operations
    │   ├── Business Logic
    │   └── State Management
    └── Repository Layer
        ├── PostgreSQL
        ├── Credential Storage
        └── User Management
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
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    active BOOLEAN DEFAULT true
);
```

#### **Credentials Table**
```sql
CREATE TABLE credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA UNIQUE NOT NULL,
    credential_public_key BYTEA NOT NULL,
    attestation_type VARCHAR(50) NOT NULL,
    aaguid BYTEA,
    sign_count BIGINT NOT NULL DEFAULT 0,
    backup_eligible BOOLEAN NOT NULL DEFAULT false,
    backup_state BOOLEAN NOT NULL DEFAULT false,
    transports JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    user_verification BOOLEAN NOT NULL DEFAULT false,
    authenticator_attachment VARCHAR(50),
    attestation_object BYTEA,
    client_data_json_hash BYTEA
);
```

#### **Attestation Metadata Table**
```sql
CREATE TABLE attestation_metadata (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    aaguid BYTEA UNIQUE NOT NULL,
    metadata_statement JSONB NOT NULL,
    trusted BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

#### **Challenge Storage Table**
```sql
CREATE TABLE challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    challenge_base64 VARCHAR(255) UNIQUE NOT NULL,
    user_id UUID REFERENCES users(id),
    challenge_type VARCHAR(20) NOT NULL, -- 'attestation' or 'assertion'
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    used BOOLEAN DEFAULT false
);
```

### 5.2 Data Security Requirements

#### **Encryption at Rest**
- **Credential Public Keys**: Stored as encrypted BYTEA
- **Attestation Objects**: Encrypted storage for privacy
- **User Identifiers**: Hashed or encrypted where possible
- **Challenge Values**: Temporary storage with automatic cleanup

#### **Access Controls**
- **Row-Level Security**: User isolation at database level
- **Audit Logging**: All credential operations logged
- **Backup Encryption**: Encrypted database backups
- **Key Rotation**: Support for cryptographic key rotation

### 5.3 In-Memory Storage Requirements

#### **Challenge Cache**
```rust
pub struct ChallengeCache {
    challenges: Arc<RwLock<HashMap<String, ChallengeEntry>>>,
}

#[derive(Debug, Clone)]
pub struct ChallengeEntry {
    pub challenge: String,
    pub user_id: Option<Uuid>,
    pub challenge_type: ChallengeType,
    pub expires_at: SystemTime,
    pub created_at: SystemTime,
}
```

#### **Session State**
```rust
pub struct WebAuthnState {
    pub challenge: String,
    pub user_id: Uuid,
    pub timeout: Duration,
    pub allowed_credentials: Vec<PublicKeyCredentialDescriptor>,
}
```

## 6. Compliance Checklist: FIDO2 Specification Compliance Points

### 6.1 WebAuthn Level 2 Compliance Checklist

#### **✅ Core Requirements**
- [ ] **RP ID Validation**: Verify RP ID against effective domain
- [ ] **Origin Validation**: Validate request origin against configured origins
- [ ] **Challenge Generation**: Cryptographically random challenges (≥16 bytes)
- [ ] **Challenge Storage**: Secure storage with expiration
- [ ] **Timeout Handling**: Configurable timeouts with proper cleanup

#### **✅ Registration Compliance**
- [ ] **Attestation Statement Validation**: Support for Packed, FIDO-U2F, None
- [ ] **Authenticator Data Validation**: Verify flags, AAGUID, counter
- [ ] **Client Data JSON Validation**: Verify type, challenge, origin
- [ ] **User Verification**: Handle required, preferred, discouraged
- [ ] **Exclude Credentials**: Prevent duplicate credential registration

#### **✅ Authentication Compliance**
- [ ] **Assertion Verification**: Verify signature, authenticator data
- [ ] **User Presence**: Verify UP flag is set
- [ ] **User Verification**: Verify UV flag when required
- [ ] **Sign Counter**: Verify and update sign counter
- [ ] **Backup Eligibility**: Handle backup state flags

#### **✅ Extension Support**
- [ ] **credProps**: Return credential properties
- [ ] **hmac-secret**: Support for HMAC secret extension
- [ ] **largeBlob**: Support for large blob storage
- [ ] **txAuthSimple**: Transaction authorization support

### 6.2 FIDO2 Metadata Service Compliance

#### **✅ MDS Integration**
- [ ] **TOC Download**: Regular download of metadata TOC
- [ ] **Metadata Validation**: Verify metadata signatures
- [ ] **Status Checking**: Check authenticator compromise status
- [ ] **Automatic Updates**: Scheduled metadata updates

#### **✅ Attestation Compliance**
- [ ] **Basic Attestation**: Verify basic attestation statements
- [ ] **Self Attestation**: Handle self-attested devices
- [ ] **None Attestation**: Support for privacy-preserving attestation
- [ ] **Anonymization**: Support for anonymized ca certificates

### 6.3 Security Compliance Checklist

#### **✅ Cryptographic Security**
- [ ] **Algorithm Support**: ES256, RS256, EdDSA
- [ ] **Random Number Generation**: CSPRNG for challenges
- [ ] **Key Storage**: Secure key storage mechanisms
- [ ] **Signature Verification**: Proper signature validation

#### **✅ Transport Security**
- [ ] **TLS 1.2+**: Minimum TLS version enforcement
- [ ] **HSTS**: HTTP Strict Transport Security
- [ ] **Certificate Validation**: Proper certificate validation
- [ ] **Forward Secrecy**: Support for perfect forward secrecy

#### **✅ Application Security**
- [ ] **Input Validation**: Comprehensive input sanitization
- [ ] **Rate Limiting**: Protection against brute force
- [ ] **CSRF Protection**: Anti-CSRF tokens
- [ ] **Secure Headers**: Security headers configuration

## 7. Risk Assessment: Security Considerations and Potential Vulnerabilities

### 7.1 High-Risk Vulnerabilities

#### **🔴 Replay Attacks**
**Risk**: Reuse of valid WebAuthn responses
**Mitigation**:
- One-time use challenges with immediate invalidation
- Short challenge expiration (5-10 minutes)
- Challenge binding to user session
- Cryptographically random challenge generation

#### **🔴 Man-in-the-Middle Attacks**
**Risk**: Interception and modification of WebAuthn communications
**Mitigation**:
- Strict origin validation
- TLS enforcement with certificate pinning
- Challenge-response verification
- RP ID validation against effective domain

#### **🔴 Credential Theft**
**Risk**: Unauthorized access to stored credentials
**Mitigation**:
- Encrypted credential storage
- Database access controls
- Regular security audits
- Key rotation procedures

### 7.2 Medium-Risk Vulnerabilities

#### **🟡 Enumeration Attacks**
**Risk**: User enumeration through registration/authentication flows
**Mitigation**:
- Consistent error messages
- Rate limiting per username/IP
- Generic failure responses
- Account lockout policies

#### **🟡 Denial of Service**
**Risk**: Resource exhaustion through malicious requests
**Mitigation**:
- Request rate limiting
- Resource usage monitoring
- Challenge cleanup automation
- Load balancing and scaling

#### **🟡 Attestation Privacy**
**Risk**: Privacy leakage through attestation data
**Mitigation**:
- Support for none attestation
- Anonymization options
- User consent for attestation
- Minimal data collection

### 7.3 Low-Risk Vulnerabilities

#### **🟢 Timing Attacks**
**Risk**: Information disclosure through response timing
**Mitigation**:
- Constant-time operations
- Response time normalization
- Random delays for failures

#### **🟢 Logging Security**
**Risk**: Sensitive data in logs
**Mitigation**:
- Sanitized logging
- Log rotation and encryption
- Access control for logs
- Audit trail maintenance

### 7.4 Security Monitoring and Incident Response

#### **Monitoring Requirements**
```rust
pub struct SecurityMetrics {
    pub failed_authentications: Counter,
    pub failed_registrations: Counter,
    pub rate_limit_violations: Counter,
    pub suspicious_origins: Counter,
    pub unusual_credential_usage: Counter,
}
```

#### **Incident Response Procedures**
1. **Immediate Response**: Block suspicious IPs/origins
2. **Investigation**: Analyze logs and patterns
3. **Containment**: Rotate compromised credentials
4. **Recovery**: Restore from secure backups
5. **Post-Mortem**: Update security measures

### 7.5 Compliance and Auditing

#### **Audit Requirements**
- **Access Logs**: All WebAuthn operations logged
- **Change Logs**: Credential modifications tracked
- **Security Events**: Suspicious activities recorded
- **Compliance Reports**: Regular compliance assessments

#### **Data Privacy Compliance**
- **GDPR**: User data protection and deletion rights
- **CCPA**: California consumer privacy compliance
- **Data Minimization**: Collect only necessary data
- **Consent Management**: Explicit user consent for data processing

---

## Implementation Priority Matrix

| Feature | Priority | Complexity | Security Impact |
|---------|----------|-----------|-----------------|
| Basic Registration/Authentication | High | Medium | Critical |
| Challenge Management | High | Low | Critical |
| TLS Enforcement | High | Low | Critical |
| Database Schema | High | Medium | High |
| Rate Limiting | High | Low | High |
| Attestation Validation | Medium | High | Medium |
| MDS Integration | Medium | High | Medium |
| Extension Support | Low | Medium | Low |
| Admin Interface | Low | Medium | Low |

This comprehensive analysis provides the foundation for implementing a secure, FIDO2-compliant WebAuthn server in Rust using the webauthn-rs library. The architecture prioritizes security while maintaining flexibility for future enhancements and compliance requirements.