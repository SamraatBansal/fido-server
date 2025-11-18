# FIDO2/WebAuthn Relying Party Server - Technical Specification

## 1. Security Requirements & FIDO Alliance Compliance

### 1.1 Core Security Requirements
- **FIDO2 Level 1 Certification Compliance**: All operations must comply with FIDO Alliance specifications
- **Cryptographic Verification**: Attestation and assertion signature validation using proper algorithms
- **Origin Validation**: Strict enforcement of allowed origins and RP ID validation
- **Challenge Entropy**: Cryptographically secure random challenge generation (≥128 bits entropy)
- **Replay Attack Prevention**: Challenge-response mechanism with time-based expiration
- **TLS Enforcement**: All communications must use TLS 1.2+ with proper certificate validation

### 1.2 Testable Security Criteria
```rust
// Security test requirements
struct SecurityTestCriteria {
    challenge_entropy_bits: u32,        // Must be ≥ 128
    challenge_timeout_seconds: u64,     // Recommended: 300s
    max_concurrent_challenges: u32,     // Rate limiting
    signature_algorithm_support: Vec<COSEAlgorithmIdentifier>,
    attestation_statement_formats: Vec<AttestationStatementFormat>,
}
```

### 1.3 FIDO2 Compliance Points
1. **WebAuthn Level 2 API Support**: Full compatibility with W3C WebAuthn recommendation
2. **CTAP2 Protocol Support**: Communication with FIDO2 authenticators
3. **Attestation Verification**: Support for packed, tpm, android-key, android-safetynet, fido-u2f
4. **User Verification**: Support for UV=required, preferred, discouraged
5. **Resident Keys**: Support for resident key (discoverable credential) operations
6. **Extension Support**: Proper handling of WebAuthn extensions

## 2. Technical Scope & Operations

### 2.1 Registration Flow (Attestation)
```rust
// Registration endpoints with success/failure conditions
pub enum RegistrationResult {
    Success {
        credential_id: Vec<u8>,
        public_key: Vec<u8>,
        sign_count: u32,
        attestation_verified: bool,
    },
    Failure(RegistrationError),
}

pub enum RegistrationError {
    InvalidChallenge,           // Test: Expired/invalid challenge
    OriginMismatch,            // Test: Wrong origin in clientDataJSON
    AttestationVerificationFailed, // Test: Invalid attestation
    DuplicateCredential,       // Test: Credential already registered
    UnsupportedAlgorithm,      // Test: Unsupported COSE algorithm
    MalformedRequest,          // Test: Invalid request structure
}
```

### 2.2 Authentication Flow (Assertion)
```rust
pub enum AuthenticationResult {
    Success {
        credential_id: Vec<u8>,
        sign_count: u32,
        user_verified: bool,
    },
    Failure(AuthenticationError),
}

pub enum AuthenticationError {
    InvalidChallenge,          // Test: Challenge mismatch/expired
    CredentialNotFound,        // Test: Unknown credential ID
    SignatureVerificationFailed, // Test: Invalid assertion signature
    CounterRollback,           // Test: Sign count decreased
    UserVerificationFailed,    // Test: UV required but not provided
    OriginMismatch,           // Test: Origin validation failure
}
```

### 2.3 Core WebAuthn Operations
1. **MakeCredential Options Generation**
   - Challenge generation with secure randomness
   - User verification requirements validation
   - Authenticator selection criteria application
   - Extension processing

2. **MakeCredential Result Processing**
   - Attestation statement verification
   - ClientDataJSON validation
   - Credential ID uniqueness verification
   - Public key extraction and validation

3. **GetAssertion Options Generation**
   - Challenge generation for authentication
   - Credential ID filtering based on user context
   - User verification policy enforcement

4. **GetAssertion Result Processing**
   - Signature verification using stored public key
   - Counter validation for replay protection
   - User presence/verification validation

## 3. Rust Architecture & Project Structure

### 3.1 Recommended Project Structure
```
fido2-webauthn-server/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── lib.rs
│   ├── api/
│   │   ├── mod.rs
│   │   ├── registration.rs      // Registration endpoints
│   │   ├── authentication.rs    // Authentication endpoints
│   │   ├── middleware.rs        // Security middleware
│   │   └── error.rs            // Error handling
│   ├── core/
│   │   ├── mod.rs
│   │   ├── webauthn.rs         // WebAuthn core logic
│   │   ├── crypto.rs           // Cryptographic operations
│   │   ├── validation.rs       // Input validation
│   │   └── config.rs           // Configuration management
│   ├── storage/
│   │   ├── mod.rs
│   │   ├── models.rs           // Data models
│   │   ├── repository.rs       // Storage abstraction
│   │   ├── memory.rs           // In-memory storage
│   │   └── postgres.rs         // PostgreSQL implementation
│   └── utils/
│       ├── mod.rs
│       ├── base64.rs           // Base64 encoding/decoding
│       └── time.rs             // Time utilities
├── tests/
│   ├── integration/
│   │   ├── registration_tests.rs
│   │   ├── authentication_tests.rs
│   │   ├── compliance_tests.rs
│   │   └── security_tests.rs
│   └── unit/
│       ├── crypto_tests.rs
│       ├── validation_tests.rs
│       └── storage_tests.rs
├── benches/
│   └── webauthn_bench.rs
└── docs/
    ├── api.md
    ├── security.md
    └── deployment.md
```

### 3.2 Key Dependencies
```toml
[dependencies]
webauthn-rs = { version = "0.5", features = ["danger-allow-state-serialisation"] }
tokio = { version = "1.0", features = ["full"] }
axum = "0.7"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
sqlx = { version = "0.8", features = ["postgres", "runtime-tokio-rustls", "uuid"] }
uuid = { version = "1.0", features = ["v4", "serde"] }
tracing = "0.1"
tracing-subscriber = "0.3"
tower = "0.4"
tower-http = { version = "0.5", features = ["cors", "trace"] }
base64 = "0.22"
url = "2.0"

[dev-dependencies]
reqwest = { version = "0.12", features = ["json"] }
tokio-test = "0.4"
```

### 3.3 Testing Architecture
```rust
// Test configuration for different scenarios
pub struct TestConfig {
    pub webauthn_config: WebauthnConfig,
    pub storage_type: StorageType,
    pub security_policy: SecurityPolicy,
    pub compliance_level: ComplianceLevel,
}

#[derive(Debug)]
pub enum StorageType {
    Memory,
    PostgresTestDb,
    MockStorage,
}

#[derive(Debug)]
pub enum ComplianceLevel {
    Basic,
    FIDO2Level1,
    FIDO2Level2,
    FIDO2Level3,
}
```

## 4. API Design & Data Flow

### 4.1 Registration Endpoints

#### POST /webauthn/register/begin
**Request:**
```json
{
  "username": "user@example.com",
  "displayName": "John Doe",
  "userVerification": "preferred",
  "authenticatorSelection": {
    "authenticatorAttachment": "platform",
    "userVerification": "preferred",
    "requireResidentKey": false
  },
  "attestation": "direct",
  "extensions": {}
}
```

**Response (Success):**
```json
{
  "status": "ok",
  "errorMessage": "",
  "rp": {
    "id": "example.com",
    "name": "Example Corp"
  },
  "user": {
    "id": "dXNlckBleGFtcGxlLmNvbQ",
    "name": "user@example.com",
    "displayName": "John Doe"
  },
  "challenge": "Y2hhbGxlbmdlU3RyaW5nMTIzNDU2Nzg5MA",
  "pubKeyCredParams": [
    {
      "type": "public-key",
      "alg": -7
    },
    {
      "type": "public-key",
      "alg": -257
    }
  ],
  "timeout": 300000,
  "excludeCredentials": [],
  "authenticatorSelection": {
    "authenticatorAttachment": "platform",
    "userVerification": "preferred",
    "requireResidentKey": false
  },
  "attestation": "direct",
  "extensions": {}
}
```

#### POST /webauthn/register/complete
**Request:**
```json
{
  "id": "credential-id-base64url",
  "rawId": "credential-id-base64url",
  "response": {
    "attestationObject": "attestation-object-base64url",
    "clientDataJSON": "client-data-json-base64url",
    "transports": ["usb", "nfc"]
  },
  "type": "public-key",
  "clientExtensionResults": {},
  "authenticatorAttachment": "platform"
}
```

**Response (Success):**
```json
{
  "status": "ok",
  "errorMessage": "",
  "verified": true
}
```

### 4.2 Authentication Endpoints

#### POST /webauthn/authenticate/begin
**Request:**
```json
{
  "username": "user@example.com",
  "userVerification": "preferred",
  "extensions": {}
}
```

**Response:**
```json
{
  "status": "ok",
  "errorMessage": "",
  "challenge": "YXV0aGVudGljYXRpb25DaGFsbGVuZ2U",
  "timeout": 300000,
  "rpId": "example.com",
  "allowCredentials": [
    {
      "type": "public-key",
      "id": "credential-id-base64url",
      "transports": ["usb", "nfc"]
    }
  ],
  "userVerification": "preferred",
  "extensions": {}
}
```

#### POST /webauthn/authenticate/complete
**Request:**
```json
{
  "id": "credential-id-base64url",
  "rawId": "credential-id-base64url",
  "response": {
    "authenticatorData": "authenticator-data-base64url",
    "signature": "signature-base64url",
    "clientDataJSON": "client-data-json-base64url",
    "userHandle": "user-handle-base64url"
  },
  "type": "public-key",
  "clientExtensionResults": {},
  "authenticatorAttachment": "platform"
}
```

**Response:**
```json
{
  "status": "ok",
  "errorMessage": "",
  "verified": true
}
```

### 4.3 Error Response Format
```json
{
  "status": "failed",
  "errorMessage": "Detailed error description",
  "errorCode": "FIDO_ERROR_CODE",
  "details": {
    "field": "Specific field that caused the error",
    "reason": "Detailed reason for the failure"
  }
}
```

### 4.4 Data Flow Architecture
```rust
// Request processing pipeline
pub struct RequestPipeline {
    validator: InputValidator,
    webauthn: WebAuthnCore,
    storage: Box<dyn StorageRepository>,
    security: SecurityMiddleware,
}

impl RequestPipeline {
    pub async fn process_registration_begin(
        &self,
        request: RegistrationBeginRequest,
    ) -> Result<RegistrationBeginResponse, WebAuthnError> {
        // 1. Input validation
        self.validator.validate_registration_begin(&request)?;
        
        // 2. Generate challenge and options
        let (challenge, creation_options) = self.webauthn
            .generate_challenge_register_options(&request).await?;
        
        // 3. Store challenge state
        self.storage.store_challenge_state(&challenge).await?;
        
        // 4. Return response
        Ok(creation_options)
    }
}
```

## 5. Storage Requirements & Data Models

### 5.1 Core Data Models
```rust
use sqlx::FromRow;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Credential {
    pub id: Vec<u8>,                    // Credential ID
    pub user_id: Uuid,                  // Foreign key to User
    pub public_key: Vec<u8>,            // Public key in COSE format
    pub sign_count: i64,                // Signature counter
    pub backup_eligible: bool,          // Backup eligible flag
    pub backup_state: bool,             // Backup state flag
    pub aaguid: Option<Vec<u8>>,        // Authenticator AAGUID
    pub attestation_format: String,     // Attestation format used
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_used: Option<chrono::DateTime<chrono::Utc>>,
    pub is_active: bool,                // Credential active status
}

#[derive(Debug, Clone)]
pub struct ChallengeState {
    pub challenge: Vec<u8>,
    pub user_id: Option<Uuid>,
    pub operation: OperationType,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub origin: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OperationType {
    Registration,
    Authentication,
}
```

### 5.2 PostgreSQL Schema
```sql
-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) NOT NULL UNIQUE,
    display_name VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Credentials table
CREATE TABLE credentials (
    id BYTEA PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key BYTEA NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    backup_eligible BOOLEAN NOT NULL DEFAULT false,
    backup_state BOOLEAN NOT NULL DEFAULT false,
    aaguid BYTEA,
    attestation_format VARCHAR(50) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used TIMESTAMPTZ,
    is_active BOOLEAN NOT NULL DEFAULT true
);

-- Challenge states (for temporary storage)
CREATE TABLE challenge_states (
    challenge BYTEA PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    operation VARCHAR(20) NOT NULL,
    origin VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

-- Indexes for performance
CREATE INDEX idx_credentials_user_id ON credentials(user_id);
CREATE INDEX idx_credentials_active ON credentials(is_active) WHERE is_active = true;
CREATE INDEX idx_challenge_expires ON challenge_states(expires_at);
CREATE INDEX idx_users_username ON users(username);

-- Cleanup expired challenges
CREATE OR REPLACE FUNCTION cleanup_expired_challenges()
RETURNS void AS $$
BEGIN
    DELETE FROM challenge_states WHERE expires_at < NOW();
END;
$$ LANGUAGE plpgsql;
```

### 5.3 Storage Repository Interface
```rust
#[async_trait::async_trait]
pub trait StorageRepository: Send + Sync {
    // User management
    async fn create_user(&self, user: &NewUser) -> Result<User, StorageError>;
    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, StorageError>;
    async fn get_user_by_id(&self, user_id: &Uuid) -> Result<Option<User>, StorageError>;

    // Credential management
    async fn store_credential(&self, credential: &NewCredential) -> Result<(), StorageError>;
    async fn get_credential(&self, credential_id: &[u8]) -> Result<Option<Credential>, StorageError>;
    async fn get_user_credentials(&self, user_id: &Uuid) -> Result<Vec<Credential>, StorageError>;
    async fn update_credential_counter(&self, credential_id: &[u8], new_count: u32) -> Result<(), StorageError>;
    async fn update_credential_usage(&self, credential_id: &[u8]) -> Result<(), StorageError>;

    // Challenge state management
    async fn store_challenge_state(&self, state: &ChallengeState) -> Result<(), StorageError>;
    async fn get_challenge_state(&self, challenge: &[u8]) -> Result<Option<ChallengeState>, StorageError>;
    async fn remove_challenge_state(&self, challenge: &[u8]) -> Result<(), StorageError>;
    async fn cleanup_expired_challenges(&self) -> Result<(), StorageError>;

    // Health check
    async fn health_check(&self) -> Result<(), StorageError>;
}
```

### 5.4 Data Validation Requirements
```rust
pub struct DataValidator;

impl DataValidator {
    pub fn validate_username(username: &str) -> Result<(), ValidationError> {
        if username.is_empty() || username.len() > 255 {
            return Err(ValidationError::InvalidUsername);
        }
        
        // Email format validation (basic)
        if !username.contains('@') || !username.contains('.') {
            return Err(ValidationError::InvalidUsernameFormat);
        }
        
        Ok(())
    }

    pub fn validate_credential_id(credential_id: &[u8]) -> Result<(), ValidationError> {
        if credential_id.is_empty() || credential_id.len() > 1023 {
            return Err(ValidationError::InvalidCredentialId);
        }
        Ok(())
    }

    pub fn validate_challenge(challenge: &[u8]) -> Result<(), ValidationError> {
        if challenge.len() < 16 {
            return Err(ValidationError::InsufficientChallengeEntropy);
        }
        Ok(())
    }

    pub fn validate_origin(origin: &str, allowed_origins: &[String]) -> Result<(), ValidationError> {
        if !allowed_origins.iter().any(|allowed| origin == allowed) {
            return Err(ValidationError::InvalidOrigin);
        }
        Ok(())
    }
}
```

## 6. FIDO2 Compliance Checklist

### 6.1 WebAuthn Level 2 Compliance
- [ ] **PublicKeyCredentialCreationOptions Support**
  - [ ] rp parameter validation
  - [ ] user parameter validation
  - [ ] challenge generation (≥16 bytes)
  - [ ] pubKeyCredParams algorithm support (-7, -35, -36, -257, -258, -259)
  - [ ] timeout handling (300-600 seconds recommended)
  - [ ] excludeCredentials processing
  - [ ] authenticatorSelection criteria
  - [ ] attestation parameter support
  - [ ] extensions processing

- [ ] **PublicKeyCredentialRequestOptions Support**
  - [ ] challenge generation (≥16 bytes)
  - [ ] rpId validation
  - [ ] allowCredentials filtering
  - [ ] userVerification policy enforcement
  - [ ] timeout handling
  - [ ] extensions processing

- [ ] **AuthenticatorAttestationResponse Processing**
  - [ ] clientDataJSON validation
  - [ ] attestationObject parsing
  - [ ] authData validation
  - [ ] credentialPublicKey extraction
  - [ ] attestation statement verification
  - [ ] Extension processing

- [ ] **AuthenticatorAssertionResponse Processing**
  - [ ] clientDataJSON validation
  - [ ] authenticatorData validation
  - [ ] signature verification
  - [ ] userHandle processing
  - [ ] Extension processing

### 6.2 FIDO2 CTAP2 Compliance
- [ ] **MakeCredential Command Support**
  - [ ] clientDataHash validation
  - [ ] rp parameter processing
  - [ ] user parameter processing
  - [ ] pubKeyCredParams validation
  - [ ] excludeList processing
  - [ ] options parameter support
  - [ ] extensions support

- [ ] **GetAssertion Command Support**
  - [ ] rpId validation
  - [ ] clientDataHash validation
  - [ ] allowList processing
  - [ ] options parameter support
  - [ ] extensions support

### 6.3 Attestation Format Support
- [ ] **Packed Attestation**
  - [ ] Self-attestation verification
  - [ ] Full attestation verification
  - [ ] Surrogate basic attestation

- [ ] **TPM Attestation**
  - [ ] TPM 2.0 attestation verification
  - [ ] TPMS_ATTEST structure validation
  - [ ] Certificate chain verification

- [ ] **Android Key Attestation**
  - [ ] Android key attestation verification
  - [ ] Certificate chain validation
  - [ ] Key description validation

- [ ] **Android SafetyNet Attestation**
  - [ ] JWS verification
  - [ ] SafetyNet response validation
  - [ ] APK certificate verification

- [ ] **FIDO U2F Attestation**
  - [ ] U2F attestation verification
  - [ ] Certificate validation
  - [ ] Signature verification

### 6.4 Cryptographic Requirements
- [ ] **Signature Algorithms**
  - [ ] ES256 (ECDSA w/ SHA-256) - Required
  - [ ] ES384 (ECDSA w/ SHA-384)
  - [ ] ES512 (ECDSA w/ SHA-512)
  - [ ] PS256 (RSASSA-PSS w/ SHA-256)
  - [ ] PS384 (RSASSA-PSS w/ SHA-384)
  - [ ] PS512 (RSASSA-PSS w/ SHA-512)
  - [ ] RS256 (RSASSA-PKCS1-v1_5 w/ SHA-256)
  - [ ] RS384 (RSASSA-PKCS1-v1_5 w/ SHA-384)
  - [ ] RS512 (RSASSA-PKCS1-v1_5 w/ SHA-512)
  - [ ] EdDSA (Ed25519)

- [ ] **Hash Algorithms**
  - [ ] SHA-256 - Required
  - [ ] SHA-384
  - [ ] SHA-512

### 6.5 Security Requirements
- [ ] **Challenge Management**
  - [ ] Cryptographically secure random generation
  - [ ] Minimum 16 bytes length
  - [ ] One-time use enforcement
  - [ ] Expiration time enforcement
  - [ ] Rate limiting

- [ ] **Origin Validation**
  - [ ] Strict origin matching
  - [ ] HTTPS enforcement
  - [ ] RP ID validation
  - [ ] Subdomain handling

- [ ] **Credential Management**
  - [ ] Unique credential ID enforcement
  - [ ] Public key validation
  - [ ] Signature counter validation
  - [ ] Backup eligibility tracking
  - [ ] Credential status management

## 7. Risk Assessment & Security Considerations

### 7.1 Threat Model
```rust
pub enum SecurityThreat {
    ReplayAttack {
        risk_level: RiskLevel::High,
        mitigation: "Challenge-response with expiration",
    },
    OriginSpoofing {
        risk_level: RiskLevel::High,
        mitigation: "Strict origin validation",
    },
    CredentialTheft {
        risk_level: RiskLevel::Medium,
        mitigation: "Hardware-bound credentials",
    },
    CounterRollback {
        risk_level: RiskLevel::Medium,
        mitigation: "Signature counter validation",
    },
    PhishingAttack {
        risk_level: RiskLevel::High,
        mitigation: "Origin binding in WebAuthn",
    },
    ManInTheMiddle {
        risk_level: RiskLevel::High,
        mitigation: "TLS enforcement",
    },
}
```

### 7.2 Mitigation Strategies

#### 7.2.1 Replay Attack Prevention
```rust
pub struct ReplayProtection {
    challenge_store: ChallengeStore,
    timeout_duration: Duration,
    max_concurrent_challenges: u32,
}

impl ReplayProtection {
    pub async fn validate_challenge(&self, challenge: &[u8]) -> Result<(), SecurityError> {
        let state = self.challenge_store.get_and_remove(challenge).await?
            .ok_or(SecurityError::InvalidChallenge)?;
        
        if state.expires_at < Utc::now() {
            return Err(SecurityError::ChallengeExpired);
        }
        
        Ok(())
    }
}
```

#### 7.2.2 Origin Validation
```rust
pub struct OriginValidator {
    allowed_origins: HashSet<String>,
    strict_mode: bool,
}

impl OriginValidator {
    pub fn validate_origin(&self, origin: &str, rp_id: &str) -> Result<(), SecurityError> {
        if !self.allowed_origins.contains(origin) {
            return Err(SecurityError::UnauthorizedOrigin);
        }

        // Validate that origin matches RP ID
        let origin_url = Url::parse(origin)?;
        let origin_host = origin_url.host_str()
            .ok_or(SecurityError::InvalidOrigin)?;

        if self.strict_mode && origin_host != rp_id {
            return Err(SecurityError::RpIdMismatch);
        }

        Ok(())
    }
}
```

#### 7.2.3 Rate Limiting
```rust
pub struct RateLimiter {
    requests_per_minute: u32,
    requests_per_hour: u32,
    storage: Box<dyn RateLimitStorage>,
}

impl RateLimiter {
    pub async fn check_rate_limit(&self, client_id: &str) -> Result<(), SecurityError> {
        let minute_count = self.storage.get_minute_count(client_id).await?;
        let hour_count = self.storage.get_hour_count(client_id).await?;

        if minute_count >= self.requests_per_minute {
            return Err(SecurityError::RateLimitExceeded);
        }

        if hour_count >= self.requests_per_hour {
            return Err(SecurityError::RateLimitExceeded);
        }

        self.storage.increment_counters(client_id).await?;
        Ok(())
    }
}
```

### 7.3 Input Validation & Sanitization
```rust
pub struct InputSanitizer;

impl InputSanitizer {
    pub fn sanitize_username(username: &str) -> Result<String, ValidationError> {
        // Remove whitespace, validate length, check format
        let cleaned = username.trim().to_lowercase();
        
        if cleaned.len() > 320 {  // Max email length
            return Err(ValidationError::UsernameTooLong);
        }

        // Basic email validation
        if !cleaned.contains('@') {
            return Err(ValidationError::InvalidEmailFormat);
        }

        Ok(cleaned)
    }

    pub fn validate_base64url(data: &str) -> Result<Vec<u8>, ValidationError> {
        base64::decode_config(data, base64::URL_SAFE_NO_PAD)
            .map_err(|_| ValidationError::InvalidBase64Encoding)
    }

    pub fn validate_json_structure<T: DeserializeOwned>(
        json: &str,
        max_size: usize,
    ) -> Result<T, ValidationError> {
        if json.len() > max_size {
            return Err(ValidationError::PayloadTooLarge);
        }

        serde_json::from_str(json)
            .map_err(|_| ValidationError::InvalidJsonStructure)
    }
}
```

### 7.4 Logging & Monitoring Requirements
```rust
pub struct SecurityLogger;

impl SecurityLogger {
    pub fn log_registration_attempt(&self, username: &str, success: bool, error: Option<&str>) {
        if success {
            info!(
                event = "registration_success",
                username = %username,
                timestamp = %Utc::now()
            );
        } else {
            warn!(
                event = "registration_failure",
                username = %username,
                error = ?error,
                timestamp = %Utc::now()
            );
        }
    }

    pub fn log_authentication_attempt(&self, username: &str, success: bool, error: Option<&str>) {
        if success {
            info!(
                event = "authentication_success",
                username = %username,
                timestamp = %Utc::now()
            );
        } else {
            warn!(
                event = "authentication_failure",
                username = %username,
                error = ?error,
                timestamp = %Utc::now()
            );
        }
    }

    pub fn log_security_violation(&self, violation_type: &str, details: &str) {
        error!(
            event = "security_violation",
            violation_type = %violation_type,
            details = %details,
            timestamp = %Utc::now()
        );
    }
}
```

### 7.5 TLS Configuration Requirements
```rust
pub struct TlsConfig {
    pub min_version: TlsVersion::V1_2,
    pub cipher_suites: Vec<CipherSuite>,
    pub require_sni: bool,
    pub certificate_validation: CertValidationLevel::Strict,
}

impl TlsConfig {
    pub fn secure_default() -> Self {
        Self {
            min_version: TlsVersion::V1_2,
            cipher_suites: vec![
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            ],
            require_sni: true,
            certificate_validation: CertValidationLevel::Strict,
        }
    }
}
```

## 8. Testing Strategy & Test Cases

### 8.1 Security Test Categories
```rust
pub enum SecurityTestCategory {
    ChallengeValidation,
    OriginValidation,
    SignatureVerification,
    AttestationVerification,
    ReplayPrevention,
    RateLimiting,
    InputValidation,
    CryptographicSecurity,
}
```

### 8.2 Compliance Test Requirements
```rust
pub struct ComplianceTestSuite {
    pub fido2_level: FIDO2Level,
    pub webauthn_level: WebAuthnLevel,
    pub test_vectors: Vec<TestVector>,
    pub negative_tests: Vec<NegativeTest>,
}

pub struct TestVector {
    pub name: String,
    pub description: String,
    pub input: serde_json::Value,
    pub expected_output: serde_json::Value,
    pub compliance_point: String,
}
```

This comprehensive specification provides the foundation for implementing a secure, compliant FIDO2/WebAuthn Relying Party Server with proper test coverage and security considerations.