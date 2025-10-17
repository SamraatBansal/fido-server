# FIDO2/WebAuthn Server - Implementation Guide

## Overview

This implementation guide provides a comprehensive roadmap for building a secure, compliant FIDO2/WebAuthn Relying Party Server in Rust using the webauthn-rs library. It synthesizes all technical specifications, security requirements, and risk assessments into actionable implementation steps.

## 1. Project Summary

### 1.1 Objectives
- Build a production-ready FIDO2/WebAuthn Relying Party Server
- Achieve FIDO Alliance conformance certification
- Implement comprehensive security controls
- Maintain 95%+ test coverage
- Support scalable architecture for enterprise deployment

### 1.2 Key Deliverables
1. **Core WebAuthn Service** - Registration and authentication flows
2. **Secure Credential Storage** - Encrypted database storage with PostgreSQL
3. **REST API** - Complete API with comprehensive error handling
4. **Security Framework** - Multi-layered security controls
5. **Testing Suite** - Unit, integration, security, and compliance tests
6. **Documentation** - Technical and user documentation

### 1.3 Success Criteria
- FIDO Alliance conformance test pass rate: 100%
- Security audit: Zero high-severity findings
- Performance: <100ms response time for 95% of requests
- Availability: 99.9% uptime
- Test coverage: ≥95% unit, 100% integration

## 2. Implementation Roadmap

### Phase 1: Foundation (Weeks 1-2)

#### Week 1: Project Setup and Core Infrastructure
**Priority**: Critical  
**Owner**: Development Team  

**Tasks**:
1. **Project Structure Setup**
   ```bash
   # Create project structure
   mkdir -p src/{config,controllers,services,db,models,repositories,middleware,routes,error,utils,schema}
   mkdir -p tests/{unit,integration,security,compliance}
   ```

2. **Dependencies Configuration**
   - Configure Cargo.toml with all required dependencies
   - Set up development dependencies for testing
   - Configure linting and formatting rules

3. **Database Schema Implementation**
   ```sql
   -- Create users table
   CREATE TABLE users (
       id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
       username VARCHAR(255) UNIQUE NOT NULL,
       display_name VARCHAR(255) NOT NULL,
       created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
       updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
       last_login TIMESTAMP WITH TIME ZONE,
       is_active BOOLEAN DEFAULT true
   );

   -- Create credentials table
   CREATE TABLE credentials (
       id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
       user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
       credential_id VARCHAR(255) UNIQUE NOT NULL,
       credential_data BYTEA NOT NULL,
       sign_count BIGINT NOT NULL DEFAULT 0,
       created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
       updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
       last_used TIMESTAMP WITH TIME ZONE,
       is_backup BOOLEAN DEFAULT false,
       transports TEXT[],
       attestation_type VARCHAR(50),
       aaguid UUID
   );

   -- Create challenges table
   CREATE TABLE challenges (
       id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
       user_id UUID REFERENCES users(id) ON DELETE CASCADE,
       challenge_hash VARCHAR(255) NOT NULL,
       challenge_type VARCHAR(20) NOT NULL,
       created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
       expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
       used BOOLEAN DEFAULT false
   );
   ```

4. **Core Configuration**
   ```rust
   // src/config/app_config.rs
   #[derive(Debug, Clone)]
   pub struct AppConfig {
       pub database_url: String,
       pub rp_id: String,
       pub rp_name: String,
       pub rp_origin: String,
       pub challenge_timeout: u64,
       pub max_credentials_per_user: u32,
   }

   // src/config/webauthn_config.rs
   use webauthn_rs::prelude::*;

   pub fn create_webauthn_config(config: &AppConfig) -> WebAuthnConfig {
       WebAuthnConfig {
           rp: Rp {
               id: config.rp_id.clone(),
               name: config.rp_name.clone(),
               origin: Url::parse(&config.rp_origin).unwrap(),
           },
           timeout: Some(config.challenge_timeout),
           ..Default::default()
       }
   }
   ```

**Deliverables**:
- [ ] Complete project structure
- [ ] Database schema and migrations
- [ ] Core configuration management
- [ ] Basic CI/CD pipeline setup

#### Week 2: Core Service Implementation
**Priority**: Critical  
**Owner**: Development Team  

**Tasks**:
1. **WebAuthn Service Core**
   ```rust
   // src/services/webauthn_service.rs
   use webauthn_rs::prelude::*;
   use uuid::Uuid;

   pub struct WebAuthnService {
       webauthn: WebAuthn<WebAuthnConfig>,
       credential_service: Arc<CredentialService>,
       user_service: Arc<UserService>,
   }

   impl WebAuthnService {
       pub async fn start_registration(&self, user: &User) -> Result<CreationChallengeResponse, WebAuthnError> {
           // Generate registration challenge
           let user_id = user.id.as_bytes();
           let user_entity = UserEntity {
               id: user_id.to_vec(),
               name: user.username.clone(),
               display_name: user.display_name.clone(),
           };

           let (ccr, state) = self.webauthn
               .start_registration(&user_entity, self.generate_registration_options()?)
               .map_err(|e| WebAuthnError::RegistrationError(e.to_string()))?;

           // Store challenge state
           self.store_challenge(&user.id, &state, "registration").await?;

           Ok(ccr)
       }

       pub async fn finish_registration(&self, user: &User, response: PublicKeyCredential) -> Result<(), WebAuthnError> {
           // Retrieve and validate challenge
           let state = self.retrieve_and_validate_challenge(&user.id, "registration", &response).await?;

           // Complete registration
           let passkey = self.webauthn
               .finish_registration(&response, &state)
               .map_err(|e| WebAuthnError::RegistrationError(e.to_string()))?;

           // Store credential
           self.credential_service.store_credential(user.id, passkey).await?;

           Ok(())
       }

       // Similar methods for authentication...
   }
   ```

2. **User Service Implementation**
   ```rust
   // src/services/user_service.rs
   pub struct UserService {
       repository: Arc<UserRepository>,
   }

   impl UserService {
       pub async fn create_user(&self, username: &str, display_name: &str) -> Result<User, UserServiceError> {
           // Validate input
           self.validate_user_input(username, display_name)?;

           // Check if user exists
           if self.repository.find_by_username(username).await?.is_some() {
               return Err(UserServiceError::UserExists);
           }

           // Create user
           let user = User {
               id: Uuid::new_v4(),
               username: username.to_string(),
               display_name: display_name.to_string(),
               created_at: Utc::now(),
               updated_at: Utc::now(),
               last_login: None,
               is_active: true,
           };

           self.repository.create(&user).await?;
           Ok(user)
       }

       pub async fn find_by_username(&self, username: &str) -> Result<Option<User>, UserServiceError> {
           self.repository.find_by_username(username).await
       }
   }
   ```

3. **Credential Service Implementation**
   ```rust
   // src/services/credential_service.rs
   pub struct CredentialService {
       repository: Arc<CredentialRepository>,
       crypto: Arc<CryptoService>,
   }

   impl CredentialService {
       pub async fn store_credential(&self, user_id: Uuid, passkey: Passkey) -> Result<(), CredentialError> {
           // Encrypt credential data
           let encrypted_data = self.crypto.encrypt_credential_data(&passkey)?;

           let credential = StoredCredential {
               id: Uuid::new_v4(),
               user_id,
               credential_id: base64url::encode(&passkey.cred_id()),
               credential_data: encrypted_data,
               sign_count: passkey.counter(),
               created_at: Utc::now(),
               updated_at: Utc::now(),
               last_used: None,
               is_backup: false,
               transports: passkey.transports().map(|t| t.iter().map(|t| t.to_string()).collect()).unwrap_or_default(),
               attestation_type: "packed".to_string(), // Determine from passkey
               aaguid: None, // Extract from passkey if available
           };

           self.repository.create(&credential).await?;
           Ok(())
       }

       pub async fn get_credential(&self, credential_id: &str) -> Result<Option<Passkey>, CredentialError> {
           if let Some(stored) = self.repository.find_by_credential_id(credential_id).await? {
               let decrypted_data = self.crypto.decrypt_credential_data(&stored.credential_data)?;
               Ok(Some(decrypted_data))
           } else {
               Ok(None)
           }
       }
   }
   ```

**Deliverables**:
- [ ] Core WebAuthn service implementation
- [ ] User management service
- [ ] Credential management service
- [ ] Basic unit tests (70% coverage)

---

### Phase 2: API Development (Weeks 3-4)

#### Week 3: REST API Implementation
**Priority**: High  
**Owner**: Development Team  

**Tasks**:
1. **API Controllers**
   ```rust
   // src/controllers/webauthn_controller.rs
   use actix_web::{web, HttpResponse, Result};
   use serde_json::json;

   pub struct WebAuthnController {
       webauthn_service: Arc<WebAuthnService>,
   }

   impl WebAuthnController {
       pub async fn start_registration(
           &self,
           req: web::Json<RegistrationRequest>,
       ) -> Result<HttpResponse> {
           match self.webauthn_service.start_registration(&req.into()).await {
               Ok(challenge) => Ok(HttpResponse::Ok().json(json!({
                   "status": "ok",
                   "data": challenge
               }))),
               Err(e) => Ok(HttpResponse::BadRequest().json(json!({
                   "status": "error",
                   "error": {
                       "code": "REGISTRATION_ERROR",
                       "message": e.to_string()
                   }
               }))),
           }
       }

       pub async fn finish_registration(
           &self,
           req: web::Json<RegistrationVerificationRequest>,
       ) -> Result<HttpResponse> {
           match self.webauthn_service.finish_registration(&req.into()).await {
               Ok(_) => Ok(HttpResponse::Ok().json(json!({
                   "status": "ok",
                   "data": {
                       "message": "Registration successful"
                   }
               }))),
               Err(e) => Ok(HttpResponse::BadRequest().json(json!({
                   "status": "error",
                   "error": {
                       "code": "REGISTRATION_ERROR",
                       "message": e.to_string()
                   }
               }))),
           }
       }
   }
   ```

2. **Request/Response Models**
   ```rust
   // src/models/requests.rs
   use serde::{Deserialize, Serialize};

   #[derive(Debug, Deserialize)]
   pub struct RegistrationRequest {
       pub username: String,
       pub display_name: String,
       pub user_verification: Option<String>,
       pub attestation: Option<String>,
   }

   #[derive(Debug, Deserialize)]
   pub struct RegistrationVerificationRequest {
       pub username: String,
       pub credential: PublicKeyCredential,
   }

   #[derive(Debug, Deserialize)]
   pub struct AuthenticationRequest {
       pub username: String,
       pub user_verification: Option<String>,
   }

   #[derive(Debug, Deserialize)]
   pub struct AuthenticationVerificationRequest {
       pub username: String,
       pub credential: PublicKeyCredential,
   }
   ```

3. **Route Configuration**
   ```rust
   // src/routes/webauthn_routes.rs
   use actix_web::{web, Scope};

   pub fn configure_routes(cfg: &mut web::ServiceConfig) {
       cfg.service(
           web::scope("/webauthn")
               .route("/register/challenge", web::post().to(start_registration))
               .route("/register/verify", web::post().to(finish_registration))
               .route("/authenticate/challenge", web::post().to(start_authentication))
               .route("/authenticate/verify", web::post().to(finish_authentication))
       );
   }
   ```

**Deliverables**:
- [ ] Complete REST API implementation
- [ ] Request/response models
- [ ] Error handling framework
- [ ] API documentation (OpenAPI/Swagger)

#### Week 4: Security Middleware and Validation
**Priority**: High  
**Owner**: Security Team  

**Tasks**:
1. **Security Middleware**
   ```rust
   // src/middleware/security_middleware.rs
   use actix_web::{dev::ServiceRequest, Error, Result};
   use actix_web_httpauth::middleware::HttpAuthentication;

   pub async fn security_middleware(
       req: ServiceRequest,
       next: Next<impl Body>,
   ) -> Result<HttpResponse, Error> {
       // Add security headers
       let response = next.call(req).await?;
       
       Ok(response.into_response().map(|mut resp| {
           resp.headers_mut().insert(
               "Strict-Transport-Security",
               "max-age=31536000; includeSubDomains".parse().unwrap(),
           );
           resp.headers_mut().insert(
               "X-Content-Type-Options",
               "nosniff".parse().unwrap(),
           );
           resp.headers_mut().insert(
               "X-Frame-Options",
               "DENY".parse().unwrap(),
           );
           resp
       }))
   }

   // Rate limiting middleware
   pub async fn rate_limit_middleware(
       req: ServiceRequest,
       next: Next<impl Body>,
   ) -> Result<HttpResponse, Error> {
       // Implement rate limiting logic
       // Check IP-based limits
       // Check user-based limits
       // Return 429 if limits exceeded
   }
   ```

2. **Input Validation**
   ```rust
   // src/utils/validation.rs
   use regex::Regex;
   use once_cell::sync::Lazy;

   static EMAIL_REGEX: Lazy<Regex> = Lazy::new(|| {
       Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap()
   });

   pub fn validate_username(username: &str) -> Result<(), ValidationError> {
       if username.len() < 3 || username.len() > 255 {
           return Err(ValidationError::InvalidLength);
       }
       
       if !EMAIL_REGEX.is_match(username) {
           return Err(ValidationError::InvalidFormat);
       }
       
       Ok(())
   }

   pub fn validate_display_name(display_name: &str) -> Result<(), ValidationError> {
       if display_name.len() < 1 || display_name.len() > 255 {
           return Err(ValidationError::InvalidLength);
       }
       
       if display_name.chars().any(|c| c.is_control()) {
           return Err(ValidationError::InvalidCharacters);
       }
       
       Ok(())
   }
   ```

3. **CORS Configuration**
   ```rust
   // src/middleware/cors_middleware.rs
   use actix_cors::Cors;
   use actix_web::http::header;

   pub fn configure_cors() -> Cors {
       Cors::default()
           .allowed_origin("https://example.com")
           .allowed_methods(vec!["GET", "POST", "PUT", "DELETE", "OPTIONS"])
           .allowed_headers(vec![
               header::CONTENT_TYPE,
               header::AUTHORIZATION,
               header::ACCEPT,
           ])
           .supports_credentials()
           .max_age(3600)
   }
   ```

**Deliverables**:
- [ ] Security middleware implementation
- [ ] Input validation framework
- [ ] CORS configuration
- [ ] Rate limiting implementation
- [ ] Integration tests for API endpoints

---

### Phase 3: Security Hardening (Weeks 5-6)

#### Week 5: Cryptographic Security
**Priority**: Critical  
**Owner**: Security Team  

**Tasks**:
1. **Encryption Service**
   ```rust
   // src/services/crypto_service.rs
   use aes_gcm::{Aes256Gcm, Key, Nonce};
   use aes_gcm::aead::{Aead, NewAead};
   use rand::RngCore;

   pub struct CryptoService {
       cipher: Aes256Gcm,
   }

   impl CryptoService {
       pub fn new(key: &[u8; 32]) -> Self {
           let key = Key::from_slice(key);
           let cipher = Aes256Gcm::new(key);
           Self { cipher }
       }

       pub fn encrypt_credential_data(&self, data: &Passkey) -> Result<Vec<u8>, CryptoError> {
           // Serialize passkey to bytes
           let serialized = serde_json::to_vec(data)
               .map_err(|e| CryptoError::SerializationError(e.to_string()))?;

           // Generate random nonce
           let mut nonce_bytes = [0u8; 12];
           rand::thread_rng().fill_bytes(&mut nonce_bytes);
           let nonce = Nonce::from_slice(&nonce_bytes);

           // Encrypt data
           let ciphertext = self.cipher
               .encrypt(nonce, serialized.as_ref())
               .map_err(|e| CryptoError::EncryptionError(e.to_string()))?;

           // Return nonce + ciphertext
           let mut result = nonce_bytes.to_vec();
           result.extend_from_slice(&ciphertext);
           Ok(result)
       }

       pub fn decrypt_credential_data(&self, encrypted_data: &[u8]) -> Result<Passkey, CryptoError> {
           if encrypted_data.len() < 12 {
               return Err(CryptoError::InvalidData);
           }

           let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
           let nonce = Nonce::from_slice(nonce_bytes);

           let plaintext = self.cipher
               .decrypt(nonce, ciphertext)
               .map_err(|e| CryptoError::DecryptionError(e.to_string()))?;

           serde_json::from_slice(&plaintext)
               .map_err(|e| CryptoError::DeserializationError(e.to_string()))
       }
   }
   ```

2. **Secure Random Number Generation**
   ```rust
   // src/utils/crypto.rs
   use rand::{RngCore, thread_rng};

   pub fn generate_secure_challenge() -> Result<String, CryptoError> {
       let mut challenge_bytes = [0u8; 32];
       thread_rng().fill_bytes(&mut challenge_bytes);
       Ok(base64url::encode(&challenge_bytes))
   }

   pub fn generate_session_token() -> Result<String, CryptoError> {
       let mut token_bytes = [0u8; 32];
       thread_rng().fill_bytes(&mut token_bytes);
       Ok(base64url::encode(&token_bytes))
   }
   ```

3. **Key Management**
   ```rust
   // src/services/key_management.rs
   use std::fs;
   use std::path::Path;

   pub struct KeyManager {
       encryption_key: [u8; 32],
   }

   impl KeyManager {
       pub fn new(key_file: &Path) -> Result<Self, KeyManagementError> {
           let encryption_key = if key_file.exists() {
               self.load_key(key_file)?
           } else {
               let key = self.generate_key()?;
               self.save_key(key_file, &key)?;
               key
           };

           Ok(Self { encryption_key })
       }

       fn generate_key(&self) -> Result<[u8; 32], KeyManagementError> {
           let mut key = [0u8; 32];
           thread_rng().fill_bytes(&mut key);
           Ok(key)
       }

       fn load_key(&self, key_file: &Path) -> Result<[u8; 32], KeyManagementError> {
           let key_data = fs::read(key_file)
               .map_err(|e| KeyManagementError::IoError(e.to_string()))?;
           
           if key_data.len() != 32 {
               return Err(KeyManagementError::InvalidKeyLength);
           }

           let mut key = [0u8; 32];
           key.copy_from_slice(&key_data);
           Ok(key)
       }

       fn save_key(&self, key_file: &Path, key: &[u8; 32]) -> Result<(), KeyManagementError> {
           fs::write(key_file, key)
               .map_err(|e| KeyManagementError::IoError(e.to_string()))?;
           
           // Set secure file permissions
           #[cfg(unix)]
           {
               use std::os::unix::fs::PermissionsExt;
               let mut perms = fs::metadata(key_file)
                   .map_err(|e| KeyManagementError::IoError(e.to_string()))?
                   .permissions();
               perms.set_mode(0o600); // Read/write for owner only
               fs::set_permissions(key_file, perms)
                   .map_err(|e| KeyManagementError::IoError(e.to_string()))?;
           }

           Ok(())
       }

       pub fn get_encryption_key(&self) -> &[u8; 32] {
           &self.encryption_key
       }
   }
   ```

**Deliverables**:
- [ ] Encryption service implementation
- [ ] Secure random number generation
- [ ] Key management system
- [ ] Security tests for cryptographic functions

#### Week 6: Advanced Security Features
**Priority**: High  
**Owner**: Security Team  

**Tasks**:
1. **Session Management**
   ```rust
   // src/services/session_service.rs
   use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
   use chrono::{Duration, Utc};

   #[derive(Debug, Serialize, Deserialize)]
   pub struct Claims {
       pub sub: String, // User ID
       pub exp: i64,    // Expiration time
       pub iat: i64,    // Issued at
       pub iss: String, // Issuer
   }

   pub struct SessionService {
       encoding_key: EncodingKey,
       decoding_key: DecodingKey,
       session_duration: Duration,
   }

   impl SessionService {
       pub fn create_session(&self, user_id: &str) -> Result<String, SessionError> {
           let now = Utc::now();
           let exp = now + self.session_duration;

           let claims = Claims {
               sub: user_id.to_string(),
               exp: exp.timestamp(),
               iat: now.timestamp(),
               iss: "fido-server".to_string(),
           };

           encode(&Header::default(), &claims, &self.encoding_key)
               .map_err(|e| SessionError::TokenCreationError(e.to_string()))
       }

       pub fn validate_session(&self, token: &str) -> Result<Claims, SessionError> {
           let token_data = decode::<Claims>(
               token,
               &self.decoding_key,
               &Validation::default(),
           ).map_err(|e| SessionError::TokenValidationError(e.to_string()))?;

           Ok(token_data.claims)
       }
   }
   ```

2. **Audit Logging**
   ```rust
   // src/services/audit_service.rs
   use serde_json::json;
   use tracing::{info, warn, error};

   #[derive(Debug, Clone)]
   pub struct AuditEvent {
       pub event_type: String,
       pub user_id: Option<String>,
       pub ip_address: Option<String>,
       pub user_agent: Option<String>,
       pub timestamp: chrono::DateTime<chrono::Utc>,
       pub details: serde_json::Value,
       pub success: bool,
   }

   pub struct AuditService {
       // Could integrate with external logging system
   }

   impl AuditService {
       pub fn log_authentication_attempt(&self, event: AuditEvent) {
           let log_entry = json!({
               "event_type": event.event_type,
               "user_id": event.user_id,
               "ip_address": event.ip_address,
               "user_agent": event.user_agent,
               "timestamp": event.timestamp,
               "details": event.details,
               "success": event.success
           });

           if event.success {
               info!("Authentication successful: {}", log_entry);
           } else {
               warn!("Authentication failed: {}", log_entry);
           }
       }

       pub fn log_registration_attempt(&self, event: AuditEvent) {
           let log_entry = json!({
               "event_type": event.event_type,
               "user_id": event.user_id,
               "ip_address": event.ip_address,
               "user_agent": event.user_agent,
               "timestamp": event.timestamp,
               "details": event.details,
               "success": event.success
           });

           if event.success {
               info!("Registration successful: {}", log_entry);
           } else {
               warn!("Registration failed: {}", log_entry);
           }
       }
   }
   ```

3. **Rate Limiting Implementation**
   ```rust
   // src/middleware/rate_limit_middleware.rs
   use std::collections::HashMap;
   use std::sync::Mutex;
   use std::time::{Duration, Instant};

   pub struct RateLimiter {
       requests: Mutex<HashMap<String, Vec<Instant>>>,
       max_requests: usize,
       window: Duration,
   }

   impl RateLimiter {
       pub fn new(max_requests: usize, window: Duration) -> Self {
           Self {
               requests: Mutex::new(HashMap::new()),
               max_requests,
               window,
           }
       }

       pub fn check_rate_limit(&self, key: &str) -> Result<(), RateLimitError> {
           let mut requests = self.requests.lock().unwrap();
           let now = Instant::now();
           
           let entry = requests.entry(key.to_string()).or_insert_with(Vec::new);
           
           // Remove old requests outside the window
           entry.retain(|&timestamp| now.duration_since(timestamp) < self.window);
           
           // Check if limit exceeded
           if entry.len() >= self.max_requests {
               return Err(RateLimitError::LimitExceeded);
           }
           
           // Add current request
           entry.push(now);
           
           Ok(())
       }
   }
   ```

**Deliverables**:
- [ ] Session management system
- [ ] Comprehensive audit logging
- [ ] Rate limiting implementation
- [ ] Security monitoring and alerting
- [ ] Security test suite completion

---

### Phase 4: Testing and Compliance (Weeks 7-8)

#### Week 7: Comprehensive Testing
**Priority**: Critical  
**Owner**: QA Team  

**Tasks**:
1. **Unit Test Enhancement**
   ```rust
   // tests/unit/webauthn_service_tests.rs
   #[cfg(test)]
   mod tests {
       use super::*;
       use mockall::predicate::*;
       use tokio_test;

       #[tokio::test]
       async fn test_registration_challenge_generation() {
           // Arrange
           let mut mock_credential_service = MockCredentialService::new();
           let mut mock_user_service = MockUserService::new();
           
           let user = create_test_user();
           mock_user_service
               .expect_find_by_username()
               .with(eq("test@example.com"))
               .returning(|_| Ok(Some(user.clone())));

           let service = WebAuthnService::new(
               create_test_webauthn(),
               Arc::new(mock_credential_service),
               Arc::new(mock_user_service),
           );

           // Act
           let result = service.start_registration(&user).await;

           // Assert
           assert!(result.is_ok());
           let challenge = result.unwrap();
           assert!(!challenge.challenge.is_empty());
           assert_eq!(challenge.rp.name, "Test RP");
           assert_eq!(challenge.user.name, "test@example.com");
       }

       #[tokio::test]
       async fn test_registration_with_invalid_user() {
           // Test registration with non-existent user
           // Should return appropriate error
       }

       #[tokio::test]
       async fn test_attestation_validation() {
           // Test various attestation formats
           // Test invalid attestation rejection
       }

       #[tokio::test]
       async fn test_authentication_flow() {
           // Test complete authentication flow
           // Test invalid assertion rejection
           // Test replay attack prevention
       }
   }
   ```

2. **Integration Test Implementation**
   ```rust
   // tests/integration/api_tests.rs
   use actix_test::TestServer;
   use serde_json::json;

   #[tokio::test]
   async fn test_complete_registration_flow() {
       // Setup test server
       let app = test::init_service(create_app()).await;
       
       // Step 1: Start registration
       let req = test::TestRequest::post()
           .uri("/webauthn/register/challenge")
           .set_json(json!({
               "username": "test@example.com",
               "displayName": "Test User"
           }))
           .to_request();
           
       let resp = test::call_service(&app, req).await;
       assert!(resp.status().is_success());
       
       let challenge: serde_json::Value = test::read_body_json(resp).await;
       let challenge_data = &challenge["data"];
       
       // Step 2: Complete registration (mock credential response)
       let req = test::TestRequest::post()
           .uri("/webauthn/register/verify")
           .set_json(json!({
               "username": "test@example.com",
               "credential": create_mock_credential_response()
           }))
           .to_request();
           
       let resp = test::call_service(&app, req).await;
       assert!(resp.status().is_success());
   }

   #[tokio::test]
   async fn test_authentication_flow() {
       // Test complete authentication flow
   }

   #[tokio::test]
   async fn test_error_handling() {
       // Test various error scenarios
   }
   ```

3. **Security Test Implementation**
   ```rust
   // tests/security/security_tests.rs
   #[tokio::test]
   async fn test_sql_injection_prevention() {
       // Test SQL injection attempts
       let malicious_inputs = vec![
           "'; DROP TABLE users; --",
           "' OR '1'='1",
           "'; INSERT INTO users VALUES ('hacker', 'password'); --",
       ];
       
       for input in malicious_inputs {
           let req = test::TestRequest::post()
               .uri("/webauthn/register/challenge")
               .set_json(json!({
                   "username": input,
                   "displayName": "Test User"
               }))
               .to_request();
               
           let resp = test::call_service(&app, req).await;
           // Should return 400 Bad Request, not 500 Internal Server Error
           assert_eq!(resp.status(), 400);
       }
   }

   #[tokio::test]
   async fn test_replay_attack_prevention() {
       // Test replay attack scenarios
   }

   #[tokio::test]
   async fn test_rate_limiting() {
       // Test rate limiting functionality
   }
   ```

**Deliverables**:
- [ ] Unit test coverage ≥95%
- [ ] Integration test coverage 100%
- [ ] Security test suite completion
- [ ] Performance test implementation
- [ ] Test automation in CI/CD

#### Week 8: FIDO Conformance Testing
**Priority**: Critical  
**Owner**: Compliance Team  

**Tasks**:
1. **FIDO Conformance Test Setup**
   ```bash
   # Clone FIDO conformance test tools
   git clone https://github.com/fido-alliance/conformance-test-tools.git
   
   # Configure test environment
   cd conformance-test-tools
   npm install
   
   # Configure server endpoints
   cp config/server-config.json.example config/server-config.json
   # Edit configuration with your server details
   ```

2. **Conformance Test Execution**
   ```rust
   // tests/compliance/fido_conformance_tests.rs
   #[tokio::test]
   async fn test_fido_server_registration() {
       // Test FIDO server registration endpoints
       // Follow FIDO test specification exactly
   }

   #[tokio::test]
   async fn test_fido_server_authentication() {
       // Test FIDO server authentication endpoints
       // Follow FIDO test specification exactly
   }

   #[tokio::test]
   async fn test_fido_server_info() {
       // Test FIDO server info endpoint
       // Verify supported algorithms and formats
   }
   ```

3. **Compliance Validation**
   ```rust
   // tests/compliance/specification_compliance.rs
   #[tokio::test]
   async fn test_webauthn_specification_compliance() {
       // Validate against WebAuthn specification
       // Test all required features
       // Validate error handling
   }

   #[tokio::test]
   async fn test_security_requirement_compliance() {
       // Validate security requirements
       // Test cryptographic implementations
       // Validate data protection
   }
   ```

**Deliverables**:
- [ ] FIDO Alliance conformance test pass
- [ ] WebAuthn specification compliance validation
- [ ] Security requirements compliance
- [ ] Compliance documentation
- [ ] Certification preparation

---

### Phase 5: Production Readiness (Weeks 9-10)

#### Week 9: Performance Optimization
**Priority**: High  
**Owner**: Performance Team  

**Tasks**:
1. **Database Optimization**
   ```sql
   -- Add performance indexes
   CREATE INDEX CONCURRENTLY idx_credentials_user_id_active 
   ON credentials(user_id) WHERE is_active = true;
   
   CREATE INDEX CONCURRENTLY idx_challenges_expires_at 
   ON challenges(expires_at) WHERE used = false;
   
   -- Analyze query performance
   EXPLAIN ANALYZE SELECT * FROM credentials WHERE user_id = $1;
   ```

2. **Caching Implementation**
   ```rust
   // src/services/cache_service.rs
   use redis::Client;
   use serde_json;

   pub struct CacheService {
       client: Client,
   }

   impl CacheService {
       pub async fn get_user(&self, user_id: &str) -> Result<Option<User>, CacheError> {
           let mut conn = self.client.get_async_connection().await?;
           let cached: Option<String> = redis::cmd("GET")
               .arg(format!("user:{}", user_id))
               .query_async(&mut conn)
               .await?;
               
           match cached {
               Some(data) => {
                   let user: User = serde_json::from_str(&data)?;
                   Ok(Some(user))
               }
               None => Ok(None)
           }
       }

       pub async fn set_user(&self, user: &User, ttl: u64) -> Result<(), CacheError> {
           let mut conn = self.client.get_async_connection().await?;
           let data = serde_json::to_string(user)?;
           
           redis::cmd("SETEX")
               .arg(format!("user:{}", user.id))
               .arg(ttl)
               .arg(data)
               .query_async(&mut conn)
               .await?;
               
           Ok(())
       }
   }
   ```

3. **Load Testing**
   ```rust
   // tests/performance/load_tests.rs
   use criterion::{black_box, criterion_group, criterion_main, Criterion};

   fn benchmark_registration_challenge(c: &mut Criterion) {
       let rt = tokio::runtime::Runtime::new().unwrap();
       let service = create_test_service();
       
       c.bench_function("registration_challenge", |b| {
           b.iter(|| {
               let user = create_test_user();
               rt.block_on(service.start_registration(black_box(&user))).unwrap()
           })
       });
   }

   fn benchmark_authentication_verification(c: &mut Criterion) {
       // Benchmark authentication verification performance
   }

   criterion_group!(
       benches,
       benchmark_registration_challenge,
       benchmark_authentication_verification
   );
   criterion_main!(benches);
   ```

**Deliverables**:
- [ ] Database performance optimization
- [ ] Caching implementation
- [ ] Load testing completion
- [ ] Performance benchmarks
- [ ] Scalability validation

#### Week 10: Production Deployment
**Priority**: Critical  
**Owner**: DevOps Team  

**Tasks**:
1. **Production Configuration**
   ```yaml
   # docker-compose.prod.yml
   version: '3.8'
   services:
     fido-server:
       image: fido-server:latest
       environment:
         - DATABASE_URL=postgresql://user:pass@postgres:5432/fido
         - RP_ID=example.com
         - RP_NAME=FIDO Server
         - LOG_LEVEL=info
       ports:
         - "443:8443"
       volumes:
         - ./ssl:/app/ssl:ro
         - ./keys:/app/keys:ro
       depends_on:
         - postgres
         - redis

     postgres:
       image: postgres:15
       environment:
         - POSTGRES_DB=fido
         - POSTGRES_USER=fido
         - POSTGRES_PASSWORD=${DB_PASSWORD}
       volumes:
         - postgres_data:/var/lib/postgresql/data
       ports:
         - "5432:5432"

     redis:
       image: redis:7-alpine
       ports:
         - "6379:6379"

   volumes:
     postgres_data:
   ```

2. **Monitoring and Alerting**
   ```yaml
   # monitoring/prometheus.yml
   global:
     scrape_interval: 15s

   scrape_configs:
     - job_name: 'fido-server'
       static_configs:
         - targets: ['fido-server:8443']
       metrics_path: '/metrics'
       scheme: 'https'

   rule_files:
     - "alert_rules.yml"

   alerting:
     alertmanagers:
       - static_configs:
           - targets:
             - alertmanager:9093
   ```

3. **Health Checks**
   ```rust
   // src/controllers/health_controller.rs
   #[derive(Debug, Serialize)]
   pub struct HealthResponse {
       pub healthy: bool,
       pub timestamp: chrono::DateTime<chrono::Utc>,
       pub checks: HashMap<String, HealthCheck>,
   }

   #[derive(Debug, Serialize)]
   pub struct HealthCheck {
       pub healthy: bool,
       pub response_time_ms: u64,
       pub error: Option<String>,
   }

   pub async fn health_check() -> Result<HttpResponse, Error> {
       let mut checks = HashMap::new();
       
       // Database health check
       let db_check = check_database_health().await;
       checks.insert("database".to_string(), db_check);
       
       // Redis health check
       let redis_check = check_redis_health().await;
       checks.insert("redis".to_string(), redis_check);
       
       let all_healthy = checks.values().all(|check| check.healthy);
       
       Ok(HttpResponse::Ok().json(HealthResponse {
           healthy: all_healthy,
           timestamp: Utc::now(),
           checks,
       }))
   }
   ```

**Deliverables**:
- [ ] Production deployment configuration
- [ ] Monitoring and alerting setup
- [ ] Health check implementation
- [ ] Backup and recovery procedures
- [ ] Documentation completion

---

## 3. Quality Assurance

### 3.1 Code Quality Standards

#### Rust Linting Configuration
```toml
# .clippy.toml
msrv = "1.70"
cognitive-complexity-threshold = 30
too-many-arguments-threshold = 7
type-complexity-threshold = 250
single-char-lifetime-names-threshold = 4
trivial-copy-size-limit = 256
```

#### Code Review Checklist
- [ ] Security considerations addressed
- [ ] Error handling comprehensive
- [ ] Performance implications considered
- [ ] Test coverage adequate
- [ ] Documentation complete
- [ ] Logging appropriate
- [ ] Configuration management
- [ ] Dependency security

### 3.2 Testing Requirements

#### Coverage Targets
- Unit tests: ≥95% line coverage
- Integration tests: 100% API endpoint coverage
- Security tests: All identified threats
- Performance tests: Load and stress scenarios
- Compliance tests: FIDO Alliance requirements

#### Test Categories
1. **Functional Tests**: Verify correct behavior
2. **Security Tests**: Verify security controls
3. **Performance Tests**: Verify performance requirements
4. **Compliance Tests**: Verify specification compliance
5. **Usability Tests**: Verify user experience

### 3.3 Documentation Requirements

#### Technical Documentation
- [ ] Architecture documentation
- [ ] API documentation (OpenAPI/Swagger)
- [ ] Security documentation
- [ ] Deployment documentation
- [ ] Troubleshooting guide

#### User Documentation
- [ ] User guide
- [ ] Integration guide
- [ ] FAQ
- [ ] Support contact information

---

## 4. Risk Management

### 4.1 Risk Mitigation Status

| Risk ID | Risk | Status | Mitigation |
|---------|------|--------|------------|
| SEC-001 | Credential Database Compromise | In Progress | Encryption at rest, access controls |
| SEC-002 | Private Key Extraction | Planned | Attestation validation, monitoring |
| SEC-003 | Replay Attacks | Implemented | Single-use challenges, counter validation |
| SEC-004 | Origin Validation Bypass | Implemented | Strict origin validation, HSTS |
| OPS-001 | Database Performance | In Progress | Optimization, caching |
| COMP-001 | FIDO Non-Compliance | In Progress | Conformance testing |

### 4.2 Monitoring Requirements

#### Key Metrics
- Authentication success rate
- Registration success rate
- Response time percentiles
- Error rates by type
- Security events
- Resource utilization

#### Alerting Thresholds
- Authentication failure rate >5%
- Response time p95 >500ms
- Error rate >1%
- Security events >10/hour
- Database connections >80%

---

## 5. Success Metrics

### 5.1 Technical Metrics
- [ ] Unit test coverage: ≥95%
- [ ] Integration test coverage: 100%
- [ ] Security test coverage: 100%
- [ ] Performance: <100ms p95 response time
- [ ] Availability: 99.9%
- [ ] FIDO conformance: 100% pass rate

### 5.2 Business Metrics
- [ ] Time to market: 10 weeks
- [ ] Development cost: Within budget
- [ ] Security incidents: 0 critical
- [ ] Customer satisfaction: >95%
- [ ] Compliance: 100%

---

## 6. Next Steps

### 6.1 Immediate Actions (Week 1)
1. Set up development environment
2. Create project structure
3. Implement database schema
4. Set up CI/CD pipeline

### 6.2 Short-term Actions (Weeks 2-4)
1. Implement core WebAuthn service
2. Develop REST API
3. Add security middleware
4. Create comprehensive tests

### 6.3 Medium-term Actions (Weeks 5-8)
1. Security hardening
2. Performance optimization
3. FIDO conformance testing
4. Documentation completion

### 6.4 Long-term Actions (Weeks 9-10)
1. Production deployment
2. Monitoring setup
3. User training
4. Maintenance planning

---

## 7. Conclusion

This implementation guide provides a comprehensive roadmap for building a secure, compliant FIDO2/WebAuthn Relying Party Server. The phased approach ensures that security, performance, and compliance requirements are met while maintaining development velocity.

Key success factors:
1. **Security-first approach** with comprehensive risk mitigation
2. **Test-driven development** with high coverage requirements
3. **FIDO Alliance compliance** as a primary objective
4. **Production-ready architecture** with scalability considerations
5. **Comprehensive monitoring** and alerting capabilities

The implementation plan is designed to deliver a production-ready system that meets all security requirements, achieves FIDO conformance, and provides a solid foundation for enterprise deployment.

Regular reviews and updates to this guide will ensure that the implementation remains aligned with evolving security requirements, industry best practices, and business needs.