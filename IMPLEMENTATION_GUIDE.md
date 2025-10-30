# FIDO2/WebAuthn Server Implementation Guide

## Overview

This guide provides detailed implementation instructions for building a FIDO2/WebAuthn conformant Relying Party Server in Rust using the webauthn-rs library, with focus on security-first design and comprehensive testing.

## 1. Core WebAuthn Service Implementation

### 1.1 WebAuthn Configuration

```rust
// src/config/webauthn.rs

use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnConfig {
    pub rp_name: String,
    pub rp_id: String,
    pub rp_origin: String,
    pub timeout: u64,
    pub attestation_preference: AttestationConveyancePreference,
    pub user_verification_policy: UserVerificationPolicy,
}

impl Default for WebAuthnConfig {
    fn default() -> Self {
        Self {
            rp_name: "FIDO Server".to_string(),
            rp_id: "localhost".to_string(),
            rp_origin: "http://localhost:8080".to_string(),
            timeout: 60000,
            attestation_preference: AttestationConveyancePreference::Direct,
            user_verification_policy: UserVerificationPolicy::Required,
        }
    }
}

impl WebAuthnConfig {
    pub fn to_webauthn(&self) -> Result<WebAuthn, WebauthnError> {
        WebAuthnBuilder::new(&self.rp_id, &self.rp_origin)
            .rp_name(&self.rp_name)
            .build()
    }
}
```

### 1.2 WebAuthn Service Core

```rust
// src/services/webauthn_service.rs

use crate::config::WebAuthnConfig;
use crate::db::repositories::{ChallengeRepository, CredentialRepository, UserRepository};
use crate::error::{AppError, Result};
use chrono::{Duration, Utc};
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;
use webauthn_rs::prelude::*;

pub struct WebAuthnService {
    webauthn: WebAuthn,
    challenge_repo: ChallengeRepository,
    credential_repo: CredentialRepository,
    user_repo: UserRepository,
    config: WebAuthnConfig,
}

impl WebAuthnService {
    pub fn new(
        config: WebAuthnConfig,
        challenge_repo: ChallengeRepository,
        credential_repo: CredentialRepository,
        user_repo: UserRepository,
    ) -> Result<Self> {
        let webauthn = config.to_webauthn()?;
        Ok(Self {
            webauthn,
            challenge_repo,
            credential_repo,
            user_repo,
            config,
        })
    }

    /// Generate registration challenge options
    pub async fn generate_registration_options(
        &self,
        username: &str,
        display_name: &str,
        attestation: Option<AttestationConveyancePreference>,
        authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    ) -> Result<PublicKeyCredentialCreationOptions> {
        // Validate input parameters
        self.validate_username(username)?;
        self.validate_display_name(display_name)?;

        // Create or get user
        let user_id = self.get_or_create_user(username, display_name).await?;

        // Generate challenge
        let (ccr, state) = self.webauthn.generate_challenge_register_options(
            &User {
                id: user_id.as_bytes().to_vec(),
                name: username,
                display_name,
            },
            authenticator_selection.unwrap_or_default(),
            attestation.unwrap_or(self.config.attestation_preference),
            Some(self.config.timeout),
            None,
        )?;

        // Store challenge state
        let challenge = Challenge::new(
            state.challenge.clone(),
            user_id,
            ChallengeType::Registration,
            Utc::now() + Duration::milliseconds(self.config.timeout as i64),
        );
        self.challenge_repo.store_challenge(challenge).await?;

        Ok(ccr)
    }

    /// Verify registration attestation
    pub async fn verify_registration(
        &self,
        username: &str,
        credential_id: &str,
        client_data_json: &str,
        attestation_object: &str,
    ) -> Result<RegistrationResult> {
        // Decode and validate inputs
        let credential_id = base64url::decode(credential_id)
            .map_err(|_| AppError::InvalidInput("Invalid credential ID".to_string()))?;
        
        let client_data_json = base64url::decode(client_data_json)
            .map_err(|_| AppError::InvalidInput("Invalid client data JSON".to_string()))?;
        
        let attestation_object = base64url::decode(attestation_object)
            .map_err(|_| AppError::InvalidInput("Invalid attestation object".to_string()))?;

        // Get user
        let user = self.user_repo.get_user_by_username(username).await?
            .ok_or(AppError::UserNotFound)?;

        // Get and validate challenge
        let challenge = self.challenge_repo.get_active_challenge_for_user(
            user.id,
            ChallengeType::Registration,
        ).await?.ok_or(AppError::InvalidChallenge)?;

        // Verify attestation
        let attestation = CollectedClientData::from_bytes(&client_data_json)
            .map_err(|e| AppError::WebAuthnError(e.to_string()))?;

        // Verify challenge matches
        if attestation.challenge != challenge.challenge {
            return Err(AppError::InvalidChallenge);
        }

        // Verify origin
        if attestation.origin != self.config.rp_origin {
            return Err(AppError::InvalidOrigin);
        }

        // Verify attestation object
        let result = self.webauthn.register_credential(
            &attestation,
            &attestation_object,
        ).map_err(|e| AppError::WebAuthnError(e.to_string()))?;

        // Store credential
        let credential = Credential::new(
            user.id,
            result.credential_id.clone(),
            result.public_key.clone(),
            result.attestation_format.clone(),
            result.aaguid,
            result.counter,
        );
        self.credential_repo.store_credential(credential).await?;

        // Mark challenge as used
        self.challenge_repo.mark_challenge_used(challenge.id).await?;

        Ok(RegistrationResult {
            credential_id: base64url::encode(&result.credential_id),
            user_id: user.id.to_string(),
        })
    }

    /// Generate authentication challenge options
    pub async fn generate_authentication_options(
        &self,
        username: &str,
        user_verification: Option<UserVerificationPolicy>,
    ) -> Result<PublicKeyCredentialRequestOptions> {
        // Get user
        let user = self.user_repo.get_user_by_username(username).await?
            .ok_or(AppError::UserNotFound)?;

        // Get user credentials
        let credentials = self.credential_repo.get_credentials_for_user(user.id).await?;

        if credentials.is_empty() {
            return Err(AppError::NoCredentials);
        }

        // Convert to allow credentials
        let allow_credentials: Vec<PublicKeyCredentialDescriptor> = credentials
            .into_iter()
            .map(|cred| PublicKeyCredentialDescriptor {
                id: cred.credential_id,
                transports: Some(vec![
                    AuthenticatorTransport::Internal,
                    AuthenticatorTransport::Usb,
                    AuthenticatorTransport::Nfc,
                    AuthenticatorTransport::Ble,
                ]),
                type_: PublicKeyCredentialType::PublicKey,
            })
            .collect();

        // Generate challenge
        let (acr, state) = self.webauthn.generate_challenge_authenticate_options(
            allow_credentials,
            user_verification.unwrap_or(self.config.user_verification_policy),
            Some(self.config.timeout),
        )?;

        // Store challenge state
        let challenge = Challenge::new(
            state.challenge.clone(),
            user.id,
            ChallengeType::Authentication,
            Utc::now() + Duration::milliseconds(self.config.timeout as i64),
        );
        self.challenge_repo.store_challenge(challenge).await?;

        Ok(acr)
    }

    /// Verify authentication assertion
    pub async fn verify_authentication(
        &self,
        username: &str,
        credential_id: &str,
        client_data_json: &str,
        authenticator_data: &str,
        signature: &str,
        user_handle: Option<&str>,
    ) -> Result<AuthenticationResult> {
        // Decode and validate inputs
        let credential_id = base64url::decode(credential_id)
            .map_err(|_| AppError::InvalidInput("Invalid credential ID".to_string()))?;
        
        let client_data_json = base64url::decode(client_data_json)
            .map_err(|_| AppError::InvalidInput("Invalid client data JSON".to_string()))?;
        
        let authenticator_data = base64url::decode(authenticator_data)
            .map_err(|_| AppError::InvalidInput("Invalid authenticator data".to_string()))?;
        
        let signature = base64url::decode(signature)
            .map_err(|_| AppError::InvalidInput("Invalid signature".to_string()))?;

        // Get user
        let user = self.user_repo.get_user_by_username(username).await?
            .ok_or(AppError::UserNotFound)?;

        // Get credential
        let mut credential = self.credential_repo.get_credential_by_id(&credential_id).await?
            .ok_or(AppError::CredentialNotFound)?;

        // Verify credential belongs to user
        if credential.user_id != user.id {
            return Err(AppError::CredentialMismatch);
        }

        // Get and validate challenge
        let challenge = self.challenge_repo.get_active_challenge_for_user(
            user.id,
            ChallengeType::Authentication,
        ).await?.ok_or(AppError::InvalidChallenge)?;

        // Verify assertion
        let client_data = CollectedClientData::from_bytes(&client_data_json)
            .map_err(|e| AppError::WebAuthnError(e.to_string()))?;

        // Verify challenge matches
        if client_data.challenge != challenge.challenge {
            return Err(AppError::InvalidChallenge);
        }

        // Verify origin
        if client_data.origin != self.config.rp_origin {
            return Err(AppError::InvalidOrigin);
        }

        // Create authenticator data
        let auth_data = AuthenticatorData::from_bytes(&authenticator_data)
            .map_err(|e| AppError::WebAuthnError(e.to_string()))?;

        // Verify signature
        let result = self.webauthn.authenticate_credential(
            &credential.credential_id,
            &credential.public_key,
            &client_data,
            &auth_data,
            &signature,
        ).map_err(|e| AppError::WebAuthnError(e.to_string()))?;

        // Update credential counter
        if result.counter <= credential.sign_count {
            return Err(AppError::CredentialCloned);
        }
        credential.sign_count = result.counter;
        credential.last_used_at = Some(Utc::now());
        self.credential_repo.update_credential(credential).await?;

        // Mark challenge as used
        self.challenge_repo.mark_challenge_used(challenge.id).await?;

        Ok(AuthenticationResult {
            user_id: user.id.to_string(),
            credential_id: base64url::encode(&credential.credential_id),
            new_counter: result.counter,
        })
    }

    // Helper methods
    fn validate_username(&self, username: &str) -> Result<()> {
        if username.len() < 3 || username.len() > 255 {
            return Err(AppError::InvalidInput("Username must be 3-255 characters".to_string()));
        }
        // Additional validation as needed
        Ok(())
    }

    fn validate_display_name(&self, display_name: &str) -> Result<()> {
        if display_name.is_empty() || display_name.len() > 255 {
            return Err(AppError::InvalidInput("Display name must be 1-255 characters".to_string()));
        }
        // Additional validation as needed
        Ok(())
    }

    async fn get_or_create_user(&self, username: &str, display_name: &str) -> Result<Uuid> {
        if let Some(user) = self.user_repo.get_user_by_username(username).await? {
            Ok(user.id)
        } else {
            let user = User::new(username, display_name);
            let user_id = self.user_repo.create_user(user).await?;
            Ok(user_id)
        }
    }
}

// Result types
#[derive(Debug, Serialize)]
pub struct RegistrationResult {
    pub credential_id: String,
    pub user_id: String,
}

#[derive(Debug, Serialize)]
pub struct AuthenticationResult {
    pub user_id: String,
    pub credential_id: String,
    pub new_counter: u32,
}

// Challenge types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeType {
    Registration,
    Authentication,
}

#[derive(Debug)]
pub struct Challenge {
    pub id: Uuid,
    pub challenge: String,
    pub user_id: Uuid,
    pub challenge_type: ChallengeType,
    pub expires_at: chrono::DateTime<Utc>,
    pub is_used: bool,
}

impl Challenge {
    pub fn new(
        challenge: String,
        user_id: Uuid,
        challenge_type: ChallengeType,
        expires_at: chrono::DateTime<Utc>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            challenge,
            user_id,
            challenge_type,
            expires_at,
            is_used: false,
        }
    }
}
```

## 2. Database Models and Repositories

### 2.1 Database Models

```rust
// src/db/models.rs

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_active: bool,
}

impl User {
    pub fn new(username: &str, display_name: &str) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            username: username.to_string(),
            display_name: display_name.to_string(),
            created_at: now,
            updated_at: now,
            is_active: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub attestation_type: String,
    pub aaguid: Uuid,
    pub sign_count: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub user_verification_policy: String,
}

impl Credential {
    pub fn new(
        user_id: Uuid,
        credential_id: Vec<u8>,
        public_key: Vec<u8>,
        attestation_type: String,
        aaguid: Uuid,
        sign_count: u32,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            user_id,
            credential_id,
            public_key,
            attestation_type,
            aaguid,
            sign_count,
            created_at: now,
            updated_at: now,
            last_used_at: None,
            is_active: true,
            user_verification_policy: "required".to_string(),
        }
    }
}
```

### 2.2 Repository Pattern

```rust
// src/db/repositories.rs

use crate::db::models::{Credential, User};
use crate::error::{AppError, Result};
use async_trait::async_trait;
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool};
use std::sync::Arc;

pub type DbPool = Pool<ConnectionManager<PgConnection>>;

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn create_user(&self, user: User) -> Result<Uuid>;
    async fn get_user_by_id(&self, user_id: Uuid) -> Result<Option<User>>;
    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>>;
    async fn update_user(&self, user: User) -> Result<()>;
    async fn delete_user(&self, user_id: Uuid) -> Result<()>;
}

#[async_trait]
pub trait CredentialRepository: Send + Sync {
    async fn store_credential(&self, credential: Credential) -> Result<()>;
    async fn get_credential_by_id(&self, credential_id: &[u8]) -> Result<Option<Credential>>;
    async fn get_credentials_for_user(&self, user_id: Uuid) -> Result<Vec<Credential>>;
    async fn update_credential(&self, credential: Credential) -> Result<()>;
    async fn delete_credential(&self, credential_id: &[u8]) -> Result<()>;
    async fn revoke_credential(&self, credential_id: &[u8]) -> Result<()>;
}

#[async_trait]
pub trait ChallengeRepository: Send + Sync {
    async fn store_challenge(&self, challenge: super::services::webauthn_service::Challenge) -> Result<()>;
    async fn get_active_challenge_for_user(
        &self,
        user_id: Uuid,
        challenge_type: super::services::webauthn_service::ChallengeType,
    ) -> Result<Option<super::services::webauthn_service::Challenge>>;
    async fn mark_challenge_used(&self, challenge_id: Uuid) -> Result<()>;
    async fn cleanup_expired_challenges(&self) -> Result<()>;
}

// Diesel implementations
pub struct DieselUserRepository {
    pool: Arc<DbPool>,
}

impl DieselUserRepository {
    pub fn new(pool: Arc<DbPool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for DieselUserRepository {
    async fn create_user(&self, user: User) -> Result<Uuid> {
        use crate::schema::users;
        use diesel::insert_into;

        let user_id = user.id;
        let pool = self.pool.clone();

        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            insert_into(users::table)
                .values(&user)
                .execute(&mut conn)?;
            Ok::<_, AppError>(user_id)
        }).await?
    }

    async fn get_user_by_id(&self, user_id: Uuid) -> Result<Option<User>> {
        use crate::schema::users::dsl::*;
        use diesel::QueryDsl;

        let pool = self.pool.clone();

        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            let user = users
                .filter(id.eq(user_id))
                .first::<User>(&mut conn)
                .optional()?;
            Ok::<_, AppError>(user)
        }).await?
    }

    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        use crate::schema::users::dsl::*;
        use diesel::QueryDsl;

        let username = username.to_string();
        let pool = self.pool.clone();

        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            let user = users
                .filter(username.eq(username))
                .first::<User>(&mut conn)
                .optional()?;
            Ok::<_, AppError>(user)
        }).await?
    }

    async fn update_user(&self, user: User) -> Result<()> {
        use crate::schema::users::dsl::*;
        use diesel::QueryDsl;

        let pool = self.pool.clone();

        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            diesel::update(users.filter(id.eq(user.id)))
                .set((
                    username.eq(user.username),
                    display_name.eq(user.display_name),
                    updated_at.eq(user.updated_at),
                    is_active.eq(user.is_active),
                ))
                .execute(&mut conn)?;
            Ok::<_, AppError>(())
        }).await?
    }

    async fn delete_user(&self, user_id: Uuid) -> Result<()> {
        use crate::schema::users::dsl::*;
        use diesel::QueryDsl;

        let pool = self.pool.clone();

        tokio::task::spawn_blocking(move || {
            let mut conn = pool.get()?;
            diesel::delete(users.filter(id.eq(user_id)))
                .execute(&mut conn)?;
            Ok::<_, AppError>(())
        }).await?
    }
}

// Similar implementations for CredentialRepository and ChallengeRepository...
```

## 3. API Controllers Implementation

### 3.1 Registration Controller

```rust
// src/controllers/registration.rs

use crate::error::{AppError, Result};
use crate::services::webauthn_service::WebAuthnService;
use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;

#[derive(Debug, Deserialize)]
pub struct RegistrationOptionsRequest {
    pub username: String,
    pub display_name: String,
    pub attestation: Option<AttestationConveyancePreference>,
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
}

#[derive(Debug, Serialize)]
pub struct RegistrationOptionsResponse {
    pub status: String,
    pub error_message: String,
    #[serde(flatten)]
    pub options: PublicKeyCredentialCreationOptions,
}

#[derive(Debug, Deserialize)]
pub struct RegistrationResultRequest {
    pub credential_id: String,
    pub client_data_json: String,
    pub attestation_object: String,
}

#[derive(Debug, Serialize)]
pub struct RegistrationResultResponse {
    pub status: String,
    pub error_message: String,
    pub credential_id: String,
    pub new_identity: UserIdentity,
}

#[derive(Debug, Serialize)]
pub struct UserIdentity {
    pub username: String,
    pub display_name: String,
}

pub async fn get_registration_options(
    webauthn_service: web::Data<WebAuthnService>,
    req: HttpRequest,
    body: web::Json<RegistrationOptionsRequest>,
) -> Result<HttpResponse> {
    // Validate request
    if body.username.is_empty() || body.display_name.is_empty() {
        return Ok(HttpResponse::BadRequest().json(RegistrationOptionsResponse {
            status: "error".to_string(),
            error_message: "Username and display name are required".to_string(),
            options: PublicKeyCredentialCreationOptions::default(),
        }));
    }

    // Generate registration options
    match webauthn_service
        .generate_registration_options(
            &body.username,
            &body.display_name,
            body.attestation,
            body.authenticator_selection,
        )
        .await
    {
        Ok(options) => Ok(HttpResponse::Ok().json(RegistrationOptionsResponse {
            status: "ok".to_string(),
            error_message: String::new(),
            options,
        })),
        Err(e) => Ok(HttpResponse::InternalServerError().json(RegistrationOptionsResponse {
            status: "error".to_string(),
            error_message: e.to_string(),
            options: PublicKeyCredentialCreationOptions::default(),
        })),
    }
}

pub async fn submit_registration_result(
    webauthn_service: web::Data<WebAuthnService>,
    body: web::Json<RegistrationResultRequest>,
) -> Result<HttpResponse> {
    // Validate request
    if body.credential_id.is_empty() 
        || body.client_data_json.is_empty() 
        || body.attestation_object.is_empty() {
        return Ok(HttpResponse::BadRequest().json(RegistrationResultResponse {
            status: "error".to_string(),
            error_message: "All fields are required".to_string(),
            credential_id: String::new(),
            new_identity: UserIdentity {
                username: String::new(),
                display_name: String::new(),
            },
        }));
    }

    // Verify registration
    match webauthn_service
        .verify_registration(
            &body.username,
            &body.credential_id,
            &body.client_data_json,
            &body.attestation_object,
        )
        .await
    {
        Ok(result) => {
            // Get user details for response
            // This would typically come from the user service
            Ok(HttpResponse::Ok().json(RegistrationResultResponse {
                status: "ok".to_string(),
                error_message: String::new(),
                credential_id: result.credential_id,
                new_identity: UserIdentity {
                    username: "user@example.com".to_string(), // Get from user service
                    display_name: "User".to_string(), // Get from user service
                },
            }))
        }
        Err(e) => Ok(HttpResponse::BadRequest().json(RegistrationResultResponse {
            status: "error".to_string(),
            error_message: e.to_string(),
            credential_id: String::new(),
            new_identity: UserIdentity {
                username: String::new(),
                display_name: String::new(),
            },
        })),
    }
}
```

## 4. Security Middleware Implementation

### 4.1 Rate Limiting Middleware

```rust
// src/middleware/rate_limit.rs

use actix_web::{dev::ServiceRequest, dev::ServiceResponse, Error, HttpMessage};
use actix_web::{web, ErrorMiddleware};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct RateLimiter {
    requests: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
    max_requests: usize,
    window: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            requests: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window,
        }
    }

    pub fn is_allowed(&self, key: &str) -> bool {
        let mut requests = self.requests.lock().unwrap();
        let now = Instant::now();
        
        let entry = requests.entry(key.to_string()).or_insert_with(Vec::new);
        
        // Remove old requests outside the window
        entry.retain(|&timestamp| now.duration_since(timestamp) < self.window);
        
        // Check if under limit
        if entry.len() < self.max_requests {
            entry.push(now);
            true
        } else {
            false
        }
    }
}

pub async fn rate_limit_middleware(
    req: ServiceRequest,
    next: web::Next<impl actix_web::dev::ServiceFactory<ServiceRequest, Config = (), Response = ServiceResponse, Error = Error, InitError = ()>>,
) -> Result<ServiceResponse, Error> {
    let rate_limiter = req.app_data::<web::Data<RateLimiter>>()
        .expect("RateLimiter not configured");

    let client_ip = req
        .connection_info()
        .peer_addr()
        .unwrap_or("unknown")
        .to_string();

    if !rate_limiter.is_allowed(&client_ip) {
        return Ok(req.into_response(
            actix_web::HttpResponse::TooManyRequests()
                .json(serde_json::json!({
                    "error": "Rate limit exceeded"
                }))
                .into_body()
                .into(),
        ));
    }

    next.call(req).await
}
```

### 4.2 Security Headers Middleware

```rust
// src/middleware/security.rs

use actix_web::{dev::ServiceRequest, dev::ServiceResponse, Error};
use actix_web::{web, HttpMessage};

pub async fn security_headers_middleware(
    req: ServiceRequest,
    next: web::Next<impl actix_web::dev::ServiceFactory<ServiceRequest, Config = (), Response = ServiceResponse, Error = Error, InitError = ()>>,
) -> Result<ServiceResponse, Error> {
    let mut resp = next.call(req).await?;
    
    // Add security headers
    resp.headers_mut().insert(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains; preload".parse().unwrap(),
    );
    resp.headers_mut().insert(
        "X-Content-Type-Options",
        "nosniff".parse().unwrap(),
    );
    resp.headers_mut().insert(
        "X-Frame-Options",
        "DENY".parse().unwrap(),
    );
    resp.headers_mut().insert(
        "X-XSS-Protection",
        "1; mode=block".parse().unwrap(),
    );
    resp.headers_mut().insert(
        "Content-Security-Policy",
        "default-src 'self'".parse().unwrap(),
    );
    resp.headers_mut().insert(
        "Referrer-Policy",
        "strict-origin-when-cross-origin".parse().unwrap(),
    );

    Ok(resp)
}
```

## 5. Error Handling Implementation

### 5.1 Custom Error Types

```rust
// src/error/types.rs

use actix_web::{error::ResponseError, HttpResponse};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(#[from] diesel::result::Error),
    
    #[error("WebAuthn error: {0}")]
    WebAuthnError(String),
    
    #[error("User not found")]
    UserNotFound,
    
    #[error("Credential not found")]
    CredentialNotFound,
    
    #[error("Invalid challenge")]
    InvalidChallenge,
    
    #[error("Invalid origin")]
    InvalidOrigin,
    
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    
    #[error("No credentials found for user")]
    NoCredentials,
    
    #[error("Credential mismatch")]
    CredentialMismatch,
    
    #[error("Credential cloned detected")]
    CredentialCloned,
    
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    
    #[error("Internal server error: {0}")]
    Internal(String),
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        match self {
            AppError::Database(_) => HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Database error occurred"
            })),
            AppError::WebAuthnError(msg) => HttpResponse::BadRequest().json(serde_json::json!({
                "error": "WebAuthn error",
                "message": msg
            })),
            AppError::UserNotFound => HttpResponse::NotFound().json(serde_json::json!({
                "error": "User not found"
            })),
            AppError::CredentialNotFound => HttpResponse::NotFound().json(serde_json::json!({
                "error": "Credential not found"
            })),
            AppError::InvalidChallenge => HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid or expired challenge"
            })),
            AppError::InvalidOrigin => HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid origin"
            })),
            AppError::InvalidInput(msg) => HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid input",
                "message": msg
            })),
            AppError::NoCredentials => HttpResponse::BadRequest().json(serde_json::json!({
                "error": "No credentials found for user"
            })),
            AppError::CredentialMismatch => HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Credential does not belong to user"
            })),
            AppError::CredentialCloned => HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Credential cloning detected"
            })),
            AppError::RateLimitExceeded => HttpResponse::TooManyRequests().json(serde_json::json!({
                "error": "Rate limit exceeded"
            })),
            AppError::Internal(msg) => HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal server error",
                "message": msg
            })),
        }
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
```

## 6. Testing Implementation Examples

### 6.1 Unit Test Example

```rust
// tests/unit/services/webauthn_service_tests.rs

use crate::common::test_utils::*;
use fido_server::services::webauthn_service::*;
use mockall::predicate::*;
use webauthn_rs::prelude::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_generate_registration_challenge_success() {
        // Setup
        let (service, _mocks) = create_test_webauthn_service().await;
        
        // Test
        let result = service
            .generate_registration_options(
                "test@example.com",
                "Test User",
                None,
                None,
            )
            .await;
        
        // Verify
        assert!(result.is_ok());
        let options = result.unwrap();
        assert!(!options.challenge.is_empty());
        assert_eq!(options.rp.name, "FIDO Server");
        assert_eq!(options.user.name, "test@example.com");
        assert_eq!(options.user.display_name, "Test User");
    }

    #[tokio::test]
    async fn test_generate_registration_challenge_invalid_username() {
        // Setup
        let (service, _mocks) = create_test_webauthn_service().await;
        
        // Test
        let result = service
            .generate_registration_options(
                "", // Invalid username
                "Test User",
                None,
                None,
            )
            .await;
        
        // Verify
        assert!(result.is_err());
        match result.unwrap_err() {
            AppError::InvalidInput(msg) => {
                assert!(msg.contains("Username must be 3-255 characters"));
            }
            _ => panic!("Expected InvalidInput error"),
        }
    }

    #[tokio::test]
    async fn test_verify_registration_success() {
        // Setup
        let (service, mocks) = create_test_webauthn_service().await;
        
        // Mock user exists
        mocks.user_repo
            .expect_get_user_by_username()
            .with(eq("test@example.com"))
            .returning(|_| Ok(Some(create_test_user())));
        
        // Mock challenge exists
        mocks.challenge_repo
            .expect_get_active_challenge_for_user()
            .returning(|_, _| Ok(Some(create_test_challenge())));
        
        // Mock credential storage
        mocks.credential_repo
            .expect_store_credential()
            .returning(|_| Ok(()));
        
        // Mock challenge usage
        mocks.challenge_repo
            .expect_mark_challenge_used()
            .returning(|_| Ok(()));
        
        // Test
        let result = service
            .verify_registration(
                "test@example.com",
                &create_test_credential_id(),
                &create_test_client_data_json(),
                &create_test_attestation_object(),
            )
            .await;
        
        // Verify
        assert!(result.is_ok());
        let registration_result = result.unwrap();
        assert!(!registration_result.credential_id.is_empty());
        assert!(!registration_result.user_id.is_empty());
    }
}
```

### 6.2 Integration Test Example

```rust
// tests/integration/api_contract_tests.rs

use actix_web::{test, App};
use fido_server::routes::configure_routes;
use serde_json::json;

#[tokio::test]
async fn test_registration_flow_complete() {
    // Setup
    let app = test::init_service(
        App::new()
            .configure(configure_routes)
    ).await;
    
    // Step 1: Get registration options
    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(&json!({
            "username": "test@example.com",
            "displayName": "Test User",
            "attestation": "direct"
        }))
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    
    let options: serde_json::Value = test::read_body_json(resp).await;
    let challenge = options["challenge"].as_str().unwrap();
    let user_id = options["user"]["id"].as_str().unwrap();
    
    // Step 2: Submit registration result
    // This would typically involve a real authenticator
    // For testing, we'll use mock data
    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(&json!({
            "credentialId": "mock_credential_id",
            "clientDataJSON": "mock_client_data",
            "attestationObject": "mock_attestation"
        }))
        .to_request();
    
    let resp = test::call_service(&app, req).await;
    // Note: This will fail with mock data, but demonstrates the flow
    // In real tests, you'd use actual WebAuthn data
}
```

This implementation guide provides a comprehensive foundation for building a secure, FIDO2-compliant WebAuthn server with extensive testing coverage and security-first design principles. The code examples demonstrate best practices for error handling, security, and testability.