# FIDO2/WebAuthn Server Implementation Guide

## Overview

This guide provides detailed implementation instructions for building a secure, FIDO2-compliant WebAuthn Relying Party Server in Rust using the webauthn-rs library.

## 1. Project Setup

### 1.1 Initial Configuration

```bash
# Create new Rust project
cargo new fido-server --lib
cd fido-server

# Add required dependencies
cargo add actix-web actix-cors actix-rt
cargo add webauthn-rs webauthn-rs-proto
cargo add serde serde_json
cargo add diesel diesel_migrations r2d2 --features "postgres r2d2 chrono uuid"
cargo add tokio futures
cargo add base64 uuid rand sha2
cargo add config dotenv
cargo add log env_logger
cargo add thiserror anyhow
cargo add chrono

# Add development dependencies
cargo add --dev actix-test mockall
cargo add --dev tokio-test testcontainers wiremock
cargo add --dev criterion proptest
```

### 1.2 Directory Structure Creation

```bash
mkdir -p src/{config,controllers,services,db,middleware,routes,error,utils,schema}
mkdir -p tests/{integration,security,performance,fixtures}
mkdir -p migrations
```

## 2. Core WebAuthn Implementation

### 2.1 WebAuthn Configuration

```rust
// src/config/webauthn.rs
use webauthn_rs::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebAuthnConfig {
    pub rp_name: String,
    pub rp_id: String,
    pub rp_origin: String,
    pub timeout: u64,
}

impl Default for WebAuthnConfig {
    fn default() -> Self {
        Self {
            rp_name: "FIDO Server".to_string(),
            rp_id: "localhost".to_string(),
            rp_origin: "http://localhost:8080".to_string(),
            timeout: 60000,
        }
    }
}

impl WebAuthnConfig {
    pub fn build_webauthn(&self) -> Result<WebAuthn, WebAuthnError> {
        WebAuthn::new(
            &self.rp_name,
            &self.rp_id,
            &[&self.rp_origin],
            self.timeout,
        )
    }
}

// Challenge management
#[derive(Debug, Clone)]
pub struct ChallengeData {
    pub challenge: String,
    pub user_id: Option<String>,
    pub challenge_type: ChallengeType,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub used_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ChallengeType {
    Registration,
    Authentication,
}
```

### 2.2 WebAuthn Service Implementation

```rust
// src/services/webauthn.rs
use crate::config::webauthn::{WebAuthnConfig, ChallengeData, ChallengeType};
use crate::error::WebAuthnError;
use webauthn_rs::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use chrono::{Utc, Duration};
use base64::{Engine as _, engine::general_purpose};

pub struct WebAuthnService {
    webauthn: WebAuthn,
    challenges: Arc<RwLock<HashMap<String, ChallengeData>>>,
    config: WebAuthnConfig,
}

impl WebAuthnService {
    pub fn new(config: WebAuthnConfig) -> Result<Self, WebAuthnError> {
        let webauthn = config.build_webauthn()?;
        
        Ok(Self {
            webauthn,
            challenges: Arc::new(RwLock::new(HashMap::new())),
            config,
        })
    }
    
    // Generate registration challenge
    pub async fn begin_registration(
        &self,
        username: &str,
        display_name: &str,
        attestation: AttestationConveyancePreference,
        authenticator_selection: Option<AuthenticatorSelectionCriteria>,
        extensions: Option<RequestRegistrationExtensions>,
    ) -> Result<CreationChallengeResponse, WebAuthnError> {
        // Generate user handle
        let user_handle = general_purpose::URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes());
        
        let user = User {
            id: user_handle.as_bytes().to_vec(),
            name: username.to_string(),
            display_name: display_name.to_string(),
        };
        
        // Generate challenge
        let (ccr, state) = self.webauthn.generate_challenge_register_options(
            user,
            authenticator_selection.unwrap_or_default(),
            attestation,
            extensions,
        )?;
        
        // Store challenge
        let challenge_data = ChallengeData {
            challenge: state.challenge.clone(),
            user_id: Some(username.to_string()),
            challenge_type: ChallengeType::Registration,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5),
            used_at: None,
        };
        
        let mut challenges = self.challenges.write().await;
        challenges.insert(state.challenge.clone(), challenge_data);
        
        Ok(ccr)
    }
    
    // Complete registration
    pub async fn finish_registration(
        &self,
        username: &str,
        response: RegisterPublicKeyCredential,
        state: &str,
    ) -> Result<AuthenticatorAttestationRawResult, WebAuthnError> {
        // Verify challenge
        self.verify_challenge(state, ChallengeType::Registration, Some(username))
            .await?;
        
        // Parse state
        let registration_state = RegistrationState {
            challenge: state.to_string(),
            user_name: Some(username.to_string()),
            user_display_name: None,
            user_id: None,
            user_verification_policy: UserVerificationPolicy::Preferred,
            request: None,
        };
        
        // Verify registration
        let result = self.webauthn.register_credential(response, &registration_state)?;
        
        // Mark challenge as used
        self.mark_challenge_used(state).await;
        
        Ok(result)
    }
    
    // Generate authentication challenge
    pub async fn begin_authentication(
        &self,
        username: &str,
        user_verification: UserVerificationPolicy,
        credentials: &[PublicKeyCredentialDescriptor],
        extensions: Option<RequestAuthenticationExtensions>,
    ) -> Result<RequestChallengeResponse, WebAuthnError> {
        // Generate challenge
        let (acr, state) = self.webauthn.generate_challenge_authentication_options(
            username,
            user_verification,
            credentials,
            extensions,
        )?;
        
        // Store challenge
        let challenge_data = ChallengeData {
            challenge: state.challenge.clone(),
            user_id: Some(username.to_string()),
            challenge_type: ChallengeType::Authentication,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::minutes(5),
            used_at: None,
        };
        
        let mut challenges = self.challenges.write().await;
        challenges.insert(state.challenge.clone(), challenge_data);
        
        Ok(acr)
    }
    
    // Complete authentication
    pub async fn finish_authentication(
        &self,
        username: &str,
        response: PublicKeyCredential,
        state: &str,
    ) -> Result<AuthenticationResult, WebAuthnError> {
        // Verify challenge
        self.verify_challenge(state, ChallengeType::Authentication, Some(username))
            .await?;
        
        // Parse state
        let authentication_state = AuthenticationState {
            challenge: state.to_string(),
            user_name: Some(username.to_string()),
            user_verification_policy: UserVerificationPolicy::Preferred,
            credentials: vec![],
            request: None,
        };
        
        // Verify authentication
        let result = self.webauthn.authenticate_credential(response, &authentication_state)?;
        
        // Mark challenge as used
        self.mark_challenge_used(state).await;
        
        Ok(result)
    }
    
    // Verify challenge
    async fn verify_challenge(
        &self,
        challenge: &str,
        expected_type: ChallengeType,
        expected_user: Option<&str>,
    ) -> Result<(), WebAuthnError> {
        let challenges = self.challenges.read().await;
        
        match challenges.get(challenge) {
            Some(challenge_data) => {
                // Check type
                if challenge_data.challenge_type != expected_type {
                    return Err(WebAuthnError::InvalidChallengeType);
                }
                
                // Check user
                if let (Some(expected_user), Some(stored_user)) = (expected_user, &challenge_data.user_id) {
                    if expected_user != stored_user {
                        return Err(WebAuthnError::InvalidUser);
                    }
                }
                
                // Check expiration
                if challenge_data.expires_at < Utc::now() {
                    return Err(WebAuthnError::ChallengeExpired);
                }
                
                // Check if already used
                if challenge_data.used_at.is_some() {
                    return Err(WebAuthnError::ChallengeAlreadyUsed);
                }
                
                Ok(())
            }
            None => Err(WebAuthnError::InvalidChallenge),
        }
    }
    
    // Mark challenge as used
    async fn mark_challenge_used(&self, challenge: &str) {
        let mut challenges = self.challenges.write().await;
        if let Some(challenge_data) = challenges.get_mut(challenge) {
            challenge_data.used_at = Some(Utc::now());
        }
    }
    
    // Cleanup expired challenges
    pub async fn cleanup_expired_challenges(&self) {
        let mut challenges = self.challenges.write().await;
        challenges.retain(|_, challenge_data| {
            challenge_data.expires_at > Utc::now() && challenge_data.used_at.is_none()
        });
    }
}
```

## 3. Database Implementation

### 3.1 Database Models

```rust
// src/db/models.rs
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use diesel::prelude::*;

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_active: bool,
}

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::credentials)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub credential_type: String,
    pub public_key: Vec<u8>,
    pub attestation_type: String,
    pub aaguid: Option<Vec<u8>>,
    pub sign_count: i64,
    pub transports: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub is_backup_eligible: bool,
    pub is_backed_up: bool,
    pub is_resident: bool,
    pub user_verification_required: bool,
    pub is_active: bool,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = crate::schema::users)]
pub struct NewUser {
    pub username: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = crate::schema::credentials)]
pub struct NewCredential {
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub credential_type: String,
    pub public_key: Vec<u8>,
    pub attestation_type: String,
    pub aaguid: Option<Vec<u8>>,
    pub sign_count: i64,
    pub transports: Option<serde_json::Value>,
    pub is_backup_eligible: bool,
    pub is_backed_up: bool,
    pub is_resident: bool,
    pub user_verification_required: bool,
}

// Implement validation
impl User {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.username.is_empty() {
            return Err(ValidationError::EmptyUsername);
        }
        
        if !self.username.contains('@') {
            return Err(ValidationError::InvalidEmail);
        }
        
        if self.display_name.is_empty() {
            return Err(ValidationError::EmptyDisplayName);
        }
        
        Ok(())
    }
}

impl Credential {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.credential_id.is_empty() {
            return Err(ValidationError::EmptyCredentialId);
        }
        
        if self.public_key.is_empty() {
            return Err(ValidationError::EmptyPublicKey);
        }
        
        if self.sign_count < 0 {
            return Err(ValidationError::InvalidSignCount);
        }
        
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("Username cannot be empty")]
    EmptyUsername,
    #[error("Invalid email format")]
    InvalidEmail,
    #[error("Display name cannot be empty")]
    EmptyDisplayName,
    #[error("Credential ID cannot be empty")]
    EmptyCredentialId,
    #[error("Public key cannot be empty")]
    EmptyPublicKey,
    #[error("Invalid sign count")]
    InvalidSignCount,
}
```

### 3.2 Database Schema

```sql
-- migrations/2023-01-01-000001_create_users.sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT true
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_active ON users(is_active);

-- migrations/2023-01-01-000002_create_credentials.sql
CREATE TABLE credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA UNIQUE NOT NULL,
    credential_type VARCHAR(50) NOT NULL DEFAULT 'public-key',
    public_key BYTEA NOT NULL,
    attestation_type VARCHAR(50) NOT NULL,
    aaguid BYTEA,
    sign_count BIGINT NOT NULL DEFAULT 0,
    transports JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    is_backup_eligible BOOLEAN DEFAULT false,
    is_backed_up BOOLEAN DEFAULT false,
    is_resident BOOLEAN DEFAULT false,
    user_verification_required BOOLEAN DEFAULT false,
    is_active BOOLEAN DEFAULT true
);

CREATE INDEX idx_credentials_user_id ON credentials(user_id);
CREATE INDEX idx_credentials_credential_id ON credentials(credential_id);
CREATE INDEX idx_credentials_active ON credentials(is_active);

-- migrations/2023-01-01-000003_create_challenges.sql
CREATE TABLE challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    challenge_hash BYTEA NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    challenge_type VARCHAR(20) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    used_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(challenge_hash, challenge_type)
);

CREATE INDEX idx_challenges_hash ON challenges(challenge_hash);
CREATE INDEX idx_challenges_expires ON challenges(expires_at);
CREATE INDEX idx_challenges_type ON challenges(challenge_type);
```

### 3.3 Repository Implementation

```rust
// src/db/repositories.rs
use crate::db::models::{User, Credential, NewUser, NewCredential};
use crate::error::DatabaseError;
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool};
use uuid::Uuid;
use std::sync::Arc;

pub type DbPool = Arc<Pool<ConnectionManager<PgConnection>>>;

pub trait UserRepository: Send + Sync {
    async fn create_user(&self, username: &str, display_name: &str) -> Result<User, DatabaseError>;
    async fn get_user_by_id(&self, user_id: Uuid) -> Result<User, DatabaseError>;
    async fn get_user_by_username(&self, username: &str) -> Result<User, DatabaseError>;
    async fn update_user_display_name(&self, user_id: Uuid, display_name: &str) -> Result<User, DatabaseError>;
    async fn delete_user(&self, user_id: Uuid) -> Result<(), DatabaseError>;
}

pub trait CredentialRepository: Send + Sync {
    async fn store_credential(&self, credential: &NewCredential) -> Result<Credential, DatabaseError>;
    async fn get_credential_by_id(&self, credential_id: Uuid) -> Result<Credential, DatabaseError>;
    async fn get_credential_by_credential_id(&self, credential_id: &[u8]) -> Result<Credential, DatabaseError>;
    async fn get_credentials_by_user_id(&self, user_id: Uuid) -> Result<Vec<Credential>, DatabaseError>;
    async fn update_sign_count(&self, credential_id: Uuid, sign_count: i64) -> Result<(), DatabaseError>;
    async fn update_last_used(&self, credential_id: Uuid) -> Result<(), DatabaseError>;
    async fn delete_credential(&self, credential_id: Uuid) -> Result<(), DatabaseError>;
}

pub struct PostgresUserRepository {
    pool: DbPool,
}

impl PostgresUserRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl UserRepository for PostgresUserRepository {
    async fn create_user(&self, username: &str, display_name: &str) -> Result<User, DatabaseError> {
        use crate::schema::users;
        
        let new_user = NewUser {
            username: username.to_string(),
            display_name: display_name.to_string(),
        };
        
        let mut conn = self.pool.get()?;
        
        let user = diesel::insert_into(users::table)
            .values(&new_user)
            .returning(User::as_returning())
            .get_result(&mut conn)?;
        
        Ok(user)
    }
    
    async fn get_user_by_id(&self, user_id: Uuid) -> Result<User, DatabaseError> {
        use crate::schema::users::dsl::*;
        
        let mut conn = self.pool.get()?;
        
        let user = users
            .filter(id.eq(user_id))
            .first::<User>(&mut conn)?;
        
        Ok(user)
    }
    
    async fn get_user_by_username(&self, username: &str) -> Result<User, DatabaseError> {
        use crate::schema::users::dsl::*;
        
        let mut conn = self.pool.get()?;
        
        let user = users
            .filter(username.eq(username))
            .first::<User>(&mut conn)?;
        
        Ok(user)
    }
    
    async fn update_user_display_name(&self, user_id: Uuid, display_name: &str) -> Result<User, DatabaseError> {
        use crate::schema::users::dsl::*;
        
        let mut conn = self.pool.get()?;
        
        let user = diesel::update(users.filter(id.eq(user_id)))
            .set(display_name.eq(display_name))
            .returning(User::as_returning())
            .get_result(&mut conn)?;
        
        Ok(user)
    }
    
    async fn delete_user(&self, user_id: Uuid) -> Result<(), DatabaseError> {
        use crate::schema::users::dsl::*;
        
        let mut conn = self.pool.get()?;
        
        diesel::delete(users.filter(id.eq(user_id))).execute(&mut conn)?;
        
        Ok(())
    }
}

pub struct PostgresCredentialRepository {
    pool: DbPool,
}

impl PostgresCredentialRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl CredentialRepository for PostgresCredentialRepository {
    async fn store_credential(&self, credential: &NewCredential) -> Result<Credential, DatabaseError> {
        use crate::schema::credentials;
        
        let mut conn = self.pool.get()?;
        
        let stored_credential = diesel::insert_into(credentials::table)
            .values(credential)
            .returning(Credential::as_returning())
            .get_result(&mut conn)?;
        
        Ok(stored_credential)
    }
    
    async fn get_credential_by_id(&self, credential_id: Uuid) -> Result<Credential, DatabaseError> {
        use crate::schema::credentials::dsl::*;
        
        let mut conn = self.pool.get()?;
        
        let credential = credentials
            .filter(id.eq(credential_id))
            .first::<Credential>(&mut conn)?;
        
        Ok(credential)
    }
    
    async fn get_credential_by_credential_id(&self, credential_id_bytes: &[u8]) -> Result<Credential, DatabaseError> {
        use crate::schema::credentials::dsl::*;
        
        let mut conn = self.pool.get()?;
        
        let credential = credentials
            .filter(credential_id.eq(credential_id_bytes))
            .first::<Credential>(&mut conn)?;
        
        Ok(credential)
    }
    
    async fn get_credentials_by_user_id(&self, user_id: Uuid) -> Result<Vec<Credential>, DatabaseError> {
        use crate::schema::credentials::dsl::*;
        
        let mut conn = self.pool.get()?;
        
        let user_credentials = credentials
            .filter(user_id.eq(user_id))
            .filter(is_active.eq(true))
            .load::<Credential>(&mut conn)?;
        
        Ok(user_credentials)
    }
    
    async fn update_sign_count(&self, credential_id: Uuid, new_sign_count: i64) -> Result<(), DatabaseError> {
        use crate::schema::credentials::dsl::*;
        
        let mut conn = self.pool.get()?;
        
        diesel::update(credentials.filter(id.eq(credential_id)))
            .set(sign_count.eq(new_sign_count))
            .execute(&mut conn)?;
        
        Ok(())
    }
    
    async fn update_last_used(&self, credential_id: Uuid) -> Result<(), DatabaseError> {
        use crate::schema::credentials::dsl::*;
        
        let mut conn = self.pool.get()?;
        
        diesel::update(credentials.filter(id.eq(credential_id)))
            .set(last_used_at.eq(diesel::dsl::now))
            .execute(&mut conn)?;
        
        Ok(())
    }
    
    async fn delete_credential(&self, credential_id: Uuid) -> Result<(), DatabaseError> {
        use crate::schema::credentials::dsl::*;
        
        let mut conn = self.pool.get()?;
        
        diesel::delete(credentials.filter(id.eq(credential_id))).execute(&mut conn)?;
        
        Ok(())
    }
}
```

## 4. API Controllers

### 4.1 Registration Controller

```rust
// src/controllers/registration.rs
use crate::services::{WebAuthnService, UserService, CredentialService};
use crate::error::WebAuthnError;
use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use validator::Validate;
use webauthn_rs::prelude::*;

#[derive(Debug, Deserialize, Validate)]
pub struct RegistrationBeginRequest {
    #[validate(email)]
    pub username: String,
    
    #[validate(length(min = 1, max = 255))]
    pub display_name: String,
    
    pub attestation: Option<String>,
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub extensions: Option<RequestRegistrationExtensions>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct RegistrationCompleteRequest {
    #[validate(custom = "validate_credential")]
    pub credential: RegisterPublicKeyCredential,
    
    #[validate(email)]
    pub username: String,
    
    #[validate(custom = "validate_session_data")]
    pub session_data: SessionData,
}

#[derive(Debug, Deserialize, Validate)]
pub struct SessionData {
    pub challenge: String,
    pub timestamp: i64,
}

#[derive(Debug, Serialize)]
pub struct RegistrationBeginResponse {
    pub status: String,
    pub error_message: String,
    #[serde(flatten)]
    pub challenge_response: CreationChallengeResponse,
}

#[derive(Debug, Serialize)]
pub struct RegistrationCompleteResponse {
    pub status: String,
    pub error_message: String,
    pub credential_id: String,
    pub new_user: bool,
}

pub struct RegistrationController {
    webauthn_service: web::Data<WebAuthnService>,
    user_service: web::Data<UserService>,
    credential_service: web::Data<CredentialService>,
}

impl RegistrationController {
    pub fn new(
        webauthn_service: web::Data<WebAuthnService>,
        user_service: web::Data<UserService>,
        credential_service: web::Data<CredentialService>,
    ) -> Self {
        Self {
            webauthn_service,
            user_service,
            credential_service,
        }
    }
    
    // Begin registration
    pub async fn begin_registration(
        &self,
        req: web::Json<RegistrationBeginRequest>,
    ) -> Result<HttpResponse> {
        // Validate request
        if let Err(validation_errors) = req.validate() {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "status": "error",
                "error_message": format!("Validation failed: {:?}", validation_errors)
            })));
        }
        
        // Parse attestation preference
        let attestation = match req.attestation.as_deref() {
            Some("none") => AttestationConveyancePreference::None,
            Some("indirect") => AttestationConveyancePreference::Indirect,
            Some("direct") => AttestationConveyancePreference::Direct,
            Some("enterprise") => AttestationConveyancePreference::Enterprise,
            _ => AttestationConveyancePreference::None,
        };
        
        // Generate registration challenge
        let challenge_response = self
            .webauthn_service
            .begin_registration(
                &req.username,
                &req.display_name,
                attestation,
                req.authenticator_selection.clone(),
                req.extensions.clone(),
            )
            .await
            .map_err(|e| {
                log::error!("Failed to begin registration: {:?}", e);
                WebAuthnError::ChallengeGenerationFailed
            })?;
        
        Ok(HttpResponse::Ok().json(RegistrationBeginResponse {
            status: "ok".to_string(),
            error_message: String::new(),
            challenge_response,
        }))
    }
    
    // Complete registration
    pub async fn complete_registration(
        &self,
        req: web::Json<RegistrationCompleteRequest>,
    ) -> Result<HttpResponse> {
        // Validate request
        if let Err(validation_errors) = req.validate() {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "status": "error",
                "error_message": format!("Validation failed: {:?}", validation_errors)
            })));
        }
        
        // Verify session data
        if let Err(e) = self.verify_session_data(&req.session_data) {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "status": "error",
                "error_message": format!("Invalid session data: {}", e)
            })));
        }
        
        // Get or create user
        let user = match self.user_service.get_user_by_username(&req.username).await {
            Ok(user) => user,
            Err(_) => {
                // Create new user
                self.user_service
                    .create_user(&req.username, &req.username)
                    .await
                    .map_err(|e| {
                        log::error!("Failed to create user: {:?}", e);
                        WebAuthnError::UserCreationFailed
                    })?
            }
        };
        
        // Complete registration
        let attestation_result = self
            .webauthn_service
            .finish_registration(&req.username, req.credential.clone(), &req.session_data.challenge)
            .await
            .map_err(|e| {
                log::error!("Failed to complete registration: {:?}", e);
                e
            })?;
        
        // Store credential
        let credential_id = base64::decode_config(
            &attestation_result.credential_id,
            base64::URL_SAFE_NO_PAD,
        )
        .map_err(|_| WebAuthnError::InvalidCredentialId)?;
        
        let new_credential = NewCredential {
            user_id: user.id,
            credential_id: credential_id.clone(),
            credential_type: "public-key".to_string(),
            public_key: attestation_result.public_key,
            attestation_type: format!("{:?}", attestation_result.attestation_format),
            aaguid: attestation_result.aaguid,
            sign_count: attestation_result.counter as i64,
            transports: attestation_result.transports.map(|t| {
                serde_json::to_value(t).unwrap_or(serde_json::Value::Null)
            }),
            is_backup_eligible: attestation_result.backup_eligible,
            is_backed_up: attestation_result.backup_state,
            is_resident: attestation_result.credential.is_resident(),
            user_verification_required: attestation_result.credential.user_verification_required(),
        };
        
        self.credential_service
            .store_credential(&new_credential)
            .await
            .map_err(|e| {
                log::error!("Failed to store credential: {:?}", e);
                WebAuthnError::CredentialStorageFailed
            })?;
        
        Ok(HttpResponse::Ok().json(RegistrationCompleteResponse {
            status: "ok".to_string(),
            error_message: String::new(),
            credential_id: base64::encode_config(&credential_id, base64::URL_SAFE_NO_PAD),
            new_user: false, // TODO: Track if user was newly created
        }))
    }
    
    fn verify_session_data(&self, session_data: &SessionData) -> Result<(), WebAuthnError> {
        // Verify timestamp is recent (within 5 minutes)
        let now = chrono::Utc::now().timestamp();
        if (now - session_data.timestamp).abs() > 300 {
            return Err(WebAuthnError::SessionExpired);
        }
        
        // Verify challenge format
        base64::decode_config(&session_data.challenge, base64::URL_SAFE_NO_PAD)
            .map_err(|_| WebAuthnError::InvalidChallenge)?;
        
        Ok(())
    }
}

// Validation functions
fn validate_credential(credential: &RegisterPublicKeyCredential) -> Result<(), validator::ValidationError> {
    // Validate credential ID
    if base64::decode_config(&credential.id, base64::URL_SAFE_NO_PAD).is_err() {
        return Err(validator::ValidationError::new("invalid_credential_id"));
    }
    
    // Validate response structure
    if credential.response.attestation_object.is_empty() {
        return Err(validator::ValidationError::new("empty_attestation_object"));
    }
    
    if credential.response.client_data_json.is_empty() {
        return Err(validator::ValidationError::new("empty_client_data_json"));
    }
    
    Ok(())
}

fn validate_session_data(session_data: &SessionData) -> Result<(), validator::ValidationError> {
    // Validate challenge format
    if base64::decode_config(&session_data.challenge, base64::URL_SAFE_NO_PAD).is_err() {
        return Err(validator::ValidationError::new("invalid_challenge"));
    }
    
    // Validate timestamp
    if session_data.timestamp <= 0 {
        return Err(validator::ValidationError::new("invalid_timestamp"));
    }
    
    Ok(())
}
```

### 4.2 Authentication Controller

```rust
// src/controllers/authentication.rs
use crate::services::{WebAuthnService, CredentialService};
use crate::error::WebAuthnError;
use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use validator::Validate;
use webauthn_rs::prelude::*;

#[derive(Debug, Deserialize, Validate)]
pub struct AuthenticationBeginRequest {
    #[validate(email)]
    pub username: String,
    pub user_verification: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct AuthenticationCompleteRequest {
    #[validate(custom = "validate_assertion")]
    pub credential: PublicKeyCredential,
    
    #[validate(email)]
    pub username: String,
    
    #[validate(custom = "validate_session_data")]
    pub session_data: SessionData,
}

#[derive(Debug, Serialize)]
pub struct AuthenticationBeginResponse {
    pub status: String,
    pub error_message: String,
    #[serde(flatten)]
    pub challenge_response: RequestChallengeResponse,
}

#[derive(Debug, Serialize)]
pub struct AuthenticationCompleteResponse {
    pub status: String,
    pub error_message: String,
    pub credential_id: String,
    pub user: UserInfo,
}

#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: String,
    pub name: String,
    pub display_name: String,
}

pub struct AuthenticationController {
    webauthn_service: web::Data<WebAuthnService>,
    credential_service: web::Data<CredentialService>,
}

impl AuthenticationController {
    pub fn new(
        webauthn_service: web::Data<WebAuthnService>,
        credential_service: web::Data<CredentialService>,
    ) -> Self {
        Self {
            webauthn_service,
            credential_service,
        }
    }
    
    // Begin authentication
    pub async fn begin_authentication(
        &self,
        req: web::Json<AuthenticationBeginRequest>,
    ) -> Result<HttpResponse> {
        // Validate request
        if let Err(validation_errors) = req.validate() {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "status": "error",
                "error_message": format!("Validation failed: {:?}", validation_errors)
            })));
        }
        
        // Parse user verification policy
        let user_verification = match req.user_verification.as_deref() {
            Some("required") => UserVerificationPolicy::Required,
            Some("preferred") => UserVerificationPolicy::Preferred,
            Some("discouraged") => UserVerificationPolicy::Discouraged,
            _ => UserVerificationPolicy::Preferred,
        };
        
        // Get user's credentials
        let credentials = self
            .credential_service
            .get_credentials_by_username(&req.username)
            .await
            .map_err(|e| {
                log::error!("Failed to get credentials: {:?}", e);
                WebAuthnError::CredentialNotFound
            })?;
        
        // Convert to PublicKeyCredentialDescriptor
        let credential_descriptors: Vec<PublicKeyCredentialDescriptor> = credentials
            .into_iter()
            .map(|cred| PublicKeyCredentialDescriptor {
                id: base64::encode_config(&cred.credential_id, base64::URL_SAFE_NO_PAD),
                transports: cred.transports
                    .and_then(|t| serde_json::from_value(t).ok())
                    .unwrap_or_default(),
                type_: "public-key".to_string(),
            })
            .collect();
        
        // Generate authentication challenge
        let challenge_response = self
            .webauthn_service
            .begin_authentication(
                &req.username,
                user_verification,
                &credential_descriptors,
                None,
            )
            .await
            .map_err(|e| {
                log::error!("Failed to begin authentication: {:?}", e);
                WebAuthnError::ChallengeGenerationFailed
            })?;
        
        Ok(HttpResponse::Ok().json(AuthenticationBeginResponse {
            status: "ok".to_string(),
            error_message: String::new(),
            challenge_response,
        }))
    }
    
    // Complete authentication
    pub async fn complete_authentication(
        &self,
        req: web::Json<AuthenticationCompleteRequest>,
    ) -> Result<HttpResponse> {
        // Validate request
        if let Err(validation_errors) = req.validate() {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "status": "error",
                "error_message": format!("Validation failed: {:?}", validation_errors)
            })));
        }
        
        // Verify session data
        if let Err(e) = self.verify_session_data(&req.session_data) {
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "status": "error",
                "error_message": format!("Invalid session data: {}", e)
            })));
        }
        
        // Get credential
        let credential_id = base64::decode_config(
            &req.credential.id,
            base64::URL_SAFE_NO_PAD,
        )
        .map_err(|_| WebAuthnError::InvalidCredentialId)?;
        
        let mut stored_credential = self
            .credential_service
            .get_credential_by_credential_id(&credential_id)
            .await
            .map_err(|e| {
                log::error!("Failed to get credential: {:?}", e);
                WebAuthnError::CredentialNotFound
            })?;
        
        // Complete authentication
        let auth_result = self
            .webauthn_service
            .finish_authentication(&req.username, req.credential.clone(), &req.session_data.challenge)
            .await
            .map_err(|e| {
                log::error!("Failed to complete authentication: {:?}", e);
                e
            })?;
        
        // Verify counter
        if auth_result.counter <= stored_credential.sign_count as u32 {
            return Err(WebAuthnError::CounterReplay);
        }
        
        // Update credential
        self.credential_service
            .update_sign_count(stored_credential.id, auth_result.counter as i64)
            .await
            .map_err(|e| {
                log::error!("Failed to update sign count: {:?}", e);
                WebAuthnError::CredentialUpdateFailed
            })?;
        
        self.credential_service
            .update_last_used(stored_credential.id)
            .await
            .map_err(|e| {
                log::error!("Failed to update last used: {:?}", e);
                WebAuthnError::CredentialUpdateFailed
            })?;
        
        // Get user info
        let user = self
            .credential_service
            .get_user_by_credential_id(stored_credential.id)
            .await
            .map_err(|e| {
                log::error!("Failed to get user: {:?}", e);
                WebAuthnError::UserNotFound
            })?;
        
        Ok(HttpResponse::Ok().json(AuthenticationCompleteResponse {
            status: "ok".to_string(),
            error_message: String::new(),
            credential_id: base64::encode_config(&credential_id, base64::URL_SAFE_NO_PAD),
            user: UserInfo {
                id: base64::encode_config(user.id.as_bytes(), base64::URL_SAFE_NO_PAD),
                name: user.username,
                display_name: user.display_name,
            },
        }))
    }
    
    fn verify_session_data(&self, session_data: &SessionData) -> Result<(), WebAuthnError> {
        // Verify timestamp is recent (within 5 minutes)
        let now = chrono::Utc::now().timestamp();
        if (now - session_data.timestamp).abs() > 300 {
            return Err(WebAuthnError::SessionExpired);
        }
        
        // Verify challenge format
        base64::decode_config(&session_data.challenge, base64::URL_SAFE_NO_PAD)
            .map_err(|_| WebAuthnError::InvalidChallenge)?;
        
        Ok(())
    }
}

// Validation functions
fn validate_assertion(assertion: &PublicKeyCredential) -> Result<(), validator::ValidationError> {
    // Validate credential ID
    if base64::decode_config(&assertion.id, base64::URL_SAFE_NO_PAD).is_err() {
        return Err(validator::ValidationError::new("invalid_credential_id"));
    }
    
    // Validate response structure
    if assertion.response.authenticator_data.is_empty() {
        return Err(validator::ValidationError::new("empty_authenticator_data"));
    }
    
    if assertion.response.client_data_json.is_empty() {
        return Err(validator::ValidationError::new("empty_client_data_json"));
    }
    
    if assertion.response.signature.is_empty() {
        return Err(validator::ValidationError::new("empty_signature"));
    }
    
    Ok(())
}
```

## 5. Error Handling

### 5.1 Error Types

```rust
// src/error/types.rs
use thiserror::Error;
use actix_web::{HttpResponse, ResponseError};
use diesel::result::Error as DieselError;

#[derive(Debug, Error)]
pub enum WebAuthnError {
    #[error("Invalid challenge")]
    InvalidChallenge,
    
    #[error("Challenge expired")]
    ChallengeExpired,
    
    #[error("Challenge already used")]
    ChallengeAlreadyUsed,
    
    #[error("Invalid challenge type")]
    InvalidChallengeType,
    
    #[error("Invalid user")]
    InvalidUser,
    
    #[error("User not found")]
    UserNotFound,
    
    #[error("User creation failed")]
    UserCreationFailed,
    
    #[error("Credential not found")]
    CredentialNotFound,
    
    #[error("Invalid credential ID")]
    InvalidCredentialId,
    
    #[error("Credential storage failed")]
    CredentialStorageFailed,
    
    #[error("Credential update failed")]
    CredentialUpdateFailed,
    
    #[error("Counter replay detected")]
    CounterReplay,
    
    #[error("Challenge generation failed")]
    ChallengeGenerationFailed,
    
    #[error("Session expired")]
    SessionExpired,
    
    #[error("Invalid origin")]
    InvalidOrigin,
    
    #[error("Invalid RP ID")]
    InvalidRpId,
    
    #[error("Attestation verification failed")]
    AttestationVerificationFailed,
    
    #[error("Authentication verification failed")]
    AuthenticationVerificationFailed,
    
    #[error("Database error: {0}")]
    Database(#[from] DatabaseError),
    
    #[error("Validation error: {0}")]
    Validation(String),
    
    #[error("Internal server error")]
    InternalServerError,
}

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("Connection error: {0}")]
    Connection(#[from] diesel::result::ConnectionError),
    
    #[error("Query error: {0}")]
    Query(#[from] DieselError),
    
    #[error("Pool error: {0}")]
    Pool(#[from] diesel::r2d2::Error),
    
    #[error("Not found")]
    NotFound,
    
    #[error("Duplicate entry")]
    Duplicate,
    
    #[error("Invalid data: {0}")]
    InvalidData(String),
}

impl ResponseError for WebAuthnError {
    fn error_response(&self) -> HttpResponse {
        match self {
            WebAuthnError::InvalidChallenge
            | WebAuthnError::ChallengeExpired
            | WebAuthnError::ChallengeAlreadyUsed
            | WebAuthnError::InvalidChallengeType => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "status": "error",
                    "error_message": self.to_string()
                }))
            }
            
            WebAuthnError::UserNotFound
            | WebAuthnError::CredentialNotFound => {
                HttpResponse::NotFound().json(serde_json::json!({
                    "status": "error",
                    "error_message": self.to_string()
                }))
            }
            
            WebAuthnError::InvalidOrigin
            | WebAuthnError::InvalidRpId
            | WebAuthnError::CounterReplay
            | WebAuthnError::AttestationVerificationFailed
            | WebAuthnError::AuthenticationVerificationFailed => {
                HttpResponse::Forbidden().json(serde_json::json!({
                    "status": "error",
                    "error_message": self.to_string()
                }))
            }
            
            WebAuthnError::Validation(msg) => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "status": "error",
                    "error_message": msg
                }))
            }
            
            _ => {
                log::error!("Internal server error: {:?}", self);
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "status": "error",
                    "error_message": "Internal server error"
                }))
            }
        }
    }
}
```

## 6. Security Middleware

### 6.1 Rate Limiting

```rust
// src/middleware/rate_limit.rs
use actix_web::{dev::ServiceRequest, dev::ServiceResponse, Error, Result};
use actix_web::dev::{forward_ready, Service, Transform};
use std::future::{ready, Ready};
use std::sync::Arc;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

pub struct RateLimiter {
    max_requests: usize,
    window: Duration,
    clients: Arc<RwLock<HashMap<String, ClientInfo>>>,
}

#[derive(Debug, Clone)]
struct ClientInfo {
    count: usize,
    window_start: Instant,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            max_requests,
            window,
            clients: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    async fn is_allowed(&self, client_ip: &str) -> bool {
        let mut clients = self.clients.write().await;
        let now = Instant::now();
        
        let client_info = clients.entry(client_ip.to_string()).or_insert_with(|| ClientInfo {
            count: 0,
            window_start: now,
        });
        
        // Reset window if expired
        if now.duration_since(client_info.window_start) > self.window {
            client_info.count = 0;
            client_info.window_start = now;
        }
        
        // Check limit
        if client_info.count >= self.max_requests {
            false
        } else {
            client_info.count += 1;
            true
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for RateLimiter
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = RateLimitMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;
    
    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RateLimitMiddleware {
            service,
            rate_limiter: self.clone(),
        }))
    }
}

pub struct RateLimitMiddleware<S> {
    service: S,
    rate_limiter: RateLimiter,
}

impl<S, B> Service<ServiceRequest> for RateLimitMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>>>>;
    
    forward_ready!(service);
    
    fn call(&self, req: ServiceRequest) -> Self::Future {
        let client_ip = req
            .connection_info()
            .peer_addr()
            .map(|addr| addr.ip().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        
        let rate_limiter = self.rate_limiter.clone();
        
        Box::pin(async move {
            if !rate_limiter.is_allowed(&client_ip).await {
                return Ok(req.into_response(
                    actix_web::HttpResponse::TooManyRequests().json(serde_json::json!({
                        "status": "error",
                        "error_message": "Rate limit exceeded"
                    }))
                    .into_body()
                    .into_response(),
                ));
            }
            
            self.service.call(req).await
        })
    }
}
```

### 6.2 Security Headers

```rust
// src/middleware/security.rs
use actix_web::{dev::ServiceRequest, dev::ServiceResponse, Error, Result};
use actix_web::dev::{forward_ready, Service, Transform};
use std::future::{ready, Ready};

pub struct SecurityHeaders;

impl<S, B> Transform<S, ServiceRequest> for SecurityHeaders
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = SecurityHeadersMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;
    
    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SecurityHeadersMiddleware { service }))
    }
}

pub struct SecurityHeadersMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for SecurityHeadersMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>>>>;
    
    forward_ready!(service);
    
    fn call(&self, req: ServiceRequest) -> Self::Future {
        Box::pin(async move {
            let res = self.service.call(req).await?;
            
            Ok(res.map_response(|mut resp| {
                // Add security headers
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
                    "Strict-Transport-Security",
                    "max-age=31536000; includeSubDomains".parse().unwrap(),
                );
                resp.headers_mut().insert(
                    "Content-Security-Policy",
                    "default-src 'self'".parse().unwrap(),
                );
                resp.headers_mut().insert(
                    "Referrer-Policy",
                    "strict-origin-when-cross-origin".parse().unwrap(),
                );
                
                resp
            }))
        })
    }
}
```

## 7. Main Application Setup

### 7.1 Application Configuration

```rust
// src/main.rs
use actix_web::{App, HttpServer, middleware::Logger};
use actix_cors::Cors;
use std::env;

mod config;
mod controllers;
mod services;
mod db;
mod middleware;
mod routes;
mod error;
mod utils;

use config::{AppConfig, WebAuthnConfig};
use services::{WebAuthnService, UserService, CredentialService};
use db::repositories::{PostgresUserRepository, PostgresCredentialRepository};
use middleware::{RateLimiter, SecurityHeaders};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load environment variables
    dotenv::dotenv().ok();
    
    // Initialize logging
    env_logger::init();
    
    // Load configuration
    let config = AppConfig::from_env().expect("Failed to load configuration");
    
    // Initialize database
    let db_pool = db::create_pool(&config.database).await
        .expect("Failed to create database pool");
    
    // Run migrations
    db::run_migrations(&db_pool).await
        .expect("Failed to run migrations");
    
    // Initialize repositories
    let user_repo = PostgresUserRepository::new(db_pool.clone());
    let credential_repo = PostgresCredentialRepository::new(db_pool);
    
    // Initialize services
    let webauthn_service = WebAuthnService::new(config.webauthn.clone())
        .expect("Failed to initialize WebAuthn service");
    let user_service = UserService::new(user_repo);
    let credential_service = CredentialService::new(credential_repo);
    
    // Start cleanup task
    let webauthn_service_cleanup = webauthn_service.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            webauthn_service_cleanup.cleanup_expired_challenges().await;
        }
    });
    
    // Create HTTP server
    let bind_addr = format!("{}:{}", config.server.host, config.server.port);
    
    log::info!("Starting server on {}", bind_addr);
    
    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin(&config.webauthn.rp_origin)
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
            .allowed_headers(vec!["Authorization", "Content-Type"])
            .supports_credentials()
            .max_age(3600);
        
        App::new()
            .wrap(cors)
            .wrap(SecurityHeaders)
            .wrap(RateLimiter::new(100, std::time::Duration::from_secs(60)))
            .wrap(Logger::default())
            .app_data(web::Data::new(webauthn_service.clone()))
            .app_data(web::Data::new(user_service.clone()))
            .app_data(web::Data::new(credential_service.clone()))
            .configure(routes::configure_routes)
    })
    .bind(&bind_addr)?
    .run()
    .await
}
```

### 7.2 Route Configuration

```rust
// src/routes/mod.rs
use actix_web::web;
use crate::controllers::{RegistrationController, AuthenticationController};

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/webauthn")
            .route("/register/begin", web::post().to(registration_begin))
            .route("/register/complete", web::post().to(registration_complete))
            .route("/authenticate/begin", web::post().to(authentication_begin))
            .route("/authenticate/complete", web::post().to(authentication_complete))
    )
    .route("/health", web::get().to(health_check));
}

// Route handlers
async fn registration_begin(
    req: web::Json<controllers::RegistrationBeginRequest>,
    webauthn_service: web::Data<services::WebAuthnService>,
    user_service: web::Data<services::UserService>,
    credential_service: web::Data<services::CredentialService>,
) -> actix_web::Result<actix_web::HttpResponse> {
    let controller = RegistrationController::new(webauthn_service, user_service, credential_service);
    controller.begin_registration(req).await
}

async fn registration_complete(
    req: web::Json<controllers::RegistrationCompleteRequest>,
    webauthn_service: web::Data<services::WebAuthnService>,
    user_service: web::Data<services::UserService>,
    credential_service: web::Data<services::CredentialService>,
) -> actix_web::Result<actix_web::HttpResponse> {
    let controller = RegistrationController::new(webauthn_service, user_service, credential_service);
    controller.complete_registration(req).await
}

async fn authentication_begin(
    req: web::Json<controllers::AuthenticationBeginRequest>,
    webauthn_service: web::Data<services::WebAuthnService>,
    credential_service: web::Data<services::CredentialService>,
) -> actix_web::Result<actix_web::HttpResponse> {
    let controller = AuthenticationController::new(webauthn_service, credential_service);
    controller.begin_authentication(req).await
}

async fn authentication_complete(
    req: web::Json<controllers::AuthenticationCompleteRequest>,
    webauthn_service: web::Data<services::WebAuthnService>,
    credential_service: web::Data<services::CredentialService>,
) -> actix_web::Result<actix_web::HttpResponse> {
    let controller = AuthenticationController::new(webauthn_service, credential_service);
    controller.complete_authentication(req).await
}

async fn health_check() -> actix_web::Result<actix_web::HttpResponse> {
    Ok(actix_web::HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now()
    })))
}
```

This implementation guide provides a comprehensive foundation for building a secure, FIDO2-compliant WebAuthn server with proper error handling, security middleware, and extensive testing capabilities. The code follows Rust best practices and implements all the security requirements outlined in the technical specification.