# FIDO2/WebAuthn Server - Implementation Guide

## Overview

This implementation guide provides detailed Rust code examples and architectural patterns for building a FIDO2/WebAuthn Relying Party Server using the webauthn-rs library. The guide follows the technical specifications and focuses on security-first, test-driven development.

## 1. Project Setup and Dependencies

### 1.1 Cargo.toml Configuration

```toml
[package]
name = "fido-server"
version = "0.1.0"
edition = "2021"
authors = ["FIDO Server Team"]

[dependencies]
# Web Framework
actix-web = "4.9"
actix-cors = "0.7"
actix-rt = "2.10"
actix-web-httpauth = "0.8"

# FIDO/WebAuthn
webauthn-rs = "0.5"
webauthn-rs-proto = "0.5"

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# Database
diesel = { version = "2.1", features = ["postgres", "r2d2", "chrono", "uuid"] }
diesel_migrations = "2.1"
r2d2 = "0.8"

# Async
tokio = { version = "1.40", features = ["full"] }
futures = "0.3"

# Cryptography
base64 = "0.22"
uuid = { version = "1.10", features = ["v4", "serde"] }
rand = "0.8"
sha2 = "0.10"

# Configuration
config = "0.14"
dotenv = "0.15"

# Logging
log = "0.4"
env_logger = "0.11"

# Error Handling
thiserror = "1.0"
anyhow = "1.0"

# Time
chrono = { version = "0.4", features = ["serde"] }

# Security
ring = "0.17"
subtle = "2.5"

[dev-dependencies]
actix-test = "0.1"
mockall = "0.13"
tokio-test = "0.4"
tempfile = "3.8"
```

### 1.2 Environment Configuration

```env
# .env
DATABASE_URL=postgres://fido_user:fido_pass@localhost/fido_db
SERVER_HOST=0.0.0.0
SERVER_PORT=8080
RP_ID=example.com
RP_NAME=FIDO Server
ALLOWED_ORIGINS=https://example.com,https://app.example.com
JWT_SECRET=your-super-secret-jwt-key
LOG_LEVEL=info
RATE_LIMIT_PER_MINUTE=100
```

## 2. Core Data Structures

### 2.1 WebAuthn Configuration

```rust
// src/config/webauthn.rs
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnConfig {
    pub rp_id: String,
    pub rp_name: String,
    pub rp_origin: String,
    pub allowed_origins: Vec<String>,
}

impl WebAuthnConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            rp_id: std::env::var("RP_ID")?,
            rp_name: std::env::var("RP_NAME")?,
            rp_origin: std::env::var("ALLOWED_ORIGINS")
                .map(|origins| origins.split(',').next().unwrap_or("").to_string())?,
            allowed_origins: std::env::var("ALLOWED_ORIGINS")
                .map(|origins| origins.split(',').map(String::from).collect())?,
        })
    }

    pub fn to_webauthn(&self) -> Result<Webauthn, WebauthnError> {
        Webauthn::new(
            &self.rp_id,
            &self.rp_name,
            &self.rp_origin,
            &self.allowed_origins,
        )
    }
}
```

### 2.2 Database Models

```rust
// src/db/models.rs
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::schema::{users, credentials, challenges};

#[derive(Debug, Clone, Queryable, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Queryable, Serialize, Deserialize)]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub attestation_type: String,
    pub aaguid: Vec<u8>,
    pub sign_count: i64,
    pub user_verification: bool,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub transports: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Queryable, Serialize, Deserialize)]
pub struct Challenge {
    pub id: Uuid,
    pub challenge: Vec<u8>,
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = users)]
pub struct NewUser {
    pub username: String,
    pub display_name: String,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = credentials)]
pub struct NewCredential {
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub attestation_type: String,
    pub aaguid: Vec<u8>,
    pub sign_count: i64,
    pub user_verification: bool,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub transports: Vec<String>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = challenges)]
pub struct NewChallenge {
    pub challenge: Vec<u8>,
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
}
```

### 2.3 API Request/Response Types

```rust
// src/controllers/types.rs
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::*;

#[derive(Debug, Deserialize)]
pub struct RegistrationChallengeRequest {
    pub username: String,
    pub display_name: String,
    #[serde(default = "default_user_verification")]
    pub user_verification: UserVerificationPolicy,
    #[serde(default)]
    pub attestation: AttestationConveyancePreference,
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub extensions: Option<RegistrationExtensionInputs>,
}

fn default_user_verification() -> UserVerificationPolicy {
    UserVerificationPolicy::Preferred
}

#[derive(Debug, Serialize)]
pub struct RegistrationChallengeResponse {
    pub challenge: String,
    pub rp: PublicKeyCredentialRpEntity,
    pub user: PublicKeyCredentialUserEntity,
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    pub timeout: u32,
    pub attestation: AttestationConveyancePreference,
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub extensions: Option<RegistrationExtensionInputs>,
}

#[derive(Debug, Deserialize)]
pub struct RegistrationVerificationRequest {
    pub credential: PublicKeyCredential<RegistrationCredential>,
    pub client_extension_results: Option<RegistrationExtensionOutputs>,
}

#[derive(Debug, Serialize)]
pub struct RegistrationVerificationResponse {
    pub credential_id: String,
    pub counter: u64,
    pub aaguid: String,
    pub attestation_type: String,
    pub user_verified: bool,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub transports: Vec<AuthenticatorTransport>,
    pub extensions: Option<RegistrationExtensionOutputs>,
}

#[derive(Debug, Deserialize)]
pub struct AuthenticationChallengeRequest {
    pub username: String,
    #[serde(default = "default_user_verification")]
    pub user_verification: UserVerificationPolicy,
    pub allow_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
    pub extensions: Option<AuthenticationExtensionInputs>,
}

#[derive(Debug, Serialize)]
pub struct AuthenticationChallengeResponse {
    pub challenge: String,
    pub allow_credentials: Vec<PublicKeyCredentialDescriptor>,
    pub user_verification: UserVerificationPolicy,
    pub timeout: u32,
    pub rp_id: String,
    pub extensions: Option<AuthenticationExtensionInputs>,
}

#[derive(Debug, Deserialize)]
pub struct AuthenticationVerificationRequest {
    pub credential: PublicKeyCredential<AssertionCredential>,
    pub client_extension_results: Option<AuthenticationExtensionOutputs>,
}

#[derive(Debug, Serialize)]
pub struct AuthenticationVerificationResponse {
    pub credential_id: String,
    pub counter: u64,
    pub user_verified: bool,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub extensions: Option<AuthenticationExtensionOutputs>,
}

#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub status: String,
    pub data: Option<T>,
    pub error: Option<ApiError>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
    pub details: Option<String>,
    pub request_id: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            status: "ok".to_string(),
            data: Some(data),
            error: None,
            timestamp: chrono::Utc::now(),
        }
    }

    pub fn error(code: &str, message: &str) -> Self {
        Self {
            status: "error".to_string(),
            data: None,
            error: Some(ApiError {
                code: code.to_string(),
                message: message.to_string(),
                details: None,
                request_id: None,
            }),
            timestamp: chrono::Utc::now(),
        }
    }
}
```

## 3. WebAuthn Service Implementation

### 3.1 Core WebAuthn Service

```rust
// src/services/webauthn.rs
use crate::config::WebAuthnConfig;
use crate::db::models::{Challenge, Credential, User};
use crate::db::repositories::{ChallengeRepository, CredentialRepository, UserRepository};
use crate::error::{WebAuthnError, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::HashMap;
use uuid::Uuid;
use webauthn_rs::prelude::*;

pub struct WebAuthnService {
    webauthn: Webauthn,
    challenge_repo: ChallengeRepository,
    credential_repo: CredentialRepository,
    user_repo: UserRepository,
    rng: SystemRandom,
}

impl WebAuthnService {
    pub fn new(
        config: &WebAuthnConfig,
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
            rng: SystemRandom::new(),
        })
    }

    pub async fn generate_registration_challenge(
        &self,
        username: &str,
        display_name: &str,
        user_verification: UserVerificationPolicy,
        attestation: AttestationConveyancePreference,
        authenticator_selection: Option<AuthenticatorSelectionCriteria>,
        extensions: Option<RegistrationExtensionInputs>,
    ) -> Result<(String, RegistrationChallengeResponse)> {
        // Check if user already exists
        if let Some(_) = self.user_repo.find_by_username(username).await? {
            return Err(WebAuthnError::UserAlreadyExists);
        }

        // Generate user ID
        let user_id = Uuid::new_v4().as_bytes().to_vec();

        // Create user entity
        let user = PublicKeyCredentialUserEntity {
            id: user_id.clone(),
            name: username.to_string(),
            display_name: display_name.to_string(),
        };

        // Generate challenge
        let challenge = self.generate_secure_challenge()?;
        let challenge_b64 = URL_SAFE_NO_PAD.encode(&challenge);

        // Store challenge
        let challenge_record = NewChallenge {
            challenge: challenge.clone(),
            user_id: None, // Will be set after successful registration
            challenge_type: "registration".to_string(),
            expires_at: Utc::now() + Duration::minutes(5),
        };
        self.challenge_repo.store(&challenge_record).await?;

        // Create registration challenge
        let (ccr, reg_state) = self.webauthn.start_registration(
            user,
            user_verification,
            attestation,
            authenticator_selection,
            extensions,
        )?;

        // Store registration state (in production, use Redis or similar)
        let state_key = format!("reg_state_{}", challenge_b64);
        // store_state(&state_key, &reg_state).await?;

        let response = RegistrationChallengeResponse {
            challenge: challenge_b64,
            rp: ccr.rp,
            user: ccr.user,
            pub_key_cred_params: ccr.pub_key_cred_params,
            timeout: ccr.timeout,
            attestation: ccr.attestation,
            authenticator_selection: ccr.authenticator_selection,
            extensions: ccr.extensions,
        };

        Ok((challenge_b64, response))
    }

    pub async fn verify_registration(
        &self,
        credential: PublicKeyCredential<RegistrationCredential>,
        client_extension_results: Option<RegistrationExtensionOutputs>,
        challenge: &str,
    ) -> Result<RegistrationVerificationResponse> {
        // Validate challenge
        let challenge_data = URL_SAFE_NO_PAD.decode(challenge)
            .map_err(|_| WebAuthnError::InvalidChallenge)?;
        
        let stored_challenge = self.challenge_repo
            .find_by_challenge(&challenge_data)
            .await?
            .ok_or(WebAuthnError::InvalidChallenge)?;

        if stored_challenge.expires_at < Utc::now() {
            return Err(WebAuthnError::ChallengeExpired);
        }

        // Retrieve registration state
        let state_key = format!("reg_state_{}", challenge);
        // let reg_state = retrieve_state::<RegistrationState>(&state_key).await?;
        // delete_state(&state_key).await?;

        // For this example, we'll create a dummy state
        let reg_state = create_dummy_registration_state(&stored_challenge)?;

        // Verify attestation
        let auth_result = self.webauthn.finish_registration(&reg_state, &credential)?;

        // Create user
        let user_id = Uuid::new_v4();
        let new_user = NewUser {
            username: auth_result.credential_data.user.name.clone(),
            display_name: auth_result.credential_data.user.display_name.clone(),
        };
        let user = self.user_repo.create(new_user).await?;

        // Store credential
        let new_credential = NewCredential {
            user_id: user.id,
            credential_id: auth_result.credential_data.cred_id.clone(),
            public_key: auth_result.credential_data.public_key.clone(),
            attestation_type: format!("{:?}", auth_result.attestation_type),
            aaguid: auth_result.credential_data.aaguid.clone(),
            sign_count: auth_result.counter as i64,
            user_verification: auth_result.user_verified,
            backup_eligible: auth_result.backup_eligible,
            backup_state: auth_result.backup_state,
            transports: auth_result.transports.iter().map(|t| format!("{:?}", t)).collect(),
        };
        self.credential_repo.store(new_credential).await?;

        // Clean up challenge
        self.challenge_repo.delete(stored_challenge.id).await?;

        Ok(RegistrationVerificationResponse {
            credential_id: URL_SAFE_NO_PAD.encode(&auth_result.credential_data.cred_id),
            counter: auth_result.counter,
            aaguid: URL_SAFE_NO_PAD.encode(&auth_result.credential_data.aaguid),
            attestation_type: format!("{:?}", auth_result.attestation_type),
            user_verified: auth_result.user_verified,
            backup_eligible: auth_result.backup_eligible,
            backup_state: auth_result.backup_state,
            transports: auth_result.transports,
            extensions: client_extension_results,
        })
    }

    pub async fn generate_authentication_challenge(
        &self,
        username: &str,
        user_verification: UserVerificationPolicy,
        allow_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
        extensions: Option<AuthenticationExtensionInputs>,
    ) -> Result<(String, AuthenticationChallengeResponse)> {
        // Find user
        let user = self.user_repo.find_by_username(username)
            .await?
            .ok_or(WebAuthnError::UserNotFound)?;

        // Get user credentials
        let credentials = self.credential_repo.find_by_user_id(user.id).await?;
        if credentials.is_empty() {
            return Err(WebAuthnError::NoCredentials);
        }

        // Convert to credential descriptors
        let allow_creds = if let Some(creds) = allow_credentials {
            creds
        } else {
            credentials.into_iter().map(|cred| {
                PublicKeyCredentialDescriptor {
                    type_: PublicKeyCredentialType::PublicKey,
                    id: cred.credential_id,
                    transports: Some(cred.transports.into_iter()
                        .filter_map(|t| parse_transport(&t))
                        .collect()),
                }
            }).collect()
        };

        // Generate challenge
        let challenge = self.generate_secure_challenge()?;
        let challenge_b64 = URL_SAFE_NO_PAD.encode(&challenge);

        // Store challenge
        let challenge_record = NewChallenge {
            challenge: challenge.clone(),
            user_id: Some(user.id),
            challenge_type: "authentication".to_string(),
            expires_at: Utc::now() + Duration::minutes(5),
        };
        self.challenge_repo.store(&challenge_record).await?;

        // Create authentication challenge
        let (acr, auth_state) = self.webauthn.start_authentication(
            allow_creds,
            user_verification,
            extensions,
        )?;

        // Store authentication state
        let state_key = format!("auth_state_{}", challenge_b64);
        // store_state(&state_key, &auth_state).await?;

        let response = AuthenticationChallengeResponse {
            challenge: challenge_b64,
            allow_credentials: acr.allow_credentials,
            user_verification: acr.user_verification,
            timeout: acr.timeout,
            rp_id: acr.rp_id,
            extensions: acr.extensions,
        };

        Ok((challenge_b64, response))
    }

    pub async fn verify_authentication(
        &self,
        credential: PublicKeyCredential<AssertionCredential>,
        client_extension_results: Option<AuthenticationExtensionOutputs>,
        challenge: &str,
    ) -> Result<AuthenticationVerificationResponse> {
        // Validate challenge
        let challenge_data = URL_SAFE_NO_PAD.decode(challenge)
            .map_err(|_| WebAuthnError::InvalidChallenge)?;
        
        let stored_challenge = self.challenge_repo
            .find_by_challenge(&challenge_data)
            .await?
            .ok_or(WebAuthnError::InvalidChallenge)?;

        if stored_challenge.expires_at < Utc::now() {
            return Err(WebAuthnError::ChallengeExpired);
        }

        // Find credential
        let cred_id = &credential.raw_id;
        let stored_credential = self.credential_repo
            .find_by_credential_id(cred_id)
            .await?
            .ok_or(WebAuthnError::CredentialNotFound)?;

        // Retrieve authentication state
        let state_key = format!("auth_state_{}", challenge);
        // let auth_state = retrieve_state::<AuthenticationState>(&state_key).await?;
        // delete_state(&state_key).await?;

        // For this example, we'll create a dummy state
        let auth_state = create_dummy_authentication_state(&stored_credential)?;

        // Verify assertion
        let auth_result = self.webauthn.finish_authentication(&auth_state, &credential)?;

        // Check for replay attack
        if auth_result.counter <= stored_credential.sign_count as u64 {
            return Err(WebAuthnError::ReplayAttack);
        }

        // Update credential
        self.credential_repo.update_counter(
            stored_credential.id,
            auth_result.counter as i64,
        ).await?;

        // Clean up challenge
        self.challenge_repo.delete(stored_challenge.id).await?;

        Ok(AuthenticationVerificationResponse {
            credential_id: URL_SAFE_NO_PAD.encode(&cred_id),
            counter: auth_result.counter,
            user_verified: auth_result.user_verified,
            backup_eligible: auth_result.backup_eligible,
            backup_state: auth_result.backup_state,
            extensions: client_extension_results,
        })
    }

    fn generate_secure_challenge(&self) -> Result<Vec<u8>> {
        let mut challenge = vec![0u8; 32];
        self.rng.fill(&mut challenge)
            .map_err(|_| WebAuthnError::RandomGenerationError)?;
        Ok(challenge)
    }
}

// Helper functions
fn parse_transport(transport: &str) -> Option<AuthenticatorTransport> {
    match transport {
        "usb" => Some(AuthenticatorTransport::Usb),
        "nfc" => Some(AuthenticatorTransport::Nfc),
        "ble" => Some(AuthenticatorTransport::Ble),
        "internal" => Some(AuthenticatorTransport::Internal),
        _ => None,
    }
}

fn create_dummy_registration_state(challenge: &Challenge) -> Result<RegistrationState> {
    // In production, this would be retrieved from secure storage
    // This is a simplified version for demonstration
    Ok(RegistrationState::new(
        PublicKeyCredentialUserEntity {
            id: challenge.user_id.unwrap_or_else(|| Uuid::new_v4().as_bytes().to_vec()),
            name: "user@example.com".to_string(),
            display_name: "Test User".to_string(),
        },
        UserVerificationPolicy::Preferred,
        AttestationConveyancePreference::None,
        None,
        None,
    ))
}

fn create_dummy_authentication_state(credential: &Credential) -> Result<AuthenticationState> {
    // In production, this would be retrieved from secure storage
    Ok(AuthenticationState::new(
        PublicKeyCredentialUserEntity {
            id: credential.user_id.as_bytes().to_vec(),
            name: "user@example.com".to_string(),
            display_name: "Test User".to_string(),
        },
        vec![PublicKeyCredentialDescriptor {
            type_: PublicKeyCredentialType::PublicKey,
            id: credential.credential_id.clone(),
            transports: Some(credential.transports.iter()
                .filter_map(|t| parse_transport(t))
                .collect()),
        }],
        UserVerificationPolicy::Preferred,
        None,
    ))
}
```

## 4. Database Repository Implementation

### 4.1 Repository Pattern

```rust
// src/db/repositories.rs
use crate::db::models::*;
use crate::error::{DatabaseError, Result};
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool};
use std::sync::Arc;
use uuid::Uuid;

pub type DbPool = Arc<Pool<ConnectionManager<PgConnection>>>;

pub struct UserRepository {
    pool: DbPool,
}

impl UserRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, new_user: NewUser) -> Result<User> {
        let mut conn = self.pool.get()?;
        let user = diesel::insert_into(users::table)
            .values(&new_user)
            .get_result(&mut conn)?;
        Ok(user)
    }

    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<User>> {
        let mut conn = self.pool.get()?;
        let user = users::table
            .filter(users::id.eq(id))
            .first::<User>(&mut conn)
            .optional()?;
        Ok(user)
    }

    pub async fn find_by_username(&self, username: &str) -> Result<Option<User>> {
        let mut conn = self.pool.get()?;
        let user = users::table
            .filter(users::username.eq(username))
            .first::<User>(&mut conn)
            .optional()?;
        Ok(user)
    }

    pub async fn update(&self, id: Uuid, updated_user: &UpdateUser) -> Result<User> {
        let mut conn = self.pool.get()?;
        let user = diesel::update(users::table.filter(users::id.eq(id)))
            .set(updated_user)
            .get_result(&mut conn)?;
        Ok(user)
    }

    pub async fn delete(&self, id: Uuid) -> Result<()> {
        let mut conn = self.pool.get()?;
        diesel::delete(users::table.filter(users::id.eq(id)))
            .execute(&mut conn)?;
        Ok(())
    }
}

pub struct CredentialRepository {
    pool: DbPool,
}

impl CredentialRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn store(&self, new_credential: NewCredential) -> Result<Credential> {
        let mut conn = self.pool.get()?;
        let credential = diesel::insert_into(credentials::table)
            .values(&new_credential)
            .get_result(&mut conn)?;
        Ok(credential)
    }

    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<Credential>> {
        let mut conn = self.pool.get()?;
        let credential = credentials::table
            .filter(credentials::id.eq(id))
            .first::<Credential>(&mut conn)
            .optional()?;
        Ok(credential)
    }

    pub async fn find_by_credential_id(&self, credential_id: &[u8]) -> Result<Option<Credential>> {
        let mut conn = self.pool.get()?;
        let credential = credentials::table
            .filter(credentials::credential_id.eq(credential_id))
            .first::<Credential>(&mut conn)
            .optional()?;
        Ok(credential)
    }

    pub async fn find_by_user_id(&self, user_id: Uuid) -> Result<Vec<Credential>> {
        let mut conn = self.pool.get()?;
        let credentials = credentials::table
            .filter(credentials::user_id.eq(user_id))
            .load::<Credential>(&mut conn)?;
        Ok(credentials)
    }

    pub async fn update_counter(&self, id: Uuid, counter: i64) -> Result<()> {
        let mut conn = self.pool.get()?;
        diesel::update(credentials::table.filter(credentials::id.eq(id)))
            .set((
                credentials::sign_count.eq(counter),
                credentials::last_used_at.eq(chrono::Utc::now()),
            ))
            .execute(&mut conn)?;
        Ok(())
    }

    pub async fn delete(&self, id: Uuid) -> Result<()> {
        let mut conn = self.pool.get()?;
        diesel::delete(credentials::table.filter(credentials::id.eq(id)))
            .execute(&mut conn)?;
        Ok(())
    }
}

pub struct ChallengeRepository {
    pool: DbPool,
}

impl ChallengeRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn store(&self, new_challenge: NewChallenge) -> Result<Challenge> {
        let mut conn = self.pool.get()?;
        let challenge = diesel::insert_into(challenges::table)
            .values(&new_challenge)
            .get_result(&mut conn)?;
        Ok(challenge)
    }

    pub async fn find_by_challenge(&self, challenge: &[u8]) -> Result<Option<Challenge>> {
        let mut conn = self.pool.get()?;
        let challenge_record = challenges::table
            .filter(challenges::challenge.eq(challenge))
            .first::<Challenge>(&mut conn)
            .optional()?;
        Ok(challenge_record)
    }

    pub async fn delete(&self, id: Uuid) -> Result<()> {
        let mut conn = self.pool.get()?;
        diesel::delete(challenges::table.filter(challenges::id.eq(id)))
            .execute(&mut conn)?;
        Ok(())
    }

    pub async fn cleanup_expired(&self) -> Result<usize> {
        let mut conn = self.pool.get()?;
        let count = diesel::delete(
            challenges::table.filter(challenges::expires_at.lt(chrono::Utc::now()))
        )
        .execute(&mut conn)?;
        Ok(count)
    }
}

// Update struct for user updates
#[derive(AsChangeset)]
#[diesel(table_name = users)]
pub struct UpdateUser {
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub updated_at: Option<chrono::DateTime<chrono::Utc>>,
}
```

## 5. Controller Implementation

### 5.1 Registration Controller

```rust
// src/controllers/registration.rs
use crate::controllers::types::*;
use crate::error::{WebAuthnError, Result};
use crate::services::WebAuthnService;
use actix_web::{web, HttpRequest, HttpResponse, Result as ActixResult};
use log::{error, info, warn};

pub struct RegistrationController {
    webauthn_service: WebAuthnService,
}

impl RegistrationController {
    pub fn new(webauthn_service: WebAuthnService) -> Self {
        Self { webauthn_service }
    }

    pub async fn challenge(
        &self,
        req: HttpRequest,
        payload: web::Json<RegistrationChallengeRequest>,
    ) -> ActixResult<HttpResponse> {
        info!("Registration challenge request for user: {}", payload.username);

        // Validate request
        if let Err(e) = validate_registration_request(&payload) {
            warn!("Invalid registration request: {}", e);
            return Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(
                "INVALID_REQUEST",
                &e.to_string(),
            )));
        }

        // Generate challenge
        match self.webauthn_service.generate_registration_challenge(
            &payload.username,
            &payload.display_name,
            payload.user_verification,
            payload.attestation,
            payload.authenticator_selection,
            payload.extensions,
        ).await {
            Ok((challenge, response)) => {
                info!("Generated registration challenge for user: {}", payload.username);
                Ok(HttpResponse::Ok().json(ApiResponse::success(response)))
            }
            Err(e) => {
                error!("Failed to generate registration challenge: {}", e);
                let (code, message) = map_webauthn_error(&e);
                Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(code, message)))
            }
        }
    }

    pub async fn verify(
        &self,
        req: HttpRequest,
        payload: web::Json<RegistrationVerificationRequest>,
    ) -> ActixResult<HttpResponse> {
        info!("Registration verification request");

        // Extract challenge from request (in production, this would come from session/state)
        let challenge = extract_challenge_from_request(&req)
            .map_err(|e| {
                warn!("Failed to extract challenge: {}", e);
                actix_web::error::ErrorBadRequest("Missing or invalid challenge")
            })?;

        // Verify registration
        match self.webauthn_service.verify_registration(
            payload.credential.clone(),
            payload.client_extension_results.clone(),
            &challenge,
        ).await {
            Ok(response) => {
                info!("Registration verification successful");
                Ok(HttpResponse::Ok().json(ApiResponse::success(response)))
            }
            Err(e) => {
                error!("Registration verification failed: {}", e);
                let (code, message) = map_webauthn_error(&e);
                Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(code, message)))
            }
        }
    }
}

fn validate_registration_request(req: &RegistrationChallengeRequest) -> Result<()> {
    // Validate username
    if req.username.len() < 3 || req.username.len() > 255 {
        return Err(WebAuthnError::InvalidUsername);
    }

    // Simple email validation
    if !req.username.contains('@') || !req.username.contains('.') {
        return Err(WebAuthnError::InvalidUsername);
    }

    // Validate display name
    if req.display_name.is_empty() || req.display_name.len() > 255 {
        return Err(WebAuthnError::InvalidDisplayName);
    }

    // Check for control characters
    if req.display_name.chars().any(|c| c.is_control()) {
        return Err(WebAuthnError::InvalidDisplayName);
    }

    Ok(())
}

fn extract_challenge_from_request(req: &HttpRequest) -> Result<String> {
    // In production, extract challenge from session, JWT, or secure storage
    // For this example, we'll extract from header
    req.headers()
        .get("X-WebAuthn-Challenge")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
        .ok_or(WebAuthnError::MissingChallenge)
}

fn map_webauthn_error(err: &WebAuthnError) -> (&'static str, &'static str) {
    match err {
        WebAuthnError::UserAlreadyExists => ("USER_EXISTS", "User already exists"),
        WebAuthnError::InvalidUsername => ("INVALID_USERNAME", "Invalid username format"),
        WebAuthnError::InvalidDisplayName => ("INVALID_DISPLAY_NAME", "Invalid display name"),
        WebAuthnError::InvalidAttestation => ("INVALID_ATTESTATION", "Invalid attestation format"),
        WebAuthnError::InvalidChallenge => ("INVALID_CHALLENGE", "Invalid or missing challenge"),
        WebAuthnError::ChallengeExpired => ("CHALLENGE_EXPIRED", "Challenge has expired"),
        WebAuthnError::InvalidRpId => ("INVALID_RP_ID", "RP ID mismatch"),
        WebAuthnError::UnsupportedAlgorithm => ("UNSUPPORTED_ALGORITHM", "Unsupported algorithm"),
        WebAuthnError::CredentialExists => ("CREDENTIAL_EXISTS", "Credential already exists"),
        WebAuthnError::UserVerificationFailed => ("USER_VERIFICATION_FAILED", "User verification failed"),
        _ => ("INTERNAL_ERROR", "Internal server error"),
    }
}
```

### 5.2 Authentication Controller

```rust
// src/controllers/authentication.rs
use crate::controllers::types::*;
use crate::error::{WebAuthnError, Result};
use crate::services::WebAuthnService;
use actix_web::{web, HttpRequest, HttpResponse, Result as ActixResult};
use log::{error, info, warn};

pub struct AuthenticationController {
    webauthn_service: WebAuthnService,
}

impl AuthenticationController {
    pub fn new(webauthn_service: WebAuthnService) -> Self {
        Self { webauthn_service }
    }

    pub async fn challenge(
        &self,
        req: HttpRequest,
        payload: web::Json<AuthenticationChallengeRequest>,
    ) -> ActixResult<HttpResponse> {
        info!("Authentication challenge request for user: {}", payload.username);

        // Generate challenge
        match self.webauthn_service.generate_authentication_challenge(
            &payload.username,
            payload.user_verification,
            payload.allow_credentials.clone(),
            payload.extensions.clone(),
        ).await {
            Ok((challenge, response)) => {
                info!("Generated authentication challenge for user: {}", payload.username);
                Ok(HttpResponse::Ok().json(ApiResponse::success(response)))
            }
            Err(e) => {
                error!("Failed to generate authentication challenge: {}", e);
                let (code, message) = map_webauthn_error(&e);
                Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(code, message)))
            }
        }
    }

    pub async fn verify(
        &self,
        req: HttpRequest,
        payload: web::Json<AuthenticationVerificationRequest>,
    ) -> ActixResult<HttpResponse> {
        info!("Authentication verification request");

        // Extract challenge from request
        let challenge = extract_challenge_from_request(&req)
            .map_err(|e| {
                warn!("Failed to extract challenge: {}", e);
                actix_web::error::ErrorBadRequest("Missing or invalid challenge")
            })?;

        // Verify authentication
        match self.webauthn_service.verify_authentication(
            payload.credential.clone(),
            payload.client_extension_results.clone(),
            &challenge,
        ).await {
            Ok(response) => {
                info!("Authentication verification successful");
                // Create session/token here
                Ok(HttpResponse::Ok().json(ApiResponse::success(response)))
            }
            Err(e) => {
                error!("Authentication verification failed: {}", e);
                let (code, message) = map_webauthn_error(&e);
                Ok(HttpResponse::BadRequest().json(ApiResponse::<()>::error(code, message)))
            }
        }
    }
}

fn map_webauthn_error(err: &WebAuthnError) -> (&'static str, &'static str) {
    match err {
        WebAuthnError::UserNotFound => ("USER_NOT_FOUND", "User not found"),
        WebAuthnError::NoCredentials => ("NO_CREDENTIALS", "No credentials found for user"),
        WebAuthnError::InvalidAssertion => ("INVALID_ASSERTION", "Invalid assertion format"),
        WebAuthnError::InvalidChallenge => ("INVALID_CHALLENGE", "Invalid or missing challenge"),
        WebAuthnError::ChallengeExpired => ("CHALLENGE_EXPIRED", "Challenge has expired"),
        WebAuthnError::CredentialNotFound => ("INVALID_CREDENTIAL", "Credential not found"),
        WebAuthnError::ReplayAttack => ("REPLAY_ATTACK", "Potential replay attack detected"),
        WebAuthnError::CounterMismatch => ("COUNTER_MISMATCH", "Counter validation failed"),
        WebAuthnError::UserVerificationFailed => ("USER_VERIFICATION_FAILED", "User verification required but not provided"),
        _ => ("INTERNAL_ERROR", "Internal server error"),
    }
}
```

## 6. Error Handling

### 6.1 Custom Error Types

```rust
// src/error/mod.rs
use thiserror::Error;

#[derive(Error, Debug)]
pub enum WebAuthnError {
    #[error("User already exists")]
    UserAlreadyExists,
    
    #[error("User not found")]
    UserNotFound,
    
    #[error("Invalid username format")]
    InvalidUsername,
    
    #[error("Invalid display name")]
    InvalidDisplayName,
    
    #[error("Invalid attestation format")]
    InvalidAttestation,
    
    #[error("Invalid assertion format")]
    InvalidAssertion,
    
    #[error("Invalid or missing challenge")]
    InvalidChallenge,
    
    #[error("Challenge has expired")]
    ChallengeExpired,
    
    #[error("RP ID mismatch")]
    InvalidRpId,
    
    #[error("Unsupported algorithm")]
    UnsupportedAlgorithm,
    
    #[error("Credential already exists")]
    CredentialExists,
    
    #[error("Credential not found")]
    CredentialNotFound,
    
    #[error("No credentials found for user")]
    NoCredentials,
    
    #[error("Potential replay attack detected")]
    ReplayAttack,
    
    #[error("Counter validation failed")]
    CounterMismatch,
    
    #[error("User verification failed")]
    UserVerificationFailed,
    
    #[error("User verification required but not provided")]
    UserVerificationRequired,
    
    #[error("Random generation error")]
    RandomGenerationError,
    
    #[error("Missing challenge")]
    MissingChallenge,
    
    #[error("Database error: {0}")]
    Database(#[from] DatabaseError),
    
    #[error("WebAuthn library error: {0}")]
    WebAuthnLib(#[from] webauthn_rs::error::WebauthnError),
    
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),
}

#[derive(Error, Debug)]
pub enum DatabaseError {
    #[error("Connection error: {0}")]
    Connection(String),
    
    #[error("Query error: {0}")]
    Query(String),
    
    #[error("Transaction error: {0}")]
    Transaction(String),
    
    #[error("Unique constraint violation")]
    UniqueViolation,
    
    #[error("Record not found")]
    NotFound,
    
    #[error("Migration error: {0}")]
    Migration(String),
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Missing environment variable: {0}")]
    MissingEnv(String),
    
    #[error("Invalid configuration: {0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, WebAuthnError>;

// Convert diesel errors to our DatabaseError
impl From<diesel::result::Error> for DatabaseError {
    fn from(err: diesel::result::Error) -> Self {
        match err {
            diesel::result::Error::DatabaseError(
                diesel::result::DatabaseErrorKind::UniqueViolation,
                _
            ) => DatabaseError::UniqueViolation,
            diesel::result::Error::NotFound => DatabaseError::NotFound,
            _ => DatabaseError::Query(err.to_string()),
        }
    }
}

impl From<diesel::ConnectionError> for DatabaseError {
    fn from(err: diesel::ConnectionError) -> Self {
        DatabaseError::Connection(err.to_string())
    }
}

impl From<diesel::r2d2::Error> for DatabaseError {
    fn from(err: diesel::r2d2::Error) -> Self {
        DatabaseError::Connection(err.to_string())
    }
}

// Convert to actix-web error
impl actix_web::error::ResponseError for WebAuthnError {
    fn error_response(&self) -> HttpResponse {
        let status = match self {
            WebAuthnError::UserAlreadyExists => HttpResponse::Conflict(),
            WebAuthnError::UserNotFound | WebAuthnError::CredentialNotFound => HttpResponse::NotFound(),
            WebAuthnError::InvalidUsername
            | WebAuthnError::InvalidDisplayName
            | WebAuthnError::InvalidAttestation
            | WebAuthnError::InvalidAssertion
            | WebAuthnError::InvalidChallenge
            | WebAuthnError::ChallengeExpired
            | WebAuthnError::InvalidRpId
            | WebAuthnError::UnsupportedAlgorithm
            | WebAuthnError::CredentialExists
            | WebAuthnError::NoCredentials
            | WebAuthnError::ReplayAttack
            | WebAuthnError::CounterMismatch
            | WebAuthnError::UserVerificationFailed
            | WebAuthnError::UserVerificationRequired
            | WebAuthnError::MissingChallenge => HttpResponse::BadRequest(),
            WebAuthnError::Database(_) | WebAuthnError::Config(_) => HttpResponse::InternalServerError(),
            WebAuthnError::RandomGenerationError => HttpResponse::InternalServerError(),
            WebAuthnError::WebAuthnLib(_) => HttpResponse::BadRequest(),
        };

        status.json(serde_json::json!({
            "status": "error",
            "error": {
                "code": format!("{:?}", self),
                "message": self.to_string()
            },
            "timestamp": chrono::Utc::now()
        }))
    }
}
```

## 7. Main Application Setup

### 7.1 Application Configuration

```rust
// src/main.rs
use actix_cors::Cors;
use actix_web::{web, App, HttpServer, middleware};
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::PgConnection;
use std::env;

mod config;
mod controllers;
mod db;
mod error;
mod middleware;
mod routes;
mod services;
mod utils;

use config::{DatabaseConfig, WebAuthnConfig};
use controllers::{AuthenticationController, RegistrationController};
use db::repositories::{ChallengeRepository, CredentialRepository, UserRepository};
use services::WebAuthnService;
use middleware::{rate_limit::RateLimitMiddleware, security::SecurityHeadersMiddleware};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logging
    env_logger::init();

    // Load configuration
    let webauthn_config = WebAuthnConfig::from_env()
        .expect("Failed to load WebAuthn configuration");
    
    let db_config = DatabaseConfig::from_env()
        .expect("Failed to load database configuration");

    // Create database connection pool
    let manager = ConnectionManager::<PgConnection>::new(&db_config.url);
    let pool = Pool::builder()
        .max_size(db_config.max_connections)
        .build(manager)
        .expect("Failed to create connection pool");

    // Run database migrations
    db::migrations::run_migrations(&pool.get().unwrap())
        .expect("Failed to run database migrations");

    // Create repositories
    let user_repo = UserRepository::new(std::sync::Arc::new(pool.clone()));
    let credential_repo = CredentialRepository::new(std::sync::Arc::new(pool.clone()));
    let challenge_repo = ChallengeRepository::new(std::sync::Arc::new(pool.clone()));

    // Create services
    let webauthn_service = WebAuthnService::new(
        &webauthn_config,
        challenge_repo,
        credential_repo,
        user_repo,
    ).expect("Failed to create WebAuthn service");

    // Create controllers
    let registration_controller = RegistrationController::new(webauthn_service.clone());
    let authentication_controller = AuthenticationController::new(webauthn_service);

    // Configure server
    let host = env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = env::var("SERVER_PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse()
        .expect("Invalid SERVER_PORT");

    log::info!("Starting FIDO2/WebAuthn server on {}:{}", host, port);

    // Start HTTP server
    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin_fn(|origin, _req_head| {
                webauthn_config.allowed_origins.contains(&origin.to_string())
            })
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
            .allowed_headers(vec!["authorization", "content-type"])
            .supports_credentials()
            .max_age(3600);

        App::new()
            .wrap(cors)
            .wrap(middleware::Logger::default())
            .wrap(SecurityHeadersMiddleware::new())
            .wrap(RateLimitMiddleware::new(100)) // 100 requests per minute
            .service(
                web::scope("/api/v1")
                    .configure(routes::webauthn::configure(
                        registration_controller.clone(),
                        authentication_controller.clone(),
                    ))
                    .configure(routes::user::configure())
                    .configure(routes::admin::configure())
            )
            .route("/health", web::get().to(health_check))
            .route("/metrics", web::get().to(metrics))
    })
    .bind(format!("{}:{}", host, port))?
    .run()
    .await
}

async fn health_check() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now()
    }))
}

async fn metrics() -> HttpResponse {
    // Return application metrics
    HttpResponse::Ok().json(serde_json::json!({
        "registrations": { "total": 0, "today": 0 },
        "authentications": { "total": 0, "today": 0 },
        "users": { "total": 0, "active_today": 0 }
    }))
}
```

### 7.2 Route Configuration

```rust
// src/routes/mod.rs
pub mod webauthn;
pub mod user;
pub mod admin;

// src/routes/webauthn.rs
use crate::controllers::{AuthenticationController, RegistrationController};
use actix_web::{web, Scope};

pub fn configure(
    registration_controller: RegistrationController,
    authentication_controller: AuthenticationController,
) -> Scope {
    web::scope("/webauthn")
        .service(
            web::resource("/register/challenge")
                .route(web::post().to({
                    let controller = registration_controller.clone();
                    move |req, payload| async move {
                        controller.challenge(req, payload).await
                    }
                }))
        )
        .service(
            web::resource("/register/verify")
                .route(web::post().to({
                    let controller = registration_controller.clone();
                    move |req, payload| async move {
                        controller.verify(req, payload).await
                    }
                }))
        )
        .service(
            web::resource("/authenticate/challenge")
                .route(web::post().to({
                    let controller = authentication_controller.clone();
                    move |req, payload| async move {
                        controller.challenge(req, payload).await
                    }
                }))
        )
        .service(
            web::resource("/authenticate/verify")
                .route(web::post().to({
                    let controller = authentication_controller.clone();
                    move |req, payload| async move {
                        controller.verify(req, payload).await
                    }
                }))
        )
}
```

This implementation guide provides a comprehensive foundation for building a secure, FIDO2-compliant WebAuthn server in Rust. The code follows security best practices, implements proper error handling, and is structured for testability and maintainability.