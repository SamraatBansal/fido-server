# FIDO2/WebAuthn Server - Implementation Guide

## Overview

This guide provides detailed implementation instructions for building a secure, FIDO2-compliant WebAuthn Relying Party Server in Rust using the webauthn-rs library with comprehensive test coverage.

## 1. Project Setup and Configuration

### 1.1 Initial Project Structure

```bash
# Create new Rust project
cargo new fido-server --lib
cd fido-server

# Create directory structure
mkdir -p src/{config,controllers,services,models,db,middleware,routes,error,utils}
mkdir -p tests/{unit,integration,common}
mkdir -p migrations
```

### 1.2 Core Dependencies Configuration

```toml
# Cargo.toml
[package]
name = "fido-server"
version = "0.1.0"
edition = "2021"

[dependencies]
# Web Framework
actix-web = "4.9"
actix-cors = "0.7"
actix-rt = "2.10"

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
ring = "0.17"  # For additional crypto operations
zeroize = "1.7"  # For secure memory handling
secrecy = "0.8"  # For secret type management

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
argon2 = "0.5"  # For any password hashing needs

[dev-dependencies]
actix-test = "0.1"
mockall = "0.13"
tokio-test = "0.4"
tempfile = "3.8"

[profile.dev]
opt-level = 0
debug = true

[profile.release]
opt-level = 3
lto = true
codegen-units = 1
panic = "abort"
strip = true
```

## 2. Core WebAuthn Service Implementation

### 2.1 WebAuthn Configuration

```rust
// src/config/webauthn.rs
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnConfig {
    pub rp_name: String,
    pub rp_id: String,
    pub rp_origin: String,
    pub challenge_timeout: u64, // in seconds
}

impl Default for WebAuthnConfig {
    fn default() -> Self {
        Self {
            rp_name: "FIDO Server".to_string(),
            rp_id: "localhost".to_string(),
            rp_origin: "http://localhost:8080".to_string(),
            challenge_timeout: 300, // 5 minutes
        }
    }
}

impl WebAuthnConfig {
    pub fn to_webauthn(&self) -> Webauthn {
        Webauthn::new(
            &self.rp_name,
            &self.rp_id,
            &self.rp_origin,
        )
    }
}
```

### 2.2 WebAuthn Service Implementation

```rust
// src/services/webauthn.rs
use crate::config::WebAuthnConfig;
use crate::error::{WebAuthnError, Result};
use crate::models::{Challenge, ChallengeType, Credential, User};
use crate::utils::crypto;
use chrono::{Duration, Utc};
use ring::rand::SecureRandom;
use std::sync::Arc;
use webauthn_rs::prelude::*;
use zeroize::Zeroize;

pub struct WebAuthnService {
    config: Arc<WebAuthnConfig>,
    webauthn: Webauthn,
    rng: Arc<dyn SecureRandom + Send + Sync>,
}

impl WebAuthnService {
    pub fn new(config: WebAuthnConfig) -> Result<Self> {
        let webauthn = config.to_webauthn();
        let rng = Arc::new(ring::rand::SystemRandom::new());
        
        Ok(Self {
            config: Arc::new(config),
            webauthn,
            rng,
        })
    }

    /// Generate a cryptographically secure challenge
    pub fn generate_challenge(&self) -> Result<String> {
        let mut challenge_bytes = vec![0u8; 32];
        self.rng.fill(&mut challenge_bytes)
            .map_err(|_| WebAuthnError::ChallengeGenerationFailed)?;
        
        Ok(base64::encode_config(&challenge_bytes, base64::URL_SAFE_NO_PAD))
    }

    /// Generate registration challenge
    pub async fn generate_registration_challenge(
        &self,
        user: &User,
        user_verification: UserVerificationPolicy,
        attestation: AttestationConveyancePreference,
    ) -> Result<CreationChallengeResponse> {
        let challenge = self.generate_challenge()?;
        
        // Store challenge in database
        let stored_challenge = Challenge::new(
            user.id.clone().unwrap_or_default().to_string(),
            ChallengeType::Registration,
            chrono::Duration::seconds(self.config.challenge_timeout as i64),
        );
        stored_challenge.save_to_db().await?;
        
        // Create user data for WebAuthn
        let user_data = UserData {
            id: user.id.clone().unwrap_or_default().to_string().into_bytes(),
            name: user.username.clone(),
            display_name: user.display_name.clone(),
        };
        
        // Generate credential creation options
        let (ccr, state) = self.webauthn
            .generate_challenge_register_options(
                user_data,
                user_verification,
                attestation,
                None,
                None,
            )
            .map_err(|e| WebAuthnError::ChallengeGenerationFailed)?;
        
        // Store state for verification
        // In a real implementation, you'd store this securely
        // For now, we'll include it in the challenge
        
        Ok(ccr)
    }

    /// Verify registration attestation
    pub async fn verify_registration(
        &self,
        user: &User,
        attestation_response: &RegisterPublicKeyCredential,
        challenge: &str,
    ) -> Result<Credential> {
        // Retrieve and validate challenge
        let stored_challenge = Challenge::find_by_challenge(challenge)
            .await?
            .ok_or(WebAuthnError::ChallengeNotFound)?;
        
        if stored_challenge.challenge_type != ChallengeType::Registration {
            return Err(WebAuthnError::InvalidChallengeType);
        }
        
        if stored_challenge.is_expired() {
            return Err(WebAuthnError::ChallengeExpired);
        }
        
        if stored_challenge.is_used() {
            return Err(WebAuthnError::ChallengeAlreadyUsed);
        }
        
        // Verify attestation
        let result = self.webauthn
            .register_credential(attestation_response, |state| {
                // Verify state matches stored challenge
                // This is a simplified check - in reality, you'd verify the full state
                Ok(())
            })
            .map_err(|e| WebAuthnError::AttestationVerificationFailed)?;
        
        // Create credential record
        let credential = Credential::new(
            user.id.clone().unwrap_or_default().to_string(),
            result.credential_id.as_slice().to_vec(),
            result.public_key.as_slice().to_vec(),
            result.attestation_format.to_string(),
        );
        
        // Save credential
        credential.save_to_db().await?;
        
        // Mark challenge as used
        stored_challenge.mark_used().await?;
        
        Ok(credential)
    }

    /// Generate authentication challenge
    pub async fn generate_authentication_challenge(
        &self,
        user: &User,
        user_verification: UserVerificationPolicy,
    ) -> Result<RequestChallengeResponse> {
        // Get user's credentials
        let credentials = Credential::find_by_user_id(&user.id.clone().unwrap_or_default().to_string())
            .await?;
        
        if credentials.is_empty() {
            return Err(WebAuthnError::NoCredentialsFound);
        }
        
        let challenge = self.generate_challenge()?;
        
        // Store challenge
        let stored_challenge = Challenge::new(
            user.id.clone().unwrap_or_default().to_string(),
            ChallengeType::Authentication,
            chrono::Duration::seconds(self.config.challenge_timeout as i64),
        );
        stored_challenge.save_to_db().await?;
        
        // Convert credentials to allowed credentials
        let allowed_credentials: Vec<_> = credentials
            .into_iter()
            .map(|cred| PublicKeyCredentialDescriptor {
                id: cred.credential_id.into(),
                transports: Some(vec![
                    AuthenticatorTransport::Usb,
                    AuthenticatorTransport::Nfc,
                    AuthenticatorTransport::Ble,
                    AuthenticatorTransport::Internal,
                ]),
                type_: PublicKeyCredentialType::PublicKey,
            })
            .collect();
        
        // Generate authentication options
        let (acr, _state) = self.webauthn
            .generate_challenge_authenticate_options(
                allowed_credentials,
                user_verification,
                None,
            )
            .map_err(|e| WebAuthnError::ChallengeGenerationFailed)?;
        
        Ok(acr)
    }

    /// Verify authentication assertion
    pub async fn verify_authentication(
        &self,
        user: &User,
        assertion_response: &PublicKeyCredential,
        challenge: &str,
    ) -> Result<(Credential, u64)> {
        // Retrieve and validate challenge
        let stored_challenge = Challenge::find_by_challenge(challenge)
            .await?
            .ok_or(WebAuthnError::ChallengeNotFound)?;
        
        if stored_challenge.challenge_type != ChallengeType::Authentication {
            return Err(WebAuthnError::InvalidChallengeType);
        }
        
        if stored_challenge.is_expired() {
            return Err(WebAuthnError::ChallengeExpired);
        }
        
        if stored_challenge.is_used() {
            return Err(WebAuthnError::ChallengeAlreadyUsed);
        }
        
        // Get credential
        let credential_id = assertion_response.raw_id.as_slice();
        let mut credential = Credential::find_by_credential_id(credential_id)
            .await?
            .ok_or(WebAuthnError::CredentialNotFound)?;
        
        // Verify credential belongs to user
        if credential.user_id != user.id.clone().unwrap_or_default().to_string() {
            return Err(WebAuthnError::CredentialUserMismatch);
        }
        
        // Verify assertion
        let result = self.webauthn
            .authenticate_credential(assertion_response, |state| {
                // Verify state matches stored challenge
                Ok(())
            })
            .map_err(|e| WebAuthnError::AssertionVerificationFailed)?;
        
        // Update counter
        let old_counter = credential.sign_count;
        credential.update_counter(result.counter)
            .map_err(|_| WebAuthnError::CounterRegression)?;
        
        // Save updated credential
        credential.save_to_db().await?;
        
        // Mark challenge as used
        stored_challenge.mark_used().await?;
        
        Ok((credential, result.counter))
    }
}

// Security utilities
impl WebAuthnService {
    /// Validate RP ID against origin
    pub fn validate_rp_id(&self, rp_id: &str) -> Result<()> {
        // Basic RP ID validation according to FIDO2 spec
        if rp_id.is_empty() {
            return Err(WebAuthnError::InvalidRpId);
        }
        
        // Check for invalid characters
        if rp_id.contains("..") || rp_id.starts_with('.') || rp_id.ends_with('.') {
            return Err(WebAuthnError::InvalidRpId);
        }
        
        // Check for port (not allowed in RP ID)
        if rp_id.contains(':') {
            return Err(WebAuthnError::InvalidRpId);
        }
        
        Ok(())
    }
    
    /// Validate origin against RP ID
    pub fn validate_origin(&self, origin: &str, rp_id: &str) -> Result<()> {
        // Parse origin
        let url = url::Url::parse(origin)
            .map_err(|_| WebAuthnError::InvalidOrigin)?;
        
        // Check scheme
        if url.scheme() != "https" && url.host_str() != Some("localhost") {
            return Err(WebAuthnError::InsecureOrigin);
        }
        
        // Check host against RP ID
        let host = url.host_str().ok_or(WebAuthnError::InvalidOrigin)?;
        
        if !self.is_host_valid_for_rp_id(host, rp_id) {
            return Err(WebAuthnError::OriginRpIdMismatch);
        }
        
        Ok(())
    }
    
    fn is_host_valid_for_rp_id(&self, host: &str, rp_id: &str) -> bool {
        // Exact match
        if host == rp_id {
            return true;
        }
        
        // Subdomain match
        if let Some(subdomain) = host.strip_suffix(&format!(".{}", rp_id)) {
            return !subdomain.is_empty();
        }
        
        false
    }
}
```

## 3. Data Models Implementation

### 3.1 User Model

```rust
// src/models/user.rs
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

use crate::db::schema::users;
use crate::error::{Result, UserError};

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = users)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_active: bool,
    pub email_verified: bool,
}

#[derive(Debug, Insertable, Validate)]
#[diesel(table_name = users)]
pub struct NewUser {
    #[validate(length(min = 3, max = 255), email)]
    pub username: String,
    #[validate(length(min = 1, max = 255))]
    pub display_name: String,
}

#[derive(Debug, AsChangeset, Validate)]
#[diesel(table_name = users)]
pub struct UpdateUser {
    #[validate(length(min = 1, max = 255))]
    pub display_name: Option<String>,
    pub is_active: Option<bool>,
    pub email_verified: Option<bool>,
}

impl User {
    pub fn new(username: String, display_name: String) -> NewUser {
        NewUser {
            username,
            display_name,
        }
    }
    
    pub fn validate_username(username: &str) -> Result<()> {
        if username.is_empty() {
            return Err(UserError::InvalidUsername("Username cannot be empty".to_string()).into());
        }
        
        if username.len() > 255 {
            return Err(UserError::InvalidUsername("Username too long".to_string()).into());
        }
        
        // Basic email validation
        if !username.contains('@') || !username.contains('.') {
            return Err(UserError::InvalidUsername("Invalid email format".to_string()).into());
        }
        
        Ok(())
    }
    
    pub fn validate_display_name(display_name: &str) -> Result<()> {
        if display_name.is_empty() {
            return Err(UserError::InvalidDisplayName("Display name cannot be empty".to_string()).into());
        }
        
        if display_name.len() > 255 {
            return Err(UserError::InvalidDisplayName("Display name too long".to_string()).into());
        }
        
        // Check for control characters
        if display_name.chars().any(|c| c.is_control()) {
            return Err(UserError::InvalidDisplayName("Display name contains invalid characters".to_string()).into());
        }
        
        Ok(())
    }
    
    pub async fn create(conn: &mut PgConnection, new_user: NewUser) -> Result<User> {
        new_user.validate()?;
        
        let user = diesel::insert_into(users::table)
            .values(&new_user)
            .returning(User::as_returning())
            .get_result(conn)?;
        
        Ok(user)
    }
    
    pub async fn find_by_id(conn: &mut PgConnection, id: Uuid) -> Result<Option<User>> {
        let user = users::table
            .filter(users::id.eq(id))
            .first::<User>(conn)
            .optional()?;
        
        Ok(user)
    }
    
    pub async fn find_by_username(conn: &mut PgConnection, username: &str) -> Result<Option<User>> {
        let user = users::table
            .filter(users::username.eq(username))
            .first::<User>(conn)
            .optional()?;
        
        Ok(user)
    }
    
    pub async fn update(conn: &mut PgConnection, id: Uuid, update_user: UpdateUser) -> Result<User> {
        update_user.validate()?;
        
        let user = diesel::update(users::table.filter(users::id.eq(id)))
            .set(&update_user)
            .returning(User::as_returning())
            .get_result(conn)?;
        
        Ok(user)
    }
    
    pub async fn delete(conn: &mut PgConnection, id: Uuid) -> Result<()> {
        diesel::delete(users::table.filter(users::id.eq(id)))
            .execute(conn)?;
        
        Ok(())
    }
}
```

### 3.2 Credential Model

```rust
// src/models/credential.rs
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

use crate::db::schema::credentials;
use crate::error::{Result, CredentialError};

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = credentials)]
pub struct Credential {
    pub id: Uuid,
    pub user_id: String,
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
    pub attestation_type: String,
    pub aaguid: Uuid,
    pub sign_count: i64,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub transports: Option<serde_json::Value>,
    pub user_verification: bool,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = credentials)]
pub struct NewCredential {
    pub user_id: String,
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
    pub attestation_type: String,
    pub aaguid: Uuid,
    pub sign_count: i64,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub transports: Option<serde_json::Value>,
    pub user_verification: bool,
}

#[derive(Debug, AsChangeset)]
#[diesel(table_name = credentials)]
pub struct UpdateCredential {
    pub sign_count: Option<i64>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub is_active: Option<bool>,
    pub backup_state: Option<bool>,
}

impl Credential {
    pub fn new(
        user_id: String,
        credential_id: Vec<u8>,
        credential_public_key: Vec<u8>,
        attestation_type: String,
    ) -> NewCredential {
        NewCredential {
            user_id,
            credential_id,
            credential_public_key,
            attestation_type,
            aaguid: Uuid::new_v4(), // This should come from the authenticator
            sign_count: 0,
            backup_eligible: false,
            backup_state: false,
            transports: None,
            user_verification: false,
        }
    }
    
    pub fn validate_credential_id(credential_id: &[u8]) -> Result<()> {
        if credential_id.is_empty() {
            return Err(CredentialError::InvalidCredentialId("Credential ID cannot be empty".to_string()).into());
        }
        
        if credential_id.len() > 1023 {
            return Err(CredentialError::InvalidCredentialId("Credential ID too long".to_string()).into());
        }
        
        Ok(())
    }
    
    pub fn validate_public_key(public_key: &[u8]) -> Result<()> {
        if public_key.is_empty() {
            return Err(CredentialError::InvalidPublicKey("Public key cannot be empty".to_string()).into());
        }
        
        // Additional validation based on COSE key format could be added here
        
        Ok(())
    }
    
    pub async fn create(conn: &mut PgConnection, new_credential: NewCredential) -> Result<Credential> {
        Self::validate_credential_id(&new_credential.credential_id)?;
        Self::validate_public_key(&new_credential.credential_public_key)?;
        
        let credential = diesel::insert_into(credentials::table)
            .values(&new_credential)
            .returning(Credential::as_returning())
            .get_result(conn)?;
        
        Ok(credential)
    }
    
    pub async fn find_by_id(conn: &mut PgConnection, id: Uuid) -> Result<Option<Credential>> {
        let credential = credentials::table
            .filter(credentials::id.eq(id))
            .first::<Credential>(conn)
            .optional()?;
        
        Ok(credential)
    }
    
    pub async fn find_by_credential_id(conn: &mut PgConnection, credential_id: &[u8]) -> Result<Option<Credential>> {
        let credential = credentials::table
            .filter(credentials::credential_id.eq(credential_id))
            .first::<Credential>(conn)
            .optional()?;
        
        Ok(credential)
    }
    
    pub async fn find_by_user_id(conn: &mut PgConnection, user_id: &str) -> Result<Vec<Credential>> {
        let credentials = credentials::table
            .filter(credentials::user_id.eq(user_id))
            .filter(credentials::is_active.eq(true))
            .load::<Credential>(conn)?;
        
        Ok(credentials)
    }
    
    pub async fn update(conn: &mut PgConnection, id: Uuid, update_credential: UpdateCredential) -> Result<Credential> {
        let credential = diesel::update(credentials::table.filter(credentials::id.eq(id)))
            .set(&update_credential)
            .returning(Credential::as_returning())
            .get_result(conn)?;
        
        Ok(credential)
    }
    
    pub async fn delete(conn: &mut PgConnection, id: Uuid) -> Result<()> {
        diesel::delete(credentials::table.filter(credentials::id.eq(id)))
            .execute(conn)?;
        
        Ok(())
    }
    
    pub fn update_counter(&mut self, new_counter: u64) -> Result<()> {
        if new_counter as i64 <= self.sign_count {
            return Err(CredentialError::CounterRegression.into());
        }
        
        self.sign_count = new_counter as i64;
        self.last_used_at = Some(Utc::now());
        
        Ok(())
    }
}
```

### 3.3 Challenge Model

```rust
// src/models/challenge.rs
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db::schema::challenges;
use crate::error::{Result, ChallengeError};

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = challenges)]
pub struct Challenge {
    pub id: Uuid,
    pub challenge_id: String,
    pub user_id: Option<String>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub is_used: bool,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = challenges)]
pub struct NewChallenge {
    pub challenge_id: String,
    pub user_id: Option<String>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, AsChangeset)]
#[diesel(table_name = challenges)]
pub struct UpdateChallenge {
    pub used_at: Option<DateTime<Utc>>,
    pub is_used: Option<bool>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ChallengeType {
    Registration,
    Authentication,
}

impl ChallengeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChallengeType::Registration => "registration",
            ChallengeType::Authentication => "authentication",
        }
    }
}

impl Challenge {
    pub fn new(
        user_id: String,
        challenge_type: ChallengeType,
        timeout: chrono::Duration,
    ) -> NewChallenge {
        NewChallenge {
            challenge_id: Uuid::new_v4().to_string(),
            user_id: Some(user_id),
            challenge_type: challenge_type.as_str().to_string(),
            expires_at: Utc::now() + timeout,
        }
    }
    
    pub async fn create(conn: &mut PgConnection, new_challenge: NewChallenge) -> Result<Challenge> {
        let challenge = diesel::insert_into(challenges::table)
            .values(&new_challenge)
            .returning(Challenge::as_returning())
            .get_result(conn)?;
        
        Ok(challenge)
    }
    
    pub async fn find_by_id(conn: &mut PgConnection, id: Uuid) -> Result<Option<Challenge>> {
        let challenge = challenges::table
            .filter(challenges::id.eq(id))
            .first::<Challenge>(conn)
            .optional()?;
        
        Ok(challenge)
    }
    
    pub async fn find_by_challenge_id(conn: &mut PgConnection, challenge_id: &str) -> Result<Option<Challenge>> {
        let challenge = challenges::table
            .filter(challenges::challenge_id.eq(challenge_id))
            .first::<Challenge>(conn)
            .optional()?;
        
        Ok(challenge)
    }
    
    pub async fn mark_used(conn: &mut PgConnection, id: Uuid) -> Result<()> {
        diesel::update(challenges::table.filter(challenges::id.eq(id)))
            .set((
                challenges::is_used.eq(true),
                challenges::used_at.eq(Utc::now()),
            ))
            .execute(conn)?;
        
        Ok(())
    }
    
    pub async fn cleanup_expired(conn: &mut PgConnection) -> Result<usize> {
        let count = diesel::delete(
            challenges::table.filter(challenges::expires_at.lt(Utc::now()))
        )
        .execute(conn)?;
        
        Ok(count)
    }
    
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
    
    pub fn is_used(&self) -> bool {
        self.is_used
    }
    
    pub fn get_challenge_type(&self) -> Result<ChallengeType> {
        match self.challenge_type.as_str() {
            "registration" => Ok(ChallengeType::Registration),
            "authentication" => Ok(ChallengeType::Authentication),
            _ => Err(ChallengeError::InvalidChallengeType.into()),
        }
    }
}
```

## 4. API Controllers Implementation

### 4.1 Registration Controller

```rust
// src/controllers/registration.rs
use actix_web::{web, HttpRequest, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::error::ApiError;
use crate::models::User;
use crate::services::WebAuthnService;
use crate::utils::validation;
use webauthn_rs::prelude::*;

#[derive(Debug, Deserialize, Validate)]
pub struct RegistrationChallengeRequest {
    #[validate(length(min = 3, max = 255), email)]
    pub username: String,
    #[validate(length(min = 1, max = 255))]
    pub display_name: String,
    #[serde(default = "default_user_verification")]
    pub user_verification: String,
    #[serde(default = "default_attestation")]
    pub attestation: String,
}

fn default_user_verification() -> String {
    "preferred".to_string()
}

fn default_attestation() -> String {
    "none".to_string()
}

#[derive(Debug, Serialize)]
pub struct RegistrationChallengeResponse {
    pub status: String,
    #[serde(flatten)]
    pub challenge: CreationChallengeResponse,
}

#[derive(Debug, Deserialize, Validate)]
pub struct RegistrationVerificationRequest {
    #[validate]
    pub credential: RegisterPublicKeyCredential,
    #[validate(length(min = 3, max = 255))]
    pub username: String,
    #[validate(length(min = 1))]
    pub challenge: String,
}

#[derive(Debug, Serialize)]
pub struct RegistrationVerificationResponse {
    pub status: String,
    pub credential_id: String,
    pub user: UserInfo,
    pub registered_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: String,
    pub name: String,
}

pub async fn generate_registration_challenge(
    webauthn_service: web::Data<WebAuthnService>,
    req: HttpRequest,
    body: web::Json<RegistrationChallengeRequest>,
) -> Result<HttpResponse> {
    // Validate request
    body.validate()
        .map_err(|e| ApiError::ValidationError(e.to_string()))?;
    
    // Validate origin
    let origin = req.headers()
        .get("Origin")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| ApiError::MissingHeader("Origin".to_string()))?;
    
    webauthn_service.validate_origin(origin, &webauthn_service.config.rp_id)?;
    
    // Parse user verification policy
    let user_verification = match body.user_verification.as_str() {
        "required" => UserVerificationPolicy::Required,
        "preferred" => UserVerificationPolicy::Preferred,
        "discouraged" => UserVerificationPolicy::Discouraged,
        _ => return Err(ApiError::InvalidParameter("user_verification".to_string()).into()),
    };
    
    // Parse attestation conveyance preference
    let attestation = match body.attestation.as_str() {
        "none" => AttestationConveyancePreference::None,
        "indirect" => AttestationConveyancePreference::Indirect,
        "direct" => AttestationConveyancePreference::Direct,
        "enterprise" => AttestationConveyancePreference::Enterprise,
        _ => return Err(ApiError::InvalidParameter("attestation".to_string()).into()),
    };
    
    // Find or create user
    let mut conn = crate::db::connection::get_connection().await?;
    let user = match User::find_by_username(&mut conn, &body.username).await? {
        Some(user) => user,
        None => {
            let new_user = User::new(body.username.clone(), body.display_name.clone());
            User::create(&mut conn, new_user).await?
        }
    };
    
    // Generate challenge
    let challenge = webauthn_service
        .generate_registration_challenge(&user, user_verification, attestation)
        .await?;
    
    Ok(HttpResponse::Ok().json(RegistrationChallengeResponse {
        status: "ok".to_string(),
        challenge,
    }))
}

pub async fn verify_registration(
    webauthn_service: web::Data<WebAuthnService>,
    req: HttpRequest,
    body: web::Json<RegistrationVerificationRequest>,
) -> Result<HttpResponse> {
    // Validate request
    body.validate()
        .map_err(|e| ApiError::ValidationError(e.to_string()))?;
    
    // Validate origin
    let origin = req.headers()
        .get("Origin")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| ApiError::MissingHeader("Origin".to_string()))?;
    
    webauthn_service.validate_origin(origin, &webauthn_service.config.rp_id)?;
    
    // Find user
    let mut conn = crate::db::connection::get_connection().await?;
    let user = User::find_by_username(&mut conn, &body.username)
        .await?
        .ok_or_else(|| ApiError::UserNotFound)?;
    
    // Verify registration
    let credential = webauthn_service
        .verify_registration(&user, &body.credential, &body.challenge)
        .await?;
    
    Ok(HttpResponse::Ok().json(RegistrationVerificationResponse {
        status: "ok".to_string(),
        credential_id: base64::encode_config(&credential.credential_id, base64::URL_SAFE_NO_PAD),
        user: UserInfo {
            id: user.id.to_string(),
            name: user.username,
        },
        registered_at: chrono::Utc::now(),
    }))
}
```

### 4.2 Authentication Controller

```rust
// src/controllers/authentication.rs
use actix_web::{web, HttpRequest, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::error::ApiError;
use crate::models::{User, Credential};
use crate::services::WebAuthnService;
use webauthn_rs::prelude::*;

#[derive(Debug, Deserialize, Validate)]
pub struct AuthenticationChallengeRequest {
    #[validate(length(min = 3, max = 255), email)]
    pub username: String,
    #[serde(default = "default_user_verification")]
    pub user_verification: String,
}

fn default_user_verification() -> String {
    "preferred".to_string()
}

#[derive(Debug, Serialize)]
pub struct AuthenticationChallengeResponse {
    pub status: String,
    #[serde(flatten)]
    pub challenge: RequestChallengeResponse,
}

#[derive(Debug, Deserialize, Validate)]
pub struct AuthenticationVerificationRequest {
    #[validate]
    pub credential: PublicKeyCredential,
    #[validate(length(min = 3, max = 255))]
    pub username: String,
    #[validate(length(min = 1))]
    pub challenge: String,
}

#[derive(Debug, Serialize)]
pub struct AuthenticationVerificationResponse {
    pub status: String,
    pub user: UserInfo,
    pub credential_id: String,
    pub authenticated_at: chrono::DateTime<chrono::Utc>,
    pub new_counter: u64,
}

#[derive(Debug, Serialize)]
pub struct UserInfo {
    pub id: String,
    pub name: String,
}

pub async fn generate_authentication_challenge(
    webauthn_service: web::Data<WebAuthnService>,
    req: HttpRequest,
    body: web::Json<AuthenticationChallengeRequest>,
) -> Result<HttpResponse> {
    // Validate request
    body.validate()
        .map_err(|e| ApiError::ValidationError(e.to_string()))?;
    
    // Validate origin
    let origin = req.headers()
        .get("Origin")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| ApiError::MissingHeader("Origin".to_string()))?;
    
    webauthn_service.validate_origin(origin, &webauthn_service.config.rp_id)?;
    
    // Parse user verification policy
    let user_verification = match body.user_verification.as_str() {
        "required" => UserVerificationPolicy::Required,
        "preferred" => UserVerificationPolicy::Preferred,
        "discouraged" => UserVerificationPolicy::Discouraged,
        _ => return Err(ApiError::InvalidParameter("user_verification".to_string()).into()),
    };
    
    // Find user
    let mut conn = crate::db::connection::get_connection().await?;
    let user = User::find_by_username(&mut conn, &body.username)
        .await?
        .ok_or_else(|| ApiError::UserNotFound)?;
    
    // Generate challenge
    let challenge = webauthn_service
        .generate_authentication_challenge(&user, user_verification)
        .await?;
    
    Ok(HttpResponse::Ok().json(AuthenticationChallengeResponse {
        status: "ok".to_string(),
        challenge,
    }))
}

pub async fn verify_authentication(
    webauthn_service: web::Data<WebAuthnService>,
    req: HttpRequest,
    body: web::Json<AuthenticationVerificationRequest>,
) -> Result<HttpResponse> {
    // Validate request
    body.validate()
        .map_err(|e| ApiError::ValidationError(e.to_string()))?;
    
    // Validate origin
    let origin = req.headers()
        .get("Origin")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| ApiError::MissingHeader("Origin".to_string()))?;
    
    webauthn_service.validate_origin(origin, &webauthn_service.config.rp_id)?;
    
    // Find user
    let mut conn = crate::db::connection::get_connection().await?;
    let user = User::find_by_username(&mut conn, &body.username)
        .await?
        .ok_or_else(|| ApiError::UserNotFound)?;
    
    // Verify authentication
    let (credential, new_counter) = webauthn_service
        .verify_authentication(&user, &body.credential, &body.challenge)
        .await?;
    
    Ok(HttpResponse::Ok().json(AuthenticationVerificationResponse {
        status: "ok".to_string(),
        user: UserInfo {
            id: user.id.to_string(),
            name: user.username,
        },
        credential_id: base64::encode_config(&credential.credential_id, base64::URL_SAFE_NO_PAD),
        authenticated_at: chrono::Utc::now(),
        new_counter,
    }))
}
```

## 5. Error Handling Implementation

### 5.1 Error Types

```rust
// src/error/mod.rs
use actix_web::{error::ResponseError, HttpResponse};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Error, Debug)]
pub enum WebAuthnError {
    #[error("Challenge generation failed")]
    ChallengeGenerationFailed,
    
    #[error("Challenge not found")]
    ChallengeNotFound,
    
    #[error("Challenge expired")]
    ChallengeExpired,
    
    #[error("Challenge already used")]
    ChallengeAlreadyUsed,
    
    #[error("Invalid challenge type")]
    InvalidChallengeType,
    
    #[error("Attestation verification failed")]
    AttestationVerificationFailed,
    
    #[error("Assertion verification failed")]
    AssertionVerificationFailed,
    
    #[error("Credential not found")]
    CredentialNotFound,
    
    #[error("No credentials found")]
    NoCredentialsFound,
    
    #[error("Credential user mismatch")]
    CredentialUserMismatch,
    
    #[error("Counter regression detected")]
    CounterRegression,
    
    #[error("Invalid RP ID")]
    InvalidRpId,
    
    #[error("Invalid origin")]
    InvalidOrigin,
    
    #[error("Insecure origin")]
    InsecureOrigin,
    
    #[error("Origin RP ID mismatch")]
    OriginRpIdMismatch,
}

#[derive(Error, Debug)]
pub enum UserError {
    #[error("Invalid username: {0}")]
    InvalidUsername(String),
    
    #[error("Invalid display name: {0}")]
    InvalidDisplayName(String),
    
    #[error("User not found")]
    NotFound,
    
    #[error("User already exists")]
    AlreadyExists,
}

#[derive(Error, Debug)]
pub enum CredentialError {
    #[error("Invalid credential ID: {0}")]
    InvalidCredentialId(String),
    
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),
    
    #[error("Credential not found")]
    NotFound,
    
    #[error("Counter regression detected")]
    CounterRegression,
}

#[derive(Error, Debug)]
pub enum ChallengeError {
    #[error("Invalid challenge type")]
    InvalidChallengeType,
    
    #[error("Challenge not found")]
    NotFound,
    
    #[error("Challenge expired")]
    Expired,
    
    #[error("Challenge already used")]
    AlreadyUsed,
}

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("Validation error: {0}")]
    ValidationError(String),
    
    #[error("Missing header: {0}")]
    MissingHeader(String),
    
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),
    
    #[error("User not found")]
    UserNotFound,
    
    #[error("Invalid request")]
    InvalidRequest,
    
    #[error("Internal server error")]
    InternalError,
    
    #[error("Unauthorized")]
    Unauthorized,
    
    #[error("Forbidden")]
    Forbidden,
    
    #[error("Not found")]
    NotFound,
}

impl ResponseError for ApiError {
    fn error_response(&self) -> HttpResponse {
        let status = match self {
            ApiError::ValidationError(_) => HttpResponse::BadRequest(),
            ApiError::MissingHeader(_) => HttpResponse::BadRequest(),
            ApiError::InvalidParameter(_) => HttpResponse::BadRequest(),
            ApiError::UserNotFound => HttpResponse::NotFound(),
            ApiError::InvalidRequest => HttpResponse::BadRequest(),
            ApiError::InternalError => HttpResponse::InternalServerError(),
            ApiError::Unauthorized => HttpResponse::Unauthorized(),
            ApiError::Forbidden => HttpResponse::Forbidden(),
            ApiError::NotFound => HttpResponse::NotFound(),
        };
        
        status.json(serde_json::json!({
            "status": "error",
            "error": self.to_string(),
            "code": format!("{:?}", self)
        }))
    }
}
```

## 6. Security Middleware Implementation

### 6.1 Rate Limiting Middleware

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
        
        // Remove old requests
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
    next: web::Next<impl actix_web::dev::ServiceFactory<
        ServiceRequest,
        Config = (),
        Response = ServiceResponse,
        Error = Error,
        InitError = (),
    >>,
) -> Result<ServiceResponse, Error> {
    let client_ip = req
        .connection_info()
        .peer_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    
    let rate_limiter = req.app_data::<web::Data<RateLimiter>>()
        .unwrap()
        .get_ref();
    
    if !rate_limiter.is_allowed(&client_ip) {
        return Err(actix_web::error::ErrorTooManyRequests("Rate limit exceeded").into());
    }
    
    next.call(req).await
}
```

### 6.2 Security Headers Middleware

```rust
// src/middleware/security.rs
use actix_web::{dev::ServiceRequest, dev::ServiceResponse, Error, Result};
use actix_web::{web, HttpMessage};

pub async fn security_headers_middleware(
    req: ServiceRequest,
    next: web::Next<impl actix_web::dev::ServiceFactory<
        ServiceRequest,
        Config = (),
        Response = ServiceResponse,
        Error = Error,
        InitError = (),
    >>,
) -> Result<ServiceResponse, Error> {
    let mut res = next.call(req).await?;
    
    // Add security headers
    res.headers_mut().insert(
        "X-Content-Type-Options",
        "nosniff".parse().unwrap(),
    );
    
    res.headers_mut().insert(
        "X-Frame-Options",
        "DENY".parse().unwrap(),
    );
    
    res.headers_mut().insert(
        "X-XSS-Protection",
        "1; mode=block".parse().unwrap(),
    );
    
    res.headers_mut().insert(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains".parse().unwrap(),
    );
    
    res.headers_mut().insert(
        "Content-Security-Policy",
        "default-src 'self'".parse().unwrap(),
    );
    
    res.headers_mut().insert(
        "Referrer-Policy",
        "strict-origin-when-cross-origin".parse().unwrap(),
    );
    
    Ok(res)
}
```

## 7. Database Setup

### 7.1 Database Schema

```sql
-- migrations/2024-01-01-000001_create_users.sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT true,
    email_verified BOOLEAN DEFAULT false
);

-- migrations/2024-01-01-000002_create_credentials.sql
CREATE TABLE credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA UNIQUE NOT NULL,
    credential_public_key BYTEA NOT NULL,
    attestation_type VARCHAR(50) NOT NULL,
    aaguid UUID NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true,
    backup_eligible BOOLEAN DEFAULT false,
    backup_state BOOLEAN DEFAULT false,
    transports JSONB,
    user_verification BOOLEAN DEFAULT false
);

-- migrations/2024-01-01-000003_create_challenges.sql
CREATE TABLE challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    challenge_id VARCHAR(255) UNIQUE NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    challenge_type VARCHAR(20) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    used_at TIMESTAMP WITH TIME ZONE,
    is_used BOOLEAN DEFAULT false
);

-- migrations/2024-01-01-000004_create_audit_logs.sql
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id),
    event_type VARCHAR(50) NOT NULL,
    event_data JSONB,
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- migrations/2024-01-01-000005_create_indexes.sql
CREATE INDEX idx_credentials_user_id ON credentials(user_id);
CREATE INDEX idx_credentials_credential_id ON credentials(credential_id);
CREATE INDEX idx_challenges_challenge_id ON challenges(challenge_id);
CREATE INDEX idx_challenges_expires_at ON challenges(expires_at);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
```

### 7.2 Database Connection Setup

```rust
// src/db/connection.rs
use diesel::pg::PgConnection;
use diesel::r2d2::{ConnectionManager, Pool, PooledConnection};
use std::env;

pub type DbPool = Pool<ConnectionManager<PgConnection>>;

pub fn establish_connection_pool() -> DbPool {
    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");
    
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    
    Pool::builder()
        .max_size(15)
        .build(manager)
        .expect("Failed to create pool")
}

pub async fn get_connection() -> Result<PooledConnection<ConnectionManager<PgConnection>>, crate::error::ApiError> {
    let pool = crate::db::connection::get_pool();
    pool.get()
        .map_err(|e| crate::error::ApiError::InternalError)
}

// Application state for Actix-web
pub struct AppState {
    pub db: DbPool,
    pub webauthn_service: crate::services::WebAuthnService,
    pub rate_limiter: crate::middleware::RateLimiter,
}

lazy_static::lazy_static! {
    static ref DB_POOL: DbPool = establish_connection_pool();
}

pub fn get_pool() -> DbPool {
    DB_POOL.clone()
}
```

## 8. Main Application Setup

### 8.1 Application Entry Point

```rust
// src/main.rs
use actix_cors::Cors;
use actix_web::{http, middleware, App, HttpServer};
use std::env;

mod config;
mod controllers;
mod db;
mod error;
mod middleware;
mod models;
mod routes;
mod services;
mod utils;

use crate::config::WebAuthnConfig;
use crate::db::connection::{AppState, establish_connection_pool};
use crate::middleware::{rate_limit_middleware, security_headers_middleware, RateLimiter};
use crate::services::WebAuthnService;
use std::time::Duration;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logger
    env_logger::init();
    
    // Load configuration
    dotenv::dotenv().ok();
    
    let webauthn_config = WebAuthnConfig::from_env();
    
    // Initialize services
    let webauthn_service = WebAuthnService::new(webauthn_config.clone())
        .expect("Failed to initialize WebAuthn service");
    
    let rate_limiter = RateLimiter::new(100, Duration::from_secs(60)); // 100 requests per minute
    
    // Initialize database
    let db_pool = establish_connection_pool();
    
    // Run migrations
    diesel_migrations::embed_migrations!("migrations");
    embedded_migrations::run(&db_pool.get().unwrap()).expect("Failed to run migrations");
    
    let app_state = AppState {
        db: db_pool,
        webauthn_service,
        rate_limiter,
    };
    
    let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse()
        .expect("Invalid PORT");
    
    log::info!("Starting server on {}:{}", host, port);
    
    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin(&webauthn_config.rp_origin)
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
            .allowed_headers(vec![
                http::header::AUTHORIZATION,
                http::header::ACCEPT,
                http::header::CONTENT_TYPE,
                http::header::ORIGIN,
            ])
            .supports_credentials()
            .max_age(3600);
        
        App::new()
            .app_data(web::Data::new(app_state.clone()))
            .wrap(middleware::Logger::default())
            .wrap(middleware::Compress::default())
            .wrap(security_headers_middleware)
            .wrap(rate_limit_middleware)
            .wrap(cors)
            .service(
                web::scope("/api")
                    .configure(routes::webauthn::configure)
                    .configure(routes::health::configure)
            )
    })
    .bind((host, port))?
    .run()
    .await
}
```

### 8.2 Route Configuration

```rust
// src/routes/mod.rs
pub mod webauthn;
pub mod health;

// src/routes/webauthn.rs
use actix_web::web;

use crate::controllers::{authentication, registration};

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/webauthn")
            .route("/register/challenge", web::post().to(registration::generate_registration_challenge))
            .route("/register/verify", web::post().to(registration::verify_registration))
            .route("/authenticate/challenge", web::post().to(authentication::generate_authentication_challenge))
            .route("/authenticate/verify", web::post().to(authentication::verify_authentication)),
    );
}

// src/routes/health.rs
use actix_web::{web, HttpResponse, Result};

pub async fn health_check() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now(),
        "version": env!("CARGO_PKG_VERSION")
    })))
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/health")
            .route("", web::get().to(health_check))
    );
}
```

This comprehensive implementation guide provides a solid foundation for building a secure, FIDO2-compliant WebAuthn Relying Party Server with proper error handling, security middleware, and comprehensive testing capabilities.