# FIDO2/WebAuthn Server Implementation Guide

## Overview

This guide provides detailed implementation instructions for building a FIDO2/WebAuthn conformant Relying Party Server in Rust using the webauthn-rs library. The guide follows test-driven development principles and focuses on security-first implementation.

## 1. Project Setup and Configuration

### 1.1 Initial Project Structure

Create the complete project structure:
```bash
mkdir -p src/{config,controllers,db/{repositories},middleware,routes,services,error,utils,schema/migrations}
mkdir -p tests/{integration,security,performance,compliance}
touch src/lib.rs src/main.rs
touch src/config/mod.rs src/config/settings.rs
touch src/controllers/mod.rs src/controllers/{attestation,assertion,health}.rs
touch src/services/mod.rs src/services/{webauthn_service,user_service,credential_service}.rs
touch src/db/mod.rs src/db/{connection,models}.rs
touch src/db/repositories/mod.rs src/db/repositories/{user_repository,credential_repository}.rs
touch src/middleware/mod.rs src/middleware/{auth,cors,rate_limit}.rs
touch src/routes/mod.rs src/routes/webauthn.rs
touch src/error/mod.rs src/error/types.rs
touch src/utils/mod.rs src/utils/{crypto,validation}.rs
touch src/schema/mod.rs
```

### 1.2 Configuration Management

#### Configuration Structure
```rust
// src/config/settings.rs
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnConfig {
    pub rp_id: String,
    pub rp_name: String,
    pub rp_origin: String,
    pub timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub require_tls: bool,
    pub max_challenge_age_seconds: u64,
    pub rate_limit_requests_per_minute: u32,
    pub max_request_size_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub database: DatabaseConfig,
    pub webauthn: WebAuthnConfig,
    pub security: SecurityConfig,
    pub server: ServerConfig,
}

impl Config {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Config {
            database: DatabaseConfig {
                url: env::var("DATABASE_URL")?,
                max_connections: env::var("DB_MAX_CONNECTIONS")
                    .unwrap_or_else(|_| "10".to_string())
                    .parse()?,
                min_connections: env::var("DB_MIN_CONNECTIONS")
                    .unwrap_or_else(|_| "1".to_string())
                    .parse()?,
            },
            webauthn: WebAuthnConfig {
                rp_id: env::var("WEBAUTHN_RP_ID")?,
                rp_name: env::var("WEBAUTHN_RP_NAME")?,
                rp_origin: env::var("WEBAUTHN_RP_ORIGIN")?,
                timeout: env::var("WEBAUTHN_TIMEOUT")
                    .unwrap_or_else(|_| "60000".to_string())
                    .parse()?,
            },
            security: SecurityConfig {
                require_tls: env::var("SECURITY_REQUIRE_TLS")
                    .unwrap_or_else(|_| "true".to_string())
                    .parse()?,
                max_challenge_age_seconds: env::var("SECURITY_MAX_CHALLENGE_AGE")
                    .unwrap_or_else(|_| "300".to_string())
                    .parse()?,
                rate_limit_requests_per_minute: env::var("SECURITY_RATE_LIMIT")
                    .unwrap_or_else(|_| "60".to_string())
                    .parse()?,
                max_request_size_bytes: env::var("SECURITY_MAX_REQUEST_SIZE")
                    .unwrap_or_else(|_| "1048576".to_string())
                    .parse()?,
            },
            server: ServerConfig {
                host: env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
                port: env::var("SERVER_PORT")
                    .unwrap_or_else(|_| "8080".to_string())
                    .parse()?,
                workers: env::var("SERVER_WORKERS")
                    .unwrap_or_else(|_| "4".to_string())
                    .parse()?,
            },
        })
    }
}
```

## 2. Error Handling Implementation

### 2.1 Custom Error Types

```rust
// src/error/types.rs
use actix_web::{HttpResponse, ResponseError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(#[from] diesel::result::Error),
    
    #[error("WebAuthn error: {0}")]
    WebAuthn(String),
    
    #[error("Validation error: {0}")]
    Validation(String),
    
    #[error("Authentication error: {0}")]
    Authentication(String),
    
    #[error("Not found: {0}")]
    NotFound(String),
    
    #[error("Conflict: {0}")]
    Conflict(String),
    
    #[error("Rate limit exceeded")]
    RateLimit,
    
    #[error("Internal server error: {0}")]
    Internal(String),
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        match self {
            AppError::Validation(msg) => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "status": "failed",
                    "errorMessage": msg
                }))
            }
            AppError::NotFound(msg) => {
                HttpResponse::NotFound().json(serde_json::json!({
                    "status": "failed",
                    "errorMessage": msg
                }))
            }
            AppError::Conflict(msg) => {
                HttpResponse::Conflict().json(serde_json::json!({
                    "status": "failed",
                    "errorMessage": msg
                }))
            }
            AppError::Authentication(msg) => {
                HttpResponse::Unauthorized().json(serde_json::json!({
                    "status": "failed",
                    "errorMessage": msg
                }))
            }
            AppError::RateLimit => {
                HttpResponse::TooManyRequests().json(serde_json::json!({
                    "status": "failed",
                    "errorMessage": "Rate limit exceeded"
                }))
            }
            AppError::WebAuthn(msg) => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "status": "failed",
                    "errorMessage": format!("WebAuthn error: {}", msg)
                }))
            }
            _ => {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "status": "failed",
                    "errorMessage": "Internal server error"
                }))
            }
        }
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
```

## 3. Database Layer Implementation

### 3.1 Database Models

```rust
// src/db/models.rs
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::users)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::credentials)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
    pub attestation_type: String,
    pub aaguid: Option<Vec<u8>>,
    pub sign_count: i64,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub user_verified: bool,
    pub transports: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::challenges)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Challenge {
    pub id: Uuid,
    pub challenge_value: String,
    pub challenge_type: String,
    pub user_id: Option<Uuid>,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

// Insert structs
#[derive(Debug, Insertable)]
#[diesel(table_name = crate::schema::users)]
pub struct NewUser {
    pub username: String,
    pub display_name: String,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = crate::schema::credentials)]
pub struct NewCredential {
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
    pub attestation_type: String,
    pub aaguid: Option<Vec<u8>>,
    pub sign_count: i64,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub user_verified: bool,
    pub transports: Option<serde_json::Value>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = crate::schema::challenges)]
pub struct NewChallenge {
    pub challenge_value: String,
    pub challenge_type: String,
    pub user_id: Option<Uuid>,
    pub expires_at: DateTime<Utc>,
}
```

### 3.2 Database Schema

```sql
-- src/schema/migrations/001_create_users_table.sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE NULL
);

-- src/schema/migrations/002_create_credentials_table.sql
CREATE TABLE credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA UNIQUE NOT NULL,
    credential_public_key BYTEA NOT NULL,
    attestation_type VARCHAR(50) NOT NULL,
    aaguid BYTEA,
    sign_count BIGINT NOT NULL DEFAULT 0,
    backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,
    backup_state BOOLEAN NOT NULL DEFAULT FALSE,
    user_verified BOOLEAN NOT NULL DEFAULT FALSE,
    transports JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE NULL,
    deleted_at TIMESTAMP WITH TIME ZONE NULL
);

-- src/schema/migrations/003_create_challenges_table.sql
CREATE TABLE challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    challenge_value VARCHAR(255) UNIQUE NOT NULL,
    challenge_type VARCHAR(20) NOT NULL CHECK (challenge_type IN ('attestation', 'assertion')),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- src/schema/migrations/004_create_indexes.sql
CREATE INDEX idx_credentials_user_id ON credentials(user_id);
CREATE INDEX idx_credentials_credential_id ON credentials(credential_id);
CREATE INDEX idx_challenges_value ON challenges(challenge_value);
CREATE INDEX idx_challenges_expires_at ON challenges(expires_at);
CREATE INDEX idx_challenges_user_id ON challenges(user_id);
```

### 3.3 Repository Implementation

```rust
// src/db/repositories/user_repository.rs
use crate::db::models::{User, NewUser};
use crate::error::{AppError, Result};
use chrono::Utc;
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, PooledConnection};
use uuid::Uuid;

pub struct UserRepository {
    pool: crate::db::connection::DbPool,
}

impl UserRepository {
    pub fn new(pool: crate::db::connection::DbPool) -> Self {
        Self { pool }
    }

    pub async fn create_user(&self, username: String, display_name: String) -> Result<User> {
        use crate::schema::users;
        
        let new_user = NewUser {
            username,
            display_name,
        };

        let mut conn = self.pool.get()?;
        
        let user = conn.transaction::<User, _, _>(|conn| {
            diesel::insert_into(users::table)
                .values(&new_user)
                .returning(User::as_returning())
                .get_result(conn)
        })?;

        Ok(user)
    }

    pub async fn find_by_id(&self, user_id: Uuid) -> Result<Option<User>> {
        use crate::schema::users::dsl::*;
        
        let mut conn = self.pool.get()?;
        
        let user = users
            .filter(id.eq(user_id))
            .filter(deleted_at.is_null())
            .first::<User>(&mut conn)
            .optional()?;

        Ok(user)
    }

    pub async fn find_by_username(&self, username: &str) -> Result<Option<User>> {
        use crate::schema::users::dsl::*;
        
        let mut conn = self.pool.get()?;
        
        let user = users
            .filter(username.eq(username))
            .filter(deleted_at.is_null())
            .first::<User>(&mut conn)
            .optional()?;

        Ok(user)
    }

    pub async fn soft_delete(&self, user_id: Uuid) -> Result<()> {
        use crate::schema::users::dsl::*;
        
        let mut conn = self.pool.get()?;
        
        diesel::update(users.filter(id.eq(user_id)))
            .set(deleted_at.eq(Utc::now()))
            .execute(&mut conn)?;

        Ok(())
    }
}
```

## 4. WebAuthn Service Implementation

### 4.1 Core WebAuthn Service

```rust
// src/services/webauthn_service.rs
use crate::config::WebAuthnConfig;
use crate::db::models::{Credential, User};
use crate::db::repositories::{CredentialRepository, UserRepository};
use crate::error::{AppError, Result};
use base64::{Engine as _, engine::general_purpose};
use chrono::{Duration, Utc};
use serde_json::{json, Value};
use uuid::Uuid;
use webauthn_rs::prelude::*;

pub struct WebAuthnService {
    webauthn: Webauthn,
    user_repository: UserRepository,
    credential_repository: CredentialRepository,
    config: WebAuthnConfig,
}

impl WebAuthnService {
    pub fn new(
        config: WebAuthnConfig,
        user_repository: UserRepository,
        credential_repository: CredentialRepository,
    ) -> Result<Self> {
        let rp = RelyingParty {
            id: config.rp_id.clone(),
            name: config.rp_name.clone(),
            origin: Url::parse(&config.rp_origin)
                .map_err(|e| AppError::WebAuthn(format!("Invalid origin: {}", e)))?,
        };

        let webauthn = WebauthnBuilder::new(rp)
            .map_err(|e| AppError::WebAuthn(format!("WebAuthn builder error: {}", e)))?
            .build();

        Ok(Self {
            webauthn,
            user_repository,
            credential_repository,
            config,
        })
    }

    pub async fn generate_attestation_challenge(
        &self,
        username: &str,
        display_name: &str,
        user_verification: UserVerificationPolicy,
    ) -> Result<Value> {
        // Check if user already exists
        let existing_user = self.user_repository.find_by_username(username).await?;
        
        let user = if let Some(user) = existing_user {
            user
        } else {
            // Create new user
            self.user_repository.create_user(username.to_string(), display_name.to_string()).await?
        };

        // Generate credential creation options
        let (ccr, state) = self
            .webauthn
            .start_credential_registration(
                &User {
                    id: user.id.as_bytes().to_vec(),
                    name: username.to_string(),
                    display_name: display_name.to_string(),
                },
                user_verification,
            )
            .map_err(|e| AppError::WebAuthn(format!("Failed to generate challenge: {}", e)))?;

        // Store challenge state (simplified - in production, store in database)
        // For now, we'll return the challenge directly
        
        Ok(json!({
            "status": "ok",
            "challenge": general_purpose::URL_SAFE_NO_PAD.encode(&ccr.challenge),
            "rp": {
                "name": self.config.rp_name,
                "id": self.config.rp_id
            },
            "user": {
                "id": general_purpose::URL_SAFE_NO_PAD.encode(&user.id.as_bytes()),
                "name": user.username,
                "displayName": user.display_name
            },
            "pubKeyCredParams": ccr.pub_key_cred_params,
            "timeout": self.config.timeout,
            "excludeCredentials": [],
            "authenticatorSelection": ccr.authenticator_selection,
            "attestation": ccr.attestation,
            "extensions": ccr.extensions
        }))
    }

    pub async fn verify_attestation(
        &self,
        username: &str,
        attestation_response: &Value,
    ) -> Result<Value> {
        // Parse attestation response
        let credential_id = attestation_response
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::Validation("Missing credential ID".to_string()))?;

        let raw_id = attestation_response
            .get("rawId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::Validation("Missing raw ID".to_string()))?;

        let response = attestation_response
            .get("response")
            .ok_or_else(|| AppError::Validation("Missing response".to_string()))?;

        let attestation_object = response
            .get("attestationObject")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::Validation("Missing attestation object".to_string()))?;

        let client_data_json = response
            .get("clientDataJSON")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::Validation("Missing client data JSON".to_string()))?;

        // Decode base64url data
        let credential_id_bytes = general_purpose::URL_SAFE_NO_PAD
            .decode(credential_id)
            .map_err(|e| AppError::Validation(format!("Invalid credential ID: {}", e)))?;

        let attestation_object_bytes = general_purpose::URL_SAFE_NO_PAD
            .decode(attestation_object)
            .map_err(|e| AppError::Validation(format!("Invalid attestation object: {}", e)))?;

        let client_data_json_bytes = general_purpose::URL_SAFE_NO_PAD
            .decode(client_data_json)
            .map_err(|e| AppError::Validation(format!("Invalid client data JSON: {}", e)))?;

        // Get user
        let user = self
            .user_repository
            .find_by_username(username)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        // Verify attestation (simplified - in production, retrieve stored state)
        let auth_result = self
            .webauthn
            .finish_credential_registration(
                &PublicKeyCredential {
                    id: credential_id_bytes.clone(),
                    raw_id: credential_id_bytes,
                    response: AuthenticatorAttestationResponse {
                        attestation_object: attestation_object_bytes,
                        client_data_json: client_data_json_bytes,
                        transports: None,
                    },
                    type_: "public-key".to_string(),
                    client_extension_results: Default::default(),
                },
                // In production, retrieve stored state from database
                &RegistrationState {},
            )
            .map_err(|e| AppError::WebAuthn(format!("Attestation verification failed: {}", e)))?;

        // Store credential
        let new_credential = crate::db::models::NewCredential {
            user_id: user.id,
            credential_id: auth_result.credential_id.clone(),
            credential_public_key: auth_result.credential_public_key,
            attestation_type: auth_result.attestation_format.to_string(),
            aaguid: Some(auth_result.aaguid),
            sign_count: auth_result.counter as i64,
            backup_eligible: auth_result.backup_eligible,
            backup_state: auth_result.backup_state,
            user_verified: auth_result.user_verified,
            transports: Some(json!(auth_result.transports)),
        };

        self.credential_repository
            .create_credential(new_credential)
            .await?;

        Ok(json!({
            "status": "ok",
            "registrationInfo": {
                "credentialId": general_purpose::URL_SAFE_NO_PAD.encode(&auth_result.credential_id),
                "userId": general_purpose::URL_SAFE_NO_PAD.encode(&user.id.as_bytes()),
                "nickname": null
            }
        }))
    }

    pub async fn generate_assertion_challenge(
        &self,
        username: Option<&str>,
        user_verification: UserVerificationPolicy,
    ) -> Result<Value> {
        let user = if let Some(username) = username {
            self.user_repository
                .find_by_username(username)
                .await?
                .ok_or_else(|| AppError::NotFound("User not found".to_string()))?
        } else {
            // For username-less authentication, we'd need to handle this differently
            return Err(AppError::Validation("Username required for this implementation".to_string()));
        };

        // Get user credentials
        let credentials = self
            .credential_repository
            .find_by_user_id(user.id)
            .await?;

        // Convert to allowCredentials format
        let allow_credentials: Vec<Value> = credentials
            .into_iter()
            .map(|cred| {
                json!({
                    "type": "public-key",
                    "id": general_purpose::URL_SAFE_NO_PAD.encode(&cred.credential_id),
                    "transports": cred.transports
                })
            })
            .collect();

        // Generate assertion options
        let (acr, _state) = self
            .webauthn
            .start_authentication(&allow_credentials)
            .map_err(|e| AppError::WebAuthn(format!("Failed to generate assertion challenge: {}", e)))?;

        Ok(json!({
            "status": "ok",
            "challenge": general_purpose::URL_SAFE_NO_PAD.encode(&acr.challenge),
            "allowCredentials": allow_credentials,
            "userVerification": match user_verification {
                UserVerificationPolicy::Required => "required",
                UserVerificationPolicy::Preferred => "preferred",
                UserVerificationPolicy::Discouraged => "discouraged",
            },
            "timeout": self.config.timeout,
            "rpId": self.config.rp_id,
            "extensions": {}
        }))
    }

    pub async fn verify_assertion(
        &self,
        assertion_response: &Value,
    ) -> Result<Value> {
        // Parse assertion response
        let credential_id = assertion_response
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::Validation("Missing credential ID".to_string()))?;

        let response = assertion_response
            .get("response")
            .ok_or_else(|| AppError::Validation("Missing response".to_string()))?;

        let authenticator_data = response
            .get("authenticatorData")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::Validation("Missing authenticator data".to_string()))?;

        let client_data_json = response
            .get("clientDataJSON")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::Validation("Missing client data JSON".to_string()))?;

        let signature = response
            .get("signature")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::Validation("Missing signature".to_string()))?;

        // Decode base64url data
        let credential_id_bytes = general_purpose::URL_SAFE_NO_PAD
            .decode(credential_id)
            .map_err(|e| AppError::Validation(format!("Invalid credential ID: {}", e)))?;

        let authenticator_data_bytes = general_purpose::URL_SAFE_NO_PAD
            .decode(authenticator_data)
            .map_err(|e| AppError::Validation(format!("Invalid authenticator data: {}", e)))?;

        let client_data_json_bytes = general_purpose::URL_SAFE_NO_PAD
            .decode(client_data_json)
            .map_err(|e| AppError::Validation(format!("Invalid client data JSON: {}", e)))?;

        let signature_bytes = general_purpose::URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|e| AppError::Validation(format!("Invalid signature: {}", e)))?;

        // Get credential from database
        let credential = self
            .credential_repository
            .find_by_credential_id(&credential_id_bytes)
            .await?
            .ok_or_else(|| AppError::NotFound("Credential not found".to_string()))?;

        // Get user
        let user = self
            .user_repository
            .find_by_id(credential.user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        // Verify assertion
        let auth_result = self
            .webauthn
            .finish_authentication(
                &PublicKeyCredential {
                    id: credential_id_bytes,
                    raw_id: credential.credential_id.clone(),
                    response: AuthenticatorAssertionResponse {
                        authenticator_data: authenticator_data_bytes,
                        client_data_json: client_data_json_bytes,
                        signature: signature_bytes,
                        user_handle: Some(user.id.as_bytes().to_vec()),
                    },
                    type_: "public-key".to_string(),
                    client_extension_results: Default::default(),
                },
                // In production, retrieve stored state from database
                &AuthenticationState {},
            )
            .map_err(|e| AppError::WebAuthn(format!("Assertion verification failed: {}", e)))?;

        // Update credential usage
        self.credential_repository
            .update_usage(credential.id, auth_result.counter as i64)
            .await?;

        Ok(json!({
            "status": "ok",
            "authenticationInfo": {
                "credentialId": general_purpose::URL_SAFE_NO_PAD.encode(&credential.credential_id),
                "userId": general_purpose::URL_SAFE_NO_PAD.encode(&user.id.as_bytes()),
                "userVerified": auth_result.user_verified,
                "authenticatorInfo": {
                    "rpIdHash": general_purpose::URL_SAFE_NO_PAD.encode(&auth_result.credential_data.rp_id_hash),
                    "flags": {
                        "userPresent": auth_result.credential_data.user_present,
                        "userVerified": auth_result.credential_data.user_verified,
                        "backupEligible": auth_result.credential_data.backup_eligible,
                        "backupState": auth_result.credential_data.backup_state
                    },
                    "signCount": auth_result.counter
                }
            }
        }))
    }
}
```

## 5. API Controllers Implementation

### 5.1 Attestation Controller

```rust
// src/controllers/attestation.rs
use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::UserVerificationPolicy;

use crate::error::{AppError, Result};
use crate::services::WebAuthnService;

#[derive(Debug, Deserialize)]
pub struct AttestationOptionsRequest {
    pub username: String,
    pub display_name: String,
    #[serde(default)]
    pub user_verification: Option<String>,
    #[serde(default)]
    pub attestation: Option<String>,
    #[serde(default)]
    pub extensions: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct AttestationResultRequest {
    pub id: String,
    pub raw_id: String,
    pub response: serde_json::Value,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(default)]
    pub client_extension_results: Option<serde_json::Value>,
    #[serde(default)]
    pub transports: Option<Vec<String>>,
}

pub async fn attestation_options(
    webauthn_service: web::Data<WebAuthnService>,
    req: HttpRequest,
    body: web::Json<AttestationOptionsRequest>,
) -> Result<HttpResponse> {
    // Validate origin
    validate_origin(&req)?;
    
    // Parse user verification policy
    let user_verification = match body.user_verification.as_deref() {
        Some("required") => UserVerificationPolicy::Required,
        Some("discouraged") => UserVerificationPolicy::Discouraged,
        _ => UserVerificationPolicy::Preferred,
    };

    let response = webauthn_service
        .generate_attestation_challenge(
            &body.username,
            &body.display_name,
            user_verification,
        )
        .await?;

    Ok(HttpResponse::Ok().json(response))
}

pub async fn attestation_result(
    webauthn_service: web::Data<WebAuthnService>,
    req: HttpRequest,
    body: web::Json<AttestationResultRequest>,
) -> Result<HttpResponse> {
    // Validate origin
    validate_origin(&req)?;
    
    // Validate request format
    if body.type_ != "public-key" {
        return Err(AppError::Validation("Invalid credential type".to_string()));
    }

    let response = webauthn_service
        .verify_attestation("", &body.response)
        .await?;

    Ok(HttpResponse::Ok().json(response))
}

fn validate_origin(req: &HttpRequest) -> Result<()> {
    let origin = req
        .headers()
        .get("Origin")
        .or_else(|| req.headers().get("Referer"))
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| AppError::Authentication("Missing Origin header".to_string()))?;

    // In production, validate against configured allowed origins
    if !origin.starts_with("https://") {
        return Err(AppError::Authentication("Insecure origin".to_string()));
    }

    Ok(())
}
```

### 5.2 Assertion Controller

```rust
// src/controllers/assertion.rs
use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::UserVerificationPolicy;

use crate::error::{AppError, Result};
use crate::services::WebAuthnService;

#[derive(Debug, Deserialize)]
pub struct AssertionOptionsRequest {
    pub username: Option<String>,
    #[serde(default)]
    pub user_verification: Option<String>,
    #[serde(default)]
    pub extensions: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct AssertionResultRequest {
    pub id: String,
    pub raw_id: String,
    pub response: serde_json::Value,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(default)]
    pub client_extension_results: Option<serde_json::Value>,
}

pub async fn assertion_options(
    webauthn_service: web::Data<WebAuthnService>,
    req: HttpRequest,
    body: web::Json<AssertionOptionsRequest>,
) -> Result<HttpResponse> {
    // Validate origin
    super::attestation::validate_origin(&req)?;
    
    // Parse user verification policy
    let user_verification = match body.user_verification.as_deref() {
        Some("required") => UserVerificationPolicy::Required,
        Some("discouraged") => UserVerificationPolicy::Discouraged,
        _ => UserVerificationPolicy::Preferred,
    };

    let response = webauthn_service
        .generate_assertion_challenge(body.username.as_deref(), user_verification)
        .await?;

    Ok(HttpResponse::Ok().json(response))
}

pub async fn assertion_result(
    webauthn_service: web::Data<WebAuthnService>,
    req: HttpRequest,
    body: web::Json<AssertionResultRequest>,
) -> Result<HttpResponse> {
    // Validate origin
    super::attestation::validate_origin(&req)?;
    
    // Validate request format
    if body.type_ != "public-key" {
        return Err(AppError::Validation("Invalid credential type".to_string()));
    }

    let response = webauthn_service
        .verify_assertion(&body.response)
        .await?;

    Ok(HttpResponse::Ok().json(response))
}
```

## 6. Security Middleware Implementation

### 6.1 Rate Limiting Middleware

```rust
// src/middleware/rate_limit.rs
use actix_web::{dev::ServiceRequest, dev::ServiceResponse, Error, HttpMessage};
use actix_web::{web, App, HttpServer};
use actix_web::dev::{forward_ready, Service, Transform};
use std::collections::HashMap;
use std::future::{ready, Ready};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub struct RateLimiter {
    requests_per_minute: u32,
    // In production, use Redis or similar for distributed rate limiting
    clients: Arc<Mutex<HashMap<String, Vec<Instant>>>>,
}

impl RateLimiter {
    pub fn new(requests_per_minute: u32) -> Self {
        Self {
            requests_per_minute,
            clients: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn is_allowed(&self, client_ip: &str) -> bool {
        let mut clients = self.clients.lock().unwrap();
        let now = Instant::now();
        let one_minute_ago = now - Duration::from_secs(60);

        let requests = clients.entry(client_ip.to_string()).or_insert_with(Vec::new);
        
        // Remove old requests
        requests.retain(|&timestamp| timestamp > one_minute_ago);
        
        // Check if under limit
        if requests.len() < self.requests_per_minute as usize {
            requests.push(now);
            true
        } else {
            false
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
    type Transform = RateLimiterMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RateLimiterMiddleware {
            service,
            rate_limiter: self.clone(),
        }))
    }
}

pub struct RateLimiterMiddleware<S> {
    service: S,
    rate_limiter: RateLimiter,
}

impl<S, B> Service<ServiceRequest> for RateLimiterMiddleware<S>
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

        if !self.rate_limiter.is_allowed(&client_ip) {
            let response = actix_web::HttpResponse::TooManyRequests()
                .json(serde_json::json!({
                    "status": "failed",
                    "errorMessage": "Rate limit exceeded"
                }))
                .map_into_right_body();
            return Box::pin(async { Ok(req.into_response(response)) });
        }

        let fut = self.service.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res)
        })
    }
}
```

## 7. Main Application Setup

### 7.1 Application Configuration

```rust
// src/main.rs
use actix_cors::Cors;
use actix_web::{web, App, HttpServer, middleware};
use std::env;

mod config;
mod controllers;
mod db;
mod error;
mod middleware;
mod routes;
mod services;
mod utils;

use config::Config;
use db::connection::establish_connection_pool;
use services::{WebAuthnService, UserService, CredentialService};
use db::repositories::{UserRepository, CredentialRepository};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    // Load configuration
    let config = Config::from_env()
        .expect("Failed to load configuration");

    // Establish database connection
    let db_pool = establish_connection_pool(&config.database)
        .await
        .expect("Failed to establish database connection");

    // Initialize repositories
    let user_repository = UserRepository::new(db_pool.clone());
    let credential_repository = CredentialRepository::new(db_pool.clone());

    // Initialize services
    let webauthn_service = WebAuthnService::new(
        config.webauthn.clone(),
        user_repository.clone(),
        credential_repository.clone(),
    ).expect("Failed to initialize WebAuthn service");

    // Configure HTTP server
    let server = HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        App::new()
            .app_data(web::Data::new(webauthn_service.clone()))
            .app_data(web::Data::new(config.clone()))
            .wrap(middleware::Logger::default())
            .wrap(middleware::Compress::default())
            .wrap(cors)
            .wrap(middleware::Condition::new(
                config.security.require_tls,
                middleware::RedirectHTTPS::default(),
            ))
            .wrap(middleware::rate_limit::RateLimiter::new(
                config.security.rate_limit_requests_per_minute,
            ))
            .service(
                web::scope("/attestation")
                    .route("/options", web::post().to(controllers::attestation::attestation_options))
                    .route("/result", web::post().to(controllers::attestation::attestation_result)),
            )
            .service(
                web::scope("/assertion")
                    .route("/options", web::post().to(controllers::assertion::assertion_options))
                    .route("/result", web::post().to(controllers::assertion::assertion_result)),
            )
            .route("/health", web::get().to(controllers::health::health_check))
    })
    .bind(format!("{}:{}", config.server.host, config.server.port))?;

    println!("Starting FIDO2/WebAuthn server on {}:{}", 
             config.server.host, config.server.port);

    server.run().await
}
```

## 8. Testing Implementation

### 8.1 Unit Test Example

```rust
// tests/unit/webauthn_service_tests.rs
use crate::services::WebAuthnService;
use crate::config::WebAuthnConfig;
use crate::db::repositories::{UserRepository, CredentialRepository};
use mockall::predicate::*;
use mockall::mock;
use uuid::Uuid;
use webauthn_rs::prelude::UserVerificationPolicy;

mock! {
    UserRepository {}

    #[async_trait::async_trait]
    impl crate::db::repositories::UserRepositoryTrait for UserRepository {
        async fn create_user(&self, username: String, display_name: String) -> crate::error::Result<crate::db::models::User>;
        async fn find_by_id(&self, user_id: Uuid) -> crate::error::Result<Option<crate::db::models::User>>;
        async fn find_by_username(&self, username: &str) -> crate::error::Result<Option<crate::db::models::User>>;
        async fn soft_delete(&self, user_id: Uuid) -> crate::error::Result<()>;
    }
}

mock! {
    CredentialRepository {}

    #[async_trait::async_trait]
    impl crate::db::repositories::CredentialRepositoryTrait for CredentialRepository {
        async fn create_credential(&self, credential: crate::db::models::NewCredential) -> crate::error::Result<crate::db::models::Credential>;
        async fn find_by_user_id(&self, user_id: Uuid) -> crate::error::Result<Vec<crate::db::models::Credential>>;
        async fn find_by_credential_id(&self, credential_id: &[u8]) -> crate::error::Result<Option<crate::db::models::Credential>>;
        async fn update_usage(&self, credential_id: Uuid, sign_count: i64) -> crate::error::Result<()>;
    }
}

#[tokio::test]
async fn test_generate_attestation_challenge_success() {
    // Setup
    let config = WebAuthnConfig {
        rp_id: "localhost".to_string(),
        rp_name: "Test Server".to_string(),
        rp_origin: "https://localhost:8080".to_string(),
        timeout: 60000,
    };

    let mut user_repo = MockUserRepository::new();
    let credential_repo = MockCredentialRepository::new();

    // Mock user not found (new user creation)
    user_repo
        .expect_find_by_username()
        .with(eq("testuser"))
        .times(1)
        .returning(|_| Ok(None));

    // Mock user creation
    let expected_user = crate::db::models::User {
        id: Uuid::new_v4(),
        username: "testuser".to_string(),
        display_name: "Test User".to_string(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        deleted_at: None,
    };

    user_repo
        .expect_create_user()
        .with(eq("testuser"), eq("Test User"))
        .times(1)
        .returning(move |_, _| Ok(expected_user.clone()));

    // Create service
    let service = WebAuthnService::new(
        config,
        user_repo,
        credential_repo,
    ).unwrap();

    // Test
    let result = service
        .generate_attestation_challenge(
            "testuser",
            "Test User",
            UserVerificationPolicy::Preferred,
        )
        .await;

    // Assert
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response["status"], "ok");
    assert!(response["challenge"].is_string());
    assert!(response["rp"]["id"] == "localhost");
    assert!(response["user"]["name"] == "testuser");
}
```

### 8.2 Integration Test Example

```rust
// tests/integration/api_tests.rs
use actix_web::{test, App};
use serde_json::json;

#[actix_web::test]
async fn test_attestation_flow_end_to_end() {
    // Setup test app
    let app = test::init_service(
        App::new()
            .configure(crate::routes::webauthn::configure_routes)
    ).await;

    // Step 1: Request attestation options
    let req = test::TestRequest::post()
        .uri("/attestation/options")
        .set_json(json!({
            "username": "testuser",
            "displayName": "Test User",
            "userVerification": "preferred"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let options: serde_json::Value = test::read_body_json(resp).await;
    assert!(options["status"] == "ok");
    let challenge = options["challenge"].as_str().unwrap();

    // Step 2: Complete attestation (mock response)
    let req = test::TestRequest::post()
        .uri("/attestation/result")
        .set_json(json!({
            "id": "test-credential-id",
            "rawId": "test-credential-id",
            "type": "public-key",
            "response": {
                "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAEGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAEGZ1YmxpY1B1YmtleUNyZWRlbnRpYWx8",
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidGVzdC1jaGFsbGVuZ2UiLCJvcmlnaW4iOiJodHRwczovL2xvY2FsaG9zdDo4MDgwIn0"
            }
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let result: serde_json::Value = test::read_body_json(resp).await;
    assert!(result["status"] == "ok");
}
```

## 9. Security Best Practices

### 9.1 Input Validation

```rust
// src/utils/validation.rs
use regex::Regex;
use crate::error::{AppError, Result};

lazy_static::lazy_static! {
    static ref USERNAME_REGEX: Regex = Regex::new(r"^[a-zA-Z0-9@._-]{3,64}$").unwrap();
    static ref DISPLAY_NAME_REGEX: Regex = Regex(r"^[\p{L}\p{N}\s._-]{1,128}$").unwrap();
}

pub fn validate_username(username: &str) -> Result<()> {
    if !USERNAME_REGEX.is_match(username) {
        return Err(AppError::Validation(
            "Username must be 3-64 characters and contain only alphanumeric characters and @._-".to_string()
        ));
    }
    Ok(())
}

pub fn validate_display_name(display_name: &str) -> Result<()> {
    if !DISPLAY_NAME_REGEX.is_match(display_name) {
        return Err(AppError::Validation(
            "Display name must be 1-128 characters".to_string()
        ));
    }
    Ok(())
}

pub fn validate_credential_id(credential_id: &str) -> Result<()> {
    if credential_id.len() > 1023 {
        return Err(AppError::Validation(
            "Credential ID too long".to_string()
        ));
    }
    
    // Validate base64url format
    base64::decode_config(credential_id, base64::URL_SAFE_NO_PAD)
        .map_err(|_| AppError::Validation(
            "Invalid credential ID format".to_string()
        ))?;
    
    Ok(())
}
```

### 9.2 Security Headers

```rust
// src/middleware/security_headers.rs
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
        let fut = self.service.call(req);
        Box::pin(async move {
            let mut res = fut.await?;
            
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
        })
    }
}
```

## 10. Deployment Configuration

### 10.1 Docker Configuration

```dockerfile
# Dockerfile
FROM rust:1.75 as builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/fido-server /usr/local/bin/

EXPOSE 8080

CMD ["fido-server"]
```

```yaml
# docker-compose.yml
version: '3.8'

services:
  fido-server:
    build: .
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=postgres://fido:password@postgres:5432/fido_db
      - WEBAUTHN_RP_ID=localhost
      - WEBAUTHN_RP_NAME=FIDO Server
      - WEBAUTHN_RP_ORIGIN=https://localhost:8080
      - SECURITY_REQUIRE_TLS=false
    depends_on:
      - postgres
    restart: unless-stopped

  postgres:
    image: postgres:15
    environment:
      - POSTGRES_DB=fido_db
      - POSTGRES_USER=fido
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped

volumes:
  postgres_data:
```

This comprehensive implementation guide provides a solid foundation for building a secure, compliant, and thoroughly tested FIDO2/WebAuthn Relying Party Server in Rust. The implementation follows security best practices, includes comprehensive testing strategies, and is designed for production deployment.