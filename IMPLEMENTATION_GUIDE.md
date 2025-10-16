# FIDO2/WebAuthn Server - Implementation Guide

## Overview

This implementation guide provides detailed code examples, best practices, and step-by-step instructions for implementing a secure FIDO2/WebAuthn Relying Party Server in Rust using the webauthn-rs library.

## 1. Project Setup and Configuration

### 1.1 Core Dependencies

Ensure your `Cargo.toml` includes all necessary dependencies:

```toml
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
jsonwebtoken = "9.2"
bcrypt = "0.15"

[dev-dependencies]
actix-test = "0.1"
mockall = "0.13"
testcontainers = "0.15"
proptest = "1.4"
quickcheck = "1.0"
```

### 1.2 Configuration Structure

Create a comprehensive configuration system:

```rust
// src/config/mod.rs
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub webauthn: WebAuthnConfig,
    pub security: SecurityConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
    pub connection_timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnConfig {
    pub rp_name: String,
    pub rp_id: String,
    pub rp_origin: String,
    pub challenge_timeout: u64,
    pub max_credentials_per_user: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub jwt_secret: String,
    pub jwt_expiration: u64,
    pub bcrypt_cost: u32,
    pub rate_limit_requests: u32,
    pub rate_limit_window: u64,
}

impl Config {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        dotenv::dotenv().ok();
        
        let config = Config {
            server: ServerConfig {
                host: env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
                port: env::var("SERVER_PORT")
                    .unwrap_or_else(|_| "8080".to_string())
                    .parse()?,
                workers: env::var("SERVER_WORKERS")
                    .unwrap_or_else(|_| "4".to_string())
                    .parse()?,
            },
            database: DatabaseConfig {
                url: env::var("DATABASE_URL")
                    .unwrap_or_else(|_| "postgresql://localhost/fido_server".to_string()),
                max_connections: env::var("DB_MAX_CONNECTIONS")
                    .unwrap_or_else(|_| "10".to_string())
                    .parse()?,
                min_connections: env::var("DB_MIN_CONNECTIONS")
                    .unwrap_or_else(|_| "1".to_string())
                    .parse()?,
                connection_timeout: env::var("DB_CONNECTION_TIMEOUT")
                    .unwrap_or_else(|_| "30".to_string())
                    .parse()?,
            },
            webauthn: WebAuthnConfig {
                rp_name: env::var("WEBAUTHN_RP_NAME")
                    .unwrap_or_else(|_| "FIDO Server".to_string()),
                rp_id: env::var("WEBAUTHN_RP_ID")
                    .unwrap_or_else(|_| "localhost".to_string()),
                rp_origin: env::var("WEBAUTHN_RP_ORIGIN")
                    .unwrap_or_else(|_| "http://localhost:8080".to_string()),
                challenge_timeout: env::var("WEBAUTHN_CHALLENGE_TIMEOUT")
                    .unwrap_or_else(|_| "300".to_string())
                    .parse()?,
                max_credentials_per_user: env::var("WEBAUTHN_MAX_CREDENTIALS")
                    .unwrap_or_else(|_| "10".to_string())
                    .parse()?,
            },
            security: SecurityConfig {
                jwt_secret: env::var("JWT_SECRET")
                    .unwrap_or_else(|_| "your-secret-key".to_string()),
                jwt_expiration: env::var("JWT_EXPIRATION")
                    .unwrap_or_else(|_| "3600".to_string())
                    .parse()?,
                bcrypt_cost: env::var("BCRYPT_COST")
                    .unwrap_or_else(|_| "12".to_string())
                    .parse()?,
                rate_limit_requests: env::var("RATE_LIMIT_REQUESTS")
                    .unwrap_or_else(|_| "10".to_string())
                    .parse()?,
                rate_limit_window: env::var("RATE_LIMIT_WINDOW")
                    .unwrap_or_else(|_| "60".to_string())
                    .parse()?,
            },
        };
        
        Ok(config)
    }
}
```

## 2. WebAuthn Service Implementation

### 2.1 Core WebAuthn Service

```rust
// src/services/webauthn.rs
use crate::config::WebAuthnConfig;
use crate::error::{WebAuthnError, WebAuthnResult};
use crate::models::{Credential, User};
use base64::{Engine as _, engine::general_purpose};
use chrono::{Duration, Utc};
use rand::{thread_rng, RngCore};
use serde_json::{json, Value};
use std::collections::HashMap;
use uuid::Uuid;
use webauthn_rs::prelude::*;

pub struct WebAuthnService {
    webauthn: Webauthn,
    config: WebAuthnConfig,
    challenges: HashMap<String, ChallengeData>,
}

#[derive(Debug, Clone)]
struct ChallengeData {
    challenge: String,
    user_id: String,
    challenge_type: ChallengeType,
    expires_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Clone)]
enum ChallengeType {
    Registration,
    Authentication,
}

impl WebAuthnService {
    pub fn new(config: WebAuthnConfig) -> WebAuthnResult<Self> {
        let rp = RelyingParty {
            id: config.rp_id.clone(),
            name: config.rp_name.clone(),
            origin: Url::parse(&config.rp_origin)
                .map_err(|e| WebAuthnError::Configuration(e.to_string()))?,
        };

        let webauthn = WebauthnBuilder::new(rp)
            .map_err(|e| WebAuthnError::Configuration(e.to_string()))?
            .build();

        Ok(WebAuthnService {
            webauthn,
            config,
            challenges: HashMap::new(),
        })
    }

    pub fn generate_registration_challenge(
        &mut self,
        username: &str,
        display_name: &str,
        user_verification: UserVerificationPolicy,
        attestation: AttestationConveyancePreference,
    ) -> WebAuthnResult<RegistrationChallengeResponse> {
        // Generate secure random challenge
        let mut challenge_bytes = vec![0u8; 32];
        thread_rng().fill_bytes(&mut challenge_bytes);
        let challenge = general_purpose::URL_SAFE_NO_PAD.encode(&challenge_bytes);

        // Create user
        let user = User {
            id: Uuid::new_v4().as_bytes().to_vec(),
            name: username.to_string(),
            display_name: display_name.to_string(),
        };

        // Store challenge data
        let challenge_data = ChallengeData {
            challenge: challenge.clone(),
            user_id: username.to_string(),
            challenge_type: ChallengeType::Registration,
            expires_at: Utc::now() + Duration::seconds(self.config.challenge_timeout as i64),
        };
        self.challenges.insert(challenge.clone(), challenge_data);

        // Generate credential creation options
        let (ccr, state) = self
            .webauthn
            .start_registration(
                &user,
                user_verification,
                attestation,
                None,
                None,
            )
            .map_err(|e| WebAuthnError::ChallengeGeneration(e.to_string()))?;

        // Convert to JSON response
        let response = RegistrationChallengeResponse {
            status: "ok".to_string(),
            challenge,
            rp: RpInfo {
                name: self.config.rp_name.clone(),
                id: self.config.rp_id.clone(),
            },
            user: UserInfo {
                id: general_purpose::URL_SAFE_NO_PAD.encode(&user.id),
                name: user.name,
                display_name: user.display_name,
            },
            pub_key_cred_params: ccr.pub_key_cred_params,
            timeout: ccr.timeout,
            exclude_credentials: ccr.exclude_credentials.unwrap_or_default(),
            authenticator_selection: ccr.authenticator_selection,
            attestation: ccr.attestation,
        };

        Ok(response)
    }

    pub fn verify_registration(
        &mut self,
        credential_data: &RegistrationCredentialData,
        username: &str,
        challenge: &str,
    ) -> WebAuthnResult<RegistrationVerificationResponse> {
        // Validate challenge
        let challenge_data = self.challenges.get(challenge)
            .ok_or(WebAuthnError::InvalidChallenge("Challenge not found".to_string()))?;

        if challenge_data.user_id != username {
            return Err(WebAuthnError::InvalidChallenge("User mismatch".to_string()));
        }

        if challenge_data.challenge_type != ChallengeType::Registration {
            return Err(WebAuthnError::InvalidChallenge("Invalid challenge type".to_string()));
        }

        if Utc::now() > challenge_data.expires_at {
            return Err(WebAuthnError::ChallengeExpired);
        }

        // Parse credential data
        let attestation_response = parse_attestation_response(credential_data)?;

        // Verify attestation
        let result = self.webauthn
            .finish_registration(&attestation_response)
            .map_err(|e| WebAuthnError::AttestationVerification(e.to_string()))?;

        // Remove used challenge
        self.challenges.remove(challenge);

        // Create credential for storage
        let credential = Credential {
            id: Uuid::new_v4(),
            user_id: username.to_string(),
            credential_id: result.credential_id,
            public_key: result.public_key,
            sign_count: result.counter,
            attestation_type: result.attestation_format,
            aaguid: result.aaguid,
            transports: result.transports,
            created_at: Utc::now(),
            last_used_at: None,
            is_active: true,
        };

        Ok(RegistrationVerificationResponse {
            status: "ok".to_string(),
            credential_id: general_purpose::URL_SAFE_NO_PAD.encode(&credential.credential_id),
            user: UserResponse {
                id: username.to_string(),
                username: username.to_string(),
            },
            credential,
        })
    }

    pub fn generate_authentication_challenge(
        &mut self,
        username: &str,
        user_verification: UserVerificationPolicy,
        user_credentials: &[Credential],
    ) -> WebAuthnResult<AuthenticationChallengeResponse> {
        // Generate secure random challenge
        let mut challenge_bytes = vec![0u8; 32];
        thread_rng().fill_bytes(&mut challenge_bytes);
        let challenge = general_purpose::URL_SAFE_NO_PAD.encode(&challenge_bytes);

        // Store challenge data
        let challenge_data = ChallengeData {
            challenge: challenge.clone(),
            user_id: username.to_string(),
            challenge_type: ChallengeType::Authentication,
            expires_at: Utc::now() + Duration::seconds(self.config.challenge_timeout as i64),
        };
        self.challenges.insert(challenge.clone(), challenge_data);

        // Convert credentials to allowCredentials format
        let allow_credentials: Vec<_> = user_credentials
            .iter()
            .map(|cred| AllowCredential {
                type_: "public-key".to_string(),
                id: general_purpose::URL_SAFE_NO_PAD.encode(&cred.credential_id),
                transports: cred.transports.clone(),
            })
            .collect();

        Ok(AuthenticationChallengeResponse {
            status: "ok".to_string(),
            challenge,
            rp_id: self.config.rp_id.clone(),
            allow_credentials: allow_credentials,
            user_verification: user_verification.to_string(),
            timeout: 60000,
        })
    }

    pub fn verify_authentication(
        &mut self,
        credential_data: &AuthenticationCredentialData,
        username: &str,
        challenge: &str,
        stored_credential: &Credential,
    ) -> WebAuthnResult<AuthenticationVerificationResponse> {
        // Validate challenge
        let challenge_data = self.challenges.get(challenge)
            .ok_or(WebAuthnError::InvalidChallenge("Challenge not found".to_string()))?;

        if challenge_data.user_id != username {
            return Err(WebAuthnError::InvalidChallenge("User mismatch".to_string()));
        }

        if challenge_data.challenge_type != ChallengeType::Authentication {
            return Err(WebAuthnError::InvalidChallenge("Invalid challenge type".to_string()));
        }

        if Utc::now() > challenge_data.expires_at {
            return Err(WebAuthnError::ChallengeExpired);
        }

        // Parse assertion response
        let assertion_response = parse_assertion_response(credential_data)?;

        // Create authenticator data from stored credential
        let authenticator_data = AuthenticatorData {
            credential_id: stored_credential.credential_id.clone(),
            public_key: stored_credential.public_key.clone(),
            counter: stored_credential.sign_count,
        };

        // Verify assertion
        let result = self.webauthn
            .finish_authentication(&assertion_response, &authenticator_data)
            .map_err(|e| WebAuthnError::AssertionVerification(e.to_string()))?;

        // Remove used challenge
        self.challenges.remove(challenge);

        // Generate session token
        let session_token = generate_session_token(username)?;

        Ok(AuthenticationVerificationResponse {
            status: "ok".to_string(),
            user: UserResponse {
                id: username.to_string(),
                username: username.to_string(),
            },
            session_token,
            new_counter: result.counter,
        })
    }

    pub fn cleanup_expired_challenges(&mut self) {
        let now = Utc::now();
        self.challenges.retain(|_, data| data.expires_at > now);
    }
}

// Helper functions and data structures

#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationChallengeResponse {
    pub status: String,
    pub challenge: String,
    pub rp: RpInfo,
    pub user: UserInfo,
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    pub timeout: u32,
    pub exclude_credentials: Vec<PublicKeyCredentialDescriptor>,
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: AttestationConveyancePreference,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationVerificationResponse {
    pub status: String,
    pub credential_id: String,
    pub user: UserResponse,
    pub credential: Credential,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticationChallengeResponse {
    pub status: String,
    pub challenge: String,
    pub rp_id: String,
    pub allow_credentials: Vec<AllowCredential>,
    pub user_verification: String,
    pub timeout: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticationVerificationResponse {
    pub status: String,
    pub user: UserResponse,
    pub session_token: String,
    pub new_counter: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RpInfo {
    pub name: String,
    pub id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: String,
    pub name: String,
    pub display_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserResponse {
    pub id: String,
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AllowCredential {
    #[serde(rename = "type")]
    pub type_: String,
    pub id: String,
    pub transports: Vec<String>,
}

fn parse_attestation_response(
    data: &RegistrationCredentialData,
) -> WebAuthnResult<PublicKeyCredential> {
    // Parse client data JSON
    let client_data_json = general_purpose::URL_SAFE_NO_PAD
        .decode(&data.response.client_data_json)
        .map_err(|e| WebAuthnError::InvalidData(format!("Invalid client data JSON: {}", e)))?;

    let client_data: Value = serde_json::from_slice(&client_data_json)
        .map_err(|e| WebAuthnError::InvalidData(format!("Invalid client data format: {}", e)))?;

    // Parse attestation object
    let attestation_object = general_purpose::URL_SAFE_NO_PAD
        .decode(&data.response.attestation_object)
        .map_err(|e| WebAuthnError::InvalidData(format!("Invalid attestation object: {}", e)))?;

    // Create PublicKeyCredential structure
    Ok(PublicKeyCredential {
        id: data.id.clone(),
        raw_id: general_purpose::URL_SAFE_NO_PAD
            .decode(&data.raw_id)
            .map_err(|e| WebAuthnError::InvalidData(format!("Invalid raw ID: {}", e)))?,
        response: AuthenticatorAttestationResponse {
            client_data_json,
            attestation_object,
        },
    })
}

fn parse_assertion_response(
    data: &AuthenticationCredentialData,
) -> WebAuthnResult<PublicKeyCredential> {
    // Parse client data JSON
    let client_data_json = general_purpose::URL_SAFE_NO_PAD
        .decode(&data.response.client_data_json)
        .map_err(|e| WebAuthnError::InvalidData(format!("Invalid client data JSON: {}", e)))?;

    // Parse authenticator data
    let authenticator_data = general_purpose::URL_SAFE_NO_PAD
        .decode(&data.response.authenticator_data)
        .map_err(|e| WebAuthnError::InvalidData(format!("Invalid authenticator data: {}", e)))?;

    // Parse signature
    let signature = general_purpose::URL_SAFE_NO_PAD
        .decode(&data.response.signature)
        .map_err(|e| WebAuthnError::InvalidData(format!("Invalid signature: {}", e)))?;

    // Parse user handle (optional)
    let user_handle = data.response.user_handle.as_ref()
        .map(|uh| general_purpose::URL_SAFE_NO_PAD.decode(uh))
        .transpose()
        .map_err(|e| WebAuthnError::InvalidData(format!("Invalid user handle: {}", e)))?;

    // Create PublicKeyCredential structure
    Ok(PublicKeyCredential {
        id: data.id.clone(),
        raw_id: general_purpose::URL_SAFE_NO_PAD
            .decode(&data.raw_id)
            .map_err(|e| WebAuthnError::InvalidData(format!("Invalid raw ID: {}", e)))?,
        response: AuthenticatorAssertionResponse {
            client_data_json,
            authenticator_data,
            signature,
            user_handle,
        },
    })
}

fn generate_session_token(username: &str) -> WebAuthnResult<String> {
    use jsonwebtoken::{encode, EncodingKey, Header};
    use chrono::{Duration, Utc};
    
    let claims = json!({
        "sub": username,
        "iat": Utc::now().timestamp(),
        "exp": (Utc::now() + Duration::hours(1)).timestamp(),
    });

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret("your-secret-key".as_ref()),
    ).map_err(|e| WebAuthnError::TokenGeneration(e.to_string()))?;

    Ok(token)
}
```

### 2.2 Request/Response Data Structures

```rust
// src/models/requests.rs
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct RegistrationChallengeRequest {
    pub username: String,
    pub display_name: String,
    pub user_verification: String,
    pub attestation: String,
}

#[derive(Debug, Deserialize)]
pub struct RegistrationVerificationRequest {
    pub credential: RegistrationCredentialData,
    pub username: String,
    pub challenge: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthenticationChallengeRequest {
    pub username: String,
    pub user_verification: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthenticationVerificationRequest {
    pub credential: AuthenticationCredentialData,
    pub username: String,
    pub challenge: String,
}

#[derive(Debug, Deserialize)]
pub struct RegistrationCredentialData {
    pub id: String,
    pub raw_id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub response: RegistrationResponseData,
}

#[derive(Debug, Deserialize)]
pub struct RegistrationResponseData {
    pub attestation_object: String,
    pub client_data_json: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthenticationCredentialData {
    pub id: String,
    pub raw_id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub response: AuthenticationResponseData,
}

#[derive(Debug, Deserialize)]
pub struct AuthenticationResponseData {
    pub authenticator_data: String,
    pub client_data_json: String,
    pub signature: String,
    pub user_handle: Option<String>,
}
```

## 3. Database Implementation

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
    pub is_active: bool,
}

#[derive(Debug, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::credentials)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Credential {
    pub id: Uuid,
    pub user_id: String,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub sign_count: i64,
    pub attestation_type: String,
    pub aaguid: Option<Vec<u8>>,
    pub transports: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub is_active: bool,
}

#[derive(Debug, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::challenges)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Challenge {
    pub id: Uuid,
    pub challenge: Vec<u8>,
    pub user_id: Option<String>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub is_used: bool,
}

#[derive(Debug, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::sessions)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub session_token: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub last_accessed_at: DateTime<Utc>,
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
    pub user_id: String,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub sign_count: i64,
    pub attestation_type: String,
    pub aaguid: Option<Vec<u8>>,
    pub transports: Option<serde_json::Value>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = crate::schema::challenges)]
pub struct NewChallenge {
    pub challenge: Vec<u8>,
    pub user_id: Option<String>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = crate::schema::sessions)]
pub struct NewSession {
    pub user_id: Uuid,
    pub session_token: String,
    pub expires_at: DateTime<Utc>,
}
```

### 3.2 Repository Pattern Implementation

```rust
// src/db/repositories.rs
use crate::db::models::*;
use crate::error::{RepositoryError, RepositoryResult};
use chrono::Utc;
use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, PooledConnection};
use std::sync::Arc;
use uuid::Uuid;

pub type DbPool = Arc<diesel::r2d2::Pool<ConnectionManager<diesel::PgConnection>>>;

pub struct UserRepository {
    pool: DbPool,
}

impl UserRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, new_user: NewUser) -> RepositoryResult<User> {
        use crate::schema::users;
        
        let mut conn = self.pool.get()?;
        
        let user = diesel::insert_into(users::table)
            .values(&new_user)
            .returning(User::as_returning())
            .get_result(&mut conn)?;
        
        Ok(user)
    }

    pub async fn find_by_username(&self, username: &str) -> RepositoryResult<Option<User>> {
        use crate::schema::users;
        
        let mut conn = self.pool.get()?;
        
        let user = users::table
            .filter(users::username.eq(username))
            .filter(users::is_active.eq(true))
            .first::<User>(&mut conn)
            .optional()?;
        
        Ok(user)
    }

    pub async fn find_by_id(&self, id: Uuid) -> RepositoryResult<Option<User>> {
        use crate::schema::users;
        
        let mut conn = self.pool.get()?;
        
        let user = users::table
            .filter(users::id.eq(id))
            .filter(users::is_active.eq(true))
            .first::<User>(&mut conn)
            .optional()?;
        
        Ok(user)
    }

    pub async fn update_last_access(&self, id: Uuid) -> RepositoryResult<()> {
        use crate::schema::users;
        
        let mut conn = self.pool.get()?;
        
        diesel::update(users::table.filter(users::id.eq(id)))
            .set(users::updated_at.eq(Utc::now()))
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

    pub async fn create(&self, new_credential: NewCredential) -> RepositoryResult<Credential> {
        use crate::schema::credentials;
        
        let mut conn = self.pool.get()?;
        
        let credential = diesel::insert_into(credentials::table)
            .values(&new_credential)
            .returning(Credential::as_returning())
            .get_result(&mut conn)?;
        
        Ok(credential)
    }

    pub async fn find_by_credential_id(&self, credential_id: &[u8]) -> RepositoryResult<Option<Credential>> {
        use crate::schema::credentials;
        
        let mut conn = self.pool.get()?;
        
        let credential = credentials::table
            .filter(credentials::credential_id.eq(credential_id))
            .filter(credentials::is_active.eq(true))
            .first::<Credential>(&mut conn)
            .optional()?;
        
        Ok(credential)
    }

    pub async fn find_by_user_id(&self, user_id: &str) -> RepositoryResult<Vec<Credential>> {
        use crate::schema::credentials;
        
        let mut conn = self.pool.get()?;
        
        let credentials = credentials::table
            .filter(credentials::user_id.eq(user_id))
            .filter(credentials::is_active.eq(true))
            .load::<Credential>(&mut conn)?;
        
        Ok(credentials)
    }

    pub async fn update_sign_count(&self, id: Uuid, new_count: i64) -> RepositoryResult<()> {
        use crate::schema::credentials;
        
        let mut conn = self.pool.get()?;
        
        diesel::update(credentials::table.filter(credentials::id.eq(id)))
            .set((
                credentials::sign_count.eq(new_count),
                credentials::last_used_at.eq(Utc::now()),
            ))
            .execute(&mut conn)?;
        
        Ok(())
    }

    pub async fn deactivate(&self, id: Uuid) -> RepositoryResult<()> {
        use crate::schema::credentials;
        
        let mut conn = self.pool.get()?;
        
        diesel::update(credentials::table.filter(credentials::id.eq(id)))
            .set(credentials::is_active.eq(false))
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

    pub async fn create(&self, new_challenge: NewChallenge) -> RepositoryResult<Challenge> {
        use crate::schema::challenges;
        
        let mut conn = self.pool.get()?;
        
        let challenge = diesel::insert_into(challenges::table)
            .values(&new_challenge)
            .returning(Challenge::as_returning())
            .get_result(&mut conn)?;
        
        Ok(challenge)
    }

    pub async fn find_valid(&self, challenge_bytes: &[u8]) -> RepositoryResult<Option<Challenge>> {
        use crate::schema::challenges;
        
        let mut conn = self.pool.get()?;
        
        let challenge = challenges::table
            .filter(challenges::challenge.eq(challenge_bytes))
            .filter(challenges::is_used.eq(false))
            .filter(challenges::expires_at.gt(Utc::now()))
            .first::<Challenge>(&mut conn)
            .optional()?;
        
        Ok(challenge)
    }

    pub async fn mark_used(&self, id: Uuid) -> RepositoryResult<()> {
        use crate::schema::challenges;
        
        let mut conn = self.pool.get()?;
        
        diesel::update(challenges::table.filter(challenges::id.eq(id)))
            .set(challenges::is_used.eq(true))
            .execute(&mut conn)?;
        
        Ok(())
    }

    pub async fn cleanup_expired(&self) -> RepositoryResult<usize> {
        use crate::schema::challenges;
        
        let mut conn = self.pool.get()?;
        
        let count = diesel::delete(
            challenges::table.filter(challenges::expires_at.lt(Utc::now()))
        ).execute(&mut conn)?;
        
        Ok(count)
    }
}

pub struct SessionRepository {
    pool: DbPool,
}

impl SessionRepository {
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, new_session: NewSession) -> RepositoryResult<Session> {
        use crate::schema::sessions;
        
        let mut conn = self.pool.get()?;
        
        let session = diesel::insert_into(sessions::table)
            .values(&new_session)
            .returning(Session::as_returning())
            .get_result(&mut conn)?;
        
        Ok(session)
    }

    pub async fn find_by_token(&self, token: &str) -> RepositoryResult<Option<Session>> {
        use crate::schema::sessions;
        
        let mut conn = self.pool.get()?;
        
        let session = sessions::table
            .filter(sessions::session_token.eq(token))
            .filter(sessions::expires_at.gt(Utc::now()))
            .first::<Session>(&mut conn)
            .optional()?;
        
        Ok(session)
    }

    pub async fn update_last_access(&self, id: Uuid) -> RepositoryResult<()> {
        use crate::schema::sessions;
        
        let mut conn = self.pool.get()?;
        
        diesel::update(sessions::table.filter(sessions::id.eq(id)))
            .set(sessions::last_accessed_at.eq(Utc::now()))
            .execute(&mut conn)?;
        
        Ok(())
    }

    pub async fn revoke(&self, id: Uuid) -> RepositoryResult<()> {
        use crate::schema::sessions;
        
        let mut conn = self.pool.get()?;
        
        diesel::delete(sessions::table.filter(sessions::id.eq(id)))
            .execute(&mut conn)?;
        
        Ok(())
    }

    pub async fn cleanup_expired(&self) -> RepositoryResult<usize> {
        use crate::schema::sessions;
        
        let mut conn = self.pool.get()?;
        
        let count = diesel::delete(
            sessions::table.filter(sessions::expires_at.lt(Utc::now()))
        ).execute(&mut conn)?;
        
        Ok(count)
    }
}
```

## 4. API Controllers Implementation

### 4.1 Registration Controller

```rust
// src/controllers/registration.rs
use crate::controllers::ResponseError;
use crate::models::requests::*;
use crate::services::WebAuthnService;
use crate::db::repositories::{UserRepository, CredentialRepository};
use actix_web::{web, HttpRequest, HttpResponse};
use base64::{Engine as _, engine::general_purpose};
use std::sync::Arc;

pub async fn registration_challenge(
    webauthn_service: web::Data<Arc<WebAuthnService>>,
    user_repo: web::Data<Arc<UserRepository>>,
    req: web::Json<RegistrationChallengeRequest>,
) -> Result<HttpResponse, ResponseError> {
    // Validate input
    if req.username.is_empty() || req.display_name.is_empty() {
        return Err(ResponseError::BadRequest("Username and display name are required".to_string()));
    }

    // Check if user already exists
    match user_repo.find_by_username(&req.username).await {
        Ok(Some(_)) => {
            // User exists, allow adding additional credentials
        }
        Ok(None) => {
            // New user, will be created during verification
        }
        Err(e) => return Err(ResponseError::InternalError(e.to_string())),
    }

    // Parse user verification policy
    let user_verification = match req.user_verification.as_str() {
        "required" => webauthn_rs::prelude::UserVerificationPolicy::Required,
        "preferred" => webauthn_rs::prelude::UserVerificationPolicy::Preferred,
        "discouraged" => webauthn_rs::prelude::UserVerificationPolicy::Discouraged,
        _ => return Err(ResponseError::BadRequest("Invalid user verification policy".to_string())),
    };

    // Parse attestation conveyance preference
    let attestation = match req.attestation.as_str() {
        "none" => webauthn_rs::prelude::AttestationConveyancePreference::None,
        "direct" => webauthn_rs::prelude::AttestationConveyancePreference::Direct,
        "enterprise" => webauthn_rs::prelude::AttestationConveyancePreference::Enterprise,
        "indirect" => webauthn_rs::prelude::AttestationConveyancePreference::Indirect,
        _ => return Err(ResponseError::BadRequest("Invalid attestation preference".to_string())),
    };

    // Generate challenge
    let mut service = webauthn_service.as_ref().clone();
    let challenge_response = service.generate_registration_challenge(
        &req.username,
        &req.display_name,
        user_verification,
        attestation,
    ).map_err(|e| ResponseError::WebAuthnError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(challenge_response))
}

pub async fn registration_verify(
    webauthn_service: web::Data<Arc<WebAuthnService>>,
    user_repo: web::Data<Arc<UserRepository>>,
    credential_repo: web::Data<Arc<CredentialRepository>>,
    req: web::Json<RegistrationVerificationRequest>,
) -> Result<HttpResponse, ResponseError> {
    // Validate input
    if req.username.is_empty() || req.challenge.is_empty() {
        return Err(ResponseError::BadRequest("Username and challenge are required".to_string()));
    }

    // Verify credential
    let mut service = webauthn_service.as_ref().clone();
    let verification_response = service.verify_registration(
        &req.credential,
        &req.username,
        &req.challenge,
    ).map_err(|e| ResponseError::WebAuthnError(e.to_string()))?;

    // Check if user exists, create if not
    let user = match user_repo.find_by_username(&req.username).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            let new_user = crate::db::models::NewUser {
                username: req.username.clone(),
                display_name: verification_response.user.display_name,
            };
            user_repo.create(new_user).await
                .map_err(|e| ResponseError::InternalError(e.to_string()))?
        }
        Err(e) => return Err(ResponseError::InternalError(e.to_string())),
    };

    // Check credential limit
    let existing_credentials = credential_repo.find_by_user_id(&user.id.to_string()).await
        .map_err(|e| ResponseError::InternalError(e.to_string()))?;
    
    if existing_credentials.len() >= 10 { // Configurable limit
        return Err(ResponseError::BadRequest("Maximum number of credentials exceeded".to_string()));
    }

    // Store credential
    let new_credential = crate::db::models::NewCredential {
        user_id: user.id.to_string(),
        credential_id: verification_response.credential.credential_id,
        public_key: verification_response.credential.public_key,
        sign_count: verification_response.credential.sign_count as i64,
        attestation_type: verification_response.credential.attestation_type,
        aaguid: verification_response.credential.aaguid,
        transports: verification_response.credential.transports.map(|t| serde_json::to_value(t).unwrap()),
    };

    credential_repo.create(new_credential).await
        .map_err(|e| ResponseError::InternalError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(verification_response))
}
```

### 4.2 Authentication Controller

```rust
// src/controllers/authentication.rs
use crate::controllers::ResponseError;
use crate::models::requests::*;
use crate::services::WebAuthnService;
use crate::db::repositories::{UserRepository, CredentialRepository, SessionRepository};
use actix_web::{web, HttpRequest, HttpResponse};
use std::sync::Arc;

pub async fn authentication_challenge(
    webauthn_service: web::Data<Arc<WebAuthnService>>,
    user_repo: web::Data<Arc<UserRepository>>,
    credential_repo: web::Data<Arc<CredentialRepository>>,
    req: web::Json<AuthenticationChallengeRequest>,
) -> Result<HttpResponse, ResponseError> {
    // Validate input
    if req.username.is_empty() {
        return Err(ResponseError::BadRequest("Username is required".to_string()));
    }

    // Find user
    let user = user_repo.find_by_username(&req.username).await
        .map_err(|e| ResponseError::InternalError(e.to_string()))?
        .ok_or_else(|| ResponseError::NotFound("User not found".to_string()))?;

    // Get user credentials
    let credentials = credential_repo.find_by_user_id(&user.id.to_string()).await
        .map_err(|e| ResponseError::InternalError(e.to_string()))?;

    if credentials.is_empty() {
        return Err(ResponseError::BadRequest("No credentials found for user".to_string()));
    }

    // Parse user verification policy
    let user_verification = match req.user_verification.as_str() {
        "required" => webauthn_rs::prelude::UserVerificationPolicy::Required,
        "preferred" => webauthn_rs::prelude::UserVerificationPolicy::Preferred,
        "discouraged" => webauthn_rs::prelude::UserVerificationPolicy::Discouraged,
        _ => return Err(ResponseError::BadRequest("Invalid user verification policy".to_string())),
    };

    // Generate challenge
    let mut service = webauthn_service.as_ref().clone();
    let challenge_response = service.generate_authentication_challenge(
        &req.username,
        user_verification,
        &credentials,
    ).map_err(|e| ResponseError::WebAuthnError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(challenge_response))
}

pub async fn authentication_verify(
    webauthn_service: web::Data<Arc<WebAuthnService>>,
    credential_repo: web::Data<Arc<CredentialRepository>>,
    session_repo: web::Data<Arc<SessionRepository>>,
    req: web::Json<AuthenticationVerificationRequest>,
) -> Result<HttpResponse, ResponseError> {
    // Validate input
    if req.username.is_empty() || req.challenge.is_empty() {
        return Err(ResponseError::BadRequest("Username and challenge are required".to_string()));
    }

    // Decode credential ID
    let credential_id = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&req.credential.id)
        .map_err(|_| ResponseError::BadRequest("Invalid credential ID".to_string()))?;

    // Find stored credential
    let stored_credential = credential_repo.find_by_credential_id(&credential_id).await
        .map_err(|e| ResponseError::InternalError(e.to_string()))?
        .ok_or_else(|| ResponseError::NotFound("Credential not found".to_string()))?;

    // Verify credential ownership
    if stored_credential.user_id != req.username {
        return Err(ResponseError::Unauthorized("Credential does not belong to user".to_string()));
    }

    // Verify assertion
    let mut service = webauthn_service.as_ref().clone();
    let verification_response = service.verify_authentication(
        &req.credential,
        &req.username,
        &req.challenge,
        &stored_credential,
    ).map_err(|e| ResponseError::WebAuthnError(e.to_string()))?;

    // Update credential sign count
    credential_repo.update_sign_count(
        stored_credential.id,
        verification_response.new_counter as i64,
    ).await.map_err(|e| ResponseError::InternalError(e.to_string()))?;

    // Create session
    let new_session = crate::db::models::NewSession {
        user_id: uuid::Uuid::parse_str(&stored_credential.user_id)
            .map_err(|_| ResponseError::InternalError("Invalid user ID".to_string()))?,
        session_token: verification_response.session_token.clone(),
        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
    };

    session_repo.create(new_session).await
        .map_err(|e| ResponseError::InternalError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(verification_response))
}
```

## 5. Error Handling

### 5.1 Custom Error Types

```rust
// src/error/mod.rs
use thiserror::Error;

#[derive(Error, Debug)]
pub enum WebAuthnError {
    #[error("Configuration error: {0}")]
    Configuration(String),
    
    #[error("Challenge generation failed: {0}")]
    ChallengeGeneration(String),
    
    #[error("Invalid challenge: {0}")]
    InvalidChallenge(String),
    
    #[error("Challenge expired")]
    ChallengeExpired,
    
    #[error("Attestation verification failed: {0}")]
    AttestationVerification(String),
    
    #[error("Assertion verification failed: {0}")]
    AssertionVerification(String),
    
    #[error("Invalid data: {0}")]
    InvalidData(String),
    
    #[error("Token generation failed: {0}")]
    TokenGeneration(String),
    
    #[error("Unsupported algorithm")]
    UnsupportedAlgorithm,
    
    #[error("Invalid signature")]
    InvalidSignature,
    
    #[error("User verification required")]
    UserVerificationRequired,
    
    #[error("Invalid counter")]
    InvalidCounter,
    
    #[error("Unsupported format")]
    UnsupportedFormat,
}

#[derive(Error, Debug)]
pub enum RepositoryError {
    #[error("Database error: {0}")]
    Database(#[from] diesel::result::Error),
    
    #[error("Connection error: {0}")]
    Connection(String),
    
    #[error("Not found: {0}")]
    NotFound(String),
    
    #[error("Duplicate entry: {0}")]
    Duplicate(String),
    
    #[error("Invalid data: {0}")]
    InvalidData(String),
}

#[derive(Error, Debug)]
pub enum ResponseError {
    #[error("Bad request: {0}")]
    BadRequest(String),
    
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    
    #[error("Forbidden: {0}")]
    Forbidden(String),
    
    #[error("Not found: {0}")]
    NotFound(String),
    
    #[error("Conflict: {0}")]
    Conflict(String),
    
    #[error("Too many requests")]
    TooManyRequests,
    
    #[error("Internal server error: {0}")]
    InternalError(String),
    
    #[error("WebAuthn error: {0}")]
    WebAuthnError(String),
}

impl actix_web::ResponseError for ResponseError {
    fn error_response(&self) -> HttpResponse {
        let status = match self {
            ResponseError::BadRequest(_) => actix_web::http::StatusCode::BAD_REQUEST,
            ResponseError::Unauthorized(_) => actix_web::http::StatusCode::UNAUTHORIZED,
            ResponseError::Forbidden(_) => actix_web::http::StatusCode::FORBIDDEN,
            ResponseError::NotFound(_) => actix_web::http::StatusCode::NOT_FOUND,
            ResponseError::Conflict(_) => actix_web::http::StatusCode::CONFLICT,
            ResponseError::TooManyRequests => actix_web::http::StatusCode::TOO_MANY_REQUESTS,
            ResponseError::InternalError(_) | ResponseError::WebAuthnError(_) => {
                actix_web::http::StatusCode::INTERNAL_SERVER_ERROR
            }
        };

        let error_response = crate::models::ErrorResponse {
            status: "error".to_string(),
            error: crate::models::ErrorDetail {
                code: self.error_code(),
                message: self.to_string(),
                details: None,
            },
        };

        HttpResponse::build(status).json(error_response)
    }
}

impl ResponseError {
    fn error_code(&self) -> &'static str {
        match self {
            ResponseError::BadRequest(_) => "BAD_REQUEST",
            ResponseError::Unauthorized(_) => "UNAUTHORIZED",
            ResponseError::Forbidden(_) => "FORBIDDEN",
            ResponseError::NotFound(_) => "NOT_FOUND",
            ResponseError::Conflict(_) => "CONFLICT",
            ResponseError::TooManyRequests => "TOO_MANY_REQUESTS",
            ResponseError::InternalError(_) => "INTERNAL_ERROR",
            ResponseError::WebAuthnError(_) => "WEBAUTHN_ERROR",
        }
    }
}

pub type WebAuthnResult<T> = Result<T, WebAuthnError>;
pub type RepositoryResult<T> = Result<T, RepositoryError>;
```

## 6. Security Middleware

### 6.1 Rate Limiting Middleware

```rust
// src/middleware/rate_limit.rs
use actix_web::{dev::ServiceRequest, dev::ServiceResponse, Error, HttpMessage};
use actix_web::{web, App, HttpServer, middleware::Logger};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use actix_web::dev::{forward_ready, Service, Transform};
use futures_util::future::{ok, Ready};

#[derive(Debug, Clone)]
struct RateLimitEntry {
    count: u32,
    window_start: Instant,
}

#[derive(Debug, Clone)]
pub struct RateLimiter {
    requests: u32,
    window: Duration,
    entries: Arc<Mutex<HashMap<String, RateLimitEntry>>>,
}

impl RateLimiter {
    pub fn new(requests: u32, window: Duration) -> Self {
        Self {
            requests,
            window,
            entries: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn is_allowed(&self, key: &str) -> bool {
        let mut entries = self.entries.lock().unwrap();
        let now = Instant::now();
        
        match entries.get_mut(key) {
            Some(entry) => {
                if now.duration_since(entry.window_start) >= self.window {
                    // Reset window
                    entry.count = 1;
                    entry.window_start = now;
                    true
                } else if entry.count < self.requests {
                    entry.count += 1;
                    true
                } else {
                    false
                }
            }
            None => {
                entries.insert(key.to_string(), RateLimitEntry {
                    count: 1,
                    window_start: now,
                });
                true
            }
        }
    }
}

pub struct RateLimitMiddleware {
    limiter: RateLimiter,
}

impl RateLimitMiddleware {
    pub fn new(requests: u32, window: Duration) -> Self {
        Self {
            limiter: RateLimiter::new(requests, window),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for RateLimitMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = RateLimitService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(RateLimitService {
            service,
            limiter: self.limiter.clone(),
        })
    }
}

pub struct RateLimitService<S> {
    service: S,
    limiter: RateLimiter,
}

impl<S, B> Service<ServiceRequest> for RateLimitService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = futures_util::future::LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let client_ip = req
            .connection_info()
            .peer_addr()
            .map(|addr| addr.ip().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        if !self.limiter.is_allowed(&client_ip) {
            let response = actix_web::HttpResponse::TooManyRequests().json(serde_json::json!({
                "status": "error",
                "error": {
                    "code": "TOO_MANY_REQUESTS",
                    "message": "Rate limit exceeded"
                }
            }));
            
            return Box::pin(async move {
                Ok(req.into_response(response))
            });
        }

        let fut = self.service.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res)
        })
    }
}
```

### 6.2 CORS and Security Headers Middleware

```rust
// src/middleware/security.rs
use actix_web::{dev::ServiceRequest, dev::ServiceResponse, Error, HttpMessage};
use actix_web::dev::{forward_ready, Service, Transform};
use futures_util::future::{ok, Ready};
use std::future::Future;

pub struct SecurityHeadersMiddleware;

impl<S, B> Transform<S, ServiceRequest> for SecurityHeadersMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = SecurityHeadersService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(SecurityHeadersService { service })
    }
}

pub struct SecurityHeadersService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for SecurityHeadersService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = futures_util::future::LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let fut = self.service.call(req);
        Box::pin(async move {
            let mut res = fut.await?;
            
            // Add security headers
            res.headers_mut().insert(
                "X-Content-Type-Options",
                actix_web::http::HeaderValue::from_static("nosniff"),
            );
            res.headers_mut().insert(
                "X-Frame-Options",
                actix_web::http::HeaderValue::from_static("DENY"),
            );
            res.headers_mut().insert(
                "X-XSS-Protection",
                actix_web::http::HeaderValue::from_static("1; mode=block"),
            );
            res.headers_mut().insert(
                "Strict-Transport-Security",
                actix_web::http::HeaderValue::from_static("max-age=31536000; includeSubDomains"),
            );
            res.headers_mut().insert(
                "Content-Security-Policy",
                actix_web::http::HeaderValue::from_static("default-src 'self'"),
            );
            res.headers_mut().insert(
                "Referrer-Policy",
                actix_web::http::HeaderValue::from_static("strict-origin-when-cross-origin"),
            );
            
            Ok(res)
        })
    }
}
```

## 7. Application Setup

### 7.1 Main Application Configuration

```rust
// src/main.rs
use actix_cors::Cors;
use actix_web::{web, App, HttpServer, middleware::Logger};
use std::sync::Arc;
use std::time::Duration;

mod config;
mod controllers;
mod db;
mod error;
mod middleware;
mod models;
mod routes;
mod services;
mod utils;

use config::Config;
use db::repositories::{UserRepository, CredentialRepository, ChallengeRepository, SessionRepository};
use services::WebAuthnService;
use middleware::{RateLimitMiddleware, SecurityHeadersMiddleware};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logger
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    // Load configuration
    let config = Config::from_env().expect("Failed to load configuration");

    // Initialize database connection pool
    let db_pool = db::connection::create_pool(&config.database)
        .await
        .expect("Failed to create database pool");

    // Run database migrations
    db::migrations::run_migrations(&db_pool)
        .await
        .expect("Failed to run database migrations");

    // Initialize repositories
    let user_repo = Arc::new(UserRepository::new(db_pool.clone()));
    let credential_repo = Arc::new(CredentialRepository::new(db_pool.clone()));
    let challenge_repo = Arc::new(ChallengeRepository::new(db_pool.clone()));
    let session_repo = Arc::new(SessionRepository::new(db_pool.clone()));

    // Initialize WebAuthn service
    let webauthn_service = Arc::new(
        WebAuthnService::new(config.webauthn.clone())
            .expect("Failed to initialize WebAuthn service")
    );

    // Start background tasks
    start_background_tasks(
        webauthn_service.clone(),
        challenge_repo.clone(),
        session_repo.clone(),
    );

    // Configure HTTP server
    let server = HttpServer::new(move || {
        App::new()
            // Add middleware
            .wrap(Logger::default())
            .wrap(SecurityHeadersMiddleware)
            .wrap(
                Cors::default()
                    .allowed_origin(&config.webauthn.rp_origin)
                    .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
                    .allowed_headers(vec!["Content-Type", "Authorization"])
                    .supports_credentials()
                    .max_age(3600),
            )
            .wrap(RateLimitMiddleware::new(
                config.security.rate_limit_requests,
                Duration::from_secs(config.security.rate_limit_window),
            ))
            
            // Add application data
            .app_data(web::Data::new(config.clone()))
            .app_data(web::Data::new(webauthn_service.clone()))
            .app_data(web::Data::new(user_repo.clone()))
            .app_data(web::Data::new(credential_repo.clone()))
            .app_data(web::Data::new(challenge_repo.clone()))
            .app_data(web::Data::new(session_repo.clone()))
            
            // Configure routes
            .configure(routes::webauthn::configure)
            .configure(routes::health::configure)
    })
    .bind(format!("{}:{}", config.server.host, config.server.port))?
    .workers(config.server.workers)
    .run();

    log::info!("Starting FIDO2/WebAuthn server on {}:{}", 
               config.server.host, config.server.port);

    server.await
}

fn start_background_tasks(
    webauthn_service: Arc<WebAuthnService>,
    challenge_repo: Arc<ChallengeRepository>,
    session_repo: Arc<SessionRepository>,
) {
    // Cleanup expired challenges
    let webauthn_cleanup = webauthn_service.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            webauthn_cleanup.cleanup_expired_challenges();
        }
    });

    // Cleanup database expired entries
    let challenge_cleanup = challenge_repo.clone();
    let session_cleanup = session_repo.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5 minutes
        loop {
            interval.tick().await;
            if let Err(e) = challenge_cleanup.cleanup_expired().await {
                log::error!("Failed to cleanup expired challenges: {}", e);
            }
            if let Err(e) = session_cleanup.cleanup_expired().await {
                log::error!("Failed to cleanup expired sessions: {}", e);
            }
        }
    });
}
```

This implementation guide provides a comprehensive foundation for building a secure, compliant FIDO2/WebAuthn Relying Party Server with proper error handling, security middleware, and database integration. The code follows Rust best practices and includes extensive testing considerations.