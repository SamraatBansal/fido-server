# FIDO2/WebAuthn Server Architecture

## Core Components

### 1. WebAuthn Configuration
```rust
// src/config/webauthn.rs
use webauthn_rs::prelude::*;

pub struct WebAuthnConfig {
    pub rp: RelyingParty,
    pub origin: Url,
    pub config: WebauthnConfig,
}

impl WebAuthnConfig {
    pub fn new(rp_name: &str, rp_id: &str, origin: &str) -> Result<Self> {
        let rp = RelyingParty {
            id: rp_id.to_string(),
            name: rp_name.to_string(),
            origin: Url::parse(origin)?,
        };

        let config = WebauthnConfig {
            rp: rp.clone(),
            timeout: Some(Duration::from_secs(300)),
            challenge_expiry: Some(Duration::from_secs(600)),
            ..Default::default()
        };

        Ok(Self { rp, origin: Url::parse(origin)?, config })
    }
}
```

### 2. Credential Storage Models
```rust
// src/db/models.rs
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::credentials)]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub sign_count: u32,
    pub attestation_type: String,
    pub transports: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub user_verified: bool,
}

#[derive(Debug, Clone, Queryable, Selectable, Serialize, Deserialize)]
#[diesel(table_name = crate::schema::users)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
```

### 3. WebAuthn Service Layer
```rust
// src/services/webauthn.rs
use webauthn_rs::prelude::*;
use crate::db::models::{Credential, User};
use crate::error::AppError;

pub struct WebAuthnService {
    webauthn: Webauthn,
    db: Arc<dyn Database>,
}

impl WebAuthnService {
    pub async fn start_registration(
        &self,
        user: &User,
        user_verification: UserVerificationPolicy,
    ) -> Result<CreationChallengeResponse, AppError> {
        // Generate registration challenge
        let user_entity = UserEntity {
            id: user.id.as_bytes().to_vec(),
            name: user.username.clone(),
            display_name: user.display_name.clone(),
        };

        let (ccr, reg_state) = self.webauthn
            .start_registration(&user_entity, user_verification)?;

        // Store registration state temporarily
        self.store_challenge(&user.id, &reg_state).await?;

        Ok(ccr)
    }

    pub async fn finish_registration(
        &self,
        user: &User,
        reg_response: RegisterPublicKeyCredential,
    ) -> Result<(), AppError> {
        // Retrieve registration state
        let reg_state = self.retrieve_challenge(&user.id).await?;

        // Verify registration
        let auth_result = self.webauthn
            .finish_registration(&reg_state, &reg_response)?;

        // Store credential
        self.store_credential(user, &auth_result).await?;

        Ok(())
    }

    pub async fn start_authentication(
        &self,
        username: &str,
        user_verification: UserVerificationPolicy,
    ) -> Result<RequestChallengeResponse, AppError> {
        // Get user and credentials
        let user = self.get_user_by_username(username).await?;
        let credentials = self.get_user_credentials(&user.id).await?;

        // Convert to webauthn-rs format
        let allow_credentials: Vec<_> = credentials
            .into_iter()
            .map(|cred| PublicKeyCredentialDescriptor {
                type_: PublicKeyCredentialType::PublicKey,
                id: cred.credential_id,
                transports: Some(cred.transports.into_iter()
                    .filter_map(|t| t.parse().ok())
                    .collect()),
            })
            .collect();

        let (acr, auth_state) = self.webauthn
            .start_authentication(&allow_credentials, user_verification)?;

        // Store authentication state
        self.store_challenge(&user.id, &auth_state).await?;

        Ok(acr)
    }

    pub async fn finish_authentication(
        &self,
        username: &str,
        auth_response: PublicKeyCredential,
    ) -> Result<AuthenticationResult, AppError> {
        // Get user and authentication state
        let user = self.get_user_by_username(username).await?;
        let auth_state = self.retrieve_challenge(&user.id).await?;

        // Verify authentication
        let auth_result = self.webauthn
            .finish_authentication(&auth_state, &auth_response)?;

        // Update credential usage
        self.update_credential_usage(&auth_result.credential_id).await?;

        Ok(auth_result)
    }
}
```

### 4. API Controllers
```rust
// src/controllers/webauthn.rs
use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct RegistrationStartRequest {
    pub username: String,
    pub display_name: String,
    pub user_verification: Option<String>, // "required", "preferred", "discouraged"
}

#[derive(Debug, Deserialize)]
pub struct RegistrationFinishRequest {
    pub username: String,
    pub credential: RegisterPublicKeyCredential,
}

#[derive(Debug, Deserialize)]
pub struct AuthenticationStartRequest {
    pub username: String,
    pub user_verification: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AuthenticationFinishRequest {
    pub username: String,
    pub credential: PublicKeyCredential,
}

pub async fn registration_start(
    req: web::Json<RegistrationStartRequest>,
    webauthn_service: web::Data<Arc<WebAuthnService>>,
) -> Result<HttpResponse> {
    let user_verification = match req.user_verification.as_deref() {
        Some("required") => UserVerificationPolicy::Required,
        Some("preferred") => UserVerificationPolicy::Preferred,
        Some("discouraged") => UserVerificationPolicy::Discouraged,
        _ => UserVerificationPolicy::Preferred,
    };

    let user = webauthn_service.get_or_create_user(
        &req.username,
        &req.display_name,
    ).await?;

    let challenge_response = webauthn_service
        .start_registration(&user, user_verification)
        .await?;

    Ok(HttpResponse::Ok().json(challenge_response))
}

pub async fn registration_finish(
    req: web::Json<RegistrationFinishRequest>,
    webauthn_service: web::Data<Arc<WebAuthnService>>,
) -> Result<HttpResponse> {
    let user = webauthn_service
        .get_user_by_username(&req.username)
        .await?;

    webauthn_service
        .finish_registration(&user, req.credential.clone())
        .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "message": "Credential registered successfully"
    })))
}

pub async fn authentication_start(
    req: web::Json<AuthenticationStartRequest>,
    webauthn_service: web::Data<Arc<WebAuthnService>>,
) -> Result<HttpResponse> {
    let user_verification = match req.user_verification.as_deref() {
        Some("required") => UserVerificationPolicy::Required,
        Some("preferred") => UserVerificationPolicy::Preferred,
        Some("discouraged") => UserVerificationPolicy::Discouraged,
        _ => UserVerificationPolicy::Preferred,
    };

    let challenge_response = webauthn_service
        .start_authentication(&req.username, user_verification)
        .await?;

    Ok(HttpResponse::Ok().json(challenge_response))
}

pub async fn authentication_finish(
    req: web::Json<AuthenticationFinishRequest>,
    webauthn_service: web::Data<Arc<WebAuthnService>>,
) -> Result<HttpResponse> {
    let auth_result = webauthn_service
        .finish_authentication(&req.username, req.credential.clone())
        .await?;

    // Create session/token here
    let session_token = webauthn_service
        .create_session(&auth_result)
        .await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "session_token": session_token,
        "user": {
            "id": auth_result.user_id,
            "authenticated": true
        }
    })))
}
```

## Security Considerations

### 1. Challenge Management
- Use cryptographically secure random challenges
- Implement challenge expiration (5-10 minutes)
- Store challenges in memory with TTL
- Prevent challenge reuse

### 2. Credential Storage
- Encrypt private keys at rest
- Use separate encryption keys per deployment
- Implement key rotation strategy
- Store only public key data

### 3. Rate Limiting
- Implement per-IP rate limiting
- Per-user authentication attempt limits
- Challenge request throttling

### 4. Input Validation
- Validate all WebAuthn inputs
- Sanitize usernames and display names
- Verify credential ID format and length
- Check attestation format validity

### 5. Transport Security
- Enforce TLS 1.3
- Implement HSTS headers
- Validate origin headers
- CSRF protection for state-changing operations