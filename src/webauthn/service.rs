//! WebAuthn service trait and implementation

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose};
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::webauthn::{
    WebAuthnConfig, ServerPublicKeyCredentialCreationOptionsRequest,
    ServerPublicKeyCredentialCreationOptionsResponse, ServerPublicKeyCredentialGetOptionsRequest,
    ServerPublicKeyCredentialGetOptionsResponse, ServerPublicKeyCredential,
    ServerPublicKeyCredentialUserEntity, ServerPublicKeyCredentialDescriptor,
    PublicKeyCredentialRpEntity, PublicKeyCredentialParameters, AuthenticatorSelectionCriteria,
    ATTESTATION_NONE, USER_VERIFICATION_PREFERRED, PUBLIC_KEY_CREDENTIAL_TYPE,
    ALG_ES256, ALG_RS256, AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM,
};

/// Challenge store trait
#[async_trait]
pub trait ChallengeStore: Send + Sync {
    async fn store_challenge(&self, challenge: &str, username: &str, expires_at: DateTime<Utc>) -> Result<()>;
    async fn validate_and_consume_challenge(&self, challenge: &str, username: &str) -> Result<bool>;
    async fn cleanup_expired_challenges(&self) -> Result<()>;
}

/// User repository trait
#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn create_user(&self, user: NewUser) -> Result<User>;
    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>>;
    async fn update_user(&self, user: User) -> Result<User>;
    async fn delete_user(&self, user_id: &str) -> Result<()>;
}

/// Credential repository trait
#[async_trait]
pub trait CredentialRepository: Send + Sync {
    async fn store_credential(&self, credential: NewCredential) -> Result<Credential>;
    async fn get_credential_by_id(&self, id: &str) -> Result<Option<Credential>>;
    async fn get_credentials_by_user(&self, user_id: &str) -> Result<Vec<Credential>>;
    async fn update_sign_count(&self, credential_id: &str, count: u32) -> Result<()>;
    async fn delete_credential(&self, credential_id: &str) -> Result<()>;
}

/// WebAuthn service trait
#[async_trait]
pub trait WebAuthnService: Send + Sync {
    async fn begin_registration(&self, request: ServerPublicKeyCredentialCreationOptionsRequest) -> Result<ServerPublicKeyCredentialCreationOptionsResponse>;
    async fn finish_registration(&self, credential: ServerPublicKeyCredential) -> Result<crate::webauthn::ServerResponse>;
    async fn begin_authentication(&self, request: ServerPublicKeyCredentialGetOptionsRequest) -> Result<ServerPublicKeyCredentialGetOptionsResponse>;
    async fn finish_authentication(&self, credential: ServerPublicKeyCredential) -> Result<crate::webauthn::ServerResponse>;
}

/// WebAuthn service implementation
pub struct WebAuthnServiceImpl<T, U, C>
where
    T: ChallengeStore,
    U: UserRepository,
    C: CredentialRepository,
{
    config: WebAuthnConfig,
    challenge_store: T,
    user_repo: U,
    credential_repo: C,
}

impl<T, U, C> WebAuthnServiceImpl<T, U, C>
where
    T: ChallengeStore,
    U: UserRepository,
    C: CredentialRepository,
{
    pub fn new(
        config: WebAuthnConfig,
        challenge_store: T,
        user_repo: U,
        credential_repo: C,
    ) -> Result<Self> {
        config.validate().map_err(|e| AppError::ValidationError(e))?;
        
        Ok(Self {
            config,
            challenge_store,
            user_repo,
            credential_repo,
        })
    }

    /// Generate a random challenge
    fn generate_challenge(&self) -> Result<String> {
        let bytes = rand::random::<[u8; 32]>();
        let challenge = general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        Ok(challenge)
    }

    /// Validate client data JSON
    fn validate_client_data_json(&self, client_data_json: &str, expected_type: &str, expected_challenge: &str, expected_origin: &str) -> Result<Value> {
        let decoded = general_purpose::STANDARD.decode(client_data_json)
            .map_err(|e| AppError::ValidationError(format!("Invalid base64 encoding: {}", e)))?;
        
        let json_str = String::from_utf8(decoded)
            .map_err(|e| AppError::ValidationError(format!("Invalid UTF-8: {}", e)))?;
        
        let data: Value = serde_json::from_str(&json_str)
            .map_err(|e| AppError::ValidationError(format!("Invalid JSON: {}", e)))?;
        
        // Validate type
        let actual_type = data.get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::ValidationError("Missing type field".to_string()))?;
        
        if actual_type != expected_type {
            return Err(AppError::ValidationError(format!(
                "Invalid type: expected {}, got {}",
                expected_type, actual_type
            )));
        }

        // Validate challenge
        let actual_challenge = data.get("challenge")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::ValidationError("Missing challenge field".to_string()))?;
        
        if actual_challenge != expected_challenge {
            return Err(AppError::ValidationError("Invalid challenge".to_string()));
        }

        // Validate origin
        let actual_origin = data.get("origin")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::ValidationError("Missing origin field".to_string()))?;
        
        if actual_origin != expected_origin {
            return Err(AppError::ValidationError("Invalid origin".to_string()));
        }

        Ok(data)
    }
}

#[async_trait]
impl<T, U, C> WebAuthnService for WebAuthnServiceImpl<T, U, C>
where
    T: ChallengeStore,
    U: UserRepository,
    C: CredentialRepository,
{
    async fn begin_registration(&self, request: ServerPublicKeyCredentialCreationOptionsRequest) -> Result<ServerPublicKeyCredentialCreationOptionsResponse> {
        // Validate input
        if request.username.is_empty() {
            return Err(AppError::ValidationError("Username cannot be empty".to_string()));
        }
        if request.display_name.is_empty() {
            return Err(AppError::ValidationError("Display name cannot be empty".to_string()));
        }

        // Check if user already exists
        let existing_user = self.user_repo.get_user_by_username(&request.username).await?;
        let exclude_credentials = if let Some(user) = existing_user {
            let credentials = self.credential_repo.get_credentials_by_user(&user.id).await?;
            credentials.into_iter().map(|cred| ServerPublicKeyCredentialDescriptor {
                r#type: PUBLIC_KEY_CREDENTIAL_TYPE.to_string(),
                id: cred.id,
                transports: None,
            }).collect()
        } else {
            Vec::new()
        };

        // Generate challenge
        let challenge = self.generate_challenge()?;
        
        // Store challenge
        let expires_at = Utc::now() + chrono::Duration::milliseconds(self.config.timeout as i64);
        self.challenge_store.store_challenge(&challenge, &request.username, expires_at).await?;

        // Create user ID (base64url encoded)
        let user_id = general_purpose::URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes());

        // Build response
        let response = ServerPublicKeyCredentialCreationOptionsResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
            rp: PublicKeyCredentialRpEntity {
                name: self.config.rp_name.clone(),
                id: Some(self.config.rp_id.clone()),
            },
            user: ServerPublicKeyCredentialUserEntity {
                id: user_id,
                name: request.username.clone(),
                display_name: request.display_name,
            },
            challenge: challenge.clone(),
            pub_key_cred_params: vec![
                PublicKeyCredentialParameters {
                    r#type: PUBLIC_KEY_CREDENTIAL_TYPE.to_string(),
                    alg: ALG_ES256,
                },
                PublicKeyCredentialParameters {
                    r#type: PUBLIC_KEY_CREDENTIAL_TYPE.to_string(),
                    alg: ALG_RS256,
                },
            ],
            timeout: Some(self.config.timeout),
            exclude_credentials: Some(exclude_credentials),
            authenticator_selection: request.authenticator_selection.or_else(|| Some(AuthenticatorSelectionCriteria {
                require_resident_key: Some(false),
                authenticator_attachment: Some(AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM.to_string()),
                user_verification: Some(USER_VERIFICATION_PREFERRED.to_string()),
            })),
            attestation: request.attestation.or_else(|| Some(ATTESTATION_NONE.to_string())),
            extensions: request.extensions,
        };

        Ok(response)
    }

    async fn finish_registration(&self, credential: ServerPublicKeyCredential) -> Result<crate::webauthn::ServerResponse> {
        // Extract attestation response
        let attestation_response = match credential.response {
            crate::webauthn::ServerAuthenticatorResponse::Attestation(ref resp) => resp,
            _ => return Err(AppError::ValidationError("Expected attestation response".to_string())),
        };

        // Parse and validate client data JSON
        let client_data = self.validate_client_data_json(
            &attestation_response.client_data_json,
            "webauthn.create",
            "", // We'll get this from challenge store
            &self.config.rp_origin,
        )?;

        let challenge = client_data.get("challenge")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::ValidationError("Missing challenge in client data".to_string()))?;

        // Extract username from challenge store or user handle
        // For now, we'll need to extract it from somewhere - let's assume it's in the user entity
        // This is a simplified approach - in production, you'd store username with challenge
        
        // Validate and consume challenge
        // Note: We need the username here - this is a simplified implementation
        let username = ""; // This should come from the challenge store or request
        
        let is_valid = self.challenge_store.validate_and_consume_challenge(challenge, username).await?;
        if !is_valid {
            return Err(AppError::ValidationError("Invalid or expired challenge".to_string()));
        }

        // TODO: Validate attestation object and signature
        // This would involve parsing the attestation object and verifying the signature
        
        // For now, we'll store the credential
        let new_credential = NewCredential {
            id: credential.id.clone(),
            user_id: username.to_string(), // This should be the actual user ID
            public_key: vec![], // This should be extracted from attestation object
            sign_count: 0,
            created_at: Utc::now(),
            attestation_format: "none".to_string(),
            aaguid: None,
        };

        self.credential_repo.store_credential(new_credential).await?;

        Ok(crate::webauthn::ServerResponse::success())
    }

    async fn begin_authentication(&self, request: ServerPublicKeyCredentialGetOptionsRequest) -> Result<ServerPublicKeyCredentialGetOptionsResponse> {
        // Validate input
        if request.username.is_empty() {
            return Err(AppError::ValidationError("Username cannot be empty".to_string()));
        }

        // Get user
        let user = self.user_repo.get_user_by_username(&request.username).await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        // Get user's credentials
        let credentials = self.credential_repo.get_credentials_by_user(&user.id).await?;
        
        if credentials.is_empty() {
            return Err(AppError::NotFound("No credentials found for user".to_string()));
        }

        // Generate challenge
        let challenge = self.generate_challenge()?;
        
        // Store challenge
        let expires_at = Utc::now() + chrono::Duration::milliseconds(self.config.timeout as i64);
        self.challenge_store.store_challenge(&challenge, &request.username, expires_at).await?;

        // Build allow credentials list
        let allow_credentials: Vec<ServerPublicKeyCredentialDescriptor> = credentials.into_iter().map(|cred| {
            ServerPublicKeyCredentialDescriptor {
                r#type: PUBLIC_KEY_CREDENTIAL_TYPE.to_string(),
                id: cred.id,
                transports: None,
            }
        }).collect();

        let response = ServerPublicKeyCredentialGetOptionsResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
            challenge,
            timeout: Some(self.config.timeout),
            rp_id: self.config.rp_id.clone(),
            allow_credentials,
            user_verification: request.user_verification.or_else(|| Some(USER_VERIFICATION_PREFERRED.to_string())),
            extensions: request.extensions,
        };

        Ok(response)
    }

    async fn finish_authentication(&self, credential: ServerPublicKeyCredential) -> Result<crate::webauthn::ServerResponse> {
        // Extract assertion response
        let assertion_response = match credential.response {
            crate::webauthn::ServerAuthenticatorResponse::Assertion(ref resp) => resp,
            _ => return Err(AppError::ValidationError("Expected assertion response".to_string())),
        };

        // Parse and validate client data JSON
        let client_data = self.validate_client_data_json(
            &assertion_response.client_data_json,
            "webauthn.get",
            "", // We'll get this from challenge store
            &self.config.rp_origin,
        )?;

        let challenge = client_data.get("challenge")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::ValidationError("Missing challenge in client data".to_string()))?;

        // Get credential from database
        let stored_credential = self.credential_repo.get_credential_by_id(&credential.id).await?
            .ok_or_else(|| AppError::NotFound("Credential not found".to_string()))?;

        // Get user for challenge validation
        let user = self.user_repo.get_user_by_username(&stored_credential.user_id).await?;
        let username = user.map(|u| u.username).unwrap_or_default();

        // Validate and consume challenge
        let is_valid = self.challenge_store.validate_and_consume_challenge(challenge, &username).await?;
        if !is_valid {
            return Err(AppError::ValidationError("Invalid or expired challenge".to_string()));
        }

        // TODO: Verify signature and authenticator data
        // This would involve:
        // 1. Parsing authenticator data
        // 2. Verifying the signature against the stored public key
        // 3. Checking the sign count

        // Update sign count
        let new_sign_count = stored_credential.sign_count + 1;
        self.credential_repo.update_sign_count(&credential.id, new_sign_count).await?;

        Ok(crate::webauthn::ServerResponse::success())
    }
}

/// User entity
#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// New user entity
#[derive(Debug, Clone)]
pub struct NewUser {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
}

/// Credential entity
#[derive(Debug, Clone)]
pub struct Credential {
    pub id: String,
    pub user_id: String,
    pub public_key: Vec<u8>,
    pub sign_count: u32,
    pub created_at: DateTime<Utc>,
    pub attestation_format: String,
    pub aaguid: Option<Vec<u8>>,
}

/// New credential entity
#[derive(Debug, Clone)]
pub struct NewCredential {
    pub id: String,
    pub user_id: String,
    pub public_key: Vec<u8>,
    pub sign_count: u32,
    pub created_at: DateTime<Utc>,
    pub attestation_format: String,
    pub aaguid: Option<Vec<u8>>,
}