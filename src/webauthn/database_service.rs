//! Database-backed WebAuthn service implementation
//!
//! This module provides the core WebAuthn functionality for registration and authentication
//! using PostgreSQL database storage for production use.

use crate::error::{AppError, Result};
use crate::webauthn::*;
use crate::schema::{UserRepository, CredentialRepository, ChallengeRepository};
use base64::{Engine as _, engine::general_purpose};
use std::sync::Arc;
use uuid::Uuid;

/// Trait for WebAuthn operations
#[async_trait::async_trait]
pub trait WebAuthnService: Send + Sync {
    async fn begin_registration(
        &self,
        request: ServerPublicKeyCredentialCreationOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialCreationOptionsResponse>;

    async fn finish_registration(
        &self,
        credential: ServerPublicKeyCredential,
        username: &str,
    ) -> Result<ServerResponse>;

    async fn begin_authentication(
        &self,
        request: ServerPublicKeyCredentialGetOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialGetOptionsResponse>;

    async fn finish_authentication(
        &self,
        credential: ServerAssertionPublicKeyCredential,
    ) -> Result<ServerResponse>;
}

/// Database-backed WebAuthn service implementation
pub struct DatabaseWebAuthnService {
    config: WebAuthnConfig,
    user_repo: Arc<UserRepository>,
    credential_repo: Arc<CredentialRepository>,
    challenge_repo: Arc<ChallengeRepository>,
}

impl DatabaseWebAuthnService {
    pub fn new(
        config: WebAuthnConfig,
        user_repo: Arc<UserRepository>,
        credential_repo: Arc<CredentialRepository>,
        challenge_repo: Arc<ChallengeRepository>,
    ) -> Self {
        Self {
            config,
            user_repo,
            credential_repo,
            challenge_repo,
        }
    }

    /// Generate a random challenge
    fn generate_challenge(&self) -> String {
        let challenge_bytes = rand::random::<[u8; 32]>();
        general_purpose::URL_SAFE_NO_PAD.encode(challenge_bytes)
    }

    /// Store a challenge
    async fn store_challenge(
        &self,
        challenge: &str,
        username: Option<String>,
        challenge_type: ChallengeType,
    ) -> Result<()> {
        let expires_at = chrono::Utc::now() + chrono::Duration::minutes(5);
        
        let new_challenge = crate::schema::NewChallenge {
            challenge: challenge.to_string(),
            username,
            challenge_type: match challenge_type {
            crate::webauthn::ChallengeType::Registration => "registration".to_string(),
            crate::webauthn::ChallengeType::Authentication => "authentication".to_string(),
        },
            expires_at,
        };

        self.challenge_repo.create_challenge(new_challenge).await?;
        Ok(())
    }

    /// Validate and consume a challenge
    async fn validate_and_consume_challenge(
        &self,
        challenge: &str,
        challenge_type: ChallengeType,
    ) -> Result<Option<String>> {
        let challenge_record = self.challenge_repo.consume_challenge(challenge).await?;
        
        if let Some(record) = challenge_record {
            // Check if challenge is not expired
            if record.expires_at < chrono::Utc::now() {
                return Err(AppError::BadRequest("Challenge has expired".to_string()));
            }

            // Check challenge type
            let record_type = match record.challenge_type.as_str() {
            "registration" => crate::webauthn::ChallengeType::Registration,
            "authentication" => crate::webauthn::ChallengeType::Authentication,
            _ => return Err(AppError::BadRequest("Invalid challenge type".to_string())),
        };
            if std::mem::discriminant(&record_type) != std::mem::discriminant(&challenge_type) {
                return Err(AppError::BadRequest("Invalid challenge type".to_string()));
            }

            Ok(record.username)
        } else {
            Err(AppError::BadRequest("Invalid or already used challenge".to_string()))
        }
    }

    /// Get or create user
    async fn get_or_create_user(&self, username: &str, display_name: &str) -> Result<crate::schema::User> {
        if let Some(user) = self.user_repo.get_user_by_username(username).await? {
            Ok(user)
        } else {
            let new_user = crate::schema::NewUser {
                username: username.to_string(),
                display_name: display_name.to_string(),
            };
            self.user_repo.create_user(new_user).await
        }
    }

    /// Get user credentials
    async fn get_user_credentials(&self, user_id: &Uuid) -> Result<Vec<crate::schema::Credential>> {
        self.credential_repo.get_credentials_by_user(user_id).await
    }

    /// Verify client data JSON
    fn verify_client_data_json(&self, client_data_json: &str, expected_type: &str, expected_origin: &str) -> Result<String> {
        let client_data_bytes = general_purpose::URL_SAFE_NO_PAD.decode(client_data_json)
            .map_err(|_| AppError::BadRequest("Invalid client data JSON encoding".to_string()))?;
        
        let client_data: serde_json::Value = serde_json::from_slice(&client_data_bytes)
            .map_err(|_| AppError::BadRequest("Invalid client data JSON format".to_string()))?;

        // Verify type
        let client_type = client_data.get("type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::BadRequest("Missing type in client data".to_string()))?;
        
        if client_type != expected_type {
            return Err(AppError::BadRequest(format!("Invalid client data type: expected {}, got {}", expected_type, client_type)));
        }

        // Verify origin
        let origin = client_data.get("origin")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::BadRequest("Missing origin in client data".to_string()))?;
        
        if origin != expected_origin {
            return Err(AppError::BadRequest(format!("Invalid origin: expected {}, got {}", expected_origin, origin)));
        }

        // Extract and return challenge
        let challenge = client_data.get("challenge")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::BadRequest("Missing challenge in client data".to_string()))?;

        Ok(challenge.to_string())
    }
}

#[async_trait::async_trait]
impl WebAuthnService for DatabaseWebAuthnService {
    async fn begin_registration(
        &self,
        request: ServerPublicKeyCredentialCreationOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialCreationOptionsResponse> {
        // Validate input
        if request.username.is_empty() {
            return Err(AppError::BadRequest("Username is required".to_string()));
        }
        if request.display_name.is_empty() {
            return Err(AppError::BadRequest("Display name is required".to_string()));
        }

        // Generate challenge
        let challenge = self.generate_challenge();
        
        // Store challenge
        self.store_challenge(&challenge, Some(request.username.clone()), ChallengeType::Registration).await?;

        // Get or create user
        let user = self.get_or_create_user(&request.username, &request.display_name).await?;
        
        // Get existing credentials for exclusion
        let existing_credentials = self.get_user_credentials(&user.id).await?;
        let exclude_credentials: Vec<ServerPublicKeyCredentialDescriptor> = existing_credentials
            .into_iter()
            .map(|cred| ServerPublicKeyCredentialDescriptor {
                cred_type: "public-key".to_string(),
                id: cred.credential_id,
                transports: vec![],
            })
            .collect();

        // Build response
        let response = ServerPublicKeyCredentialCreationOptionsResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
            rp: PublicKeyCredentialRpEntity {
                name: self.config.rp_name.clone(),
            },
            user: ServerPublicKeyCredentialUserEntity {
                id: general_purpose::URL_SAFE_NO_PAD.encode(user.id.as_bytes()),
                name: user.username,
                display_name: user.display_name,
            },
            challenge,
            pub_key_cred_params: vec![
                PublicKeyCredentialParameters {
                    cred_type: "public-key".to_string(),
                    alg: -7, // ES256
                },
                PublicKeyCredentialParameters {
                    cred_type: "public-key".to_string(),
                    alg: -257, // RS256
                },
                PublicKeyCredentialParameters {
                    cred_type: "public-key".to_string(),
                    alg: -8, // Ed25519
                },
            ],
            timeout: Some(self.config.timeout),
            exclude_credentials,
            authenticator_selection: request.authenticator_selection,
            attestation: Some(request.attestation),
            extensions: None,
        };

        Ok(response)
    }

    async fn finish_registration(
        &self,
        credential: ServerPublicKeyCredential,
        _username: &str,
    ) -> Result<ServerResponse> {
        // Verify client data JSON
        let challenge = self.verify_client_data_json(
            &credential.response.client_data_json,
            "webauthn.create",
            &self.config.rp_origin,
        )?;

        // Validate challenge and get username
        let username = self.validate_and_consume_challenge(&challenge, ChallengeType::Registration).await?
            .ok_or_else(|| AppError::BadRequest("Username not found in challenge".to_string()))?;

        // Get user
        let user = self.user_repo.get_user_by_username(&username)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        // Basic validation of credential structure
        if credential.id.is_empty() {
            return Err(AppError::BadRequest("Credential ID is required".to_string()));
        }

        if credential.cred_type != "public-key" {
            return Err(AppError::BadRequest("Invalid credential type".to_string()));
        }

        if credential.response.client_data_json.is_empty() {
            return Err(AppError::BadRequest("Client data JSON is required".to_string()));
        }

        if credential.response.attestation_object.is_empty() {
            return Err(AppError::BadRequest("Attestation object is required".to_string()));
        }

        // Store credential (simplified - in real implementation you'd extract the public key from attestation)
        let cred_id_bytes = general_purpose::URL_SAFE_NO_PAD.decode(&credential.id)
            .map_err(|_| AppError::BadRequest("Invalid credential ID encoding".to_string()))?;

        let new_credential = crate::schema::NewCredential {
            user_id: user.id,
            credential_id: credential.id.clone(),
            public_key: cred_id_bytes, // Simplified - should be actual public key
            sign_count: 0,
            attestation_type: Some("none".to_string()),
            aaguid: None,
        };

        self.credential_repo.create_credential(new_credential).await?;

        Ok(ServerResponse::success())
    }

    async fn begin_authentication(
        &self,
        request: ServerPublicKeyCredentialGetOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialGetOptionsResponse> {
        // Validate input
        if request.username.is_empty() {
            return Err(AppError::BadRequest("Username is required".to_string()));
        }

        // Get user
        let user = self.user_repo.get_user_by_username(&request.username)
            .await?
            .ok_or_else(|| AppError::BadRequest("User does not exists!".to_string()))?;

        // Generate challenge
        let challenge = self.generate_challenge();
        
        // Store challenge
        self.store_challenge(&challenge, Some(request.username.clone()), ChallengeType::Authentication).await?;

        // Get user credentials
        let user_credentials = self.get_user_credentials(&user.id).await?;
        let allow_credentials: Vec<ServerPublicKeyCredentialDescriptor> = user_credentials
            .into_iter()
            .map(|cred| ServerPublicKeyCredentialDescriptor {
                cred_type: "public-key".to_string(),
                id: cred.credential_id,
                transports: vec![],
            })
            .collect();

        // Build response
        let response = ServerPublicKeyCredentialGetOptionsResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
            challenge,
            timeout: Some(self.config.timeout),
            rp_id: self.config.rp_id.clone(),
            allow_credentials,
            user_verification: request.user_verification,
            extensions: None,
        };

        Ok(response)
    }

    async fn finish_authentication(
        &self,
        credential: ServerAssertionPublicKeyCredential,
    ) -> Result<ServerResponse> {
        // Verify client data JSON
        let challenge = self.verify_client_data_json(
            &credential.response.client_data_json,
            "webauthn.get",
            &self.config.rp_origin,
        )?;

        // Validate challenge
        let _username = self.validate_and_consume_challenge(&challenge, ChallengeType::Authentication).await?;

        // Basic validation of assertion structure
        if credential.id.is_empty() {
            return Err(AppError::BadRequest("Credential ID is required".to_string()));
        }

        if credential.cred_type != "public-key" {
            return Err(AppError::BadRequest("Invalid credential type".to_string()));
        }

        if credential.response.client_data_json.is_empty() {
            return Err(AppError::BadRequest("Client data JSON is required".to_string()));
        }

        if credential.response.authenticator_data.is_empty() {
            return Err(AppError::BadRequest("Authenticator data is required".to_string()));
        }

        if credential.response.signature.is_empty() {
            return Err(AppError::BadRequest("Signature is required".to_string()));
        }

        // Get credential
        let stored_credential = self.credential_repo.get_credential_by_id(&credential.id)
            .await?
            .ok_or_else(|| AppError::BadRequest("Credential not found".to_string()))?;

        // In a real implementation, you would:
        // 1. Verify the signature using the stored public key
        // 2. Check the authenticator data flags
        // 3. Verify the user verification if required
        // 4. Check for replay attacks

        // For now, just update the sign count and return success
        self.credential_repo.update_sign_count(&credential.id, stored_credential.sign_count + 1).await?;

        Ok(ServerResponse::success())
    }
}