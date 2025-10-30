use crate::error::{AppError, Result};
use crate::dtos::*;
use crate::models::{User, NewUser, NewCredential, NewChallenge};
use crate::repositories::{UserRepository, CredentialRepository, ChallengeRepository};
use base64::{Engine as _, engine::general_purpose};
use uuid::Uuid;
use chrono::{Utc, Duration};
use std::sync::Arc;
use rand::RngCore;

#[async_trait::async_trait]
pub trait WebAuthnService: Send + Sync {
    async fn begin_registration(&self, request: ServerPublicKeyCredentialCreationOptionsRequest) -> Result<ServerPublicKeyCredentialCreationOptionsResponse>;
    async fn finish_registration(&self, credential: ServerPublicKeyCredential) -> Result<ServerResponse>;
    async fn begin_authentication(&self, request: ServerPublicKeyCredentialGetOptionsRequest) -> Result<ServerPublicKeyCredentialGetOptionsResponse>;
    async fn finish_authentication(&self, credential: ServerPublicKeyCredential) -> Result<ServerResponse>;
}

pub struct WebAuthnServiceImpl {
    user_repo: Arc<dyn UserRepository>,
    credential_repo: Arc<dyn CredentialRepository>,
    challenge_repo: Arc<dyn ChallengeRepository>,
    rp_name: String,
    rp_id: String,
    #[allow(dead_code)]
    rp_origin: String,
}

impl WebAuthnServiceImpl {
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        credential_repo: Arc<dyn CredentialRepository>,
        challenge_repo: Arc<dyn ChallengeRepository>,
        rp_name: String,
        rp_id: String,
        rp_origin: String,
    ) -> Result<Self> {
        // For now, we'll create a simple WebAuthn service without full webauthn-rs integration
        // This will be expanded later for full FIDO2 compliance

        Ok(Self {
            user_repo,
            credential_repo,
            challenge_repo,
            rp_name,
            rp_id,
            rp_origin,
        })
    }

    fn generate_challenge(&self) -> String {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    async fn get_or_create_user(&self, username: &str, display_name: &str) -> Result<User> {
        if let Some(user) = self.user_repo.find_by_username(username).await? {
            Ok(user)
        } else {
            let new_user = NewUser {
                id: Uuid::new_v4().to_string(),
                username: username.to_string(),
                display_name: display_name.to_string(),
            };
            self.user_repo.create_user(&new_user).await
        }
    }
}

#[async_trait::async_trait]
impl WebAuthnService for WebAuthnServiceImpl {
    async fn begin_registration(&self, request: ServerPublicKeyCredentialCreationOptionsRequest) -> Result<ServerPublicKeyCredentialCreationOptionsResponse> {
        let user = self.get_or_create_user(&request.username, &request.display_name).await?;
        
        // Get existing credentials for excludeCredentials
        let existing_creds = self.credential_repo.find_by_user_id(&user.id).await?;
        let exclude_credentials: Vec<ServerPublicKeyCredentialDescriptor> = existing_creds
            .into_iter()
            .map(|cred| ServerPublicKeyCredentialDescriptor {
                cred_type: "public-key".to_string(),
                id: general_purpose::URL_SAFE_NO_PAD.encode(&cred.credential_id),
                transports: None,
            })
            .collect();

        // Generate challenge
        let challenge = self.generate_challenge();
        
        // Store challenge
        let new_challenge = NewChallenge {
            id: Uuid::new_v4().to_string(),
            user_id: Some(user.id.clone()),
            challenge: challenge.clone(),
            challenge_type: "registration".to_string(),
            expires_at: (Utc::now() + Duration::minutes(5)).to_rfc3339(),
        };
        self.challenge_repo.create_challenge(&new_challenge).await?;

        // Build user entity for response
        let user_entity = ServerPublicKeyCredentialUserEntity {
            id: general_purpose::URL_SAFE_NO_PAD.encode(user.id.as_bytes()),
            name: user.username,
            display_name: user.display_name,
        };

        // Build RP entity
        let rp_entity = PublicKeyCredentialRpEntity {
            name: self.rp_name.clone(),
        };

        // Build credential parameters
        let pub_key_cred_params = vec![
            PublicKeyCredentialParameters {
                cred_type: "public-key".to_string(),
                alg: -7, // ES256
            },
        ];

        Ok(ServerPublicKeyCredentialCreationOptionsResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
            rp: rp_entity,
            user: user_entity,
            challenge,
            pub_key_cred_params,
            timeout: Some(10000),
            exclude_credentials: Some(exclude_credentials),
            authenticator_selection: request.authenticator_selection,
            attestation: request.attestation,
        })
    }

    async fn finish_registration(&self, credential: ServerPublicKeyCredential) -> Result<ServerResponse> {
        let ServerAuthenticatorResponse::Attestation(attestation_response) = credential.response else {
            return Err(AppError::InvalidRequest("Expected attestation response".to_string()));
        };

        // Decode client data JSON
        let client_data_json = general_purpose::URL_SAFE_NO_PAD.decode(&attestation_response.client_data_json)
            .map_err(|e| AppError::Base64(e))?;
        
        let client_data: serde_json::Value = serde_json::from_slice(&client_data_json)
            .map_err(|e| AppError::Serialization(e))?;

        // Extract challenge from client data
        let challenge = client_data.get("challenge")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::InvalidRequest("Missing challenge in client data".to_string()))?;

        // Verify challenge
        let stored_challenge = self.challenge_repo
            .find_and_consume_challenge(challenge, "registration")
            .await?
            .ok_or(AppError::ChallengeNotFound)?;

        // Get user
        let user_id = stored_challenge.user_id
            .ok_or(AppError::InvalidRequest("Challenge has no user ID".to_string()))?;
        
        let user = self.user_repo.find_by_id(&user_id).await?
            .ok_or(AppError::UserNotFound("User not found".to_string()))?;

        // Decode attestation object
        let attestation_object = general_purpose::URL_SAFE_NO_PAD.decode(&attestation_response.attestation_object)
            .map_err(|e| AppError::Base64(e))?;

        // Decode credential ID
        let credential_id = general_purpose::URL_SAFE_NO_PAD.decode(&credential.id)
            .map_err(|e| AppError::Base64(e))?;

        // For now, we'll store the credential without full WebAuthn verification
        // In a production implementation, you would verify the attestation using webauthn-rs
        let new_credential = NewCredential {
            id: Uuid::new_v4().to_string(),
            user_id: user.id.clone(),
            credential_id: credential_id.clone(),
            public_key: attestation_object, // Store attestation object for now
            sign_count: 0,
            attestation_format: "none".to_string(),
            attestation_data: None,
        };

        self.credential_repo.create_credential(&new_credential).await?;

        Ok(ServerResponse::success())
    }

    async fn begin_authentication(&self, request: ServerPublicKeyCredentialGetOptionsRequest) -> Result<ServerPublicKeyCredentialGetOptionsResponse> {
        let user = self.user_repo.find_by_username(&request.username).await?
            .ok_or(AppError::UserNotFound(request.username))?;

        // Get user's credentials
        let credentials = self.credential_repo.find_by_user_id(&user.id).await?;
        
        if credentials.is_empty() {
            return Err(AppError::CredentialNotFound);
        }

        // Generate challenge
        let challenge = self.generate_challenge();
        
        // Store challenge
        let new_challenge = NewChallenge {
            id: Uuid::new_v4().to_string(),
            user_id: Some(user.id.clone()),
            challenge: challenge.clone(),
            challenge_type: "authentication".to_string(),
            expires_at: (Utc::now() + Duration::minutes(5)).to_rfc3339(),
        };
        self.challenge_repo.create_challenge(&new_challenge).await?;

        // Build allowCredentials
        let allow_credentials: Vec<ServerPublicKeyCredentialDescriptor> = credentials
            .into_iter()
            .map(|cred| ServerPublicKeyCredentialDescriptor {
                cred_type: "public-key".to_string(),
                id: general_purpose::URL_SAFE_NO_PAD.encode(&cred.credential_id),
                transports: None,
            })
            .collect();

        Ok(ServerPublicKeyCredentialGetOptionsResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
            challenge,
            timeout: Some(20000),
            rp_id: self.rp_id.clone(),
            allow_credentials,
            user_verification: request.user_verification,
        })
    }

    async fn finish_authentication(&self, credential: ServerPublicKeyCredential) -> Result<ServerResponse> {
        let ServerAuthenticatorResponse::Assertion(assertion_response) = credential.response else {
            return Err(AppError::InvalidRequest("Expected assertion response".to_string()));
        };

        // Decode client data JSON
        let client_data_json = general_purpose::URL_SAFE_NO_PAD.decode(&assertion_response.client_data_json)
            .map_err(|e| AppError::Base64(e))?;
        
        let client_data: serde_json::Value = serde_json::from_slice(&client_data_json)
            .map_err(|e| AppError::Serialization(e))?;

        // Extract challenge from client data
        let challenge = client_data.get("challenge")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::InvalidRequest("Missing challenge in client data".to_string()))?;

        // Verify challenge
        let _stored_challenge = self.challenge_repo
            .find_and_consume_challenge(challenge, "authentication")
            .await?
            .ok_or(AppError::ChallengeNotFound)?;

        // Decode credential ID
        let credential_id = general_purpose::URL_SAFE_NO_PAD.decode(&credential.id)
            .map_err(|e| AppError::Base64(e))?;

        // Find credential
        let mut stored_credential = self.credential_repo.find_by_credential_id(&credential_id).await?
            .ok_or(AppError::CredentialNotFound)?;

        // For now, we'll just update the sign count without full verification
        // In a production implementation, you would verify the assertion signature
        stored_credential.sign_count += 1;
        self.credential_repo.update_sign_count(&credential_id, stored_credential.sign_count).await?;

        Ok(ServerResponse::success())
    }
}