//! WebAuthn service trait and implementation

use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose};
use std::sync::Arc;
use uuid::Uuid;
use webauthn_rs::prelude::*;
use chrono::{DateTime, Utc, Duration};

use crate::schema::*;
use crate::services::repositories::{UserRepository, CredentialRepository, ChallengeRepository};
use crate::error::{Result, AppError};

/// WebAuthn service trait
#[async_trait]
pub trait WebAuthnService: Send + Sync {
    async fn generate_registration_challenge(
        &self, 
        request: ServerPublicKeyCredentialCreationOptionsRequest
    ) -> Result<ServerPublicKeyCredentialCreationOptionsResponse>;
    
    async fn verify_registration(
        &self, 
        credential: ServerPublicKeyCredential
    ) -> Result<ServerResponse>;
    
    async fn generate_authentication_challenge(
        &self, 
        request: ServerPublicKeyCredentialGetOptionsRequest
    ) -> Result<ServerPublicKeyCredentialGetOptionsResponse>;
    
    async fn verify_authentication(
        &self, 
        credential: ServerPublicKeyCredential
    ) -> Result<ServerResponse>;
}

/// WebAuthn service implementation
pub struct WebAuthnServiceImpl {
    webauthn: WebAuthn<Config>,
    user_repo: Arc<dyn UserRepository>,
    credential_repo: Arc<dyn CredentialRepository>,
    challenge_repo: Arc<dyn ChallengeRepository>,
}

impl WebAuthnServiceImpl {
    pub fn new(
        rp_id: &str,
        rp_name: &str,
        rp_origin: &str,
        user_repo: Arc<dyn UserRepository>,
        credential_repo: Arc<dyn CredentialRepository>,
        challenge_repo: Arc<dyn ChallengeRepository>,
    ) -> Result<Self> {
        let config = Config {
            rp: Rp {
                id: rp_id.to_string(),
                name: rp_name.to_string(),
            },
            origin: rp_origin.to_string(),
            ..Default::default()
        };

        let webauthn = WebAuthn::new(config);

        Ok(Self {
            webauthn,
            user_repo,
            credential_repo,
            challenge_repo,
        })
    }
}

#[async_trait]
impl WebAuthnService for WebAuthnServiceImpl {
    async fn generate_registration_challenge(
        &self,
        request: ServerPublicKeyCredentialCreationOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialCreationOptionsResponse> {
        // Find or create user
        let user = match self.user_repo.find_by_username(&request.username).await? {
            Some(user) => user,
            None => {
                let new_user = NewUser {
                    username: request.username.clone(),
                    display_name: request.display_name.clone(),
                    email: None,
                };
                self.user_repo.create(&new_user).await?
            }
        };

        // Get existing credentials for excludeCredentials
        let existing_creds = self.user_repo.find_by_username(&request.username).await
            .map_err(|_| AppError::WebAuthn("Failed to find user".to_string()))?;

        let exclude_credentials = if let Some(user) = existing_creds {
            let credentials = self.credential_repo.find_by_user_id(user.id).await?;
            credentials.into_iter().map(|cred| {
                ServerPublicKeyCredentialDescriptor {
                    credential_type: "public-key".to_string(),
                    id: general_purpose::URL_SAFE_NO_PAD.encode(&cred.credential_id),
                    transports: None,
                }
            }).collect()
        } else {
            vec![]
        };

        // Generate challenge
        let challenge_bytes = rand::random::<[u8; 32]>();
        let challenge = general_purpose::URL_SAFE_NO_PAD.encode(challenge_bytes);

        // Store challenge
        let expires_at = Utc::now() + Duration::minutes(5);
        let new_challenge = NewChallenge {
            user_id: Some(user.id),
            challenge: challenge.clone(),
            challenge_type: "registration".to_string(),
            expires_at,
        };
        self.challenge_repo.create(&new_challenge).await?;

        // Build response
        let mut response = ServerPublicKeyCredentialCreationOptionsResponse::default();
        response.rp.name = "Example Corporation".to_string();
        response.user = ServerPublicKeyCredentialUserEntity {
            id: general_purpose::URL_SAFE_NO_PAD.encode(user.id.as_bytes()),
            name: user.username,
            display_name: user.display_name,
        };
        response.challenge = challenge;
        response.exclude_credentials = Some(exclude_credentials);
        response.authenticator_selection = request.authenticator_selection;
        response.attestation = request.attestation.or(Some("none".to_string()));

        Ok(response)
    }

    async fn verify_registration(
        &self,
        credential: ServerPublicKeyCredential,
    ) -> Result<ServerResponse> {
        // Extract attestation response
        let attestation_response = match credential.response {
            ServerAuthenticatorResponse::Attestation(att) => att,
            _ => return Err(AppError::WebAuthn("Expected attestation response".to_string())),
        };

        // Decode client data JSON
        let client_data_json = general_purpose::URL_SAFE_NO_PAD.decode(&attestation_response.client_data_json)
            .map_err(|_| AppError::WebAuthn("Invalid client data JSON".to_string()))?;

        // Decode attestation object
        let attestation_object = general_purpose::URL_SAFE_NO_PAD.decode(&attestation_response.attestation_object)
            .map_err(|_| AppError::WebAuthn("Invalid attestation object".to_string()))?;

        // Parse client data to get challenge
        let client_data: serde_json::Value = serde_json::from_slice(&client_data_json)
            .map_err(|_| AppError::WebAuthn("Invalid client data format".to_string()))?;

        let challenge = client_data.get("challenge")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::WebAuthn("Missing challenge in client data".to_string()))?;

        // Verify challenge exists and is not expired
        let stored_challenge = self.challenge_repo.find_by_challenge(challenge).await?
            .ok_or_else(|| AppError::InvalidChallenge("Challenge not found".to_string()))?;

        if stored_challenge.challenge_type != "registration" {
            return Err(AppError::InvalidChallenge("Invalid challenge type".to_string()));
        }

        if stored_challenge.expires_at < Utc::now() {
            return Err(AppError::InvalidChallenge("Challenge expired".to_string()));
        }

        // Get user
        let user = self.user_repo.find_by_id(stored_challenge.user_id.unwrap())
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        // Create webauthn-rs credential verification request
        let mut verify_request = VerifyRegistrationResponse {
            credential: webauthn_rs::prelude::PublicKeyCredential {
                id: credential.id.clone(),
                raw_id: general_purpose::URL_SAFE_NO_PAD.decode(&credential.id)
                    .map_err(|_| AppError::WebAuthn("Invalid credential ID".to_string()))?,
                response: webauthn_rs::prelude::AuthenticatorAttestationResponse {
                    client_data_json,
                    attestation_object,
                },
                type_: "public-key".to_string(),
                extensions: None,
            },
            user_verification: None,
        };

        // Verify the registration
        let verification_result = self.webauthn.register_credential(&mut verify_request)
            .map_err(|e| AppError::WebAuthn(format!("Registration verification failed: {:?}", e)))?;

        // Store the credential
        let new_credential = NewCredential {
            user_id: user.id,
            credential_id: verification_result.credential_id,
            public_key: verification_result.public_key,
            sign_count: verification_result.counter as i64,
            attestation_format: verification_result.attestation_format,
            attestation_data: Some(verification_result.attestation_data),
            transports: None,
        };

        self.credential_repo.create(&new_credential).await?;

        // Clean up challenge
        self.challenge_repo.delete(stored_challenge.id).await?;

        Ok(ServerResponse::success())
    }

    async fn generate_authentication_challenge(
        &self,
        request: ServerPublicKeyCredentialGetOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialGetOptionsResponse> {
        // Find user
        let user = self.user_repo.find_by_username(&request.username).await?
            .ok_or_else(|| AppError::NotFound("User does not exists!".to_string()))?;

        // Get user's credentials
        let credentials = self.credential_repo.find_by_user_id(user.id).await?;
        
        if credentials.is_empty() {
            return Err(AppError::NotFound("No credentials found for user".to_string()));
        }

        // Build allowCredentials
        let allow_credentials: Vec<ServerPublicKeyCredentialDescriptor> = credentials.into_iter().map(|cred| {
            ServerPublicKeyCredentialDescriptor {
                credential_type: "public-key".to_string(),
                id: general_purpose::URL_SAFE_NO_PAD.encode(&cred.credential_id),
                transports: None,
            }
        }).collect();

        // Generate challenge
        let challenge_bytes = rand::random::<[u8; 32]>();
        let challenge = general_purpose::URL_SAFE_NO_PAD.encode(challenge_bytes);

        // Store challenge
        let expires_at = Utc::now() + Duration::minutes(5);
        let new_challenge = NewChallenge {
            user_id: Some(user.id),
            challenge: challenge.clone(),
            challenge_type: "authentication".to_string(),
            expires_at,
        };
        self.challenge_repo.create(&new_challenge).await?;

        // Build response
        let mut response = ServerPublicKeyCredentialGetOptionsResponse::default();
        response.challenge = challenge;
        response.allow_credentials = allow_credentials;
        response.user_verification = request.user_verification.or(Some("preferred".to_string()));

        Ok(response)
    }

    async fn verify_authentication(
        &self,
        credential: ServerPublicKeyCredential,
    ) -> Result<ServerResponse> {
        // Extract assertion response
        let assertion_response = match credential.response {
            ServerAuthenticatorResponse::Assertion(assert) => assert,
            _ => return Err(AppError::WebAuthn("Expected assertion response".to_string())),
        };

        // Decode client data JSON
        let client_data_json = general_purpose::URL_SAFE_NO_PAD.decode(&assertion_response.client_data_json)
            .map_err(|_| AppError::WebAuthn("Invalid client data JSON".to_string()))?;

        // Decode authenticator data
        let authenticator_data = general_purpose::URL_SAFE_NO_PAD.decode(&assertion_response.authenticator_data)
            .map_err(|_| AppError::WebAuthn("Invalid authenticator data".to_string()))?;

        // Decode signature
        let signature = general_purpose::URL_SAFE_NO_PAD.decode(&assertion_response.signature)
            .map_err(|_| AppError::WebAuthn("Invalid signature".to_string()))?;

        // Parse client data to get challenge
        let client_data: serde_json::Value = serde_json::from_slice(&client_data_json)
            .map_err(|_| AppError::WebAuthn("Invalid client data format".to_string()))?;

        let challenge = client_data.get("challenge")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::WebAuthn("Missing challenge in client data".to_string()))?;

        // Verify challenge exists and is not expired
        let stored_challenge = self.challenge_repo.find_by_challenge(challenge).await?
            .ok_or_else(|| AppError::InvalidChallenge("Challenge not found".to_string()))?;

        if stored_challenge.challenge_type != "authentication" {
            return Err(AppError::InvalidChallenge("Invalid challenge type".to_string()));
        }

        if stored_challenge.expires_at < Utc::now() {
            return Err(AppError::InvalidChallenge("Challenge expired".to_string()));
        }

        // Find credential by ID
        let credential_id = general_purpose::URL_SAFE_NO_PAD.decode(&credential.id)
            .map_err(|_| AppError::WebAuthn("Invalid credential ID".to_string()))?;

        let stored_credential = self.credential_repo.find_by_credential_id(&credential_id).await?
            .ok_or_else(|| AppError::NotFound("Credential not found".to_string()))?;

        // Create authentication request
        let auth_request = AuthenticateCredential {
            credential: webauthn_rs::prelude::PublicKeyCredential {
                id: credential.id.clone(),
                raw_id: credential_id,
                response: webauthn_rs::prelude::AuthenticatorAssertionResponse {
                    authenticator_data,
                    client_data_json,
                    signature,
                    user_handle: assertion_response.user_handle
                        .and_then(|uh| general_purpose::URL_SAFE_NO_PAD.decode(&uh).ok()),
                },
                type_: "public-key".to_string(),
                extensions: None,
            },
            user_verification: None,
        };

        // Verify the authentication
        let verification_result = self.webauthn.authenticate_credential(auth_request)
            .map_err(|e| AppError::WebAuthn(format!("Authentication verification failed: {:?}", e)))?;

        // Update sign count
        self.credential_repo.update_sign_count(
            stored_credential.id, 
            verification_result.counter as i64
        ).await?;

        // Clean up challenge
        self.challenge_repo.delete(stored_challenge.id).await?;

        Ok(ServerResponse::success())
    }
}