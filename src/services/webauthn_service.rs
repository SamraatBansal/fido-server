//! WebAuthn service implementation

use std::sync::Arc;
use uuid::Uuid;
use webauthn_rs::{Webauthn, WebauthnBuilder};
use crate::config::WebAuthnConfig;
use crate::db::repositories::{UserRepository, CredentialRepository, ChallengeRepository};
use crate::models::{
    ServerPublicKeyCredentialCreationOptionsRequest, ServerPublicKeyCredentialCreationOptionsResponse,
    ServerPublicKeyCredentialGetOptionsRequest, ServerPublicKeyCredentialGetOptionsResponse,
    ServerPublicKeyCredential, ServerAuthenticatorResponse, RegistrationResultResponse,
    AuthenticationResultResponse, PublicKeyCredentialRpEntity, ServerPublicKeyCredentialUserEntity,
    ServerPublicKeyCredentialDescriptor, ChallengeType, StoredChallenge, User, Credential,
};
use crate::error::{AppError, Result};

/// WebAuthn service
pub struct WebAuthnService {
    webauthn: WebAuthn,
    user_repo: Arc<dyn UserRepository>,
    credential_repo: Arc<dyn CredentialRepository>,
    challenge_repo: Arc<dyn ChallengeRepository>,
    config: WebAuthnConfig,
}

impl WebAuthnService {
    /// Create a new WebAuthn service
    pub fn new(
        config: WebAuthnConfig,
        user_repo: Arc<dyn UserRepository>,
        credential_repo: Arc<dyn CredentialRepository>,
        challenge_repo: Arc<dyn ChallengeRepository>,
    ) -> Result<Self> {
        let webauthn = WebauthnBuilder::new(&config.rp_id, &config.rp_origin)
            .rp_name(&config.rp_name)
            .build()
            .map_err(|e| AppError::Configuration(format!("Failed to create WebAuthn instance: {}", e)))?;

        Ok(Self {
            webauthn,
            user_repo,
            credential_repo,
            challenge_repo,
            config,
        })
    }

    /// Generate registration options
    pub async fn generate_registration_options(
        &self,
        request: ServerPublicKeyCredentialCreationOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialCreationOptionsResponse> {
        // Validate input
        if request.username.trim().is_empty() {
            return Err(AppError::InvalidInput("Username is required".to_string()));
        }
        if request.display_name.trim().is_empty() {
            return Err(AppError::InvalidInput("Display name is required".to_string()));
        }
        if request.username.len() > 255 {
            return Err(AppError::InvalidInput("Username too long".to_string()));
        }
        if request.display_name.len() > 255 {
            return Err(AppError::InvalidInput("Display name too long".to_string()));
        }

        // Get or create user
        let user = match self.user_repo.get_user_by_username(&request.username).await? {
            Some(user) => user,
            None => self.user_repo.create_user(&request.username, &request.display_name).await?,
        };

        // Get existing credentials for exclusion
        let existing_credentials = self.credential_repo.get_credentials_for_user(user.id).await?;
        let exclude_credentials: Vec<ServerPublicKeyCredentialDescriptor> = existing_credentials
            .into_iter()
            .map(|cred| ServerPublicKeyCredentialDescriptor {
                credential_type: "public-key".to_string(),
                id: crate::utils::encode_base64url(&cred.credential_id),
                transports: None,
            })
            .collect();

        // Generate challenge
        let (options, state) = self.webauthn
            .generate_challenge_register_options(
                &user.to_webauthn_user(),
                request.authenticator_selection.unwrap_or_default(),
                request.attestation.unwrap_or(self.config.attestation_preference),
                self.config.timeout,
                None,
            )
            .map_err(|e| AppError::WebAuthn(e))?;

        // Store challenge
        let stored_challenge = StoredChallenge {
            challenge: state.challenge.clone(),
            user_id: user.id,
            challenge_type: ChallengeType::Registration,
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(300), // 5 minutes
        };
        self.challenge_repo.store_challenge(&stored_challenge).await?;

        // Convert to response format
        let response = ServerPublicKeyCredentialCreationOptionsResponse {
            response: crate::models::ServerResponse::success(),
            rp: PublicKeyCredentialRpEntity {
                name: self.config.rp_name.clone(),
            },
            user: ServerPublicKeyCredentialUserEntity {
                id: crate::utils::encode_base64url(user.id.as_bytes()),
                name: user.username,
                display_name: user.display_name,
            },
            challenge: state.challenge,
            pub_key_cred_params: options.pub_key_cred_params,
            timeout: options.timeout,
            exclude_credentials,
            authenticator_selection: options.authenticator_selection,
            attestation: options.attestation,
            extensions: options.extensions.map(|ext| {
                ext.into_iter().map(|(k, v)| (k, serde_json::to_value(v).unwrap_or_default())).collect()
            }),
        };

        Ok(response)
    }

    /// Verify registration response
    pub async fn verify_registration(
        &self,
        credential: ServerPublicKeyCredential,
    ) -> Result<RegistrationResultResponse> {
        let ServerAuthenticatorResponse::Attestation(attestation_response) = credential.response else {
            return Err(AppError::InvalidInput("Expected attestation response".to_string()));
        };

        // Decode client data JSON
        let client_data_json = crate::utils::decode_base64url(&attestation_response.client_data_json)
            .map_err(|_| AppError::InvalidInput("Invalid client data JSON encoding".to_string()))?;

        // Parse client data JSON to get challenge
        let client_data: serde_json::Value = serde_json::from_slice(&client_data_json)
            .map_err(|_| AppError::InvalidInput("Invalid client data JSON format".to_string()))?;

        let challenge = client_data.get("challenge")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::InvalidInput("Missing challenge in client data".to_string()))?;

        // Get and consume challenge
        let stored_challenge = self.challenge_repo
            .consume_challenge(challenge, ChallengeType::Registration)
            .await?
            .ok_or_else(|| AppError::ChallengeNotFound("Challenge not found or expired".to_string()))?;

        // Check if challenge has expired
        if stored_challenge.expires_at < chrono::Utc::now() {
            return Err(AppError::ChallengeNotFound("Challenge has expired".to_string()));
        }

        // Get user
        let user = self.user_repo.get_user_by_id(stored_challenge.user_id).await?
            .ok_or_else(|| AppError::UserNotFound("User not found".to_string()))?;

        // Decode attestation object
        let attestation_object = crate::utils::decode_base64url(&attestation_response.attestation_object)
            .map_err(|_| AppError::InvalidInput("Invalid attestation object encoding".to_string()))?;

        // Create webauthn-rs credential
        let webauthn_credential = webauthn_rs_proto::PublicKeyCredential {
            id: credential.id.clone(),
            raw_id: crate::utils::decode_base64url(&credential.id)
                .map_err(|_| AppError::InvalidInput("Invalid credential ID encoding".to_string()))?,
            response: webauthn_rs_proto::AuthenticatorAttestationResponseRaw {
                attestation_object,
                client_data_json,
            },
            extensions: credential.get_client_extension_results.unwrap_or_default(),
        };

        // Verify registration
        let result = self.webauthn.register_credential(&webauthn_credential)
            .map_err(|e| AppError::RegistrationFailed(format!("Registration verification failed: {}", e)))?;

        // Store credential
        let credential_model = Credential {
            id: Uuid::new_v4(),
            credential_id: result.credential_id.clone(),
            user_id: user.id,
            public_key: result.public_key,
            sign_count: result.sign_count,
            attestation_format: result.attestation_format,
            attestation_data: result.attestation_data,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        self.credential_repo.create_credential(&credential_model).await?;

        Ok(RegistrationResultResponse {
            response: crate::models::ServerResponse::success(),
            credential_id: Some(crate::utils::encode_base64url(&result.credential_id)),
        })
    }

    /// Generate authentication options
    pub async fn generate_authentication_options(
        &self,
        request: ServerPublicKeyCredentialGetOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialGetOptionsResponse> {
        // Validate input
        if request.username.trim().is_empty() {
            return Err(AppError::InvalidInput("Username is required".to_string()));
        }

        // Get user
        let user = self.user_repo.get_user_by_username(&request.username).await?
            .ok_or_else(|| AppError::UserNotFound("User not found".to_string()))?;

        // Get user credentials
        let credentials = self.credential_repo.get_credentials_for_user(user.id).await?;
        if credentials.is_empty() {
            return Err(AppError::CredentialNotFound("No credentials found for user".to_string()));
        }

        // Convert to allow credentials format
        let allow_credentials: Vec<ServerPublicKeyCredentialDescriptor> = credentials
            .into_iter()
            .map(|cred| ServerPublicKeyCredentialDescriptor {
                credential_type: "public-key".to_string(),
                id: crate::utils::encode_base64url(&cred.credential_id),
                transports: None,
            })
            .collect();

        // Generate challenge
        let (options, state) = self.webauthn
            .generate_challenge_authenticate_options(
                allow_credentials.iter().map(|desc| webauthn_rs_proto::PublicKeyCredentialDescriptor {
                    type_: webauthn_rs_proto::PublicKeyCredentialType::PublicKey,
                    id: crate::utils::decode_base64url(&desc.id).unwrap_or_default(),
                    transports: None,
                }).collect(),
                request.user_verification.unwrap_or(webauthn_rs_proto::UserVerificationPolicy::Preferred),
                self.config.timeout,
                None,
            )
            .map_err(|e| AppError::WebAuthn(e))?;

        // Store challenge
        let stored_challenge = StoredChallenge {
            challenge: state.challenge.clone(),
            user_id: user.id,
            challenge_type: ChallengeType::Authentication,
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(300), // 5 minutes
        };
        self.challenge_repo.store_challenge(&stored_challenge).await?;

        // Convert to response format
        let response = ServerPublicKeyCredentialGetOptionsResponse {
            response: crate::models::ServerResponse::success(),
            challenge: state.challenge,
            timeout: options.timeout,
            rp_id: self.config.rp_id.clone(),
            allow_credentials,
            user_verification: options.user_verification,
            extensions: options.extensions.map(|ext| {
                ext.into_iter().map(|(k, v)| (k, serde_json::to_value(v).unwrap_or_default())).collect()
            }),
        };

        Ok(response)
    }

    /// Verify authentication response
    pub async fn verify_authentication(
        &self,
        credential: ServerPublicKeyCredential,
    ) -> Result<AuthenticationResultResponse> {
        let ServerAuthenticatorResponse::Assertion(assertion_response) = credential.response else {
            return Err(AppError::InvalidInput("Expected assertion response".to_string()));
        };

        // Decode client data JSON
        let client_data_json = crate::utils::decode_base64url(&assertion_response.client_data_json)
            .map_err(|_| AppError::InvalidInput("Invalid client data JSON encoding".to_string()))?;

        // Parse client data JSON to get challenge
        let client_data: serde_json::Value = serde_json::from_slice(&client_data_json)
            .map_err(|_| AppError::InvalidInput("Invalid client data JSON format".to_string()))?;

        let challenge = client_data.get("challenge")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::InvalidInput("Missing challenge in client data".to_string()))?;

        // Get and consume challenge
        let stored_challenge = self.challenge_repo
            .consume_challenge(challenge, ChallengeType::Authentication)
            .await?
            .ok_or_else(|| AppError::ChallengeNotFound("Challenge not found or expired".to_string()))?;

        // Check if challenge has expired
        if stored_challenge.expires_at < chrono::Utc::now() {
            return Err(AppError::ChallengeNotFound("Challenge has expired".to_string()));
        }

        // Get credential
        let credential_id = crate::utils::decode_base64url(&credential.id)
            .map_err(|_| AppError::InvalidInput("Invalid credential ID encoding".to_string()))?;

        let mut stored_credential = self.credential_repo.get_credential_by_id(&credential_id).await?
            .ok_or_else(|| AppError::CredentialNotFound("Credential not found".to_string()))?;

        // Verify user ownership
        if stored_credential.user_id != stored_challenge.user_id {
            return Err(AppError::AuthenticationFailed("Credential does not belong to user".to_string()));
        }

        // Decode authenticator data and signature
        let authenticator_data = crate::utils::decode_base64url(&assertion_response.authenticator_data)
            .map_err(|_| AppError::InvalidInput("Invalid authenticator data encoding".to_string()))?;

        let signature = crate::utils::decode_base64url(&assertion_response.signature)
            .map_err(|_| AppError::InvalidInput("Invalid signature encoding".to_string()))?;

        // Create webauthn-rs credential
        let webauthn_credential = webauthn_rs_proto::PublicKeyCredential {
            id: credential.id.clone(),
            raw_id: credential_id,
            response: webauthn_rs::proto::AuthenticatorAssertionResponseRaw {
                authenticator_data,
                signature,
                user_handle: assertion_response.user_handle
                    .and_then(|uh| crate::utils::decode_base64url(&uh).ok()),
                client_data_json,
            },
            extensions: credential.get_client_extension_results.unwrap_or_default(),
        };

        // Verify authentication
        let result = self.webauthn.authenticate_credential(&webauthn_credential, &stored_credential.to_webauthn_credential())
            .map_err(|e| AppError::AuthenticationFailed(format!("Authentication verification failed: {}", e)))?;

        // Update credential sign count
        stored_credential.sign_count = result.new_sign_count;
        stored_credential.updated_at = chrono::Utc::now();
        self.credential_repo.update_credential(&stored_credential).await?;

        Ok(AuthenticationResultResponse {
            response: crate::models::ServerResponse::success(),
        })
    }
}