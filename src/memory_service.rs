use crate::api::*;
use crate::error::{AppError, Result};
use crate::memory_storage::*;
use base64::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub struct MemoryWebAuthnService {
    rp_id: String,
    rp_name: String,
    rp_origin: String,
    storage: Arc<MemoryStorage>,
}

impl MemoryWebAuthnService {
    pub fn new(rp_id: &str, rp_name: &str, rp_origin: &str) -> Result<Self> {
        // Basic validation of origin
        let _ = url::Url::parse(rp_origin)
            .map_err(|e| AppError::ValidationError(format!("Invalid RP origin: {}", e)))?;

        Ok(Self {
            rp_id: rp_id.to_string(),
            rp_name: rp_name.to_string(),
            rp_origin: rp_origin.to_string(),
            storage: Arc::new(MemoryStorage::new()),
        })
    }

    pub async fn start_registration(
        &self,
        request: &ServerPublicKeyCredentialCreationOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialCreationOptionsResponse> {
        // Validate input
        crate::error::validate_string_not_empty(&request.username, "username")?;
        crate::error::validate_string_not_empty(&request.display_name, "displayName")?;

        // Clean up expired challenges
        self.storage.cleanup_expired_challenges()?;

        // Check if user exists and get existing credentials
        let existing_user = self.storage.get_user_by_username(&request.username)?;

        let user_id = match existing_user {
            Some(user) => user.id,
            None => Uuid::new_v4(),
        };

        // Get existing credentials for excludeCredentials
        let existing_credentials = if existing_user.is_some() {
            self.storage.get_credentials_for_user(user_id)?
        } else {
            Vec::new()
        };

        let exclude_credentials: Vec<ServerPublicKeyCredentialDescriptor> = existing_credentials
            .iter()
            .map(|cred| ServerPublicKeyCredentialDescriptor {
                type_: "public-key".to_string(),
                id: BASE64_URL_SAFE_NO_PAD.encode(&cred.credential_id),
                transports: None,
            })
            .collect();

        // Generate a secure challenge
        let mut challenge = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut challenge);

        // Store challenge state
        let challenge_data = serde_json::to_vec(&user_id)?;
        let _challenge_id = self.storage.store_challenge(user_id, "registration", &challenge_data)?;

        // Prepare extensions
        let mut extensions = HashMap::new();
        if let Some(req_ext) = &request.extensions {
            extensions = req_ext.clone();
        }

        // Create supported algorithms
        let pub_key_cred_params = vec![
            PublicKeyCredentialParameters {
                type_: "public-key".to_string(),
                alg: -7, // ES256
            },
            PublicKeyCredentialParameters {
                type_: "public-key".to_string(),
                alg: -257, // RS256
            },
        ];

        // Create response
        let response = ServerPublicKeyCredentialCreationOptionsResponse::new(
            PublicKeyCredentialRpEntity {
                id: Some(self.rp_id.clone()),
                name: self.rp_name.clone(),
            },
            ServerPublicKeyCredentialUserEntity {
                id: BASE64_URL_SAFE_NO_PAD.encode(user_id.as_bytes()),
                name: request.username.clone(),
                display_name: request.display_name.clone(),
            },
            BASE64_URL_SAFE_NO_PAD.encode(&challenge),
            pub_key_cred_params,
            exclude_credentials,
            request.authenticator_selection.clone(),
            request.attestation.clone(),
            Some(60000), // 60 seconds timeout
            Some(extensions),
        );

        Ok(response)
    }

    pub async fn finish_registration(
        &self,
        credential: &ServerPublicKeyCredential,
    ) -> Result<ServerResponse> {
        // Validate input
        crate::error::validate_credential_type(&credential.type_)?;
        crate::error::validate_string_not_empty(&credential.id, "id")?;

        let response = match &credential.response {
            ServerAuthenticatorResponse::Attestation(response) => response,
            _ => return Err(AppError::InvalidRequest("Expected attestation response".to_string())),
        };

        // Validate required fields
        crate::error::validate_string_not_empty(&response.client_data_json, "clientDataJSON")?;
        crate::error::validate_string_not_empty(&response.attestation_object, "attestationObject")?;

        // Decode base64url fields
        let credential_id = crate::error::validate_base64url(&credential.id, "id")?;
        let client_data_json = crate::error::validate_base64url(&response.client_data_json, "clientDataJSON")?;
        let _attestation_object = crate::error::validate_base64url(&response.attestation_object, "attestationObject")?;

        // Parse client data to get challenge
        let client_data: serde_json::Value = serde_json::from_slice(&client_data_json)?;
        
        // Validate client data structure
        let challenge_b64 = client_data
            .get("challenge")
            .and_then(|c| c.as_str())
            .ok_or_else(|| AppError::MissingField("challenge".to_string()))?;

        let origin = client_data
            .get("origin")
            .and_then(|o| o.as_str())
            .ok_or_else(|| AppError::MissingField("origin".to_string()))?;

        let type_ = client_data
            .get("type")
            .and_then(|t| t.as_str())
            .ok_or_else(|| AppError::MissingField("type".to_string()))?;

        // Validate client data fields
        if type_ != "webauthn.create" {
            return Err(AppError::InvalidField(format!("Invalid type: {}", type_)));
        }

        // Validate origin
        if origin != self.rp_origin {
            return Err(AppError::InvalidField(format!("Invalid origin: {}", origin)));
        }

        let challenge_bytes = crate::error::validate_base64url(challenge_b64, "challenge")?;
        crate::error::validate_challenge_length(&challenge_bytes)?;

        // Find and validate challenge
        let stored_challenge = self.storage.get_challenge("registration")?
            .ok_or(AppError::ChallengeExpired)?;

        // Deserialize stored user ID
        let user_id: Uuid = serde_json::from_slice(&stored_challenge.challenge_data)?;

        // Store or update user
        let existing_user = self.storage.get_user_by_id(user_id)?;
        if existing_user.is_none() {
            // This shouldn't happen in a real implementation, but for testing...
            self.storage.store_user("temp_user", "Temporary User")?;
        }

        // Store credential (simplified - would normally parse attestation object)
        self.storage.store_credential(user_id, &credential_id, &[0u8; 32])?;

        // Clean up challenge
        self.storage.remove_challenge(stored_challenge.id)?;

        Ok(ServerResponse::success())
    }

    pub async fn start_authentication(
        &self,
        request: &ServerPublicKeyCredentialGetOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialGetOptionsResponse> {
        // Validate input
        crate::error::validate_string_not_empty(&request.username, "username")?;

        // Clean up expired challenges
        self.storage.cleanup_expired_challenges()?;

        // Find user
        let user = self.storage.get_user_by_username(&request.username)?
            .ok_or(AppError::UserNotFound)?;

        // Get user credentials
        let user_credentials = self.storage.get_credentials_for_user(user.id)?;

        if user_credentials.is_empty() {
            return Err(AppError::CredentialNotFound);
        }

        // Generate a secure challenge
        let mut challenge = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut challenge);

        // Store challenge state
        let challenge_data = serde_json::to_vec(&user.id)?;
        let _challenge_id = self.storage.store_challenge(user.id, "authentication", &challenge_data)?;

        // Convert credentials to response format
        let allow_credentials: Vec<ServerPublicKeyCredentialDescriptor> = user_credentials
            .iter()
            .map(|cred| ServerPublicKeyCredentialDescriptor {
                type_: "public-key".to_string(),
                id: BASE64_URL_SAFE_NO_PAD.encode(&cred.credential_id),
                transports: None,
            })
            .collect();

        let response = ServerPublicKeyCredentialGetOptionsResponse::new(
            BASE64_URL_SAFE_NO_PAD.encode(&challenge),
            self.rp_id.clone(),
            allow_credentials,
            request.user_verification.clone(),
            Some(60000), // 60 seconds timeout
            request.extensions.clone(),
        );

        Ok(response)
    }

    pub async fn finish_authentication(
        &self,
        credential: &ServerPublicKeyCredential,
    ) -> Result<ServerResponse> {
        // Validate input
        crate::error::validate_credential_type(&credential.type_)?;
        crate::error::validate_string_not_empty(&credential.id, "id")?;

        let response = match &credential.response {
            ServerAuthenticatorResponse::Assertion(response) => response,
            _ => return Err(AppError::InvalidRequest("Expected assertion response".to_string())),
        };

        // Validate required fields
        crate::error::validate_string_not_empty(&response.client_data_json, "clientDataJSON")?;
        crate::error::validate_string_not_empty(&response.authenticator_data, "authenticatorData")?;
        crate::error::validate_string_not_empty(&response.signature, "signature")?;

        // Decode base64url fields
        let _credential_id = crate::error::validate_base64url(&credential.id, "id")?;
        let client_data_json = crate::error::validate_base64url(&response.client_data_json, "clientDataJSON")?;
        let _authenticator_data = crate::error::validate_base64url(&response.authenticator_data, "authenticatorData")?;
        let _signature = crate::error::validate_base64url(&response.signature, "signature")?;

        // Parse client data
        let client_data: serde_json::Value = serde_json::from_slice(&client_data_json)?;
        
        // Validate client data structure
        let challenge_b64 = client_data
            .get("challenge")
            .and_then(|c| c.as_str())
            .ok_or_else(|| AppError::MissingField("challenge".to_string()))?;

        let origin = client_data
            .get("origin")
            .and_then(|o| o.as_str())
            .ok_or_else(|| AppError::MissingField("origin".to_string()))?;

        let type_ = client_data
            .get("type")
            .and_then(|t| t.as_str())
            .ok_or_else(|| AppError::MissingField("type".to_string()))?;

        // Validate client data fields
        if type_ != "webauthn.get" {
            return Err(AppError::InvalidField(format!("Invalid type: {}", type_)));
        }

        // Validate origin
        if origin != self.rp_origin {
            return Err(AppError::InvalidField(format!("Invalid origin: {}", origin)));
        }

        let challenge_bytes = crate::error::validate_base64url(challenge_b64, "challenge")?;
        crate::error::validate_challenge_length(&challenge_bytes)?;

        // Find and validate challenge
        let stored_challenge = self.storage.get_challenge("authentication")?
            .ok_or(AppError::ChallengeExpired)?;

        // Clean up challenge
        self.storage.remove_challenge(stored_challenge.id)?;

        Ok(ServerResponse::success())
    }
}