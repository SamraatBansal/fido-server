//! WebAuthn service implementation

use crate::error::{AppError, Result};
use crate::models::{
    ServerPublicKeyCredentialCreationOptionsResponse,
    ServerPublicKeyCredentialGetOptionsResponse,
    ServerPublicKeyCredential,
    ServerPublicKeyCredentialAssertion,
    PublicKeyCredentialRpEntity,
    ServerPublicKeyCredentialUserEntity,
    PublicKeyCredentialParameters,
    AuthenticatorSelectionCriteria,
};
use base64::{Engine as _, engine::general_purpose};
use rand::{distributions::Alphanumeric, Rng};
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;

/// WebAuthn service configuration
#[derive(Debug, Clone)]
pub struct WebAuthnConfig {
    /// Relying party ID
    pub rp_id: String,
    /// Relying party name
    pub rp_name: String,
    /// Relying party origin
    pub rp_origin: String,
}

impl Default for WebAuthnConfig {
    fn default() -> Self {
        Self {
            rp_id: "localhost".to_string(),
            rp_name: "FIDO Server".to_string(),
            rp_origin: "http://localhost:8080".to_string(),
        }
    }
}

/// WebAuthn service
pub struct WebAuthnService {
    config: WebAuthnConfig,
}

impl WebAuthnService {
    /// Create a new WebAuthn service
    pub fn new(config: WebAuthnConfig) -> Result<Self> {
        Ok(Self { config })
    }

    /// Begin registration (attestation) process
    pub async fn begin_registration(
        &self,
        username: &str,
        display_name: &str,
        authenticator_selection: Option<AuthenticatorSelectionCriteria>,
        attestation: Option<String>,
    ) -> Result<ServerPublicKeyCredentialCreationOptionsResponse> {
        // Generate user ID
        let user_id = Uuid::new_v4();

        // Generate challenge
        let challenge = self.generate_challenge();

        // Convert to our response format
        let session_id = self.generate_session_id();

        Ok(ServerPublicKeyCredentialCreationOptionsResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
            session_id,
            rp: PublicKeyCredentialRpEntity {
                name: self.config.rp_name.clone(),
            },
            user: ServerPublicKeyCredentialUserEntity {
                id: general_purpose::URL_SAFE_NO_PAD.encode(user_id.as_bytes()),
                name: username.to_string(),
                display_name: display_name.to_string(),
            },
            challenge,
            pub_key_cred_params: vec![
                PublicKeyCredentialParameters {
                    cred_type: "public-key".to_string(),
                    alg: -7, // ES256
                },
            ],
            timeout: Some(60000),
            exclude_credentials: vec![], // TODO: Get existing credentials
            authenticator_selection,
            attestation: attestation.or_else(|| Some("none".to_string())),
            extensions: Some(HashMap::new()),
        })
    }

    /// Complete registration (attestation) process
    pub async fn finish_registration(
        &self,
        credential: ServerPublicKeyCredential,
    ) -> Result<()> {
        // TODO: Retrieve stored state from session/database
        // For now, we'll just validate the basic structure

        // Decode base64url fields
        let client_data_json = general_purpose::URL_SAFE_NO_PAD
            .decode(&credential.response.client_data_json)
            .map_err(|_| AppError::InvalidRequest("Invalid clientDataJSON encoding".to_string()))?;

        let attestation_object = general_purpose::URL_SAFE_NO_PAD
            .decode(&credential.response.attestation_object)
            .map_err(|e| AppError::InvalidRequest(format!("Invalid attestationObject: {}", e)))?;

        // Parse client data
        let client_data: Value = serde_json::from_slice(&client_data_json)
            .map_err(|e| AppError::InvalidRequest(format!("Invalid clientDataJSON format: {}", e)))?;

        // Validate challenge exists and is not empty
        let challenge = client_data.get("challenge")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::InvalidRequest("Missing challenge field".to_string()))?;
        
        if challenge.is_empty() {
            return Err(AppError::InvalidRequest("Empty challenge field".to_string()));
        }

        // Validate origin
        let _origin = client_data.get("origin")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::InvalidRequest("Missing origin field".to_string()))?;

        // Validate type
        let client_type = client_data.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if client_type != "webauthn.create" {
            return Err(AppError::InvalidRequest("Invalid client data type".to_string()));
        }

        // Basic validation of attestation object format
        if attestation_object.len() < 50 {
            return Err(AppError::InvalidRequest("Invalid attestation object format".to_string()));
        }

        // TODO: Verify attestation with webauthn-rs
        // TODO: Store credential in database
        Ok(())
    }

    /// Begin authentication (assertion) process
    pub async fn begin_authentication(
        &self,
        _username: &str,
        user_verification: Option<String>,
    ) -> Result<ServerPublicKeyCredentialGetOptionsResponse> {
        // TODO: Get user's existing credentials from database
        let allow_credentials = vec![]; // Empty for now

        // Generate challenge
        let challenge = self.generate_challenge();
        let session_id = self.generate_session_id();

        Ok(ServerPublicKeyCredentialGetOptionsResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
            session_id,
            challenge,
            timeout: Some(60000),
            rp_id: self.config.rp_id.clone(),
            allow_credentials,
            user_verification,
            extensions: Some(HashMap::new()),
        })
    }

    /// Complete authentication (assertion) process
    pub async fn finish_authentication(
        &self,
        credential: ServerPublicKeyCredentialAssertion,
    ) -> Result<()> {
        // TODO: Retrieve stored state from session/database

        // Decode base64url fields
        let client_data_json = general_purpose::URL_SAFE_NO_PAD
            .decode(&credential.response.client_data_json)
            .map_err(|_| AppError::InvalidRequest("Invalid clientDataJSON encoding".to_string()))?;

        let authenticator_data = general_purpose::URL_SAFE_NO_PAD
            .decode(&credential.response.authenticator_data)
            .map_err(|e| AppError::InvalidRequest(format!("Invalid authenticatorData: {}", e)))?;

        let signature = general_purpose::URL_SAFE_NO_PAD
            .decode(&credential.response.signature)
            .map_err(|e| AppError::InvalidRequest(format!("Invalid signature: {}", e)))?;

        // Parse client data
        let client_data: Value = serde_json::from_slice(&client_data_json)
            .map_err(|e| AppError::InvalidRequest(format!("Invalid clientDataJSON format: {}", e)))?;

        // Validate challenge exists and is not empty
        let challenge = client_data.get("challenge")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::InvalidRequest("Missing challenge field".to_string()))?;
        
        if challenge.is_empty() {
            return Err(AppError::InvalidRequest("Empty challenge field".to_string()));
        }

        // Validate origin
        let _origin = client_data.get("origin")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::InvalidRequest("Missing origin field".to_string()))?;

        // Validate type
        let client_type = client_data.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if client_type != "webauthn.get" {
            return Err(AppError::InvalidRequest("Invalid client data type".to_string()));
        }

        // Basic validation of authenticator data format
        if authenticator_data.len() < 37 {
            return Err(AppError::InvalidRequest("Invalid authenticator data format".to_string()));
        }

        // Basic validation of signature format
        if signature.len() < 32 {
            return Err(AppError::InvalidRequest("Invalid signature format".to_string()));
        }

        // TODO: Verify assertion with webauthn-rs
        // TODO: Verify signature and authenticator data
        // TODO: Update credential counter
        // TODO: Update last used timestamp

        Ok(())
    }

    /// Generate a cryptographically random challenge
    fn generate_challenge(&self) -> String {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect()
    }

    /// Generate a session ID
    fn generate_session_id(&self) -> String {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect()
    }
}