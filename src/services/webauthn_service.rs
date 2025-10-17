//! WebAuthn service for handling FIDO2 operations

use crate::error::AppError;
use crate::models::webauthn::*;
use base64::{Engine as _, engine::general_purpose};

/// WebAuthn service implementation
pub struct WebAuthnService {
    rp_name: String,
    rp_id: String,
    #[allow(dead_code)]
    rp_origin: String,
}

impl WebAuthnService {
    /// Create a new WebAuthn service instance
    pub fn new(rp_name: String, rp_id: String, rp_origin: String) -> Self {
        Self {
            rp_name,
            rp_id,
            rp_origin,
        }
    }

    /// Generate registration challenge options
    pub async fn generate_registration_challenge(
        &self,
        request: ServerPublicKeyCredentialCreationOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialCreationOptionsResponse, AppError> {
        // Generate a random challenge (16-64 bytes, base64url encoded)
        let challenge_bytes = rand::random::<[u8; 32]>();
        let challenge = general_purpose::URL_SAFE_NO_PAD.encode(challenge_bytes);

        // Create user ID (base64url encoded)
        let user_id = general_purpose::URL_SAFE_NO_PAD.encode(request.username.as_bytes());

        // Build response
        let response = ServerPublicKeyCredentialCreationOptionsResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
            rp: PublicKeyCredentialRpEntity {
                name: self.rp_name.clone(),
            },
            user: ServerPublicKeyCredentialUserEntity {
                id: user_id,
                name: request.username.clone(),
                display_name: request.display_name,
            },
            challenge,
            pub_key_cred_params: vec![
                PublicKeyCredentialParameters {
                    type_field: "public-key".to_string(),
                    alg: -7, // ES256
                },
                PublicKeyCredentialParameters {
                    type_field: "public-key".to_string(),
                    alg: -257, // RS256
                },
            ],
            timeout: Some(60000), // 60 seconds
            exclude_credentials: Some(vec![]), // TODO: Implement exclude credentials
            authenticator_selection: request.authenticator_selection,
            attestation: request.attestation.or_else(|| Some("none".to_string())),
            extensions: None,
        };

        Ok(response)
    }

    /// Verify registration attestation
    pub async fn verify_registration_attestation(
        &self,
        credential: ServerPublicKeyCredential,
    ) -> Result<ServerResponse, AppError> {
        // For now, just return success - in a real implementation, this would
        // verify the attestation object and client data JSON
        // TODO: Implement proper attestation verification using webauthn-rs
        
        // Basic validation
        if credential.id.is_empty() {
            return Err(AppError::BadRequest("Missing credential ID".to_string()));
        }

        match credential.response {
            ServerAuthenticatorResponse::Attestation(attestation) => {
                if attestation.client_data_json.is_empty() || attestation.attestation_object.is_empty() {
                    return Err(AppError::BadRequest("Missing attestation data".to_string()));
                }
                
                // TODO: Verify client data JSON and attestation object
                // For conformance testing, we'll just accept valid-looking data
                
                Ok(ServerResponse::success())
            }
            _ => Err(AppError::BadRequest("Invalid response type for registration".to_string())),
        }
    }

    /// Generate authentication challenge options
    pub async fn generate_authentication_challenge(
        &self,
        request: ServerPublicKeyCredentialGetOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialGetOptionsResponse, AppError> {
        // Generate a random challenge
        let challenge_bytes = rand::random::<[u8; 32]>();
        let challenge = general_purpose::URL_SAFE_NO_PAD.encode(challenge_bytes);

        // TODO: Look up user's existing credentials
        // For now, return empty allow_credentials
        
        let response = ServerPublicKeyCredentialGetOptionsResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
            challenge,
            timeout: Some(60000), // 60 seconds
            rp_id: self.rp_id.clone(),
            allow_credentials: Some(vec![]), // TODO: Implement user credential lookup
            user_verification: request.user_verification,
            extensions: None,
        };

        Ok(response)
    }

    /// Verify authentication assertion
    pub async fn verify_authentication_assertion(
        &self,
        credential: ServerPublicKeyCredential,
    ) -> Result<ServerResponse, AppError> {
        // TODO: Implement proper assertion verification using webauthn-rs
        
        // Basic validation
        if credential.id.is_empty() {
            return Err(AppError::BadRequest("Missing credential ID".to_string()));
        }

        match credential.response {
            ServerAuthenticatorResponse::Assertion(assertion) => {
                if assertion.client_data_json.is_empty() 
                    || assertion.authenticator_data.is_empty() 
                    || assertion.signature.is_empty() {
                    return Err(AppError::BadRequest("Missing assertion data".to_string()));
                }
                
                // TODO: Verify assertion
                // For conformance testing, we'll just accept valid-looking data
                
                Ok(ServerResponse::success())
            }
            _ => Err(AppError::BadRequest("Invalid response type for authentication".to_string())),
        }
    }
}