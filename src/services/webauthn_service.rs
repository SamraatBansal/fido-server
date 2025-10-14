//! WebAuthn service for handling FIDO2 operations

use crate::error::{AppError, Result};
use crate::models::*;
use base64::{Engine as _, engine::general_purpose};
use serde_json::json;
use std::collections::HashMap;
use uuid::Uuid;
use webauthn_rs::prelude::*;

/// WebAuthn service configuration
#[derive(Debug, Clone)]
pub struct WebAuthnConfig {
    pub rp_name: String,
    pub rp_id: String,
    pub rp_origin: String,
}

impl Default for WebAuthnConfig {
    fn default() -> Self {
        Self {
            rp_name: "FIDO Server".to_string(),
            rp_id: "localhost".to_string(),
            rp_origin: "http://localhost:3000".to_string(),
        }
    }
}

/// WebAuthn service
pub struct WebAuthnService {
    webauthn: Webauthn,
    config: WebAuthnConfig,
    challenges: std::sync::Arc<std::sync::Mutex<HashMap<String, (ChallengeType, String)>>>,
}

#[derive(Debug, Clone)]
enum ChallengeType {
    Registration,
    Authentication,
}

impl WebAuthnService {
    /// Create a new WebAuthn service
    pub fn new(config: WebAuthnConfig) -> Result<Self> {
        let rp = RelyingParty {
            name: config.rp_name.clone(),
            id: config.rp_id.clone(),
            origin: Url::parse(&config.rp_origin)
                .map_err(|e| AppError::bad_request(format!("Invalid origin URL: {}", e)))?,
            ..Default::default()
        };

        let webauthn = Webauthn::new(rp);

        Ok(Self {
            webauthn,
            config,
            challenges: std::sync::Arc::new(std::sync::Mutex::new(HashMap::new())),
        })
    }

    /// Generate registration challenge
    pub fn generate_registration_challenge(
        &self,
        request: &ServerPublicKeyCredentialCreationOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialCreationOptionsResponse> {
        let user_uuid = Uuid::new_v4();
        let user_id = user_uuid.as_bytes().to_vec();
        let user_id_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&user_id);

        let user = User {
            id: user_id,
            name: request.username.clone(),
            display_name: request.displayName.clone(),
        };

        let (creation_challenge_response, state) = self
            .webauthn
            .start_registration(&user, None)
            .map_err(|e| AppError::WebAuthn(e))?;

        // Store challenge state
        let challenge_id = Uuid::new_v4().to_string();
        let state_json = serde_json::to_string(&state).map_err(AppError::Serialization)?;
        
        {
            let mut challenges = self.challenges.lock().unwrap();
            challenges.insert(challenge_id.clone(), (ChallengeType::Registration, state_json));
        }

        // Convert to our response format
        let challenge_b64 = general_purpose::URL_SAFE_NO_PAD.encode(creation_challenge_response.challenge.0);

        let mut response = ServerPublicKeyCredentialCreationOptionsResponse {
            status: "ok".to_string(),
            errorMessage: None,
            rp: PublicKeyCredentialRpEntity {
                name: self.config.rp_name.clone(),
                id: self.config.rp_id.clone(),
            },
            user: ServerPublicKeyCredentialUserEntity {
                id: user_id_b64,
                name: request.username.clone(),
                displayName: request.displayName.clone(),
            },
            challenge: challenge_b64,
            pubKeyCredParams: vec![
                PublicKeyCredentialParameters {
                    alg_type: "public-key".to_string(),
                    alg: -7, // ES256
                },
                PublicKeyCredentialParameters {
                    alg_type: "public-key".to_string(),
                    alg: -257, // RS256
                },
            ],
            timeout: Some(300000), // 5 minutes
            excludeCredentials: vec![],
            authenticatorSelection: request.authenticatorSelection.clone(),
            attestation: Some(request.attestation.clone()),
            extensions: None,
        };

        Ok(response)
    }

    /// Verify registration response
    pub fn verify_registration(
        &self,
        credential: &ServerPublicKeyCredential,
        username: &str,
    ) -> Result<ServerResponse> {
        // For now, just return success - we'll implement full verification later
        Ok(ServerResponse::success())
    }

    /// Generate authentication challenge
    pub fn generate_authentication_challenge(
        &self,
        request: &ServerPublicKeyCredentialGetOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialGetOptionsResponse> {
        let user_uuid = Uuid::new_v4();
        let challenge_bytes = user_uuid.as_bytes().to_vec();
        let challenge_b64 = general_purpose::URL_SAFE_NO_PAD.encode(&challenge_bytes);

        // Store challenge
        let challenge_id = Uuid::new_v4().to_string();
        {
            let mut challenges = self.challenges.lock().unwrap();
            challenges.insert(
                challenge_id.clone(),
                (ChallengeType::Authentication, challenge_b64.clone()),
            );
        }

        let response = ServerPublicKeyCredentialGetOptionsResponse {
            status: "ok".to_string(),
            errorMessage: None,
            challenge: challenge_b64,
            timeout: Some(300000), // 5 minutes
            rpId: self.config.rp_id.clone(),
            allowCredentials: vec![], // Will be populated with user's credentials
            userVerification: request.userVerification.clone(),
        };

        Ok(response)
    }

    /// Verify authentication response
    pub fn verify_authentication(
        &self,
        credential: &ServerPublicKeyCredential,
        username: &str,
    ) -> Result<ServerResponse> {
        // For now, just return success - we'll implement full verification later
        Ok(ServerResponse::success())
    }
}