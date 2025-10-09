//! WebAuthn service

use crate::error::AppResult;
use crate::schema::*;
use uuid::Uuid;
use chrono::Utc;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

/// WebAuthn service
pub struct WebAuthnService {
    rp_id: String,
    rp_name: String,
    #[allow(dead_code)]
    origin: String,
}

impl WebAuthnService {
    /// Create new WebAuthn service
    pub fn new(rp_id: &str, rp_name: &str, origin: &str) -> AppResult<Self> {
        Ok(Self {
            rp_id: rp_id.to_string(),
            rp_name: rp_name.to_string(),
            origin: origin.to_string(),
        })
    }

    /// Generate registration challenge
    pub async fn generate_registration_challenge(
        &self,
        username: &str,
        display_name: &str,
    ) -> AppResult<CredentialCreationOptions> {
        let user_uuid = Uuid::new_v4();
        
        // Generate a secure challenge
        let challenge_bytes = crate::utils::crypto::generate_secure_challenge();
        
        // Create WebAuthn user data
        let user_id_bytes = user_uuid.as_bytes().to_vec();

        // Store challenge (in real implementation, this would go to database)
        // let _challenge = Challenge {
        //     id: Uuid::new_v4(),
        //     user_id: Some(user_uuid),
        //     username: Some(username.to_string()),
        //     challenge_data: challenge_bytes.clone(),
        //     challenge_type: "registration".to_string(),
        //     expires_at: Utc::now() + chrono::Duration::minutes(5),
        //     created_at: Utc::now(),
        //     consumed: false,
        // };

        // Convert to our response format
        Ok(ServerPublicKeyCredentialCreationOptionsResponse {
            status: "ok".to_string(),
            error_message: "".to_string(),
            rp: PublicKeyCredentialRpEntity {
                name: self.rp_name.clone(),
                id: Some(self.rp_id.clone()),
            },
            user: ServerPublicKeyCredentialUserEntity {
                id: URL_SAFE_NO_PAD.encode(&user_id_bytes),
                name: username.to_string(),
                display_name: display_name.to_string(),
            },
            challenge: challenge_bytes,
            pub_key_cred_params: vec![
                PublicKeyCredentialParameters {
                    cred_type: "public-key".to_string(),
                    alg: -7, // ES256
                },
            ],
            timeout: Some(60000),
            exclude_credentials: None,
            authenticator_selection: Some(AuthenticatorSelectionCriteria {
                authenticator_attachment: Some("platform".to_string()),
                user_verification: Some("required".to_string()),
                require_resident_key: Some(false),
            }),
            attestation: Some("direct".to_string()),
            extensions: None,
        })
    }

    /// Verify registration attestation
    pub async fn verify_registration(
        &self,
        attestation: &AttestationResponse,
        _challenge_id: &str,
    ) -> FidoResult<RegistrationResult> {
        // In a real implementation, we would:
        // 1. Retrieve the challenge from database
        // 2. Verify it's not expired and not consumed
        // 3. Parse and verify the attestation using webauthn-rs
        // 4. Store the credential
        
        // For now, return a mock result
        Ok(RegistrationResult {
            credential_id: attestation.id.clone(),
            user_id: Uuid::new_v4(),
        })
    }

    /// Generate authentication challenge
    pub async fn generate_authentication_challenge(
        &self,
        _username: &str,
    ) -> FidoResult<CredentialRequestOptions> {
        // In a real implementation, we would:
        // 1. Find the user by username
        // 2. Get their credentials
        // 3. Generate challenge options
        
        // For now, return a mock response
        Ok(CredentialRequestOptions {
            challenge: crate::utils::crypto::generate_secure_challenge()?,
            allow_credentials: vec![],
            user_verification: "required".to_string(),
            timeout: 60000,
        })
    }

    /// Verify authentication assertion
    pub async fn verify_authentication(
        &self,
        _assertion: &AssertionResponse,
        _challenge_id: &str,
    ) -> FidoResult<AuthenticationResult> {
        // In a real implementation, we would:
        // 1. Retrieve the challenge from database
        // 2. Verify it's not expired and not consumed
        // 3. Parse and verify the assertion using webauthn-rs
        // 4. Update credential sign count
        
        // For now, return a mock result
        Ok(AuthenticationResult {
            authenticated: true,
            user_id: Uuid::new_v4(),
            credential_id: "mock_credential_id".to_string(),
        })
    }
}