//! WebAuthn service

use crate::error::{FidoError, FidoResult};
use crate::schema::webauthn::*;
use crate::schema::credential::{RegistrationResult, AuthenticationResult};
use crate::db::models::{User, Credential, Challenge};
use uuid::Uuid;
use std::sync::Arc;
use webauthn_rs::prelude::*;
use chrono::Utc;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

/// WebAuthn service
pub struct WebAuthnService {
    webauthn: Webauthn,
    // TODO: Add repositories when implemented
}

impl WebAuthnService {
    /// Create new WebAuthn service
    pub fn new(rp_id: &str, rp_name: &str, origin: &str) -> FidoResult<Self> {
        let webauthn = Webauthn::new(
            rp_id,
            rp_name,
            vec![origin],
            vec![
                COSEAlgorithm::ES256,
                COSEAlgorithm::RS256,
                COSEAlgorithm::EdDSA,
            ],
        ).map_err(|e| FidoError::WebAuthn(e.to_string()))?;

        Ok(Self {
            webauthn,
        })
    }

    /// Generate registration challenge
    pub async fn generate_registration_challenge(
        &self,
        username: &str,
        display_name: &str,
    ) -> FidoResult<CredentialCreationOptions> {
        let user_uuid = Uuid::new_v4();
        
        let user = User {
            id: user_uuid,
            username: username.to_string(),
            display_name: display_name.to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Create WebAuthn user
        let webauthn_user = webauthn_rs::prelude::User {
            id: user.id.as_bytes().to_vec(),
            name: username.to_string(),
            display_name: display_name.to_string(),
        };

        // Generate credential creation options
        let (ccr, state) = self.webauthn
            .generate_challenge_register_options(
                &webauthn_user,
                Some(UserVerificationPolicy::Required),
                Some(AttestationConveyancePreference::Direct),
                None,
            )
            .map_err(|e| FidoError::WebAuthn(e.to_string()))?;

        // Store challenge (in real implementation, this would go to database)
        let challenge = Challenge {
            id: Uuid::new_v4(),
            user_id: Some(user.id),
            username: Some(username.to_string()),
            challenge_data: base64::encode_config(&state.challenge, base64::URL_SAFE_NO_PAD),
            challenge_type: "registration".to_string(),
            expires_at: Utc::now() + chrono::Duration::minutes(5),
            created_at: Utc::now(),
            consumed: false,
        };

        // Convert to our response format
        Ok(CredentialCreationOptions {
            rp: RelyingParty {
                id: self.webauthn.get_rp_id().to_string(),
                name: self.webauthn.get_rp_name().to_string(),
            },
            user: User {
                id: base64::encode_config(&webauthn_user.id, base64::URL_SAFE_NO_PAD),
                name: webauthn_user.name,
                display_name: webauthn_user.display_name,
            },
            challenge: base64::encode_config(&state.challenge, base64::URL_SAFE_NO_PAD),
            pub_key_cred_params: ccr.pub_key_cred_params.into_iter().map(|p| PublicKeyCredentialParameters {
                cred_type: p.type_,
                alg: p.alg,
            }).collect(),
            timeout: ccr.timeout as u64,
            attestation: ccr.attestation.map(|a| a.to_string()).unwrap_or_else(|| "none".to_string()),
            authenticator_selection: AuthenticatorSelectionCriteria {
                authenticator_attachment: ccr.authenticator_selection.as_ref().and_then(|a| a.authenticator_attachment.clone()),
                user_verification: ccr.authenticator_selection
                    .as_ref()
                    .map(|a| a.user_verification.to_string())
                    .unwrap_or_else(|| "preferred".to_string()),
                require_resident_key: ccr.authenticator_selection
                    .as_ref()
                    .map(|a| a.resident_key == ResidentKeyRequirement::Required)
                    .unwrap_or(false),
            },
        })
    }

    /// Verify registration attestation
    pub async fn verify_registration(
        &self,
        attestation: &AttestationResponse,
        challenge_id: &str,
    ) -> FidoResult<RegistrationResult> {
        // In a real implementation, we would:
        // 1. Retrieve the challenge from database
        // 2. Verify it's not expired and not consumed
        // 3. Parse and verify the attestation
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
        username: &str,
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
        // 3. Parse and verify the assertion
        // 4. Update credential sign count
        
        // For now, return a mock result
        Ok(AuthenticationResult {
            authenticated: true,
            user_id: Uuid::new_v4(),
            credential_id: "mock_credential_id".to_string(),
        })
    }
}