//! WebAuthn service for FIDO2 operations

use crate::error::Result;
use crate::types::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::{distributions::Alphanumeric, Rng};

/// WebAuthn service for handling FIDO2 operations
#[allow(dead_code)]
pub struct WebAuthnService {
    rp_name: String,
    rp_id: String,
    origin: String,
}

impl WebAuthnService {
    /// Create a new WebAuthn service instance
    #[allow(dead_code)]
    pub fn new(rp_name: &str, rp_id: &str, origin: &str) -> Result<Self> {
        Ok(Self {
            rp_name: rp_name.to_string(),
            rp_id: rp_id.to_string(),
            origin: origin.to_string(),
        })
    }

    /// Generate a random challenge (16-64 bytes, base64url encoded)
    fn generate_challenge() -> String {
        let rng = rand::thread_rng();
        let challenge: String = rng
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();
        URL_SAFE_NO_PAD.encode(challenge.as_bytes())
    }

    /// Create credential creation options for registration
    pub async fn credential_creation_options(
        &self,
        request: ServerPublicKeyCredentialCreationOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialCreationOptionsResponse> {
        let challenge = Self::generate_challenge();

        // Convert username to user ID (base64url encoded)
        let user_id = URL_SAFE_NO_PAD.encode(request.username.as_bytes());

        // Create user entity
        let user = ServerPublicKeyCredentialUserEntity {
            id: user_id,
            name: request.username.clone(),
            display_name: request.display_name.clone(),
        };

        // Create RP entity
        let rp = PublicKeyCredentialRpEntity {
            name: "Example Corporation".to_string(), // This should be configurable
        };

        // Set default pubKeyCredParams (ES256 -7, RS256 -257)
        let pub_key_cred_params = vec![
            PublicKeyCredentialParameters {
                cred_type: "public-key".to_string(),
                alg: -7,  // ES256
            },
            PublicKeyCredentialParameters {
                cred_type: "public-key".to_string(),
                alg: -257, // RS256
            },
        ];

        // For now, return empty excludeCredentials
        // In a real implementation, this would contain existing credentials for the user
        let exclude_credentials = vec![];

        let response = ServerPublicKeyCredentialCreationOptionsResponse {
            base: ServerResponse::success(),
            rp,
            user,
            challenge,
            pub_key_cred_params,
            timeout: Some(10000),
            exclude_credentials,
            authenticator_selection: request.authenticator_selection,
            attestation: Some(request.attestation),
            extensions: None,
        };

        Ok(response)
    }

    /// Verify attestation response
    pub async fn verify_attestation(
        &self,
        _credential: ServerPublicKeyCredential,
    ) -> Result<ServerResponse> {
        // For now, just return success
        // In a real implementation, this would:
        // 1. Decode the clientDataJSON and attestationObject
        // 2. Verify the challenge matches what was issued
        // 3. Verify the origin
        // 4. Verify the attestation signature
        // 5. Store the credential

        Ok(ServerResponse::success())
    }

    /// Create credential get options for authentication
    pub async fn credential_get_options(
        &self,
        request: ServerPublicKeyCredentialGetOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialGetOptionsResponse> {
        let challenge = Self::generate_challenge();

        // For now, return empty allowCredentials
        // In a real implementation, this would contain existing credentials for the user
        let allow_credentials = vec![];

        let response = ServerPublicKeyCredentialGetOptionsResponse {
            base: ServerResponse::success(),
            challenge,
            timeout: Some(20000),
            rpId: "example.com".to_string(), // This should be configurable
            allowCredentials: allow_credentials,
            userVerification: request.userVerification,
            extensions: None,
        };

        Ok(response)
    }

    /// Verify assertion response
    pub async fn verify_assertion(
        &self,
        _credential: ServerPublicKeyCredential,
    ) -> Result<ServerResponse> {
        // For now, just return success
        // In a real implementation, this would:
        // 1. Decode the clientDataJSON and authenticatorData
        // 2. Verify the challenge matches what was issued
        // 3. Verify the origin and rpId
        // 4. Verify the assertion signature
        // 5. Check the user verification requirement

        Ok(ServerResponse::success())
    }
}