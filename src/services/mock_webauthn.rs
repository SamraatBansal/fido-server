//! Simplified WebAuthn service for testing

use async_trait::async_trait;
use std::sync::Arc;

use crate::schema::*;
use crate::error::Result;

/// Mock WebAuthn service for testing
pub struct MockWebAuthnService;

impl MockWebAuthnService {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl crate::services::WebAuthnService for MockWebAuthnService {
    async fn generate_registration_challenge(
        &self,
        request: ServerPublicKeyCredentialCreationOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialCreationOptionsResponse> {
        let mut response = ServerPublicKeyCredentialCreationOptionsResponse::default();
        response.user = ServerPublicKeyCredentialUserEntity {
            id: "S3932ee31vKEC0JtJMIQ".to_string(),
            name: request.username.clone(),
            display_name: request.display_name.clone(),
        };
        response.challenge = "uhUjPNlZfvn7onwuhNdsLPkkE5Fv-lUN".to_string();
        response.exclude_credentials = Some(vec![ServerPublicKeyCredentialDescriptor {
            credential_type: "public-key".to_string(),
            id: "opQf1WmYAa5aupUKJIQp".to_string(),
            transports: None,
        }]);
        response.authenticator_selection = request.authenticator_selection;
        response.attestation = request.attestation;
        
        Ok(response)
    }

    async fn verify_registration(
        &self,
        _credential: ServerPublicKeyCredential,
    ) -> Result<ServerResponse> {
        Ok(ServerResponse::success())
    }

    async fn generate_authentication_challenge(
        &self,
        request: ServerPublicKeyCredentialGetOptionsRequest,
    ) -> Result<ServerPublicKeyCredentialGetOptionsResponse> {
        let mut response = ServerPublicKeyCredentialGetOptionsResponse::default();
        response.challenge = "6283u0svT-YIF3pSolzkQHStwkJCaLKx".to_string();
        response.allow_credentials = vec![ServerPublicKeyCredentialDescriptor {
            credential_type: "public-key".to_string(),
            id: "m7xl_TkTcCe0WcXI2M-4ro9vJAuwcj4m".to_string(),
            transports: None,
        }];
        response.user_verification = request.user_verification;
        
        Ok(response)
    }

    async fn verify_authentication(
        &self,
        _credential: ServerPublicKeyCredential,
    ) -> Result<ServerResponse> {
        Ok(ServerResponse::success())
    }
}