//! WebAuthn service implementation

use webauthn_rs::prelude::*;
use crate::error::{AppError, Result};
use uuid::Uuid;

/// WebAuthn service for handling FIDO2 operations
pub struct WebAuthnService {
    webauthn: Webauthn,
}

impl WebAuthnService {
    /// Create a new WebAuthn service
    pub fn new(rp_id: &str, rp_origin: &str, rp_name: Option<&str>) -> Result<Self> {
        let rp_name = rp_name.unwrap_or("FIDO Server");
        
        let webauthn = WebauthnBuilder::new(rp_id, &url::Url::parse(rp_origin)
            .map_err(|e| AppError::InternalError(format!("Invalid origin URL: {}", e)))?)
            .map_err(|e| AppError::InternalError(format!("Failed to create WebAuthn builder: {}", e)))?
            .rp_name(rp_name)
            .build()
            .map_err(|e| AppError::InternalError(format!("Failed to build WebAuthn: {}", e)))?;

        Ok(Self { webauthn })
    }

    /// Start registration process
    pub fn start_registration(
        &self,
        user_id: &[u8],
        username: &str,
        display_name: &str,
        exclude_credentials: Option<Vec<CredentialID>>,
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration)> {
        let user_unique_id = Uuid::from_slice(user_id)
            .map_err(|e| AppError::ValidationError(format!("Invalid user ID: {}", e)))?;

        let exclude_creds = exclude_credentials.unwrap_or_default();

        let (ccr, reg_state) = self.webauthn
            .start_passkey_registration(
                user_unique_id,
                username,
                display_name,
                Some(exclude_creds),
            )
            .map_err(|e| AppError::WebAuthnError(format!("Failed to start registration: {}", e)))?;

        Ok((ccr, reg_state))
    }

    /// Finish registration process
    pub fn finish_registration(
        &self,
        reg: &RegisterPublicKeyCredential,
        state: &PasskeyRegistration,
    ) -> Result<Passkey> {
        let passkey = self.webauthn
            .finish_passkey_registration(reg, state)
            .map_err(|e| AppError::WebAuthnError(format!("Failed to finish registration: {}", e)))?;

        Ok(passkey)
    }

    /// Start authentication process
    pub fn start_authentication(
        &self,
        allowed_credentials: Vec<Passkey>,
    ) -> Result<(RequestChallengeResponse, PasskeyAuthentication)> {
        let (rcr, auth_state) = self.webauthn
            .start_passkey_authentication(&allowed_credentials)
            .map_err(|e| AppError::WebAuthnError(format!("Failed to start authentication: {}", e)))?;

        Ok((rcr, auth_state))
    }

    /// Finish authentication process
    pub fn finish_authentication(
        &self,
        auth: &PublicKeyCredential,
        state: &PasskeyAuthentication,
    ) -> Result<AuthenticationResult> {
        let result = self.webauthn
            .finish_passkey_authentication(auth, state)
            .map_err(|e| AppError::WebAuthnError(format!("Failed to finish authentication: {}", e)))?;

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webauthn_service_creation() {
        let service = WebAuthnService::new(
            "localhost",
            "http://localhost:8080",
            Some("Test FIDO Server")
        );
        assert!(service.is_ok());
    }

    #[test]
    fn test_webauthn_service_invalid_origin() {
        let service = WebAuthnService::new(
            "localhost",
            "invalid-url",
            Some("Test FIDO Server")
        );
        assert!(service.is_err());
    }
}