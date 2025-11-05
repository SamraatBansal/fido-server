use crate::config::WebAuthnConfig;
use crate::error::{AppError, Result};
use crate::schema::{
    ServerAuthenticatorAttestationResponse, ServerAuthenticatorAssertionResponse,
    ServerPublicKeyCredential,
};
use std::sync::Arc;
use webauthn_rs::prelude::*;

#[derive(Clone)]
pub struct WebAuthnService {
    webauthn: Arc<WebAuthn>,
    config: Arc<WebAuthnConfig>,
}

impl WebAuthnService {
    pub fn new(config: &WebAuthnConfig) -> Result<Self> {
        let webauthn = WebauthnBuilder::new(&config.rp_id, &config.rp_origin)?
            .rp_name(&config.rp_name)
            .build()?;

        Ok(Self {
            webauthn: Arc::new(webauthn),
            config: Arc::new(config.clone()),
        })
    }

    // Registration methods
    pub async fn start_passkey_registration(
        &self,
        user_id: &[u8],
        username: &str,
        display_name: &str,
        exclude_credentials: Option<Vec<CredentialID>>,
        authenticator_selection: Option<AuthenticatorSelectionCriteria>,
        attestation: Option<AttestationConveyancePreference>,
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration)> {
        let user_uuid = Uuid::from_slice(user_id).map_err(|_| {
            AppError::validation("Invalid user ID format")
        })?;

        let mut builder = self.webauthn.start_passkey_registration(
            user_uuid,
            username,
            display_name,
            exclude_credentials,
        )?;

        // Apply authenticator selection if provided
        if let Some(auth_sel) = authenticator_selection {
            // The webauthn-rs library handles authenticator selection internally
            // We just need to ensure it's passed through the creation challenge
        }

        Ok(builder)
    }

    pub async fn finish_passkey_registration(
        &self,
        reg_credential: &ServerPublicKeyCredential,
        state: &PasskeyRegistration,
    ) -> Result<Passkey> {
        // Convert ServerPublicKeyCredential to RegisterPublicKeyCredential
        let reg_pkc = self.convert_to_register_credential(reg_credential)?;
        
        let passkey = self.webauthn.finish_passkey_registration(&reg_pkc, state)?;
        Ok(passkey)
    }

    // Authentication methods
    pub async fn start_passkey_authentication(
        &self,
        allow_credentials: Vec<CredentialID>,
    ) -> Result<(RequestChallengeResponse, PasskeyAuthentication)> {
        let (challenge_response, auth_state) = self
            .webauthn
            .start_passkey_authentication(&allow_credentials)?;

        Ok((challenge_response, auth_state))
    }

    pub async fn finish_passkey_authentication(
        &self,
        auth_credential: &ServerPublicKeyCredential,
        state: &PasskeyAuthentication,
        passkey: &Passkey,
    ) -> Result<AuthenticationResult> {
        // Convert ServerPublicKeyCredential to PublicKeyCredential
        let auth_pkc = self.convert_to_auth_credential(auth_credential)?;
        
        let result = self.webauthn.finish_passkey_authentication(&auth_pkc, state)?;
        Ok(result)
    }

    // Helper methods for credential conversion
    fn convert_to_register_credential(
        &self,
        server_cred: &ServerPublicKeyCredential,
    ) -> Result<RegisterPublicKeyCredential> {
        if let crate::schema::ServerAuthenticatorResponse::Attestation(attestation_response) = &server_cred.response {
            // Decode base64url encoded fields
            let client_data_json = base64::decode_config(&attestation_response.client_data_json, base64::URL_SAFE_NO_PAD)
                .map_err(|_| AppError::validation("Invalid clientDataJSON encoding"))?;
            
            let attestation_object = base64::decode_config(&attestation_response.attestation_object, base64::URL_SAFE_NO_PAD)
                .map_err(|_| AppError::validation("Invalid attestationObject encoding"))?;

            let credential_id = base64::decode_config(&server_cred.id, base64::URL_SAFE_NO_PAD)
                .map_err(|_| AppError::validation("Invalid credential ID encoding"))?;

            Ok(RegisterPublicKeyCredential {
                id: server_cred.id.clone(),
                raw_id: credential_id,
                response: AuthenticatorAttestationResponseRaw {
                    client_data_json,
                    attestation_object,
                },
                type_: "public-key".to_string(),
                extensions: serde_json::Map::new(),
            })
        } else {
            Err(AppError::validation("Expected attestation response for registration"))
        }
    }

    fn convert_to_auth_credential(
        &self,
        server_cred: &ServerPublicKeyCredential,
    ) -> Result<PublicKeyCredential> {
        if let crate::schema::ServerAuthenticatorResponse::Assertion(assertion_response) = &server_cred.response {
            // Decode base64url encoded fields
            let client_data_json = base64::decode_config(&assertion_response.client_data_json, base64::URL_SAFE_NO_PAD)
                .map_err(|_| AppError::validation("Invalid clientDataJSON encoding"))?;
            
            let authenticator_data = base64::decode_config(&assertion_response.authenticator_data, base64::URL_SAFE_NO_PAD)
                .map_err(|_| AppError::validation("Invalid authenticatorData encoding"))?;

            let signature = base64::decode_config(&assertion_response.signature, base64::URL_SAFE_NO_PAD)
                .map_err(|_| AppError::validation("Invalid signature encoding"))?;

            let user_handle = if let Some(uh) = &assertion_response.user_handle {
                if !uh.is_empty() {
                    Some(base64::decode_config(uh, base64::URL_SAFE_NO_PAD)
                        .map_err(|_| AppError::validation("Invalid userHandle encoding"))?)
                } else {
                    None
                }
            } else {
                None
            };

            let credential_id = base64::decode_config(&server_cred.id, base64::URL_SAFE_NO_PAD)
                .map_err(|_| AppError::validation("Invalid credential ID encoding"))?;

            Ok(PublicKeyCredential {
                id: server_cred.id.clone(),
                raw_id: credential_id,
                response: AuthenticatorAssertionResponseRaw {
                    client_data_json,
                    authenticator_data,
                    signature,
                    user_handle,
                },
                type_: "public-key".to_string(),
                extensions: server_cred.get_client_extension_results.clone().unwrap_or_default(),
            })
        } else {
            Err(AppError::validation("Expected assertion response for authentication"))
        }
    }

    pub fn get_timeout(&self) -> u32 {
        self.config.timeout_ms
    }

    pub fn get_rp_id(&self) -> &str {
        &self.config.rp_id
    }
}