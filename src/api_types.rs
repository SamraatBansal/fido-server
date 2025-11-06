use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;

// Base response type for all API responses
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
}

impl ServerResponse {
    pub fn ok() -> Self {
        Self {
            status: "ok".to_string(),
            error_message: "".to_string(),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            status: "failed".to_string(),
            error_message: message.into(),
        }
    }
}

// Registration request/response types
#[derive(Debug, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsRequest {
    pub username: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: Option<AttestationConveyancePreference>,
    pub extensions: Option<RequestRegistrationExtensions>,
}

#[derive(Debug, Serialize)]
pub struct ServerPublicKeyCredentialCreationOptionsResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
    pub rp: PublicKeyCredentialRpEntity,
    pub user: ServerPublicKeyCredentialUserEntity,
    pub challenge: String,
    #[serde(rename = "pubKeyCredParams")]
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    #[serde(rename = "excludeCredentials")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub exclude_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
    #[serde(rename = "authenticatorSelection")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<AttestationConveyancePreference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<RequestRegistrationExtensions>,
}

#[derive(Debug, Serialize)]
pub struct ServerPublicKeyCredentialUserEntity {
    pub id: String,
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ServerPublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub type_: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<AuthenticatorTransport>>,
}

// Authentication request/response types
#[derive(Debug, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsRequest {
    pub username: String,
    #[serde(rename = "userVerification")]
    pub user_verification: Option<UserVerificationPolicy>,
    pub extensions: Option<RequestAuthenticationExtensions>,
}

#[derive(Debug, Serialize)]
pub struct ServerPublicKeyCredentialGetOptionsResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
    pub challenge: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    #[serde(rename = "rpId")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    #[serde(rename = "allowCredentials")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allow_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
    #[serde(rename = "userVerification")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<UserVerificationPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<RequestAuthenticationExtensions>,
}

// Server versions of WebAuthn credential types
#[derive(Debug, Deserialize)]
pub struct ServerPublicKeyCredential {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub response: ServerAuthenticatorResponse,
    #[serde(rename = "getClientExtensionResults")]
    pub get_client_extension_results: Option<AuthenticationExtensionsClientOutputs>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum ServerAuthenticatorResponse {
    Attestation(ServerAuthenticatorAttestationResponse),
    Assertion(ServerAuthenticatorAssertionResponse),
}

#[derive(Debug, Deserialize)]
pub struct ServerAuthenticatorAttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<AuthenticatorTransport>>,
}

#[derive(Debug, Deserialize)]
pub struct ServerAuthenticatorAssertionResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    pub signature: String,
    #[serde(rename = "userHandle")]
    pub user_handle: Option<String>,
}

// Validation helpers
impl ServerPublicKeyCredential {
    pub fn validate_basic_structure(&self) -> Result<(), crate::error::AppError> {
        use crate::error::AppError;
        
        if self.id.is_empty() {
            return Err(AppError::MissingField("id".to_string()));
        }
        
        if self.type_ != "public-key" {
            return Err(AppError::InvalidInput(
                format!("type must be 'public-key', got '{}'", self.type_)
            ));
        }
        
        // Validate base64url format for id
        if !self.id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Err(AppError::InvalidFormat(
                "id must be base64url encoded".to_string()
            ));
        }
        
        Ok(())
    }
}

impl ServerAuthenticatorAttestationResponse {
    pub fn validate_structure(&self) -> Result<(), crate::error::AppError> {
        use crate::error::AppError;
        
        if self.client_data_json.is_empty() {
            return Err(AppError::MissingField("clientDataJSON".to_string()));
        }
        
        if self.attestation_object.is_empty() {
            return Err(AppError::MissingField("attestationObject".to_string()));
        }
        
        // Validate base64url format
        if !self.client_data_json.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Err(AppError::InvalidFormat(
                "clientDataJSON must be base64url encoded".to_string()
            ));
        }
        
        if !self.attestation_object.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Err(AppError::InvalidFormat(
                "attestationObject must be base64url encoded".to_string()
            ));
        }
        
        Ok(())
    }
}

impl ServerAuthenticatorAssertionResponse {
    pub fn validate_structure(&self) -> Result<(), crate::error::AppError> {
        use crate::error::AppError;
        
        if self.client_data_json.is_empty() {
            return Err(AppError::MissingField("clientDataJSON".to_string()));
        }
        
        if self.authenticator_data.is_empty() {
            return Err(AppError::MissingField("authenticatorData".to_string()));
        }
        
        if self.signature.is_empty() {
            return Err(AppError::MissingField("signature".to_string()));
        }
        
        // Validate base64url format
        let fields = [
            ("clientDataJSON", &self.client_data_json),
            ("authenticatorData", &self.authenticator_data),
            ("signature", &self.signature),
        ];
        
        for (field_name, field_value) in fields {
            if !field_value.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                return Err(AppError::InvalidFormat(
                    format!("{} must be base64url encoded", field_name)
                ));
            }
        }
        
        if let Some(user_handle) = &self.user_handle {
            if !user_handle.is_empty() && !user_handle.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                return Err(AppError::InvalidFormat(
                    "userHandle must be base64url encoded".to_string()
                ));
            }
        }
        
        Ok(())
    }
}