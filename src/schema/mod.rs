//! Request and response schemas for FIDO2/WebAuthn API

use serde::{Deserialize, Serialize};
use validator::Validate;
use uuid::Uuid;

/// Base server response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
}

impl ServerResponse {
    pub fn success() -> Self {
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

/// Registration options request
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ServerPublicKeyCredentialCreationOptionsRequest {
    #[validate(length(min = 1, max = 64), regex = "crate::utils::validation::USERNAME_REGEX")]
    pub username: String,
    
    #[validate(length(min = 1, max = 64))]
    #[serde(rename = "displayName")]
    pub display_name: String,
    
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    
    #[validate(custom = "crate::utils::validation::validate_attestation")]
    pub attestation: Option<String>,
}

/// Registration options response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
    pub rp: PublicKeyCredentialRpEntity,
    pub user: ServerPublicKeyCredentialUserEntity,
    pub challenge: String,
    #[serde(rename = "pubKeyCredParams")]
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    pub timeout: Option<u64>,
    #[serde(rename = "excludeCredentials")]
    pub exclude_credentials: Option<Vec<ServerPublicKeyCredentialDescriptor>>,
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: Option<String>,
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
}

/// RP entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialRpEntity {
    pub name: String,
    pub id: Option<String>,
}

/// User entity for registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialUserEntity {
    pub id: String,
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

/// Public key credential parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub alg: i32,
}

/// Authenticator selection criteria
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorSelectionCriteria {
    #[serde(rename = "requireResidentKey")]
    pub require_resident_key: Option<bool>,
    #[serde(rename = "userVerification")]
    pub user_verification: Option<String>,
    #[serde(rename = "authenticatorAttachment")]
    pub authenticator_attachment: Option<String>,
}

/// Credential descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub id: String,
    pub transports: Option<Vec<String>>,
}

/// Authentication extensions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationExtensionsClientInputs {
    #[serde(flatten)]
    pub extensions: std::collections::HashMap<String, serde_json::Value>,
}

/// Registration response (attestation result)
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ServerPublicKeyCredentialAttestationResponse {
    #[validate(length(min = 1))]
    pub id: String,
    
    #[validate(length(min = 1))]
    pub raw_id: String,
    
    #[validate]
    pub response: ServerAuthenticatorAttestationResponse,
    
    #[validate(custom = "crate::utils::validation::validate_credential_type")]
    #[serde(rename = "type")]
    pub cred_type: String,
    
    pub get_client_extension_results: Option<AuthenticationExtensionsClientOutputs>,
}

/// Attestation response data
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ServerAuthenticatorAttestationResponse {
    #[validate(length(min = 1))]
    pub client_data_json: String,
    
    #[validate(length(min = 1))]
    pub attestation_object: String,
}

/// Authentication options request
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ServerPublicKeyCredentialGetOptionsRequest {
    pub username: Option<String>,
    
    #[validate(custom = "crate::utils::validation::validate_user_verification")]
    #[serde(rename = "userVerification")]
    pub user_verification: Option<String>,
}

/// Authentication options response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsResponse {
    pub status: String,
    pub error_message: String,
    pub challenge: String,
    pub timeout: Option<u64>,
    #[serde(rename = "rpId")]
    pub rp_id: String,
    pub allow_credentials: Option<Vec<ServerPublicKeyCredentialDescriptor>>,
    pub user_verification: Option<String>,
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
}

/// Authentication response (assertion result)
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ServerPublicKeyCredentialAssertionResponse {
    #[validate(length(min = 1))]
    pub id: String,
    
    #[validate(length(min = 1))]
    pub raw_id: String,
    
    #[validate]
    pub response: ServerAuthenticatorAssertionResponse,
    
    #[validate(custom = "crate::utils::validation::validate_credential_type")]
    #[serde(rename = "type")]
    pub cred_type: String,
    
    pub get_client_extension_results: Option<AuthenticationExtensionsClientOutputs>,
}

/// Assertion response data
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ServerAuthenticatorAssertionResponse {
    #[validate(length(min = 1))]
    pub authenticator_data: String,
    
    #[validate(length(min = 1))]
    pub client_data_json: String,
    
    #[validate(length(min = 1))]
    pub signature: String,
    
    pub user_handle: Option<String>,
}

/// Authentication extension outputs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationExtensionsClientOutputs {
    #[serde(flatten)]
    pub extensions: std::collections::HashMap<String, serde_json::Value>,
}

impl Default for ServerPublicKeyCredentialCreationOptionsResponse {
    fn default() -> Self {
        Self {
            status: "ok".to_string(),
            error_message: "".to_string(),
            rp: PublicKeyCredentialRpEntity {
                name: "Test RP".to_string(),
                id: Some("localhost".to_string()),
            },
            user: ServerPublicKeyCredentialUserEntity {
                id: Uuid::new_v4().to_string(),
                name: "testuser".to_string(),
                display_name: "Test User".to_string(),
            },
            challenge: "".to_string(),
            pub_key_cred_params: vec![
                PublicKeyCredentialParameters {
                    cred_type: "public-key".to_string(),
                    alg: -7, // ES256
                },
            ],
            timeout: Some(60000),
            exclude_credentials: None,
            authenticator_selection: None,
            attestation: None,
            extensions: None,
        }
    }
}

impl Default for ServerPublicKeyCredentialGetOptionsResponse {
    fn default() -> Self {
        Self {
            status: "ok".to_string(),
            error_message: "".to_string(),
            challenge: "".to_string(),
            timeout: Some(60000),
            rp_id: "localhost".to_string(),
            allow_credentials: None,
            user_verification: None,
            extensions: None,
        }
    }
}