//! Data Transfer Objects for FIDO2/WebAuthn API

use serde::{Deserialize, Serialize};
use validator::Validate;

/// Base server response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerResponse {
    pub status: String,
    pub errorMessage: String,
}

impl ServerResponse {
    pub fn success() -> Self {
        Self {
            status: "ok".to_string(),
            errorMessage: "".to_string(),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            status: "failed".to_string(),
            errorMessage: message.into(),
        }
    }
}

/// Registration challenge request
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ServerPublicKeyCredentialCreationOptionsRequest {
    #[validate(length(min = 1, max = 254))]
    pub username: String,
    
    #[validate(length(min = 1, max = 128))]
    pub displayName: String,
    
    pub authenticatorSelection: Option<AuthenticatorSelectionCriteria>,
    
    #[serde(default = "default_attestation")]
    pub attestation: String,
}

fn default_attestation() -> String {
    "none".to_string()
}

/// Registration challenge response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsResponse {
    pub status: String,
    pub errorMessage: String,
    pub rp: PublicKeyCredentialRpEntity,
    pub user: ServerPublicKeyCredentialUserEntity,
    pub challenge: String,
    pub pubKeyCredParams: Vec<PublicKeyCredentialParameters>,
    pub timeout: Option<u32>,
    pub excludeCredentials: Option<Vec<ServerPublicKeyCredentialDescriptor>>,
    pub authenticatorSelection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: Option<String>,
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
}

impl From<ServerResponse> for ServerPublicKeyCredentialCreationOptionsResponse {
    fn from(resp: ServerResponse) -> Self {
        Self {
            status: resp.status,
            errorMessage: resp.errorMessage,
            rp: PublicKeyCredentialRpEntity::default(),
            user: ServerPublicKeyCredentialUserEntity::default(),
            challenge: String::new(),
            pubKeyCredParams: vec![],
            timeout: None,
            excludeCredentials: None,
            authenticatorSelection: None,
            attestation: None,
            extensions: None,
        }
    }
}

/// Authentication challenge request
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ServerPublicKeyCredentialGetOptionsRequest {
    #[validate(length(min = 1, max = 254))]
    pub username: String,
    
    #[serde(default)]
    pub userVerification: Option<String>,
}

/// Authentication challenge response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsResponse {
    pub status: String,
    pub errorMessage: String,
    pub challenge: String,
    pub timeout: Option<u32>,
    pub rpId: String,
    pub allowCredentials: Option<Vec<ServerPublicKeyCredentialDescriptor>>,
    pub userVerification: Option<String>,
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
}

impl From<ServerResponse> for ServerPublicKeyCredentialGetOptionsResponse {
    fn from(resp: ServerResponse) -> Self {
        Self {
            status: resp.status,
            errorMessage: resp.errorMessage,
            challenge: String::new(),
            timeout: None,
            rpId: String::new(),
            allowCredentials: None,
            userVerification: None,
            extensions: None,
        }
    }
}

/// Server public key credential for attestation and assertion
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ServerPublicKeyCredential {
    #[validate(length(min = 1))]
    pub id: String,
    
    #[validate(custom(function = "validate_credential_type"))]
    #[serde(rename = "type")]
    pub credential_type: String,
    
    pub response: ServerAuthenticatorResponse,
    
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub getClientExtensionResults: Option<AuthenticationExtensionsClientOutputs>,
}

fn validate_credential_type(credential_type: &str) -> Result<(), validator::ValidationError> {
    if credential_type != "public-key" {
        return Err(validator::ValidationError::new("invalid_type"));
    }
    Ok(())
}

/// Server authenticator response (union type)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ServerAuthenticatorResponse {
    Attestation(ServerAuthenticatorAttestationResponse),
    Assertion(ServerAuthenticatorAssertionResponse),
}

/// Attestation response
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ServerAuthenticatorAttestationResponse {
    #[validate(length(min = 1))]
    pub clientDataJSON: String,
    
    #[validate(length(min = 1))]
    pub attestationObject: String,
}

/// Assertion response
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ServerAuthenticatorAssertionResponse {
    #[validate(length(min = 1))]
    pub authenticatorData: String,
    
    #[validate(length(min = 1))]
    pub signature: String,
    
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub userHandle: Option<String>,
    
    #[validate(length(min = 1))]
    pub clientDataJSON: String,
}

/// RP entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialRpEntity {
    pub name: String,
}

impl Default for PublicKeyCredentialRpEntity {
    fn default() -> Self {
        Self {
            name: "Example Corporation".to_string(),
        }
    }
}

/// User entity for registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialUserEntity {
    pub id: String,
    pub name: String,
    pub displayName: String,
}

impl Default for ServerPublicKeyCredentialUserEntity {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            displayName: String::new(),
        }
    }
}

/// Public key credential parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    pub credential_type: String,
    pub alg: i32,
}

/// Credential descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub credential_type: String,
    pub id: String,
    
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
}

/// Authenticator selection criteria
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorSelectionCriteria {
    #[serde(default)]
    pub requireResidentKey: bool,
    
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authenticatorAttachment: Option<String>,
    
    #[serde(default = "default_user_verification")]
    pub userVerification: String,
}

fn default_user_verification() -> String {
    "preferred".to_string()
}

/// Authentication extensions client inputs
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthenticationExtensionsClientInputs {
    #[serde(flatten)]
    pub extensions: serde_json::Map<String, serde_json::Value>,
}

/// Authentication extensions client outputs
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthenticationExtensionsClientOutputs {
    #[serde(flatten)]
    pub extensions: serde_json::Map<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use validator::Validate;

    #[test]
    fn test_server_response_creation() {
        let success = ServerResponse::success();
        assert_eq!(success.status, "ok");
        assert_eq!(success.errorMessage, "");

        let error = ServerResponse::error("Test error");
        assert_eq!(error.status, "failed");
        assert_eq!(error.errorMessage, "Test error");
    }

    #[test]
    fn test_registration_request_validation() {
        let valid_request = ServerPublicKeyCredentialCreationOptionsRequest {
            username: "test@example.com".to_string(),
            displayName: "Test User".to_string(),
            authenticatorSelection: None,
            attestation: "direct".to_string(),
        };
        assert!(valid_request.validate().is_ok());

        let invalid_request = ServerPublicKeyCredentialCreationOptionsRequest {
            username: "".to_string(),
            displayName: "Test User".to_string(),
            authenticatorSelection: None,
            attestation: "direct".to_string(),
        };
        assert!(invalid_request.validate().is_err());
    }

    #[test]
    fn test_credential_type_validation() {
        let valid_credential = ServerPublicKeyCredential {
            id: "test-id".to_string(),
            credential_type: "public-key".to_string(),
            response: ServerAuthenticatorResponse::Attestation(ServerAuthenticatorAttestationResponse {
                clientDataJSON: "test".to_string(),
                attestationObject: "test".to_string(),
            }),
            getClientExtensionResults: None,
        };
        assert!(valid_credential.validate().is_ok());

        let invalid_credential = ServerPublicKeyCredential {
            id: "test-id".to_string(),
            credential_type: "invalid".to_string(),
            response: ServerAuthenticatorResponse::Attestation(ServerAuthenticatorAttestationResponse {
                clientDataJSON: "test".to_string(),
                attestationObject: "test".to_string(),
            }),
            getClientExtensionResults: None,
        };
        assert!(invalid_credential.validate().is_err());
    }
}