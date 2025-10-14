//! Data Transfer Objects for WebAuthn API

use serde::{Deserialize, Serialize};
use webauthn_rs::proto::{
    AuthenticatorSelectionCriteria, AttestationConveyancePreference, 
    PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity,
    PublicKeyCredentialParameters, AuthenticatorTransport,
    UserVerificationPolicy, COSEAlgorithmIdentifier,
};

// Registration Request DTOs

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsRequest {
    pub username: String,
    pub display_name: String,
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: Option<AttestationConveyancePreference>,
}

impl Default for ServerPublicKeyCredentialCreationOptionsRequest {
    fn default() -> Self {
        Self {
            username: String::new(),
            display_name: String::new(),
            authenticator_selection: None,
            attestation: Some(AttestationConveyancePreference::None),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsResponse {
    pub status: String,
    pub error_message: String,
    pub rp: PublicKeyCredentialRpEntity,
    pub user: ServerPublicKeyCredentialUserEntity,
    pub challenge: String,
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    pub timeout: u32,
    pub exclude_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
    pub authenticator_selection: AuthenticatorSelectionCriteria,
    pub attestation: AttestationConveyancePreference,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialUserEntity {
    pub id: String, // Base64url encoded
    pub name: String,
    pub display_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub id: String, // Base64url encoded
    pub transports: Option<Vec<AuthenticatorTransport>>,
}

// Registration Response DTOs

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredential {
    pub id: String, // Base64url encoded
    pub response: ServerAuthenticatorAttestationResponse,
    #[serde(rename = "type")]
    pub cred_type: String,
    pub get_client_extension_results: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerAuthenticatorAttestationResponse {
    pub client_data_json: String, // Base64url encoded
    pub attestation_object: String, // Base64url encoded
}

// Authentication Request DTOs

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsRequest {
    pub username: String,
    pub user_verification: Option<UserVerificationPolicy>,
}

impl Default for ServerPublicKeyCredentialGetOptionsRequest {
    fn default() -> Self {
        Self {
            username: String::new(),
            user_verification: Some(UserVerificationPolicy::Preferred),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsResponse {
    pub status: String,
    pub error_message: String,
    pub challenge: String,
    pub timeout: u32,
    pub rp_id: String,
    pub allow_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
    pub user_verification: UserVerificationPolicy,
}

// Authentication Response DTOs

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerAuthenticatorAssertionResponse {
    pub authenticator_data: String, // Base64url encoded
    pub client_data_json: String, // Base64url encoded
    pub signature: String, // Base64url encoded
    pub user_handle: Option<String>, // Base64url encoded
}

// Generic Server Response

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerResponse {
    pub status: String,
    pub error_message: String,
}

impl ServerResponse {
    pub fn success() -> Self {
        Self {
            status: "ok".to_string(),
            error_message: "".to_string(),
        }
    }

    pub fn error(message: &str) -> Self {
        Self {
            status: "failed".to_string(),
            error_message: message.to_string(),
        }
    }
}

impl Default for ServerResponse {
    fn default() -> Self {
        Self::success()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_response_success() {
        let response = ServerResponse::success();
        assert_eq!(response.status, "ok");
        assert_eq!(response.error_message, "");
    }

    #[test]
    fn test_server_response_error() {
        let response = ServerResponse::error("test error");
        assert_eq!(response.status, "failed");
        assert_eq!(response.error_message, "test error");
    }

    #[test]
    fn test_server_response_default() {
        let response = ServerResponse::default();
        assert_eq!(response.status, "ok");
        assert_eq!(response.error_message, "");
    }

    #[test]
    fn test_registration_request_default() {
        let request = ServerPublicKeyCredentialCreationOptionsRequest::default();
        assert!(request.username.is_empty());
        assert!(request.display_name.is_empty());
        assert!(request.authenticator_selection.is_none());
        assert_eq!(request.attestation, Some(AttestationConveyancePreference::None));
    }

    #[test]
    fn test_authentication_request_default() {
        let request = ServerPublicKeyCredentialGetOptionsRequest::default();
        assert!(request.username.is_empty());
        assert_eq!(request.user_verification, Some(UserVerificationPolicy::Preferred));
    }
}