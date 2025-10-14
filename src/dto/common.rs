//! Common DTOs used across FIDO2 API endpoints

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Standard server response format for FIDO2 conformance tests
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
}

impl ServerResponse {
    pub fn ok() -> Self {
        Self {
            status: "ok".to_string(),
            error_message: String::new(),
        }
    }

    pub fn failed(message: &str) -> Self {
        Self {
            status: "failed".to_string(),
            error_message: message.to_string(),
        }
    }
}

/// Authenticator selection criteria
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthenticatorSelectionCriteria {
    #[serde(rename = "requireResidentKey", skip_serializing_if = "Option::is_none")]
    pub require_resident_key: Option<bool>,
    
    #[serde(rename = "authenticatorAttachment", skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<String>,
    
    #[serde(rename = "userVerification", skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<String>,
    
    #[serde(rename = "residentKey", skip_serializing_if = "Option::is_none")]
    pub resident_key: Option<String>,
}

/// Public key credential parameters
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    pub credential_type: String,
    pub alg: i32,
}

impl Default for PublicKeyCredentialParameters {
    fn default() -> Self {
        Self {
            credential_type: "public-key".to_string(),
            alg: -7, // ES256
        }
    }
}

/// Relying Party entity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PublicKeyCredentialRpEntity {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

/// User entity for server responses
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerPublicKeyCredentialUserEntity {
    pub id: String,
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

/// Credential descriptor
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerPublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub credential_type: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
}

/// Client extension results
pub type AuthenticationExtensionsClientOutputs = HashMap<String, serde_json::Value>;

/// Client extension inputs
pub type AuthenticationExtensionsClientInputs = HashMap<String, serde_json::Value>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_response_ok() {
        let response = ServerResponse::ok();
        assert_eq!(response.status, "ok");
        assert_eq!(response.error_message, "");
    }

    #[test]
    fn test_server_response_failed() {
        let response = ServerResponse::failed("Test error");
        assert_eq!(response.status, "failed");
        assert_eq!(response.error_message, "Test error");
    }

    #[test]
    fn test_server_response_serialization() {
        let response = ServerResponse::ok();
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"status\":\"ok\""));
        assert!(json.contains("\"errorMessage\":\"\""));
    }

    #[test]
    fn test_public_key_credential_parameters_default() {
        let params = PublicKeyCredentialParameters::default();
        assert_eq!(params.credential_type, "public-key");
        assert_eq!(params.alg, -7);
    }

    #[test]
    fn test_authenticator_selection_criteria_serialization() {
        let criteria = AuthenticatorSelectionCriteria {
            require_resident_key: Some(false),
            authenticator_attachment: Some("cross-platform".to_string()),
            user_verification: Some("preferred".to_string()),
            resident_key: None,
        };
        
        let json = serde_json::to_string(&criteria).unwrap();
        assert!(json.contains("\"requireResidentKey\":false"));
        assert!(json.contains("\"authenticatorAttachment\":\"cross-platform\""));
        assert!(json.contains("\"userVerification\":\"preferred\""));
        assert!(!json.contains("\"residentKey\""));
    }

    #[test]
    fn test_rp_entity_serialization() {
        let rp = PublicKeyCredentialRpEntity {
            name: "Example Corporation".to_string(),
            id: Some("example.com".to_string()),
        };
        
        let json = serde_json::to_string(&rp).unwrap();
        assert!(json.contains("\"name\":\"Example Corporation\""));
        assert!(json.contains("\"id\":\"example.com\""));
    }

    #[test]
    fn test_user_entity_serialization() {
        let user = ServerPublicKeyCredentialUserEntity {
            id: "S3932ee31vKEC0JtJMIQ".to_string(),
            name: "johndoe@example.com".to_string(),
            display_name: "John Doe".to_string(),
        };
        
        let json = serde_json::to_string(&user).unwrap();
        assert!(json.contains("\"id\":\"S3932ee31vKEC0JtJMIQ\""));
        assert!(json.contains("\"name\":\"johndoe@example.com\""));
        assert!(json.contains("\"displayName\":\"John Doe\""));
    }

    #[test]
    fn test_credential_descriptor_serialization() {
        let descriptor = ServerPublicKeyCredentialDescriptor {
            credential_type: "public-key".to_string(),
            id: "opQf1WmYAa5aupUKJIQp".to_string(),
            transports: Some(vec!["usb".to_string(), "nfc".to_string()]),
        };
        
        let json = serde_json::to_string(&descriptor).unwrap();
        assert!(json.contains("\"type\":\"public-key\""));
        assert!(json.contains("\"id\":\"opQf1WmYAa5aupUKJIQp\""));
        assert!(json.contains("\"transports\":[\"usb\",\"nfc\"]"));
    }
}