use serde::{Deserialize, Serialize};

/// Base response structure for all FIDO2 conformance API responses
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

    pub fn failed(error_message: impl Into<String>) -> Self {
        Self {
            status: "failed".to_string(),
            error_message: error_message.into(),
        }
    }
}

/// Relying Party Entity as defined in WebAuthn specification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyCredentialRpEntity {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

/// User Entity for server responses (base64url encoded id)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialUserEntity {
    pub id: String, // base64url encoded
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

/// Public Key Credential Parameters
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    pub credential_type: String, // "public-key"
    pub alg: i32, // COSE algorithm identifier
}

/// Authenticator Selection Criteria
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthenticatorSelectionCriteria {
    #[serde(rename = "authenticatorAttachment", skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<String>, // "platform" | "cross-platform"
    #[serde(rename = "requireResidentKey", skip_serializing_if = "Option::is_none")]
    pub require_resident_key: Option<bool>,
    #[serde(rename = "residentKey", skip_serializing_if = "Option::is_none")]
    pub resident_key: Option<String>, // "discouraged" | "preferred" | "required"
    #[serde(rename = "userVerification", skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<String>, // "required" | "preferred" | "discouraged"
}

/// Public Key Credential Descriptor for server responses
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub credential_type: String, // "public-key"
    pub id: String, // base64url encoded credential ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>, // ["usb", "nfc", "ble", "internal"]
}

/// Authentication Extensions Client Inputs
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AuthenticationExtensionsClientInputs {
    #[serde(rename = "credProps", skip_serializing_if = "Option::is_none")]
    pub cred_props: Option<bool>,
    #[serde(rename = "largeBlob", skip_serializing_if = "Option::is_none")]
    pub large_blob: Option<serde_json::Value>,
}

/// Authentication Extensions Client Outputs
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AuthenticationExtensionsClientOutputs {
    #[serde(rename = "credProps", skip_serializing_if = "Option::is_none")]
    pub cred_props: Option<serde_json::Value>,
    #[serde(rename = "largeBlob", skip_serializing_if = "Option::is_none")]
    pub large_blob: Option<serde_json::Value>,
}

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
        assert!(json.contains("\"displayName\":\"John Doe\""));
    }

    #[test]
    fn test_authenticator_selection_criteria() {
        let criteria = AuthenticatorSelectionCriteria {
            authenticator_attachment: Some("cross-platform".to_string()),
            require_resident_key: Some(false),
            resident_key: None,
            user_verification: Some("preferred".to_string()),
        };
        let json = serde_json::to_string(&criteria).unwrap();
        assert!(json.contains("\"authenticatorAttachment\":\"cross-platform\""));
        assert!(json.contains("\"requireResidentKey\":false"));
        assert!(json.contains("\"userVerification\":\"preferred\""));
    }
}