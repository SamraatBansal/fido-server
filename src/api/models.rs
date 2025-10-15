use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Base response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
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

    pub fn error(message: &str) -> Self {
        Self {
            status: "failed".to_string(),
            error_message: message.to_string(),
        }
    }
}

// Registration (Attestation) Models
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationOptionsRequest {
    pub username: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "authenticatorSelection", skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    #[serde(default = "default_attestation")]
    pub attestation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationOptionsResponse {
    #[serde(flatten)]
    pub base: ServerResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rp: Option<RelyingParty>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<UserEntity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(rename = "pubKeyCredParams", skip_serializing_if = "Option::is_none")]
    pub pub_key_cred_params: Option<Vec<PubKeyCredParam>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    #[serde(rename = "excludeCredentials", skip_serializing_if = "Option::is_none")]
    pub exclude_credentials: Option<Vec<CredentialDescriptor>>,
    #[serde(rename = "authenticatorSelection", skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelyingParty {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserEntity {
    pub id: String,
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PubKeyCredParam {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub alg: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialDescriptor {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResultRequest {
    pub id: String,
    #[serde(rename = "rawId", skip_serializing_if = "Option::is_none")]
    pub raw_id: Option<String>,
    pub response: AttestationResponse,
    #[serde(rename = "getClientExtensionResults", skip_serializing_if = "Option::is_none")]
    pub get_client_extension_results: Option<HashMap<String, serde_json::Value>>,
    #[serde(rename = "type")]
    pub cred_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
}

// Authentication (Assertion) Models
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionOptionsRequest {
    pub username: String,
    #[serde(rename = "userVerification", skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionOptionsResponse {
    #[serde(flatten)]
    pub base: ServerResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    #[serde(rename = "rpId", skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    #[serde(rename = "allowCredentials", skip_serializing_if = "Option::is_none")]
    pub allow_credentials: Option<Vec<CredentialDescriptor>>,
    #[serde(rename = "userVerification", skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionResultRequest {
    pub id: String,
    #[serde(rename = "rawId", skip_serializing_if = "Option::is_none")]
    pub raw_id: Option<String>,
    pub response: AssertionResponse,
    #[serde(rename = "getClientExtensionResults", skip_serializing_if = "Option::is_none")]
    pub get_client_extension_results: Option<HashMap<String, serde_json::Value>>,
    #[serde(rename = "type")]
    pub cred_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionResponse {
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    pub signature: String,
    #[serde(rename = "userHandle", skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<String>,
}

fn default_attestation() -> String {
    "none".to_string()
}

// Test helper implementations
impl AttestationOptionsRequest {
    pub fn new(username: &str, display_name: &str) -> Self {
        Self {
            username: username.to_string(),
            display_name: display_name.to_string(),
            authenticator_selection: None,
            attestation: default_attestation(),
        }
    }

    pub fn with_authenticator_selection(mut self, selection: AuthenticatorSelectionCriteria) -> Self {
        self.authenticator_selection = Some(selection);
        self
    }

    pub fn with_attestation(mut self, attestation: &str) -> Self {
        self.attestation = attestation.to_string();
        self
    }
}

impl AuthenticatorSelectionCriteria {
    pub fn new() -> Self {
        Self {
            require_resident_key: None,
            authenticator_attachment: None,
            user_verification: None,
            resident_key: None,
        }
    }

    pub fn with_user_verification(mut self, uv: &str) -> Self {
        self.user_verification = Some(uv.to_string());
        self
    }

    pub fn with_authenticator_attachment(mut self, attachment: &str) -> Self {
        self.authenticator_attachment = Some(attachment.to_string());
        self
    }

    pub fn with_resident_key(mut self, resident_key: bool) -> Self {
        self.require_resident_key = Some(resident_key);
        self
    }
}

impl AssertionOptionsRequest {
    pub fn new(username: &str) -> Self {
        Self {
            username: username.to_string(),
            user_verification: None,
        }
    }

    pub fn with_user_verification(mut self, uv: &str) -> Self {
        self.user_verification = Some(uv.to_string());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_server_response_ok() {
        let response = ServerResponse::ok();
        assert_eq!(response.status, "ok");
        assert_eq!(response.error_message, "");
    }

    #[test]
    fn test_server_response_error() {
        let response = ServerResponse::error("Test error");
        assert_eq!(response.status, "failed");
        assert_eq!(response.error_message, "Test error");
    }

    #[test]
    fn test_attestation_options_request_serialization() {
        let request = AttestationOptionsRequest::new("test@example.com", "Test User")
            .with_attestation("direct")
            .with_authenticator_selection(
                AuthenticatorSelectionCriteria::new()
                    .with_user_verification("required")
                    .with_authenticator_attachment("cross-platform")
            );

        let json = serde_json::to_string(&request).expect("Failed to serialize");
        let deserialized: AttestationOptionsRequest = 
            serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(request.username, deserialized.username);
        assert_eq!(request.display_name, deserialized.display_name);
        assert_eq!(request.attestation, deserialized.attestation);
    }

    #[test]
    fn test_attestation_options_request_default_attestation() {
        let request = AttestationOptionsRequest::new("test@example.com", "Test User");
        assert_eq!(request.attestation, "none");
    }

    #[test]
    fn test_assertion_options_request_serialization() {
        let request = AssertionOptionsRequest::new("test@example.com")
            .with_user_verification("preferred");

        let json = serde_json::to_string(&request).expect("Failed to serialize");
        let deserialized: AssertionOptionsRequest = 
            serde_json::from_str(&json).expect("Failed to deserialize");

        assert_eq!(request.username, deserialized.username);
        assert_eq!(request.user_verification, deserialized.user_verification);
    }

    #[test]
    fn test_attestation_result_request_deserialization() {
        let json = r#"{
            "id": "test-credential-id",
            "response": {
                "clientDataJSON": "test-client-data",
                "attestationObject": "test-attestation-object"
            },
            "type": "public-key"
        }"#;

        let request: AttestationResultRequest = 
            serde_json::from_str(json).expect("Failed to deserialize");

        assert_eq!(request.id, "test-credential-id");
        assert_eq!(request.response.client_data_json, "test-client-data");
        assert_eq!(request.response.attestation_object, "test-attestation-object");
        assert_eq!(request.cred_type, "public-key");
    }

    #[test]
    fn test_assertion_result_request_deserialization() {
        let json = r#"{
            "id": "test-credential-id",
            "response": {
                "authenticatorData": "test-auth-data",
                "clientDataJSON": "test-client-data",
                "signature": "test-signature"
            },
            "type": "public-key"
        }"#;

        let request: AssertionResultRequest = 
            serde_json::from_str(json).expect("Failed to deserialize");

        assert_eq!(request.id, "test-credential-id");
        assert_eq!(request.response.authenticator_data, "test-auth-data");
        assert_eq!(request.response.client_data_json, "test-client-data");
        assert_eq!(request.response.signature, "test-signature");
        assert_eq!(request.cred_type, "public-key");
    }

    #[test]
    fn test_attestation_options_response_serialization() {
        let response = AttestationOptionsResponse {
            base: ServerResponse::ok(),
            rp: Some(RelyingParty {
                name: "Test RP".to_string(),
                id: Some("example.com".to_string()),
            }),
            user: Some(UserEntity {
                id: "test-user-id".to_string(),
                name: "test@example.com".to_string(),
                display_name: "Test User".to_string(),
            }),
            challenge: Some("test-challenge".to_string()),
            pub_key_cred_params: Some(vec![
                PubKeyCredParam {
                    cred_type: "public-key".to_string(),
                    alg: -7,
                }
            ]),
            timeout: Some(60000),
            exclude_credentials: None,
            authenticator_selection: None,
            attestation: Some("none".to_string()),
            extensions: None,
        };

        let json = serde_json::to_string(&response).expect("Failed to serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("Failed to parse JSON");

        assert_eq!(parsed["status"], "ok");
        assert_eq!(parsed["rp"]["name"], "Test RP");
        assert_eq!(parsed["user"]["name"], "test@example.com");
        assert_eq!(parsed["challenge"], "test-challenge");
    }

    #[test]
    fn test_assertion_options_response_serialization() {
        let response = AssertionOptionsResponse {
            base: ServerResponse::ok(),
            challenge: Some("test-challenge".to_string()),
            timeout: Some(60000),
            rp_id: Some("example.com".to_string()),
            allow_credentials: Some(vec![
                CredentialDescriptor {
                    cred_type: "public-key".to_string(),
                    id: "test-cred-id".to_string(),
                    transports: Some(vec!["usb".to_string(), "nfc".to_string()]),
                }
            ]),
            user_verification: Some("required".to_string()),
            extensions: None,
        };

        let json = serde_json::to_string(&response).expect("Failed to serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("Failed to parse JSON");

        assert_eq!(parsed["status"], "ok");
        assert_eq!(parsed["challenge"], "test-challenge");
        assert_eq!(parsed["rpId"], "example.com");
        assert_eq!(parsed["userVerification"], "required");
    }

    #[test]
    fn test_invalid_json_deserialization() {
        let invalid_json = r#"{"invalid": "json"}"#;
        
        let result: Result<AttestationOptionsRequest, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());

        let result: Result<AssertionOptionsRequest, _> = serde_json::from_str(invalid_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_required_fields() {
        // Test missing username in attestation options
        let json = r#"{"displayName": "Test User"}"#;
        let result: Result<AttestationOptionsRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());

        // Test missing displayName in attestation options
        let json = r#"{"username": "test@example.com"}"#;
        let result: Result<AttestationOptionsRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());

        // Test missing username in assertion options
        let json = r#"{"userVerification": "required"}"#;
        let result: Result<AssertionOptionsRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_optional_fields_handling() {
        // Test attestation options with minimal fields
        let json = r#"{
            "username": "test@example.com",
            "displayName": "Test User"
        }"#;
        let request: AttestationOptionsRequest = 
            serde_json::from_str(json).expect("Failed to deserialize");
        
        assert_eq!(request.username, "test@example.com");
        assert_eq!(request.display_name, "Test User");
        assert_eq!(request.attestation, "none"); // Default value
        assert!(request.authenticator_selection.is_none());

        // Test assertion options with minimal fields
        let json = r#"{"username": "test@example.com"}"#;
        let request: AssertionOptionsRequest = 
            serde_json::from_str(json).expect("Failed to deserialize");
        
        assert_eq!(request.username, "test@example.com");
        assert!(request.user_verification.is_none());
    }
}