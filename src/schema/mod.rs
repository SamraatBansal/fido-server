use serde::{Deserialize, Serialize};
use validator::Validate;

/// Request schema for attestation options
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct AttestationOptionsRequest {
    #[validate(length(min = 1, max = 255))]
    pub username: String,
    #[validate(length(min = 1, max = 255))]
    pub display_name: String,
    #[serde(default = "default_attestation")]
    pub attestation: String,
    #[serde(default)]
    pub authenticator_selection: Option<AuthenticatorSelection>,
}

fn default_attestation() -> String {
    "direct".to_string()
}

/// Authenticator selection criteria
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct AuthenticatorSelection {
    #[serde(default)]
    pub authenticator_attachment: Option<String>,
    #[serde(default)]
    pub require_resident_key: Option<bool>,
    #[serde(default = "default_user_verification")]
    pub user_verification: String,
}

fn default_user_verification() -> String {
    "preferred".to_string()
}

/// Response schema for attestation options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationOptionsResponse {
    pub challenge: String,
    pub rp: RelyingParty,
    pub user: User,
    pub pub_key_cred_params: Vec<PubKeyCredParam>,
    pub timeout: u64,
    pub attestation: String,
}

/// Relying party information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelyingParty {
    pub name: String,
    pub id: String,
}

/// User information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub name: String,
    pub display_name: String,
}

/// Public key credential parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PubKeyCredParam {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub alg: i32,
}

/// Request schema for attestation result
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct AttestationResultRequest {
    #[validate(length(min = 1))]
    pub id: String,
    #[validate(length(min = 1))]
    pub raw_id: String,
    pub response: AttestationResponse,
    #[serde(rename = "type")]
    pub cred_type: String,
}

/// Attestation response data
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct AttestationResponse {
    #[validate(length(min = 1))]
    pub attestation_object: String,
    #[validate(length(min = 1))]
    pub client_data_json: String,
}

/// Response schema for attestation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResultResponse {
    pub status: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error_message: String,
}

/// Request schema for assertion options
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct AssertionOptionsRequest {
    #[validate(length(min = 1, max = 255))]
    pub username: String,
    #[serde(default = "default_user_verification")]
    pub user_verification: String,
}

/// Response schema for assertion options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionOptionsResponse {
    pub challenge: String,
    pub rp_id: String,
    pub allow_credentials: Vec<AllowCredential>,
    pub timeout: u64,
    pub user_verification: String,
}

/// Allowed credential for assertion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowCredential {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub id: String,
}

/// Request schema for assertion result
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct AssertionResultRequest {
    #[validate(length(min = 1))]
    pub id: String,
    #[validate(length(min = 1))]
    pub raw_id: String,
    pub response: AssertionResponse,
    #[serde(rename = "type")]
    pub cred_type: String,
}

/// Assertion response data
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct AssertionResponse {
    #[validate(length(min = 1))]
    pub authenticator_data: String,
    #[validate(length(min = 1))]
    pub client_data_json: String,
    #[validate(length(min = 1))]
    pub signature: String,
    #[serde(default)]
    pub user_handle: Option<String>,
}

/// Response schema for assertion result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionResultResponse {
    pub status: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error_message: String,
}

/// Error response schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use validator::Validate;

    #[test]
    fn test_attestation_options_request_validation() {
        // Valid request
        let valid_request = AttestationOptionsRequest {
            username: "alice".to_string(),
            display_name: "Alice Smith".to_string(),
            attestation: "direct".to_string(),
            authenticator_selection: None,
        };
        assert!(valid_request.validate().is_ok());

        // Invalid request - empty username
        let invalid_request = AttestationOptionsRequest {
            username: "".to_string(),
            display_name: "Alice Smith".to_string(),
            attestation: "direct".to_string(),
            authenticator_selection: None,
        };
        assert!(invalid_request.validate().is_err());

        // Invalid request - username too long
        let invalid_request = AttestationOptionsRequest {
            username: "a".repeat(256),
            display_name: "Alice Smith".to_string(),
            attestation: "direct".to_string(),
            authenticator_selection: None,
        };
        assert!(invalid_request.validate().is_err());
    }

    #[test]
    fn test_attestation_result_request_validation() {
        // Valid request
        let valid_request = AttestationResultRequest {
            id: "credential_id".to_string(),
            raw_id: "credential_id".to_string(),
            response: AttestationResponse {
                attestation_object: "attestation_data".to_string(),
                client_data_json: "client_data".to_string(),
            },
            cred_type: "public-key".to_string(),
        };
        assert!(valid_request.validate().is_ok());

        // Invalid request - empty id
        let invalid_request = AttestationResultRequest {
            id: "".to_string(),
            raw_id: "credential_id".to_string(),
            response: AttestationResponse {
                attestation_object: "attestation_data".to_string(),
                client_data_json: "client_data".to_string(),
            },
            cred_type: "public-key".to_string(),
        };
        assert!(invalid_request.validate().is_err());
    }

    #[test]
    fn test_serialization() {
        let request = AttestationOptionsRequest {
            username: "alice".to_string(),
            display_name: "Alice Smith".to_string(),
            attestation: "direct".to_string(),
            authenticator_selection: Some(AuthenticatorSelection {
                authenticator_attachment: Some("platform".to_string()),
                require_resident_key: Some(false),
                user_verification: "preferred".to_string(),
            }),
        };

        let json = serde_json::to_string(&request).unwrap();
        let parsed: AttestationOptionsRequest = serde_json::from_str(&json).unwrap();
        
        assert_eq!(parsed.username, request.username);
        assert_eq!(parsed.display_name, request.display_name);
    }
}