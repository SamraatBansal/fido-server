use serde::{Deserialize, Serialize};
use super::common::*;

/// Request for /assertion/options endpoint
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsRequest {
    pub username: String,
    #[serde(rename = "userVerification", skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<String>, // "required" | "preferred" | "discouraged"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
}

/// Response for /assertion/options endpoint
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsResponse {
    #[serde(flatten)]
    pub base: ServerResponse,
    pub challenge: String, // base64url encoded
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    #[serde(rename = "rpId")]
    pub rp_id: String,
    #[serde(rename = "allowCredentials", default)]
    pub allow_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
    #[serde(rename = "userVerification", skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
}

/// Authenticator Assertion Response (server format with base64url encoding)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerAuthenticatorAssertionResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String, // base64url encoded
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String, // base64url encoded
    pub signature: String, // base64url encoded
    #[serde(rename = "userHandle", skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<String>, // base64url encoded, can be empty string
}

/// Public Key Credential for assertion result
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialAssertion {
    pub id: String, // base64url encoded credential ID
    #[serde(rename = "rawId", skip_serializing_if = "Option::is_none")]
    pub raw_id: Option<String>, // base64url encoded raw ID
    #[serde(rename = "type")]
    pub credential_type: String, // "public-key"
    pub response: ServerAuthenticatorAssertionResponse,
    #[serde(rename = "getClientExtensionResults", default)]
    pub get_client_extension_results: AuthenticationExtensionsClientOutputs,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
}

/// Request for /assertion/result endpoint
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssertionResultRequest {
    #[serde(flatten)]
    pub credential: ServerPublicKeyCredentialAssertion,
}

/// Response for /assertion/result endpoint
pub type AssertionResultResponse = ServerResponse;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_assertion_options_request_deserialization() {
        let json = r#"{
            "username": "johndoe@example.com",
            "userVerification": "required"
        }"#;

        let request: ServerPublicKeyCredentialGetOptionsRequest = 
            serde_json::from_str(json).unwrap();
        
        assert_eq!(request.username, "johndoe@example.com");
        assert_eq!(request.user_verification, Some("required".to_string()));
    }

    #[test]
    fn test_assertion_options_request_minimal() {
        let json = r#"{
            "username": "johndoe@example.com"
        }"#;

        let request: ServerPublicKeyCredentialGetOptionsRequest = 
            serde_json::from_str(json).unwrap();
        
        assert_eq!(request.username, "johndoe@example.com");
        assert_eq!(request.user_verification, None);
    }

    #[test]
    fn test_assertion_options_response_serialization() {
        let response = ServerPublicKeyCredentialGetOptionsResponse {
            base: ServerResponse::ok(),
            challenge: "6283u0svT-YIF3pSolzkQHStwkJCaLKx".to_string(),
            timeout: Some(20000),
            rp_id: "example.com".to_string(),
            allow_credentials: vec![
                ServerPublicKeyCredentialDescriptor {
                    credential_type: "public-key".to_string(),
                    id: "m7xl_TkTcCe0WcXI2M-4ro9vJAuwcj4m".to_string(),
                    transports: None,
                }
            ],
            user_verification: Some("required".to_string()),
            extensions: None,
        };

        let json = serde_json::to_string_pretty(&response).unwrap();
        assert!(json.contains("\"status\":\"ok\""));
        assert!(json.contains("\"challenge\":\"6283u0svT-YIF3pSolzkQHStwkJCaLKx\""));
        assert!(json.contains("\"rpId\":\"example.com\""));
        assert!(json.contains("\"allowCredentials\""));
        assert!(json.contains("\"userVerification\":\"required\""));
    }

    #[test]
    fn test_assertion_result_request_deserialization() {
        let json = r#"{
            "id":"LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA",
            "response":{
                "authenticatorData":"SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAA",
                "signature":"MEYCIQCv7EqsBRtf2E4o_BjzZfBwNpP8fLjd5y6TUOLWt5l9DQIhANiYig9newAJZYTzG1i5lwP-YQk9uXFnnDaHnr2yCKXL",
                "userHandle":"",
                "clientDataJSON":"eyJjaGFsbGVuZ2UiOiJ4ZGowQ0JmWDY5MnFzQVRweTBrTmM4NTMzSmR2ZExVcHFZUDh3RFRYX1pFIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9"
            },
            "getClientExtensionResults": {},
            "type":"public-key"
        }"#;

        let request: AssertionResultRequest = serde_json::from_str(json).unwrap();
        
        assert_eq!(request.credential.id, "LFdoCFJTyB82ZzSJUHc-c72yraRc_1mPvGX8ToE8su39xX26Jcqd31LUkKOS36FIAWgWl6itMKqmDvruha6ywA");
        assert_eq!(request.credential.credential_type, "public-key");
        assert!(!request.credential.response.authenticator_data.is_empty());
        assert!(!request.credential.response.signature.is_empty());
        assert!(!request.credential.response.client_data_json.is_empty());
        assert_eq!(request.credential.response.user_handle, Some("".to_string()));
    }

    #[test]
    fn test_assertion_result_request_with_user_handle() {
        let json = r#"{
            "id":"test-credential-id",
            "response":{
                "authenticatorData":"test-auth-data",
                "signature":"test-signature",
                "userHandle":"dGVzdC11c2VyLWhhbmRsZQ",
                "clientDataJSON":"test-client-data"
            },
            "type":"public-key"
        }"#;

        let request: AssertionResultRequest = serde_json::from_str(json).unwrap();
        
        assert_eq!(request.credential.response.user_handle, Some("dGVzdC11c2VyLWhhbmRsZQ".to_string()));
    }

    #[test]
    fn test_assertion_result_request_without_user_handle() {
        let json = r#"{
            "id":"test-credential-id",
            "response":{
                "authenticatorData":"test-auth-data",
                "signature":"test-signature",
                "clientDataJSON":"test-client-data"
            },
            "type":"public-key"
        }"#;

        let request: AssertionResultRequest = serde_json::from_str(json).unwrap();
        
        assert_eq!(request.credential.response.user_handle, None);
    }

    #[test]
    fn test_missing_required_fields_assertion() {
        let json = r#"{
            "response":{
                "authenticatorData":"test-auth-data",
                "signature":"test-signature",
                "clientDataJSON":"test-client-data"
            },
            "type":"public-key"
        }"#;

        let request: Result<AssertionResultRequest, _> = serde_json::from_str(json);
        assert!(request.is_err());
    }

    #[test]
    fn test_empty_username_assertion_options() {
        let json = r#"{
            "username": ""
        }"#;

        let request: Result<ServerPublicKeyCredentialGetOptionsRequest, _> = 
            serde_json::from_str(json);
        
        // Should deserialize but validation should happen at service layer
        assert!(request.is_ok());
        let req = request.unwrap();
        assert_eq!(req.username, "");
    }
}