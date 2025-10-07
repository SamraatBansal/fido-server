//! Authentication request/response schemas

use serde::{Deserialize, Serialize};

/// Authentication start request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationStartRequest {
    pub username: String,
    pub user_verification: Option<String>,
}

/// Authentication start response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationStartResponse {
    pub challenge_id: String,
    pub credential_request_options: serde_json::Value,
}

/// Authentication finish request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationFinishRequest {
    pub challenge_id: String,
    pub credential: PublicKeyCredentialAssertion,
}

/// Public key credential assertion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialAssertion {
    pub id: String,
    pub raw_id: String,
    pub response: AuthenticatorAssertionResponse,
    #[serde(rename = "type")]
    pub credential_type: String,
}

/// Authenticator assertion response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorAssertionResponse {
    pub authenticator_data: String,
    pub client_data_json: String,
    pub signature: String,
    pub user_handle: Option<String>,
}

/// Authentication finish response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationFinishResponse {
    pub status: String,
    pub user_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authentication_start_request_serialization() {
        let request = AuthenticationStartRequest {
            username: "test@example.com".to_string(),
            user_verification: Some("required".to_string()),
        };

        let serialized = serde_json::to_string(&request).unwrap();
        let deserialized: AuthenticationStartRequest = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.username, request.username);
        assert_eq!(deserialized.user_verification, request.user_verification);
    }

    #[test]
    fn test_public_key_credential_assertion_serialization() {
        let assertion = PublicKeyCredentialAssertion {
            id: "test-credential-id".to_string(),
            raw_id: "dGVzdC1jcmVkZW50aWFsLWlk".to_string(),
            response: AuthenticatorAssertionResponse {
                authenticator_data: "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAAQ==".to_string(),
                client_data_json: "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoidGVzdC1jaGFsbGVuZ2UiLCJvcmlnaW4iOiJodHRwczovL2V4YW1wbGUuY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ==".to_string(),
                signature: "MEUCIQCdwBCYm5PjT_Q-wwOuyRvEYR_8f2vHqGhJp3b7b8jwIgYKqL8xRf9N8f2vHqGhJp3b7b8jwYKqL8xRf9N8f2vHqGhJp3b7b8jw".to_string(),
                user_handle: Some("dGVzdC11c2VyLWhhbmRsZQ==".to_string()),
            },
            credential_type: "public-key".to_string(),
        };

        let serialized = serde_json::to_string(&assertion).unwrap();
        let deserialized: PublicKeyCredentialAssertion = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.id, assertion.id);
        assert_eq!(deserialized.credential_type, assertion.credential_type);
        assert!(deserialized.response.user_handle.is_some());
    }
}