//! Registration request/response schemas

use serde::{Deserialize, Serialize};

/// Registration start request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationStartRequest {
    pub username: String,
    pub display_name: String,
    pub attestation: Option<String>,
    pub authenticator_selection: Option<AuthenticatorSelection>,
}

/// Authenticator selection criteria
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorSelection {
    pub authenticator_attachment: Option<String>,
    pub require_resident_key: Option<bool>,
    pub user_verification: Option<String>,
}

/// Registration start response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationStartResponse {
    pub challenge_id: String,
    pub credential_creation_options: serde_json::Value,
}

/// Registration finish request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationFinishRequest {
    pub challenge_id: String,
    pub credential: PublicKeyCredential,
}

/// Public key credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredential {
    pub id: String,
    pub raw_id: String,
    pub response: AuthenticatorAttestationResponse,
    #[serde(rename = "type")]
    pub credential_type: String,
}

/// Authenticator attestation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorAttestationResponse {
    pub attestation_object: String,
    pub client_data_json: String,
}

/// Registration finish response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationFinishResponse {
    pub status: String,
    pub credential_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registration_start_request_serialization() {
        let request = RegistrationStartRequest {
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
            attestation: Some("direct".to_string()),
            authenticator_selection: Some(AuthenticatorSelection {
                authenticator_attachment: Some("platform".to_string()),
                require_resident_key: Some(false),
                user_verification: Some("preferred".to_string()),
            }),
        };

        let serialized = serde_json::to_string(&request).unwrap();
        let deserialized: RegistrationStartRequest = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.username, request.username);
        assert_eq!(deserialized.display_name, request.display_name);
    }

    #[test]
    fn test_public_key_credential_serialization() {
        let credential = PublicKeyCredential {
            id: "test-credential-id".to_string(),
            raw_id: "dGVzdC1jcmVkZW50aWFsLWlk".to_string(),
            response: AuthenticatorAttestationResponse {
                attestation_object: "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAEGdhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAEGdhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
                client_data_json: "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidGVzdC1jaGFsbGVuZ2UiLCJvcmlnaW4iOiJodHRwczovL2V4YW1wbGUuY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ==".to_string(),
            },
            credential_type: "public-key".to_string(),
        };

        let serialized = serde_json::to_string(&credential).unwrap();
        let deserialized: PublicKeyCredential = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.id, credential.id);
        assert_eq!(deserialized.credential_type, credential.credential_type);
    }
}