//! Authentication request/response schemas

use serde::{Deserialize, Serialize};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Request to start authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationStartRequest {
    /// Username (email address)
    pub username: String,
    /// User verification preference
    #[serde(default = "default_user_verification")]
    pub user_verification: String,
}

fn default_user_verification() -> String {
    "preferred".to_string()
}

/// Response for authentication start
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationStartResponse {
    /// Challenge ID for tracking
    pub challenge_id: String,
    /// Credential request options
    pub credential_request_options: CredentialRequestOptions,
}

/// Credential request options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRequestOptions {
    /// Challenge (base64url encoded)
    pub challenge: String,
    /// Allowed credentials
    pub allow_credentials: Vec<AllowCredentials>,
    /// User verification requirement
    pub user_verification: String,
    /// Timeout in milliseconds
    pub timeout: u32,
}

/// Allow credentials structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowCredentials {
    /// Type (always "public-key")
    #[serde(rename = "type")]
    pub cred_type: String,
    /// Credential ID (base64url encoded)
    pub id: String,
    /// Supported transports
    pub transports: Option<Vec<String>>,
}

/// Request to finish authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationFinishRequest {
    /// Challenge ID
    pub challenge_id: String,
    /// Credential ID
    pub credential_id: String,
    /// Client data JSON (base64url encoded)
    pub client_data_json: String,
    /// Authenticator data (base64url encoded)
    pub authenticator_data: String,
    /// Signature (base64url encoded)
    pub signature: String,
    /// User handle (base64url encoded, optional)
    pub user_handle: Option<String>,
}

/// Response for authentication finish
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationFinishResponse {
    /// Status of the operation
    pub status: String,
    /// User ID
    pub user_id: String,
}

impl AuthenticationStartRequest {
    /// Validate the request
    pub fn validate(&self) -> Result<(), String> {
        if self.username.is_empty() {
            return Err("Username cannot be empty".to_string());
        }

        if !self.username.contains('@') {
            return Err("Username must be a valid email address".to_string());
        }

        let valid_user_verification = ["required", "preferred", "discouraged"];
        if !valid_user_verification.contains(&self.user_verification.as_str()) {
            return Err("Invalid user verification preference".to_string());
        }

        Ok(())
    }
}

impl AuthenticationFinishRequest {
    /// Validate the request
    pub fn validate(&self) -> Result<(), String> {
        if self.challenge_id.is_empty() {
            return Err("Challenge ID cannot be empty".to_string());
        }

        if self.credential_id.is_empty() {
            return Err("Credential ID cannot be empty".to_string());
        }

        if self.client_data_json.is_empty() {
            return Err("Client data JSON cannot be empty".to_string());
        }

        if self.authenticator_data.is_empty() {
            return Err("Authenticator data cannot be empty".to_string());
        }

        if self.signature.is_empty() {
            return Err("Signature cannot be empty".to_string());
        }

        // Validate base64url encoding
        if let Err(_) = URL_SAFE_NO_PAD.decode(&self.credential_id) {
            return Err("Invalid credential ID encoding".to_string());
        }

        if let Err(_) = URL_SAFE_NO_PAD.decode(&self.client_data_json) {
            return Err("Invalid client data JSON encoding".to_string());
        }

        if let Err(_) = URL_SAFE_NO_PAD.decode(&self.authenticator_data) {
            return Err("Invalid authenticator data encoding".to_string());
        }

        if let Err(_) = URL_SAFE_NO_PAD.decode(&self.signature) {
            return Err("Invalid signature encoding".to_string());
        }

        // Validate user handle if present
        if let Some(ref user_handle) = self.user_handle {
            if !user_handle.is_empty() {
                if let Err(_) = URL_SAFE_NO_PAD.decode(user_handle) {
                    return Err("Invalid user handle encoding".to_string());
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authentication_start_request_validation_success() {
        let request = AuthenticationStartRequest {
            username: "test@example.com".to_string(),
            user_verification: "preferred".to_string(),
        };

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_authentication_start_request_invalid_username() {
        let request = AuthenticationStartRequest {
            username: "invalid-email".to_string(),
            user_verification: "preferred".to_string(),
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_authentication_finish_request_validation_success() {
        let request = AuthenticationFinishRequest {
            challenge_id: "challenge-123".to_string(),
            credential_id: URL_SAFE_NO_PAD.encode(&[1, 2, 3, 4]),
            client_data_json: URL_SAFE_NO_PAD.encode(b"{}"),
            authenticator_data: URL_SAFE_NO_PAD.encode(&[5, 6, 7, 8]),
            signature: URL_SAFE_NO_PAD.encode(&[9, 10, 11, 12]),
            user_handle: Some(URL_SAFE_NO_PAD.encode(&[13, 14, 15, 16])),
        };

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_authentication_finish_request_invalid_encoding() {
        let request = AuthenticationFinishRequest {
            challenge_id: "challenge-123".to_string(),
            credential_id: "invalid-base64!".to_string(),
            client_data_json: URL_SAFE_NO_PAD.encode(b"{}"),
            authenticator_data: URL_SAFE_NO_PAD.encode(&[5, 6, 7, 8]),
            signature: URL_SAFE_NO_PAD.encode(&[9, 10, 11, 12]),
            user_handle: None,
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_allow_credentials_serialization() {
        let allow_creds = AllowCredentials {
            cred_type: "public-key".to_string(),
            id: URL_SAFE_NO_PAD.encode(&[1, 2, 3, 4]),
            transports: Some(vec!["usb".to_string(), "nfc".to_string()]),
        };

        let serialized = serde_json::to_string(&allow_creds).unwrap();
        let deserialized: AllowCredentials = serde_json::from_str(&serialized).unwrap();

        assert_eq!(allow_creds.cred_type, deserialized.cred_type);
        assert_eq!(allow_creds.id, deserialized.id);
        assert_eq!(allow_creds.transports, deserialized.transports);
    }
}