//! Registration request/response schemas

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Request to start registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationStartRequest {
    /// Username (email address)
    pub username: String,
    /// Display name for the user
    pub display_name: String,
    /// User verification preference
    #[serde(default = "default_user_verification")]
    pub user_verification: String,
    /// Resident key preference
    #[serde(default = "default_resident_key")]
    pub resident_key: String,
}

fn default_user_verification() -> String {
    "preferred".to_string()
}

fn default_resident_key() -> String {
    "discouraged".to_string()
}

/// Response for registration start
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationStartResponse {
    /// Challenge ID for tracking
    pub challenge_id: String,
    /// Credential creation options
    pub credential_creation_options: CredentialCreationOptions,
}

/// Credential creation options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialCreationOptions {
    /// Challenge (base64url encoded)
    pub challenge: String,
    /// Relying party information
    pub rp: PublicKeyCredentialRpEntity,
    /// User information
    pub user: PublicKeyCredentialUserEntity,
    /// Public key credential parameters
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    /// Timeout in milliseconds
    pub timeout: u32,
    /// Attestation conveyance preference
    pub attestation: String,
    /// Authenticator selection criteria
    pub authenticator_selection: AuthenticatorSelectionCriteria,
}

/// Relying party entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialRpEntity {
    /// RP name
    pub name: String,
    /// RP ID
    pub id: String,
}

/// User entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialUserEntity {
    /// User ID (base64url encoded)
    pub id: String,
    /// Username
    pub name: String,
    /// Display name
    pub display_name: String,
}

/// Public key credential parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialParameters {
    /// Type (always "public-key")
    #[serde(rename = "type")]
    pub cred_type: String,
    /// Algorithm identifier (COSE algorithm)
    pub alg: i32,
}

/// Authenticator selection criteria
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorSelectionCriteria {
    /// User verification requirement
    pub user_verification: String,
    /// Resident key requirement
    pub resident_key: String,
}

/// Request to finish registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationFinishRequest {
    /// Challenge ID
    pub challenge_id: String,
    /// Credential ID
    pub credential_id: String,
    /// Client data JSON (base64url encoded)
    pub client_data_json: String,
    /// Attestation object (base64url encoded)
    pub attestation_object: String,
}

/// Response for registration finish
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationFinishResponse {
    /// Status of the operation
    pub status: String,
    /// Credential ID (base64url encoded)
    pub credential_id: String,
}

impl RegistrationStartRequest {
    /// Validate the request
    pub fn validate(&self) -> Result<(), String> {
        if self.username.is_empty() {
            return Err("Username cannot be empty".to_string());
        }

        if !self.username.contains('@') {
            return Err("Username must be a valid email address".to_string());
        }

        if self.display_name.is_empty() {
            return Err("Display name cannot be empty".to_string());
        }

        if self.display_name.len() > 255 {
            return Err("Display name too long (max 255 characters)".to_string());
        }

        let valid_user_verification = ["required", "preferred", "discouraged"];
        if !valid_user_verification.contains(&self.user_verification.as_str()) {
            return Err("Invalid user verification preference".to_string());
        }

        let valid_resident_key = ["required", "preferred", "discouraged"];
        if !valid_resident_key.contains(&self.resident_key.as_str()) {
            return Err("Invalid resident key preference".to_string());
        }

        Ok(())
    }
}

impl RegistrationFinishRequest {
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

        if self.attestation_object.is_empty() {
            return Err("Attestation object cannot be empty".to_string());
        }

        // Validate base64url encoding
        if let Err(_) = URL_SAFE_NO_PAD.decode(&self.credential_id) {
            return Err("Invalid credential ID encoding".to_string());
        }

        if let Err(_) = URL_SAFE_NO_PAD.decode(&self.client_data_json) {
            return Err("Invalid client data JSON encoding".to_string());
        }

        if let Err(_) = URL_SAFE_NO_PAD.decode(&self.attestation_object) {
            return Err("Invalid attestation object encoding".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registration_start_request_validation_success() {
        let request = RegistrationStartRequest {
            username: "test@example.com".to_string(),
            display_name: "Test User".to_string(),
            user_verification: "preferred".to_string(),
            resident_key: "discouraged".to_string(),
        };

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_registration_start_request_invalid_username() {
        let request = RegistrationStartRequest {
            username: "invalid-email".to_string(),
            display_name: "Test User".to_string(),
            user_verification: "preferred".to_string(),
            resident_key: "discouraged".to_string(),
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_registration_start_request_empty_display_name() {
        let request = RegistrationStartRequest {
            username: "test@example.com".to_string(),
            display_name: "".to_string(),
            user_verification: "preferred".to_string(),
            resident_key: "discouraged".to_string(),
        };

        assert!(request.validate().is_err());
    }

    #[test]
    fn test_registration_finish_request_validation_success() {
        let request = RegistrationFinishRequest {
            challenge_id: "challenge-123".to_string(),
            credential_id: URL_SAFE_NO_PAD.encode(&[1, 2, 3, 4]),
            client_data_json: URL_SAFE_NO_PAD.encode(b"{}"),
            attestation_object: URL_SAFE_NO_PAD.encode(&[5, 6, 7, 8]),
        };

        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_registration_finish_request_invalid_encoding() {
        let request = RegistrationFinishRequest {
            challenge_id: "challenge-123".to_string(),
            credential_id: "invalid-base64!".to_string(),
            client_data_json: URL_SAFE_NO_PAD.encode(b"{}"),
            attestation_object: URL_SAFE_NO_PAD.encode(&[5, 6, 7, 8]),
        };

        assert!(request.validate().is_err());
    }
}