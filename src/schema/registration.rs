//! Registration request/response schemas

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// User verification policy
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum UserVerificationPolicy {
    /// User verification is discouraged
    Discouraged,
    /// User verification is preferred
    Preferred,
    /// User verification is required
    Required,
}

impl Default for UserVerificationPolicy {
    fn default() -> Self {
        Self::Preferred
    }
}

/// Attestation conveyance preference
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum AttestationConveyancePreference {
    /// No attestation
    None,
    /// Indirect attestation
    Indirect,
    /// Direct attestation
    Direct,
    /// Enterprise attestation
    Enterprise,
}

impl Default for AttestationConveyancePreference {
    fn default() -> Self {
        Self::None
    }
}

/// Authenticator attachment
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum AuthenticatorAttachment {
    /// Cross-platform authenticator
    CrossPlatform,
    /// Platform authenticator
    Platform,
}

/// Resident key requirement
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ResidentKeyRequirement {
    /// Resident key discouraged
    Discouraged,
    /// Resident key preferred
    Preferred,
    /// Resident key required
    Required,
}

impl Default for ResidentKeyRequirement {
    fn default() -> Self {
        Self::Discouraged
    }
}

/// Authenticator selection criteria
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthenticatorSelection {
    /// Authenticator attachment
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
    /// Resident key requirement
    pub resident_key: ResidentKeyRequirement,
    /// User verification requirement
    pub user_verification: UserVerificationPolicy,
}

impl Default for AuthenticatorSelection {
    fn default() -> Self {
        Self {
            authenticator_attachment: None,
            resident_key: ResidentKeyRequirement::default(),
            user_verification: UserVerificationPolicy::default(),
        }
    }
}

/// Public key credential parameters
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PublicKeyCredentialParameters {
    /// Credential type
    #[serde(rename = "type")]
    pub cred_type: String,
    /// Algorithm identifier
    pub alg: i32,
}

impl PublicKeyCredentialParameters {
    /// Create ES256 parameters
    pub fn es256() -> Self {
        Self {
            cred_type: "public-key".to_string(),
            alg: -7, // ES256
        }
    }

    /// Create Ed25519 parameters
    pub fn ed25519() -> Self {
        Self {
            cred_type: "public-key".to_string(),
            alg: -8, // Ed25519
        }
    }

    /// Create RS256 parameters
    pub fn rs256() -> Self {
        Self {
            cred_type: "public-key".to_string(),
            alg: -257, // RS256
        }
    }
}

/// Relying party entity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RelyingParty {
    /// RP name
    pub name: String,
    /// RP ID
    pub id: String,
}

/// User entity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct User {
    /// User ID (base64url encoded)
    pub id: String,
    /// Username
    pub name: String,
    /// Display name
    pub display_name: String,
}

/// Public key credential creation options
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PublicKeyCredentialCreationOptions {
    /// Challenge (base64url encoded)
    pub challenge: String,
    /// Relying party
    pub rp: RelyingParty,
    /// User
    pub user: User,
    /// Public key credential parameters
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    /// Timeout in milliseconds
    pub timeout: u32,
    /// Attestation conveyance preference
    pub attestation: AttestationConveyancePreference,
    /// Authenticator selection criteria
    pub authenticator_selection: AuthenticatorSelection,
    /// Extensions
    pub extensions: Option<HashMap<String, serde_json::Value>>,
}

/// Registration start request
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RegistrationStartRequest {
    /// Username (email address)
    pub username: String,
    /// Display name
    pub display_name: String,
    /// User verification policy
    #[serde(default = "UserVerificationPolicy::default")]
    pub user_verification: UserVerificationPolicy,
    /// Attestation conveyance preference
    #[serde(default = "AttestationConveyancePreference::default")]
    pub attestation: AttestationConveyancePreference,
    /// Authenticator attachment
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
    /// Resident key requirement
    #[serde(default = "ResidentKeyRequirement::default")]
    pub resident_key: ResidentKeyRequirement,
}

/// Registration start response
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RegistrationStartResponse {
    /// Public key credential creation options
    #[serde(rename = "publicKey")]
    pub public_key: PublicKeyCredentialCreationOptions,
}

/// Registration finish request
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RegistrationFinishRequest {
    /// Credential ID
    pub id: String,
    /// Raw ID
    #[serde(rename = "rawId")]
    pub raw_id: String,
    /// Response data
    pub response: RegistrationFinishResponseData,
    /// Authenticator attachment
    #[serde(rename = "authenticatorAttachment")]
    pub authenticator_attachment: Option<String>,
    /// Client extension results
    #[serde(rename = "clientExtensionResults")]
    pub client_extension_results: Option<HashMap<String, serde_json::Value>>,
    /// Type
    #[serde(rename = "type")]
    pub cred_type: String,
}

/// Registration finish response data
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RegistrationFinishResponseData {
    /// Client data JSON
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    /// Attestation object
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
    /// Transports
    pub transports: Option<Vec<String>>,
}

/// Registration finish response
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RegistrationFinishResponse {
    /// Status
    pub status: String,
    /// Credential ID
    #[serde(rename = "credentialId")]
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
            user_verification: UserVerificationPolicy::Preferred,
            attestation: AttestationConveyancePreference::Direct,
            authenticator_attachment: Some(AuthenticatorAttachment::CrossPlatform),
            resident_key: ResidentKeyRequirement::Preferred,
        };

        let serialized = serde_json::to_string(&request).unwrap();
        let deserialized: RegistrationStartRequest = serde_json::from_str(&serialized).unwrap();

        assert_eq!(request, deserialized);
    }

    #[test]
    fn test_public_key_credential_parameters() {
        let es256 = PublicKeyCredentialParameters::es256();
        assert_eq!(es256.alg, -7);
        assert_eq!(es256.cred_type, "public-key");

        let ed25519 = PublicKeyCredentialParameters::ed25519();
        assert_eq!(ed25519.alg, -8);

        let rs256 = PublicKeyCredentialParameters::rs256();
        assert_eq!(rs256.alg, -257);
    }

    #[test]
    fn test_authenticator_selection_default() {
        let selection = AuthenticatorSelection::default();
        assert_eq!(selection.resident_key, ResidentKeyRequirement::Discouraged);
        assert_eq!(selection.user_verification, UserVerificationPolicy::Preferred);
        assert!(selection.authenticator_attachment.is_none());
    }

    #[test]
    fn test_user_verification_policy_default() {
        let policy = UserVerificationPolicy::default();
        assert_eq!(policy, UserVerificationPolicy::Preferred);
    }

    #[test]
    fn test_attestation_conveyance_preference_default() {
        let preference = AttestationConveyancePreference::default();
        assert_eq!(preference, AttestationConveyancePreference::None);
    }

    #[test]
    fn test_registration_finish_request() {
        let request = RegistrationFinishRequest {
            id: "credential-id".to_string(),
            raw_id: "raw-id".to_string(),
            response: RegistrationFinishResponseData {
                client_data_json: "client-data".to_string(),
                attestation_object: "attestation-object".to_string(),
                transports: Some(vec!["usb".to_string(), "nfc".to_string()]),
            },
            authenticator_attachment: Some("cross-platform".to_string()),
            client_extension_results: None,
            cred_type: "public-key".to_string(),
        };

        assert_eq!(request.id, "credential-id");
        assert_eq!(request.response.client_data_json, "client-data");
        assert_eq!(request.cred_type, "public-key");
    }
}