//! Registration request and response schemas

use serde::{Deserialize, Serialize};
use validator::Validate;
use crate::schema::common::{UserVerificationPolicy, AttestationConveyancePreference, AuthenticatorSelectionCriteria};

/// Request to start registration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct RegistrationStartRequest {
    /// Username for the user
    #[validate(length(min = 1, max = 255), regex = "USERNAME_REGEX")]
    pub username: String,
    /// Display name for the user
    #[validate(length(min = 1, max = 255))]
    pub display_name: String,
    /// User verification preference
    #[serde(default)]
    pub user_verification: UserVerificationPolicy,
    /// Attestation preference
    #[serde(default)]
    pub attestation: AttestationConveyancePreference,
    /// Authenticator selection criteria
    #[serde(default)]
    pub authenticator_selection: AuthenticatorSelectionCriteria,
    /// Origin URL (for validation)
    #[validate(url)]
    pub origin: Option<String>,
    /// Additional extensions
    #[serde(default)]
    pub extensions: serde_json::Value,
}

/// Response for registration start
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationStartResponse {
    /// Challenge ID for verification
    pub challenge_id: uuid::Uuid,
    /// Public key credential creation options
    pub public_key: webauthn_rs::prelude::PublicKeyCredentialCreationOptions,
}

/// Request to finish registration
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct RegistrationFinishRequest {
    /// Challenge ID from start response
    #[validate(uuid)]
    pub challenge_id: uuid::Uuid,
    /// Credential from authenticator
    pub credential: RegistrationCredential,
}

/// Registration credential from authenticator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationCredential {
    pub id: String,
    pub raw_id: String,
    pub response: AuthenticatorAttestationResponse,
    pub authenticator_attachment: Option<String>,
    pub client_extension_results: serde_json::Value,
    pub type_: String,
}

/// Authenticator attestation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorAttestationResponse {
    pub client_data_json: String,
    pub attestation_object: String,
}

/// Response for successful registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationFinishResponse {
    /// Credential ID
    pub credential_id: String,
    /// User ID
    pub user_id: uuid::Uuid,
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Authenticator information
    pub authenticator_info: AuthenticatorInfo,
}

/// Authenticator information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorInfo {
    /// AAGUID of the authenticator
    pub aaguid: Option<String>,
    /// Signature counter
    pub sign_count: u32,
    /// Whether clone warning is active
    pub clone_warning: bool,
    /// Backup eligible
    pub backup_eligible: bool,
    /// Backup state
    pub backup_state: bool,
}

// Custom validation for username regex
lazy_static::lazy_static! {
    static ref USERNAME_REGEX: regex::Regex = regex::Regex::new(r"^[a-zA-Z0-9._-]+$").unwrap();
}