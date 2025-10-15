use serde::{Deserialize, Serialize};
use webauthn_rs_proto::{
    AttestationConveyancePreference, AuthenticatorAttachment, 
    UserVerificationPolicy, ResidentKeyPolicy, AuthenticatorTransport,
    PublicKeyCredentialParameters, COSEAlgorithm,
};

// Base response structure
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
}

impl ServerResponse {
    pub fn ok() -> Self {
        Self {
            status: "ok".to_string(),
            error_message: "".to_string(),
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
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsRequest {
    pub username: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "authenticatorSelection", skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    #[serde(default = "default_attestation")]
    pub attestation: AttestationConveyancePreference,
}

fn default_attestation() -> AttestationConveyancePreference {
    AttestationConveyancePreference::None
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticatorSelectionCriteria {
    #[serde(rename = "requireResidentKey", skip_serializing_if = "Option::is_none")]
    pub require_resident_key: Option<bool>,
    #[serde(rename = "authenticatorAttachment", skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
    #[serde(rename = "userVerification", skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<UserVerificationPolicy>,
    #[serde(rename = "residentKey", skip_serializing_if = "Option::is_none")]
    pub resident_key: Option<ResidentKeyPolicy>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsResponse {
    #[serde(flatten)]
    pub base: ServerResponse,
    pub rp: PublicKeyCredentialRpEntity,
    pub user: ServerPublicKeyCredentialUserEntity,
    pub challenge: String,
    #[serde(rename = "pubKeyCredParams")]
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    #[serde(rename = "excludeCredentials", skip_serializing_if = "Option::is_none")]
    pub exclude_credentials: Option<Vec<ServerPublicKeyCredentialDescriptor>>,
    #[serde(rename = "authenticatorSelection", skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    #[serde(default = "default_attestation")]
    pub attestation: AttestationConveyancePreference,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKeyCredentialRpEntity {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialUserEntity {
    pub id: String,
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub type_: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<AuthenticatorTransport>>,
}

// Attestation Result Models
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredential {
    pub id: String,
    #[serde(rename = "rawId", skip_serializing_if = "Option::is_none")]
    pub raw_id: Option<String>,
    pub response: ServerAuthenticatorResponse,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(rename = "getClientExtensionResults", skip_serializing_if = "Option::is_none")]
    pub get_client_extension_results: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ServerAuthenticatorResponse {
    Attestation(ServerAuthenticatorAttestationResponse),
    Assertion(ServerAuthenticatorAssertionResponse),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerAuthenticatorAttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
}

// Authentication (Assertion) Models
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsRequest {
    pub username: String,
    #[serde(rename = "userVerification", skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<UserVerificationPolicy>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsResponse {
    #[serde(flatten)]
    pub base: ServerResponse,
    pub challenge: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    #[serde(rename = "rpId", skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    #[serde(rename = "allowCredentials", skip_serializing_if = "Option::is_none")]
    pub allow_credentials: Option<Vec<ServerPublicKeyCredentialDescriptor>>,
    #[serde(rename = "userVerification", skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<UserVerificationPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerAuthenticatorAssertionResponse {
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    pub signature: String,
    #[serde(rename = "userHandle", skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<String>,
}

// Domain Models for internal use
#[derive(Debug, Clone)]
pub struct User {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct Credential {
    pub id: Vec<u8>,
    pub user_id: String,
    pub public_key: Vec<u8>,
    pub sign_count: u32,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct Challenge {
    pub challenge: Vec<u8>,
    pub user_id: String,
    pub challenge_type: ChallengeType,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub used: bool,
}

#[derive(Debug, Clone)]
pub enum ChallengeType {
    Registration,
    Authentication,
}

impl Default for PublicKeyCredentialParameters {
    fn default() -> Self {
        Self {
            type_: "public-key".to_string(),
            alg: COSEAlgorithm::ES256,
        }
    }
}