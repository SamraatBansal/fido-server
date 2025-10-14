//! Database models

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub attestation_type: String,
    pub aaguid: Option<Vec<u8>>,
    pub sign_count: i64,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub transports: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub id: Uuid,
    pub challenge: Vec<u8>,
    pub user_id: Option<Uuid>,
    pub challenge_type: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub used: bool,
}

// Request/Response DTOs
#[derive(Debug, Deserialize)]
pub struct RegistrationChallengeRequest {
    pub username: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: Option<AuthenticatorSelection>,
    pub attestation: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AuthenticatorSelection {
    #[serde(rename = "requireResidentKey")]
    pub require_resident_key: Option<bool>,
    #[serde(rename = "authenticatorAttachment")]
    pub authenticator_attachment: Option<String>,
    #[serde(rename = "userVerification")]
    pub user_verification: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegistrationChallengeResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
    pub rp: RelyingParty,
    pub user: UserEntity,
    pub challenge: String,
    #[serde(rename = "pubKeyCredParams")]
    pub pub_key_cred_params: Vec<PubKeyCredParam>,
    pub timeout: u32,
    #[serde(rename = "excludeCredentials")]
    pub exclude_credentials: Vec<CredentialDescriptor>,
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: Option<AuthenticatorSelection>,
    pub attestation: String,
}

#[derive(Debug, Serialize)]
pub struct RelyingParty {
    pub name: String,
    pub id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UserEntity {
    pub id: String,
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

#[derive(Debug, Serialize)]
pub struct PubKeyCredParam {
    #[serde(rename = "type")]
    pub type_: String,
    pub alg: i32,
}

#[derive(Debug, Serialize)]
pub struct CredentialDescriptor {
    #[serde(rename = "type")]
    pub type_: String,
    pub id: String,
    pub transports: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct RegistrationVerificationRequest {
    pub credential: PublicKeyCredential,
    #[serde(rename = "sessionData")]
    pub session_data: Option<SessionData>,
}

#[derive(Debug, Deserialize)]
pub struct PublicKeyCredential {
    pub id: String,
    #[serde(rename = "rawId")]
    pub raw_id: Option<String>,
    pub response: AuthenticatorResponse,
    #[serde(rename = "getClientExtensionResults")]
    pub get_client_extension_results: Option<serde_json::Value>,
    #[serde(rename = "type")]
    pub type_: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum AuthenticatorResponse {
    Attestation(AttestationResponse),
    Assertion(AssertionResponse),
}

#[derive(Debug, Deserialize)]
pub struct AttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
}

#[derive(Debug, Deserialize)]
pub struct AssertionResponse {
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    pub signature: String,
    #[serde(rename = "userHandle")]
    pub user_handle: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
}

#[derive(Debug, Deserialize)]
pub struct SessionData {
    pub challenge: String,
    #[serde(rename = "userId")]
    pub user_id: String,
}

#[derive(Debug, Serialize)]
pub struct ServerResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
}

// Authentication DTOs
#[derive(Debug, Deserialize)]
pub struct AuthenticationChallengeRequest {
    pub username: String,
    #[serde(rename = "userVerification")]
    pub user_verification: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuthenticationChallengeResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
    pub challenge: String,
    #[serde(rename = "allowCredentials")]
    pub allow_credentials: Vec<CredentialDescriptor>,
    #[serde(rename = "userVerification")]
    pub user_verification: String,
    pub timeout: u32,
    #[serde(rename = "rpId")]
    pub rp_id: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthenticationVerificationRequest {
    pub credential: PublicKeyCredential,
    #[serde(rename = "sessionData")]
    pub session_data: Option<SessionData>,
}

#[derive(Debug, Serialize)]
pub struct AuthenticationVerificationResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
    #[serde(rename = "userId")]
    pub user_id: Option<String>,
    #[serde(rename = "credentialId")]
    pub credential_id: Option<String>,
    #[serde(rename = "newCounter")]
    pub new_counter: Option<i64>,
}