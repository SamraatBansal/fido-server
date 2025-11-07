use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use webauthn_rs_proto::{
    AttestationConveyancePreference, AuthenticatorSelectionCriteria,
    UserVerificationPolicy, PubKeyCredParams,
};

// Base response schema
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerResponse {
    pub status: String, // "ok" or "failed"
    #[serde(rename = "errorMessage")]
    pub error_message: String,
}

impl ServerResponse {
    pub fn ok() -> Self {
        Self {
            status: "ok".to_string(),
            error_message: String::new(),
        }
    }

    pub fn failed(message: &str) -> Self {
        Self {
            status: "failed".to_string(),
            error_message: message.to_string(),
        }
    }
}

// Registration response schemas
#[derive(Debug, Serialize, Deserialize)]
pub struct RegistrationBeginResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
    pub rp: RelyingParty,
    pub user: PublicKeyCredentialUserEntity,
    pub challenge: String, // base64url encoded
    #[serde(rename = "pubKeyCredParams")]
    pub pub_key_cred_params: Vec<PubKeyCredParams>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    #[serde(rename = "excludeCredentials")]
    pub exclude_credentials: Vec<PublicKeyCredentialDescriptor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    #[serde(default = "default_attestation")]
    pub attestation: AttestationConveyancePreference,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<HashMap<String, serde_json::Value>>,
}

fn default_attestation() -> AttestationConveyancePreference {
    AttestationConveyancePreference::None
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RelyingParty {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKeyCredentialUserEntity {
    pub id: String, // base64url encoded
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub credential_type: String, // "public-key"
    pub id: String, // base64url encoded credential ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
}

// Authentication response schemas
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticationBeginResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
    pub challenge: String, // base64url encoded
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
    #[serde(rename = "rpId")]
    pub rp_id: String,
    #[serde(rename = "allowCredentials")]
    pub allow_credentials: Vec<PublicKeyCredentialDescriptor>,
    #[serde(rename = "userVerification")]
    pub user_verification: UserVerificationPolicy,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<HashMap<String, serde_json::Value>>,
}