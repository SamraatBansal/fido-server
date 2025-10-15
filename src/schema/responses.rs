use serde::{Deserialize, Serialize};
use super::requests::{AttestationConveyancePreference, AuthenticatorSelectionCriteria, UserVerificationRequirement};

/// Base response structure for all endpoints
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
}

/// Response for /attestation/options endpoint
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttestationOptionsResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rp: Option<RelyingParty>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<UserEntity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(rename = "pubKeyCredParams", skip_serializing_if = "Option::is_none")]
    pub pub_key_cred_params: Option<Vec<PublicKeyCredentialParameters>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    #[serde(rename = "excludeCredentials", skip_serializing_if = "Option::is_none")]
    pub exclude_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
    #[serde(rename = "authenticatorSelection", skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<AttestationConveyancePreference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

/// Response for /assertion/options endpoint
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AssertionOptionsResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    #[serde(rename = "rpId", skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    #[serde(rename = "allowCredentials", skip_serializing_if = "Option::is_none")]
    pub allow_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
    #[serde(rename = "userVerification", skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<UserVerificationRequirement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RelyingParty {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UserEntity {
    pub id: String,
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PublicKeyCredentialParameters {
    #[serde(rename = "type")]
    pub credential_type: String,
    pub alg: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub credential_type: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
}

impl ServerResponse {
    pub fn ok() -> Self {
        Self {
            status: "ok".to_string(),
            error_message: String::new(),
        }
    }

    pub fn error(message: &str) -> Self {
        Self {
            status: "failed".to_string(),
            error_message: message.to_string(),
        }
    }
}

impl AttestationOptionsResponse {
    pub fn ok(
        rp: RelyingParty,
        user: UserEntity,
        challenge: String,
        pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
        timeout: Option<u32>,
        exclude_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
        authenticator_selection: Option<AuthenticatorSelectionCriteria>,
        attestation: Option<AttestationConveyancePreference>,
    ) -> Self {
        Self {
            status: "ok".to_string(),
            error_message: String::new(),
            rp: Some(rp),
            user: Some(user),
            challenge: Some(challenge),
            pub_key_cred_params: Some(pub_key_cred_params),
            timeout,
            exclude_credentials,
            authenticator_selection,
            attestation,
            extensions: None,
        }
    }

    pub fn error(message: &str) -> Self {
        Self {
            status: "failed".to_string(),
            error_message: message.to_string(),
            rp: None,
            user: None,
            challenge: None,
            pub_key_cred_params: None,
            timeout: None,
            exclude_credentials: None,
            authenticator_selection: None,
            attestation: None,
            extensions: None,
        }
    }
}

impl AssertionOptionsResponse {
    pub fn ok(
        challenge: String,
        timeout: Option<u32>,
        rp_id: String,
        allow_credentials: Option<Vec<PublicKeyCredentialDescriptor>>,
        user_verification: Option<UserVerificationRequirement>,
    ) -> Self {
        Self {
            status: "ok".to_string(),
            error_message: String::new(),
            challenge: Some(challenge),
            timeout,
            rp_id: Some(rp_id),
            allow_credentials,
            user_verification,
            extensions: None,
        }
    }

    pub fn error(message: &str) -> Self {
        Self {
            status: "failed".to_string(),
            error_message: message.to_string(),
            challenge: None,
            timeout: None,
            rp_id: None,
            allow_credentials: None,
            user_verification: None,
            extensions: None,
        }
    }
}