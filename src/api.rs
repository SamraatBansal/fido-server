use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use webauthn_rs::prelude::*;

// Base server response type
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
}

// Registration request types
#[derive(Deserialize, Debug, Clone)]
pub struct ServerPublicKeyCredentialCreationOptionsRequest {
    pub username: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: Option<AttestationConveyancePreference>,
    pub extensions: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Serialize, Debug, Clone)]
pub struct ServerPublicKeyCredentialCreationOptionsResponse {
    #[serde(flatten)]
    pub base: ServerResponse,
    pub rp: PublicKeyCredentialRpEntity,
    pub user: ServerPublicKeyCredentialUserEntity,
    pub challenge: String,
    #[serde(rename = "pubKeyCredParams")]
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    pub timeout: Option<u32>,
    #[serde(rename = "excludeCredentials")]
    pub exclude_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: Option<AttestationConveyancePreference>,
    pub extensions: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerPublicKeyCredentialUserEntity {
    pub id: String,
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ServerPublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub type_: String,
    pub id: String,
    pub transports: Option<Vec<AuthenticatorTransport>>,
}

// Registration result types
#[derive(Deserialize, Debug, Clone)]
pub struct ServerPublicKeyCredential {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub response: ServerAuthenticatorResponse,
    #[serde(rename = "getClientExtensionResults")]
    pub get_client_extension_results: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum ServerAuthenticatorResponse {
    Attestation(ServerAuthenticatorAttestationResponse),
    Assertion(ServerAuthenticatorAssertionResponse),
}

#[derive(Deserialize, Debug, Clone)]
pub struct ServerAuthenticatorAttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
}

// Authentication request types
#[derive(Deserialize, Debug, Clone)]
pub struct ServerPublicKeyCredentialGetOptionsRequest {
    pub username: String,
    #[serde(rename = "userVerification")]
    pub user_verification: Option<UserVerificationPolicy>,
    pub extensions: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Serialize, Debug, Clone)]
pub struct ServerPublicKeyCredentialGetOptionsResponse {
    #[serde(flatten)]
    pub base: ServerResponse,
    pub challenge: String,
    pub timeout: Option<u32>,
    #[serde(rename = "rpId")]
    pub rp_id: String,
    #[serde(rename = "allowCredentials")]
    pub allow_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
    #[serde(rename = "userVerification")]
    pub user_verification: Option<UserVerificationPolicy>,
    pub extensions: Option<HashMap<String, serde_json::Value>>,
}

// Authentication result types
#[derive(Deserialize, Debug, Clone)]
pub struct ServerAuthenticatorAssertionResponse {
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    pub signature: String,
    #[serde(rename = "userHandle")]
    pub user_handle: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
}

impl ServerResponse {
    pub fn success() -> Self {
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

impl ServerPublicKeyCredentialCreationOptionsResponse {
    pub fn new(
        rp: PublicKeyCredentialRpEntity,
        user: ServerPublicKeyCredentialUserEntity,
        challenge: String,
        pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
        exclude_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
        authenticator_selection: Option<AuthenticatorSelectionCriteria>,
        attestation: Option<AttestationConveyancePreference>,
        timeout: Option<u32>,
        extensions: Option<HashMap<String, serde_json::Value>>,
    ) -> Self {
        Self {
            base: ServerResponse::success(),
            rp,
            user,
            challenge,
            pub_key_cred_params,
            timeout,
            exclude_credentials,
            authenticator_selection,
            attestation,
            extensions,
        }
    }
}

impl ServerPublicKeyCredentialGetOptionsResponse {
    pub fn new(
        challenge: String,
        rp_id: String,
        allow_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
        user_verification: Option<UserVerificationPolicy>,
        timeout: Option<u32>,
        extensions: Option<HashMap<String, serde_json::Value>>,
    ) -> Self {
        Self {
            base: ServerResponse::success(),
            challenge,
            timeout,
            rp_id,
            allow_credentials,
            user_verification,
            extensions,
        }
    }
}