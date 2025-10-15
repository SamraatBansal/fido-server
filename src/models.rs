use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Base response type for all FIDO2 API responses
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

    pub fn failed(message: &str) -> Self {
        Self {
            status: "failed".to_string(),
            error_message: message.to_string(),
        }
    }
}

// Registration (Attestation) Models

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttestationOptionsRequest {
    pub username: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "authenticatorSelection", skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    #[serde(default = "default_attestation")]
    pub attestation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthenticatorSelectionCriteria {
    #[serde(rename = "requireResidentKey", skip_serializing_if = "Option::is_none")]
    pub require_resident_key: Option<bool>,
    #[serde(rename = "authenticatorAttachment", skip_serializing_if = "Option::is_none")]
    pub authenticator_attachment: Option<String>,
    #[serde(rename = "userVerification", skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttestationOptionsResponse {
    #[serde(flatten)]
    pub base: ServerResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rp: Option<RelyingParty>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<UserEntity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(rename = "pubKeyCredParams", skip_serializing_if = "Option::is_none")]
    pub pub_key_cred_params: Option<Vec<PubKeyCredParam>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    #[serde(rename = "excludeCredentials", skip_serializing_if = "Option::is_none")]
    pub exclude_credentials: Option<Vec<CredentialDescriptor>>,
    #[serde(rename = "authenticatorSelection", skip_serializing_if = "Option::is_none")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<String>,
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
pub struct PubKeyCredParam {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub alg: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CredentialDescriptor {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transports: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttestationResultRequest {
    pub id: String,
    #[serde(rename = "rawId", skip_serializing_if = "Option::is_none")]
    pub raw_id: Option<String>,
    pub response: AttestationResponse,
    #[serde(rename = "getClientExtensionResults", skip_serializing_if = "Option::is_none")]
    pub get_client_extension_results: Option<HashMap<String, serde_json::Value>>,
    #[serde(rename = "type")]
    pub cred_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
}

// Authentication (Assertion) Models

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AssertionOptionsRequest {
    pub username: String,
    #[serde(rename = "userVerification", skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AssertionOptionsResponse {
    #[serde(flatten)]
    pub base: ServerResponse,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
    #[serde(rename = "rpId", skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    #[serde(rename = "allowCredentials", skip_serializing_if = "Option::is_none")]
    pub allow_credentials: Option<Vec<CredentialDescriptor>>,
    #[serde(rename = "userVerification", skip_serializing_if = "Option::is_none")]
    pub user_verification: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AssertionResultRequest {
    pub id: String,
    #[serde(rename = "rawId", skip_serializing_if = "Option::is_none")]
    pub raw_id: Option<String>,
    pub response: AssertionResponse,
    #[serde(rename = "getClientExtensionResults", skip_serializing_if = "Option::is_none")]
    pub get_client_extension_results: Option<HashMap<String, serde_json::Value>>,
    #[serde(rename = "type")]
    pub cred_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AssertionResponse {
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    pub signature: String,
    #[serde(rename = "userHandle", skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<String>,
}

// Helper functions
fn default_attestation() -> String {
    "none".to_string()
}

// Test helper implementations
#[cfg(test)]
impl AttestationOptionsRequest {
    pub fn new(username: &str, display_name: &str) -> Self {
        Self {
            username: username.to_string(),
            display_name: display_name.to_string(),
            authenticator_selection: None,
            attestation: default_attestation(),
        }
    }

    pub fn with_authenticator_selection(mut self, selection: AuthenticatorSelectionCriteria) -> Self {
        self.authenticator_selection = Some(selection);
        self
    }

    pub fn with_attestation(mut self, attestation: &str) -> Self {
        self.attestation = attestation.to_string();
        self
    }
}

#[cfg(test)]
impl AuthenticatorSelectionCriteria {
    pub fn new() -> Self {
        Self {
            require_resident_key: None,
            authenticator_attachment: None,
            user_verification: None,
        }
    }

    pub fn with_resident_key(mut self, required: bool) -> Self {
        self.require_resident_key = Some(required);
        self
    }

    pub fn with_attachment(mut self, attachment: &str) -> Self {
        self.authenticator_attachment = Some(attachment.to_string());
        self
    }

    pub fn with_user_verification(mut self, verification: &str) -> Self {
        self.user_verification = Some(verification.to_string());
        self
    }
}

#[cfg(test)]
impl AssertionOptionsRequest {
    pub fn new(username: &str) -> Self {
        Self {
            username: username.to_string(),
            user_verification: None,
        }
    }

    pub fn with_user_verification(mut self, verification: &str) -> Self {
        self.user_verification = Some(verification.to_string());
        self
    }
}