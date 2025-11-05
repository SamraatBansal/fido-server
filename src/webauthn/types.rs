//! FIDO2/WebAuthn data structures

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Base server response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerResponse {
    pub status: String,
    pub error_message: String,
}

impl ServerResponse {
    pub fn success() -> Self {
        Self {
            status: "ok".to_string(),
            error_message: "".to_string(),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            status: "failed".to_string(),
            error_message: message.into(),
        }
    }
}

/// Registration request structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsRequest {
    pub username: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: Option<String>,
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
}

/// Registration response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
    pub rp: PublicKeyCredentialRpEntity,
    pub user: ServerPublicKeyCredentialUserEntity,
    pub challenge: String,
    #[serde(rename = "pubKeyCredParams")]
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    pub timeout: Option<u64>,
    #[serde(rename = "excludeCredentials")]
    pub exclude_credentials: Option<Vec<ServerPublicKeyCredentialDescriptor>>,
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: Option<String>,
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
}

/// Authentication request structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsRequest {
    pub username: String,
    pub user_verification: Option<String>,
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
}

/// Authentication response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
    pub challenge: String,
    pub timeout: Option<u64>,
    #[serde(rename = "rpId")]
    pub rp_id: String,
    #[serde(rename = "allowCredentials")]
    pub allow_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
    #[serde(rename = "userVerification")]
    pub user_verification: Option<String>,
    pub extensions: Option<AuthenticationExtensionsClientInputs>,
}

/// Server public key credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredential {
    pub id: String,
    pub r#type: String,
    pub response: ServerAuthenticatorResponse,
    #[serde(rename = "getClientExtensionResults")]
    pub get_client_extension_results: Option<AuthenticationExtensionsClientOutputs>,
}

/// Server authenticator response (enum for attestation and assertion)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ServerAuthenticatorResponse {
    Attestation(ServerAuthenticatorAttestationResponse),
    Assertion(ServerAuthenticatorAssertionResponse),
}

/// Server authenticator attestation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAuthenticatorAttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    pub attestation_object: String,
}

/// Server authenticator assertion response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerAuthenticatorAssertionResponse {
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    pub signature: String,
    #[serde(rename = "userHandle")]
    pub user_handle: Option<String>,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
}

/// Server public key credential user entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialUserEntity {
    pub id: String,
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

/// Server public key credential descriptor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPublicKeyCredentialDescriptor {
    pub r#type: String,
    pub id: String,
    pub transports: Option<Vec<String>>,
}

/// Public key credential RP entity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialRpEntity {
    pub name: String,
    pub id: Option<String>,
}

/// Public key credential parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyCredentialParameters {
    pub r#type: String,
    pub alg: i32,
}

/// Authenticator selection criteria
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatorSelectionCriteria {
    #[serde(rename = "requireResidentKey")]
    pub require_resident_key: Option<bool>,
    #[serde(rename = "authenticatorAttachment")]
    pub authenticator_attachment: Option<String>,
    #[serde(rename = "userVerification")]
    pub user_verification: Option<String>,
}

/// Authentication extensions client inputs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationExtensionsClientInputs {
    #[serde(flatten)]
    pub extensions: HashMap<String, serde_json::Value>,
}

/// Authentication extensions client outputs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationExtensionsClientOutputs {
    #[serde(flatten)]
    pub extensions: HashMap<String, serde_json::Value>,
}

/// Attestation conveyance preference values
pub const ATTESTATION_NONE: &str = "none";
pub const ATTESTATION_INDIRECT: &str = "indirect";
pub const ATTESTATION_DIRECT: &str = "direct";

/// User verification values
pub const USER_VERIFICATION_REQUIRED: &str = "required";
pub const USER_VERIFICATION_PREFERRED: &str = "preferred";
pub const USER_VERIFICATION_DISCOURAGED: &str = "discouraged";

/// Authenticator attachment values
pub const AUTHENTICATOR_ATTACHMENT_PLATFORM: &str = "platform";
pub const AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM: &str = "cross-platform";

/// Public key credential type
pub const PUBLIC_KEY_CREDENTIAL_TYPE: &str = "public-key";

/// Supported algorithms
pub const ALG_ES256: i32 = -7;
pub const ALG_RS256: i32 = -257;
pub const ALG_EDDSA: i32 = -8;

impl Default for ServerPublicKeyCredentialCreationOptionsRequest {
    fn default() -> Self {
        Self {
            username: String::new(),
            display_name: String::new(),
            authenticator_selection: None,
            attestation: Some(ATTESTATION_NONE.to_string()),
            extensions: None,
        }
    }
}

impl Default for ServerPublicKeyCredentialGetOptionsRequest {
    fn default() -> Self {
        Self {
            username: String::new(),
            user_verification: Some(USER_VERIFICATION_PREFERRED.to_string()),
            extensions: None,
        }
    }
}