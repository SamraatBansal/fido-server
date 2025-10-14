//! WebAuthn controllers for FIDO2 operations

use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use webauthn_rs_proto::{
    AttestationConveyancePreference, AuthenticatorSelectionCriteria, 
    AuthenticatorTransport, PublicKeyCredentialParameters, 
    UserVerificationPolicy,
};

// Request/Response types matching the Newman API specification

#[derive(Debug, Deserialize)]
pub struct ServerPublicKeyCredentialCreationOptionsRequest {
    pub username: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: Option<AttestationConveyancePreference>,
}

#[derive(Debug, Serialize)]
pub struct ServerResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
}

#[derive(Debug, Serialize)]
pub struct ServerPublicKeyCredentialRpEntity {
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct ServerPublicKeyCredentialUserEntity {
    pub id: String,
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

#[derive(Debug, Serialize)]
pub struct ServerPublicKeyCredentialDescriptor {
    #[serde(rename = "type")]
    pub credential_type: String,
    pub id: String,
    pub transports: Option<Vec<AuthenticatorTransport>>,
}

#[derive(Debug, Serialize)]
pub struct ServerPublicKeyCredentialCreationOptionsResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
    pub rp: ServerPublicKeyCredentialRpEntity,
    pub user: ServerPublicKeyCredentialUserEntity,
    pub challenge: String,
    #[serde(rename = "pubKeyCredParams")]
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    pub timeout: Option<u32>,
    #[serde(rename = "excludeCredentials")]
    pub exclude_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
    #[serde(rename = "authenticatorSelection")]
    pub authenticator_selection: Option<AuthenticatorSelectionCriteria>,
    pub attestation: AttestationConveyancePreference,
}

#[derive(Debug, Deserialize)]
pub struct ServerAuthenticatorAttestationResponse {
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
    #[serde(rename = "attestationObject")]
    pub attestation_object: String,
}

#[derive(Debug, Deserialize)]
pub struct ServerPublicKeyCredential {
    pub id: String,
    pub response: ServerAuthenticatorAttestationResponse,
    #[serde(rename = "getClientExtensionResults")]
    pub get_client_extension_results: Option<serde_json::Value>,
    #[serde(rename = "type")]
    pub credential_type: String,
}

#[derive(Debug, Deserialize)]
pub struct ServerPublicKeyCredentialGetOptionsRequest {
    pub username: String,
    #[serde(rename = "userVerification")]
    pub user_verification: Option<UserVerificationPolicy>,
}

#[derive(Debug, Serialize)]
pub struct ServerPublicKeyCredentialGetOptionsResponse {
    pub status: String,
    #[serde(rename = "errorMessage")]
    pub error_message: String,
    pub challenge: String,
    pub timeout: Option<u32>,
    #[serde(rename = "rpId")]
    pub rp_id: String,
    #[serde(rename = "allowCredentials")]
    pub allow_credentials: Vec<ServerPublicKeyCredentialDescriptor>,
    #[serde(rename = "userVerification")]
    pub user_verification: UserVerificationPolicy,
}

#[derive(Debug, Deserialize)]
pub struct ServerAuthenticatorAssertionResponse {
    #[serde(rename = "authenticatorData")]
    pub authenticator_data: String,
    pub signature: String,
    #[serde(rename = "userHandle")]
    pub user_handle: String,
    #[serde(rename = "clientDataJSON")]
    pub client_data_json: String,
}

#[derive(Debug, Deserialize)]
pub struct ServerPublicKeyCredentialAssertion {
    pub id: String,
    pub response: ServerAuthenticatorAssertionResponse,
    #[serde(rename = "getClientExtensionResults")]
    pub get_client_extension_results: Option<serde_json::Value>,
    #[serde(rename = "type")]
    pub credential_type: String,
}

/// Start registration (attestation/options)
pub async fn attestation_options(
    req: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
) -> Result<HttpResponse> {
    log::info!("Starting registration for user: {}", req.username);

    // Generate a random challenge (base64url encoded)
    let challenge = base64::encode_config(
        &rand::random::<[u8; 32]>(),
        base64::URL_SAFE_NO_PAD,
    );

    // Generate a random user ID (base64url encoded)
    let user_id = base64::encode_config(
        &rand::random::<[u8; 16]>(),
        base64::URL_SAFE_NO_PAD,
    );

    let response = ServerPublicKeyCredentialCreationOptionsResponse {
        status: "ok".to_string(),
        error_message: "".to_string(),
        rp: ServerPublicKeyCredentialRpEntity {
            name: "Example Corporation".to_string(),
        },
        user: ServerPublicKeyCredentialUserEntity {
            id: user_id,
            name: req.username.clone(),
            display_name: req.display_name.clone(),
        },
        challenge,
        pub_key_cred_params: vec![
            PublicKeyCredentialParameters {
                type_: "public-key".to_string(),
                alg: -7, // ES256
            },
            PublicKeyCredentialParameters {
                type_: "public-key".to_string(),
                alg: -257, // RS256
            },
        ],
        timeout: Some(60000),
        exclude_credentials: vec![],
        authenticator_selection: req.authenticator_selection.clone(),
        attestation: req.attestation.unwrap_or(AttestationConveyancePreference::None),
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Finish registration (attestation/result)
pub async fn attestation_result(
    _req: web::Json<ServerPublicKeyCredential>,
) -> Result<HttpResponse> {
    log::info!("Finishing registration");

    // TODO: Implement actual attestation verification
    // For now, return success
    let response = ServerResponse {
        status: "ok".to_string(),
        error_message: "".to_string(),
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Start authentication (assertion/options)
pub async fn assertion_options(
    req: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
) -> Result<HttpResponse> {
    log::info!("Starting authentication for user: {}", req.username);

    // Generate a random challenge (base64url encoded)
    let challenge = base64::encode_config(
        &rand::random::<[u8; 32]>(),
        base64::URL_SAFE_NO_PAD,
    );

    let response = ServerPublicKeyCredentialGetOptionsResponse {
        status: "ok".to_string(),
        error_message: "".to_string(),
        challenge,
        timeout: Some(20000),
        rp_id: "example.com".to_string(),
        allow_credentials: vec![
            ServerPublicKeyCredentialDescriptor {
                credential_type: "public-key".to_string(),
                id: "m7xl_TkTcCe0WcXI2M-4ro9vJAuwcj4m".to_string(),
                transports: None,
            }
        ],
        user_verification: req.user_verification.unwrap_or(UserVerificationPolicy::Preferred),
    };

    Ok(HttpResponse::Ok().json(response))
}

/// Finish authentication (assertion/result)
pub async fn assertion_result(
    _req: web::Json<ServerPublicKeyCredentialAssertion>,
) -> Result<HttpResponse> {
    log::info!("Finishing authentication");

    // TODO: Implement actual assertion verification
    // For now, return success
    let response = ServerResponse {
        status: "ok".to_string(),
        error_message: "".to_string(),
    };

    Ok(HttpResponse::Ok().json(response))
}