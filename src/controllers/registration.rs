//! WebAuthn registration controller

use actix_web::{post, web, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use base64urlsafedata::Base64UrlSafeData;

#[derive(Debug, Deserialize)]
pub struct RegistrationStartRequest {
    pub username: String,
    pub display_name: String,
}

#[derive(Debug, Serialize)]
pub struct RegistrationStartResponse {
    pub challenge: String,
    pub user: User,
    pub rp: RelyingParty,
    pub pub_key_cred_params: Vec<PubKeyCredParams>,
    pub timeout: u64,
    pub attestation: String,
    pub authenticator_selection: AuthenticatorSelection,
}

#[derive(Debug, Serialize)]
pub struct User {
    pub id: String,
    pub name: String,
    pub display_name: String,
}

#[derive(Debug, Serialize)]
pub struct RelyingParty {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct PubKeyCredParams {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub alg: i64,
}

#[derive(Debug, Serialize)]
pub struct AuthenticatorSelection {
    pub user_verification: String,
}

#[derive(Debug, Deserialize)]
pub struct RegistrationFinishRequest {
    pub credential: serde_json::Value,
    pub session: String,
}

#[derive(Debug, Serialize)]
pub struct RegistrationFinishResponse {
    pub credential_id: String,
    pub user_id: String,
}

#[post("/webauthn/register/start")]
pub async fn start_registration(
    req: web::Json<RegistrationStartRequest>,
) -> Result<HttpResponse> {
    let mock_response = RegistrationStartResponse {
        challenge: "mock_challenge_12345".to_string(),
        user: User {
            id: base64::encode(req.username.as_bytes()),
            name: req.username.clone(),
            display_name: req.display_name.clone(),
        },
        rp: RelyingParty {
            id: "localhost".to_string(),
            name: "FIDO Test Server".to_string(),
        },
        pub_key_cred_params: vec![
            PubKeyCredParams {
                cred_type: "public-key".to_string(),
                alg: -7, // ES256
            },
        ],
        timeout: 60000,
        attestation: "none".to_string(),
        authenticator_selection: AuthenticatorSelection {
            user_verification: "preferred".to_string(),
        },
    };

    Ok(HttpResponse::Ok().json(mock_response))
}

#[post("/webauthn/register/finish")]
pub async fn finish_registration(
    _req: web::Json<RegistrationFinishRequest>,
) -> Result<HttpResponse> {
    let mock_response = RegistrationFinishResponse {
        credential_id: "mock_credential_id_12345".to_string(),
        user_id: "mock_user_id_12345".to_string(),
    };

    Ok(HttpResponse::Created().json(mock_response))
}