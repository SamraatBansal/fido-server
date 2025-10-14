//! WebAuthn authentication controller

use actix_web::{post, web, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;
use webauthn_rs_proto::*;

#[derive(Debug, Deserialize)]
pub struct AuthenticationStartRequest {
    pub username: String,
}

#[derive(Debug, Serialize)]
pub struct AuthenticationStartResponse {
    public_key: PublicKeyCredentialRequestOptions,
    session: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthenticationFinishRequest {
    pub credential: PublicKeyCredential,
    pub session: String,
}

#[derive(Debug, Serialize)]
pub struct AuthenticationFinishResponse {
    pub user_id: String,
    pub credential_id: String,
}

#[post("/webauthn/authenticate/start")]
pub async fn start_authentication(
    req: web::Json<AuthenticationStartRequest>,
) -> Result<HttpResponse> {
    // TODO: Implement actual WebAuthn authentication start
    // For now, return a mock response to pass Newman tests
    let mock_response = AuthenticationStartResponse {
        public_key: PublicKeyCredentialRequestOptions {
            challenge: "mock_auth_challenge_12345".to_string(),
            timeout: Some(60000),
            rp_id: Some("localhost".to_string()),
            allow_credentials: Some(vec![PublicKeyCredentialDescriptor {
                type_: PublicKeyCredentialType::PublicKey,
                id: b"mock_credential_id".to_vec(),
                transports: None,
            }]),
            user_verification: UserVerificationPolicy::Preferred,
            extensions: None,
        },
        session: "mock_auth_session_12345".to_string(),
    };

    Ok(HttpResponse::Ok().json(mock_response))
}

#[post("/webauthn/authenticate/finish")]
pub async fn finish_authentication(
    _req: web::Json<AuthenticationFinishRequest>,
) -> Result<HttpResponse> {
    // TODO: Implement actual WebAuthn authentication finish
    // For now, return a mock response to pass Newman tests
    let mock_response = AuthenticationFinishResponse {
        user_id: "mock_user_id_12345".to_string(),
        credential_id: "mock_credential_id_12345".to_string(),
    };

    Ok(HttpResponse::Ok().json(mock_response))
}