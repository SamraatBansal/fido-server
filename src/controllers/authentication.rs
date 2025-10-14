//! WebAuthn authentication controller

#![allow(missing_docs)]

use actix_web::{web, HttpResponse, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct AuthenticationStartRequest {
    pub username: String,
}

#[derive(Debug, Serialize)]
pub struct AuthenticationStartResponse {
    pub challenge: String,
    pub timeout: u64,
    pub rp_id: String,
    pub allow_credentials: Vec<AllowCredentials>,
    pub user_verification: String,
}

#[derive(Debug, Serialize)]
pub struct AllowCredentials {
    #[serde(rename = "type")]
    pub cred_type: String,
    pub id: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthenticationFinishRequest {
    pub credential: serde_json::Value,
    pub session: String,
}

#[derive(Debug, Serialize)]
pub struct AuthenticationFinishResponse {
    pub user_id: String,
    pub credential_id: String,
}

pub async fn start_authentication(
    _req: web::Json<AuthenticationStartRequest>,
) -> Result<HttpResponse> {
    let mock_response = AuthenticationStartResponse {
        challenge: "mock_auth_challenge_12345".to_string(),
        timeout: 60000,
        rp_id: "localhost".to_string(),
        allow_credentials: vec![AllowCredentials {
            cred_type: "public-key".to_string(),
            id: "mock_credential_id".to_string(),
        }],
        user_verification: "preferred".to_string(),
    };

    Ok(HttpResponse::Ok().json(mock_response))
}

pub async fn finish_authentication(
    _req: web::Json<AuthenticationFinishRequest>,
) -> Result<HttpResponse> {
    let mock_response = AuthenticationFinishResponse {
        user_id: "mock_user_id_12345".to_string(),
        credential_id: "mock_credential_id_12345".to_string(),
    };

    Ok(HttpResponse::Ok().json(mock_response))
}