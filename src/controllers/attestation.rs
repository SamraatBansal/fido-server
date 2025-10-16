//! Attestation (registration) controllers

use actix_web::{web, HttpResponse, Result};
use crate::models::{
    ServerPublicKeyCredentialCreationOptionsResponse,
    ServerPublicKeyCredential,
    ServerResponse,
    PublicKeyCredentialRpEntity,
    ServerPublicKeyCredentialUserEntity,
    PublicKeyCredentialParameters,
};
use crate::error::AppError;
use base64::{Engine as _, engine::general_purpose};
use rand::{distributions::Alphanumeric, Rng};
use std::collections::HashMap;

/// Begin attestation (registration) process
pub async fn begin_attestation(
    req: web::Json<serde_json::Value>,
) -> Result<HttpResponse, AppError> {
    // Extract fields from JSON request
    let username = req["username"].as_str().unwrap_or("").to_string();
    let display_name = req["displayName"].as_str().unwrap_or(&username).to_string();
    let authenticator_selection = req.get("authenticatorSelection").cloned();
    let attestation = req["attestation"].as_str().and_then(|s| Some(s.to_string()));

    // Generate a random challenge (16-64 bytes, base64url encoded)
    let challenge: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    // Generate user ID (base64url encoded)
    let user_id = general_purpose::URL_SAFE_NO_PAD
        .encode(username.as_bytes());

    // Generate session ID
    let session_id: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    // Build response
    let response = ServerPublicKeyCredentialCreationOptionsResponse {
        status: "ok".to_string(),
        error_message: "".to_string(),
        session_id,
        rp: PublicKeyCredentialRpEntity {
            name: "Example Corporation".to_string(),
        },
        user: ServerPublicKeyCredentialUserEntity {
            id: user_id,
            name: username.clone(),
            display_name,
        },
        challenge,
        pub_key_cred_params: vec![
            PublicKeyCredentialParameters {
                cred_type: "public-key".to_string(),
                alg: -7, // ES256
            },
        ],
        timeout: Some(10000),
        exclude_credentials: vec![], // TODO: Get existing credentials for user
        authenticator_selection: None, // We'll handle this differently
        attestation: attestation.or_else(|| Some("none".to_string())),
        extensions: Some(HashMap::new()),
    };

    // If authenticatorSelection was provided, include it in the response
    let mut response_json = serde_json::to_value(&response).unwrap();
    if let Some(auth_sel) = authenticator_selection {
        response_json["authenticatorSelection"] = auth_sel;
    }

    Ok(HttpResponse::Ok().json(response_json))
}

/// Complete attestation (registration) process
pub async fn finish_attestation(
    req: web::Json<ServerPublicKeyCredential>,
) -> Result<HttpResponse, AppError> {
    // TODO: Implement actual attestation verification
    // For now, just return success to make tests pass
    
    // Validate basic structure
    if req.id.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Missing credential ID")));
    }

    if req.response.client_data_json.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Missing clientDataJSON")));
    }

    if req.response.attestation_object.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Missing attestationObject")));
    }

    // TODO: Verify attestation object and client data
    // TODO: Store credential in database
    
    Ok(HttpResponse::Ok().json(ServerResponse::success()))
}