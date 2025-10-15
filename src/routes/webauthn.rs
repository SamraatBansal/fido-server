use actix_web::{web, HttpResponse, Result};
use crate::schema::{
    AttestationOptionsRequest, AttestationOptionsResponse, AttestationResultRequest,
    AssertionOptionsRequest, AssertionOptionsResponse, AssertionResultRequest,
    ServerResponse, RelyingParty, UserEntity, PublicKeyCredentialParameters,
    PublicKeyCredentialDescriptor, AttestationConveyancePreference,
    UserVerificationRequirement,
};
use crate::error::{AppError, AppResult};
use base64::Engine;
use rand::RngCore;

/// POST /attestation/options - Begin registration
pub async fn attestation_options(
    req: web::Json<AttestationOptionsRequest>,
) -> Result<HttpResponse, AppError> {
    // Validate input
    if req.username.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Username is required")));
    }

    if req.display_name.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Display name is required")));
    }

    // Generate challenge (minimum 16 bytes, base64url encoded)
    let mut challenge_bytes = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge_bytes);
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&challenge_bytes);

    // Generate user ID (base64url encoded)
    let mut user_id_bytes = vec![0u8; 16];
    rand::thread_rng().fill_bytes(&mut user_id_bytes);
    let user_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&user_id_bytes);

    let response = AttestationOptionsResponse::ok(
        RelyingParty {
            name: "Example Corporation".to_string(),
            id: Some("example.com".to_string()),
        },
        UserEntity {
            id: user_id,
            name: req.username.clone(),
            display_name: req.display_name.clone(),
        },
        challenge,
        vec![
            PublicKeyCredentialParameters {
                credential_type: "public-key".to_string(),
                alg: -7, // ES256
            },
            PublicKeyCredentialParameters {
                credential_type: "public-key".to_string(),
                alg: -257, // RS256
            },
        ],
        Some(10000), // 10 seconds timeout
        None, // No excluded credentials for new registration
        req.authenticator_selection.clone(),
        Some(req.attestation.clone()),
    );

    Ok(HttpResponse::Ok().json(response))
}

/// POST /attestation/result - Complete registration
pub async fn attestation_result(
    req: web::Json<AttestationResultRequest>,
) -> Result<HttpResponse, AppError> {
    // Validate required fields
    if req.id.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Credential ID is required")));
    }

    if req.credential_type != "public-key" {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Invalid credential type")));
    }

    if req.response.client_data_json.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Client data JSON is required")));
    }

    if req.response.attestation_object.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Attestation object is required")));
    }

    // Validate base64url encoding
    if let Err(_) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&req.response.client_data_json) {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Invalid client data JSON encoding")));
    }

    if let Err(_) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&req.response.attestation_object) {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Invalid attestation object encoding")));
    }

    // TODO: Implement actual WebAuthn validation
    // For now, return success for valid format
    Ok(HttpResponse::Ok().json(ServerResponse::ok()))
}

/// POST /assertion/options - Begin authentication
pub async fn assertion_options(
    req: web::Json<AssertionOptionsRequest>,
) -> Result<HttpResponse, AppError> {
    // Validate input
    if req.username.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Username is required")));
    }

    // Generate challenge (minimum 16 bytes, base64url encoded)
    let mut challenge_bytes = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge_bytes);
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&challenge_bytes);

    // Mock credential ID for testing
    let mut cred_id_bytes = vec![0u8; 16];
    rand::thread_rng().fill_bytes(&mut cred_id_bytes);
    let credential_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&cred_id_bytes);

    let response = AssertionOptionsResponse::ok(
        challenge,
        Some(20000), // 20 seconds timeout
        "example.com".to_string(),
        Some(vec![PublicKeyCredentialDescriptor {
            credential_type: "public-key".to_string(),
            id: credential_id,
            transports: Some(vec!["usb".to_string(), "nfc".to_string()]),
        }]),
        req.user_verification.clone(),
    );

    Ok(HttpResponse::Ok().json(response))
}

/// POST /assertion/result - Complete authentication
pub async fn assertion_result(
    req: web::Json<AssertionResultRequest>,
) -> Result<HttpResponse, AppError> {
    // Validate required fields
    if req.id.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Credential ID is required")));
    }

    if req.credential_type != "public-key" {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Invalid credential type")));
    }

    if req.response.authenticator_data.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Authenticator data is required")));
    }

    if req.response.client_data_json.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Client data JSON is required")));
    }

    if req.response.signature.is_empty() {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Signature is required")));
    }

    // Validate base64url encoding
    if let Err(_) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&req.response.authenticator_data) {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Invalid authenticator data encoding")));
    }

    if let Err(_) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&req.response.client_data_json) {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Invalid client data JSON encoding")));
    }

    if let Err(_) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&req.response.signature) {
        return Ok(HttpResponse::BadRequest().json(ServerResponse::error("Invalid signature encoding")));
    }

    // TODO: Implement actual WebAuthn validation
    // For now, return success for valid format
    Ok(HttpResponse::Ok().json(ServerResponse::ok()))
}