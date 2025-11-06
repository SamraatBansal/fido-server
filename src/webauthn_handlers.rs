use crate::api::*;
use crate::error::{AppError, Result};
use crate::webauthn_service::WebAuthnService;
use actix_web::{web, HttpResponse};
use serde_json::Value;

pub async fn start_registration(
    request: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
    service: web::Data<WebAuthnService>,
) -> Result<HttpResponse> {
    // Comprehensive validation for FIDO conformance
    
    // Validate required fields
    if request.username.is_empty() {
        return Err(AppError::MissingField("username".to_string()));
    }
    if request.display_name.is_empty() {
        return Err(AppError::MissingField("displayName".to_string()));
    }
    
    let response = service.start_registration(&request).await?;
    Ok(HttpResponse::Ok().json(response))
}

pub async fn finish_registration(
    credential: web::Json<ServerPublicKeyCredential>,
    service: web::Data<WebAuthnService>,
) -> Result<HttpResponse> {
    // Comprehensive validation for FIDO conformance
    
    // Validate that required fields are present
    if credential.id.is_empty() {
        return Err(AppError::MissingField("id".to_string()));
    }
    
    // Validate type field is present and correct
    if credential.type_ != "public-key" {
        return Err(AppError::InvalidField("type must be 'public-key'".to_string()));
    }
    
    // Validate response field exists
    match &credential.response {
        ServerAuthenticatorResponse::Attestation(response) => {
            // Additional validation for attestation response
            if response.client_data_json.is_empty() {
                return Err(AppError::MissingField("clientDataJSON".to_string()));
            }
            if response.attestation_object.is_empty() {
                return Err(AppError::MissingField("attestationObject".to_string()));
            }
        },
        _ => return Err(AppError::MissingField("response".to_string())),
    }
    
    let response = service.finish_registration(&credential).await?;
    Ok(HttpResponse::Ok().json(response))
}

pub async fn start_authentication(
    request: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
    service: web::Data<WebAuthnService>,
) -> Result<HttpResponse> {
    // Validate required fields
    if request.username.is_empty() {
        return Err(AppError::MissingField("username".to_string()));
    }
    
    let response = service.start_authentication(&request).await?;
    Ok(HttpResponse::Ok().json(response))
}

pub async fn finish_authentication(
    credential: web::Json<ServerPublicKeyCredential>,
    service: web::Data<WebAuthnService>,
) -> Result<HttpResponse> {
    // Comprehensive validation for FIDO conformance
    
    // Validate that required fields are present
    if credential.id.is_empty() {
        return Err(AppError::MissingField("id".to_string()));
    }
    
    // Validate type field is present and correct
    if credential.type_ != "public-key" {
        return Err(AppError::InvalidField("type must be 'public-key'".to_string()));
    }
    
    // Validate response field exists
    match &credential.response {
        ServerAuthenticatorResponse::Assertion(response) => {
            // Additional validation for assertion response
            if response.client_data_json.is_empty() {
                return Err(AppError::MissingField("clientDataJSON".to_string()));
            }
            if response.authenticator_data.is_empty() {
                return Err(AppError::MissingField("authenticatorData".to_string()));
            }
            if response.signature.is_empty() {
                return Err(AppError::MissingField("signature".to_string()));
            }
        },
        _ => return Err(AppError::MissingField("response".to_string())),
    }
    
    let response = service.finish_authentication(&credential).await?;
    Ok(HttpResponse::Ok().json(response))
}

pub async fn health_check() -> HttpResponse {
    HttpResponse::Ok().json(ServerResponse::success())
}