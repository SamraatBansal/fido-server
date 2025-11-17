use crate::services::{
    ServerPublicKeyCredential, ServerPublicKeyCredentialCreationOptionsRequest,
    ServerPublicKeyCredentialCreationOptionsResponse, WebAuthnService,
};
use crate::{AppError, Result};
use actix_web::{web, HttpResponse};

#[actix_web::post("/attestation/options")]
pub async fn attestation_options(
    service: web::Data<WebAuthnService>,
    request: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
) -> Result<HttpResponse> {
    log::info!("Attestation options request for user: {}", request.username);
    
    // Validate request
    if request.username.is_empty() {
        return Err(AppError::Validation {
            message: "Username is required".to_string(),
        });
    }
    
    if request.display_name.is_empty() {
        return Err(AppError::Validation {
            message: "Display name is required".to_string(),
        });
    }
    
    let response = service.start_registration(&request)?;
    Ok(HttpResponse::Ok().json(response))
}

#[actix_web::post("/attestation/result")]
pub async fn attestation_result(
    service: web::Data<WebAuthnService>,
    credential: web::Json<ServerPublicKeyCredential>,
) -> Result<HttpResponse> {
    log::info!("Attestation result for credential: {}", credential.id);
    
    // Validate request
    if credential.id.is_empty() {
        return Err(AppError::Validation {
            message: "Credential ID is required".to_string(),
        });
    }
    
    if credential.type_ != "public-key" {
        return Err(AppError::Validation {
            message: "Invalid credential type".to_string(),
        });
    }
    
    if credential.response.client_data_json.is_empty() {
        return Err(AppError::Validation {
            message: "Client data JSON is required".to_string(),
        });
    }
    
    if credential.response.attestation_object.is_empty() {
        return Err(AppError::Validation {
            message: "Attestation object is required".to_string(),
        });
    }
    
    let response = service.complete_registration(&credential)?;
    Ok(HttpResponse::Ok().json(response))
}