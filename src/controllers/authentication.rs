use crate::services::{
    ServerPublicKeyCredentialAssertion, ServerPublicKeyCredentialGetOptionsRequest,
    WebAuthnService,
};
use crate::{AppError, Result};
use actix_web::{web, HttpResponse};

#[actix_web::post("/assertion/options")]
pub async fn assertion_options(
    service: web::Data<WebAuthnService>,
    request: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
) -> Result<HttpResponse> {
    log::info!("Assertion options request for user: {}", request.username);
    
    // Validate request
    if request.username.is_empty() {
        return Err(AppError::Validation {
            message: "Username is required".to_string(),
        });
    }
    
    let response = service.start_authentication(&request)?;
    Ok(HttpResponse::Ok().json(response))
}

#[actix_web::post("/assertion/result")]
pub async fn assertion_result(
    service: web::Data<WebAuthnService>,
    assertion: web::Json<ServerPublicKeyCredentialAssertion>,
) -> Result<HttpResponse> {
    log::info!("Assertion result for credential: {}", assertion.id);
    
    // Validate request
    if assertion.id.is_empty() {
        return Err(AppError::Validation {
            message: "Credential ID is required".to_string(),
        });
    }
    
    if assertion.type_ != "public-key" {
        return Err(AppError::Validation {
            message: "Invalid credential type".to_string(),
        });
    }
    
    if assertion.response.client_data_json.is_empty() {
        return Err(AppError::Validation {
            message: "Client data JSON is required".to_string(),
        });
    }
    
    if assertion.response.authenticator_data.is_empty() {
        return Err(AppError::Validation {
            message: "Authenticator data is required".to_string(),
        });
    }
    
    if assertion.response.signature.is_empty() {
        return Err(AppError::Validation {
            message: "Signature is required".to_string(),
        });
    }
    
    let response = service.complete_authentication(&assertion)?;
    Ok(HttpResponse::Ok().json(response))
}