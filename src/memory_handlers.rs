use crate::api::*;
use crate::error::{AppError, Result};
use crate::memory_service::MemoryWebAuthnService;
use actix_web::{web, HttpResponse};
use base64::prelude::*;
use serde_json::Value;

pub async fn start_registration(
    request: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
    service: web::Data<MemoryWebAuthnService>,
) -> Result<HttpResponse> {
    let response = service.start_registration(&request).await?;
    Ok(HttpResponse::Ok().json(response))
}

pub async fn finish_registration(
    credential: web::Json<ServerPublicKeyCredential>,
    service: web::Data<MemoryWebAuthnService>,
) -> Result<HttpResponse> {
    // Comprehensive validation for FIDO conformance
    
    // Validate credential ID field
    if credential.id.is_empty() {
        return Err(AppError::MissingField("id".to_string()));
    }
    
    // Validate base64url encoding of credential ID
    if !is_valid_base64url(&credential.id) {
        return Err(AppError::InvalidField("id is not valid base64url".to_string()));
    }
    
    // Validate type field
    if credential.type_ != "public-key" {
        return Err(AppError::InvalidField("type must be 'public-key'".to_string()));
    }

    // Validate response field exists and is attestation
    let response = match &credential.response {
        ServerAuthenticatorResponse::Attestation(response) => response,
        _ => return Err(AppError::InvalidRequest("Expected attestation response".to_string())),
    };
    
    // Validate clientDataJSON
    if response.client_data_json.is_empty() {
        return Err(AppError::InvalidField("clientDataJSON cannot be empty".to_string()));
    }
    
    // Validate base64url encoding of clientDataJSON
    let client_data_bytes = match BASE64_URL_SAFE_NO_PAD.decode(&response.client_data_json) {
        Ok(bytes) => bytes,
        Err(_) => return Err(AppError::InvalidField("clientDataJSON is not valid base64url".to_string())),
    };
    
    // Parse and validate client data JSON structure
    let client_data: Value = match serde_json::from_slice(&client_data_bytes) {
        Ok(data) => data,
        Err(_) => return Err(AppError::InvalidField("clientDataJSON is not valid JSON".to_string())),
    };
    
    // Validate type field in clientDataJSON
    match client_data.get("type") {
        Some(Value::String(type_val)) if type_val == "webauthn.create" => {},
        Some(Value::String(type_val)) => {
            return Err(AppError::InvalidField(format!("clientDataJSON.type must be 'webauthn.create', got: {}", type_val)));
        },
        Some(_) => {
            return Err(AppError::InvalidField("clientDataJSON.type must be a string".to_string()));
        },
        None => {
            return Err(AppError::MissingField("clientDataJSON.type".to_string()));
        }
    }
    
    // Validate challenge field in clientDataJSON
    match client_data.get("challenge") {
        Some(Value::String(challenge)) if !challenge.is_empty() => {
            if !is_valid_base64url(challenge) {
                return Err(AppError::InvalidField("clientDataJSON.challenge is not valid base64url".to_string()));
            }
        },
        Some(Value::String(_)) => {
            return Err(AppError::InvalidField("clientDataJSON.challenge cannot be empty".to_string()));
        },
        Some(_) => {
            return Err(AppError::InvalidField("clientDataJSON.challenge must be a string".to_string()));
        },
        None => {
            return Err(AppError::MissingField("clientDataJSON.challenge".to_string()));
        }
    }
    
    // Validate origin field in clientDataJSON
    match client_data.get("origin") {
        Some(Value::String(origin)) if !origin.is_empty() => {},
        Some(Value::String(_)) => {
            return Err(AppError::InvalidField("clientDataJSON.origin cannot be empty".to_string()));
        },
        Some(_) => {
            return Err(AppError::InvalidField("clientDataJSON.origin must be a string".to_string()));
        },
        None => {
            return Err(AppError::MissingField("clientDataJSON.origin".to_string()));
        }
    }
    
    // Validate tokenBinding if present
    if let Some(token_binding) = client_data.get("tokenBinding") {
        if !token_binding.is_object() {
            return Err(AppError::InvalidField("clientDataJSON.tokenBinding must be an object".to_string()));
        }
        
        let token_binding_obj = token_binding.as_object().unwrap();
        match token_binding_obj.get("status") {
            Some(Value::String(status)) => {
                if !matches!(status.as_str(), "present" | "supported" | "not-supported") {
                    return Err(AppError::InvalidField("clientDataJSON.tokenBinding.status must be 'present', 'supported', or 'not-supported'".to_string()));
                }
            },
            Some(_) => {
                return Err(AppError::InvalidField("clientDataJSON.tokenBinding.status must be a string".to_string()));
            },
            None => {
                return Err(AppError::MissingField("clientDataJSON.tokenBinding.status".to_string()));
            }
        }
    }
    
    // Validate attestationObject
    if response.attestation_object.is_empty() {
        return Err(AppError::InvalidField("attestationObject cannot be empty".to_string()));
    }
    
    // Validate base64url encoding of attestationObject
    match BASE64_URL_SAFE_NO_PAD.decode(&response.attestation_object) {
        Ok(_) => {},
        Err(_) => return Err(AppError::InvalidField("attestationObject is not valid base64url".to_string())),
    }
    
    // Call service to finish registration
    let response = service.finish_registration(&credential).await?;
    Ok(HttpResponse::Ok().json(response))
}

pub async fn start_authentication(
    request: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
    service: web::Data<MemoryWebAuthnService>,
) -> Result<HttpResponse> {
    let response = service.start_authentication(&request).await?;
    Ok(HttpResponse::Ok().json(response))
}

pub async fn finish_authentication(
    credential: web::Json<ServerPublicKeyCredential>,
    service: web::Data<MemoryWebAuthnService>,
) -> Result<HttpResponse> {
    // Comprehensive validation for FIDO conformance
    
    // Validate credential ID field
    if credential.id.is_empty() {
        return Err(AppError::MissingField("id".to_string()));
    }
    
    // Validate base64url encoding of credential ID
    if !is_valid_base64url(&credential.id) {
        return Err(AppError::InvalidField("id is not valid base64url".to_string()));
    }
    
    // Validate type field
    if credential.type_ != "public-key" {
        return Err(AppError::InvalidField("type must be 'public-key'".to_string()));
    }

    // Validate response field exists and is assertion
    let response = match &credential.response {
        ServerAuthenticatorResponse::Assertion(response) => response,
        _ => return Err(AppError::InvalidRequest("Expected assertion response".to_string())),
    };
    
    // Validate clientDataJSON
    if response.client_data_json.is_empty() {
        return Err(AppError::InvalidField("clientDataJSON cannot be empty".to_string()));
    }
    
    // Validate base64url encoding of clientDataJSON
    let client_data_bytes = match BASE64_URL_SAFE_NO_PAD.decode(&response.client_data_json) {
        Ok(bytes) => bytes,
        Err(_) => return Err(AppError::InvalidField("clientDataJSON is not valid base64url".to_string())),
    };
    
    // Parse and validate client data JSON structure
    let client_data: Value = match serde_json::from_slice(&client_data_bytes) {
        Ok(data) => data,
        Err(_) => return Err(AppError::InvalidField("clientDataJSON is not valid JSON".to_string())),
    };
    
    // Validate type field in clientDataJSON
    match client_data.get("type") {
        Some(Value::String(type_val)) if type_val == "webauthn.get" => {},
        Some(Value::String(type_val)) => {
            return Err(AppError::InvalidField(format!("clientDataJSON.type must be 'webauthn.get', got: {}", type_val)));
        },
        Some(_) => {
            return Err(AppError::InvalidField("clientDataJSON.type must be a string".to_string()));
        },
        None => {
            return Err(AppError::MissingField("clientDataJSON.type".to_string()));
        }
    }
    
    // Validate challenge field in clientDataJSON
    match client_data.get("challenge") {
        Some(Value::String(challenge)) if !challenge.is_empty() => {
            if !is_valid_base64url(challenge) {
                return Err(AppError::InvalidField("clientDataJSON.challenge is not valid base64url".to_string()));
            }
        },
        Some(Value::String(_)) => {
            return Err(AppError::InvalidField("clientDataJSON.challenge cannot be empty".to_string()));
        },
        Some(_) => {
            return Err(AppError::InvalidField("clientDataJSON.challenge must be a string".to_string()));
        },
        None => {
            return Err(AppError::MissingField("clientDataJSON.challenge".to_string()));
        }
    }
    
    // Validate origin field in clientDataJSON
    match client_data.get("origin") {
        Some(Value::String(origin)) if !origin.is_empty() => {},
        Some(Value::String(_)) => {
            return Err(AppError::InvalidField("clientDataJSON.origin cannot be empty".to_string()));
        },
        Some(_) => {
            return Err(AppError::InvalidField("clientDataJSON.origin must be a string".to_string()));
        },
        None => {
            return Err(AppError::MissingField("clientDataJSON.origin".to_string()));
        }
    }
    
    // Validate authenticatorData
    if response.authenticator_data.is_empty() {
        return Err(AppError::InvalidField("authenticatorData cannot be empty".to_string()));
    }
    
    // Validate base64url encoding of authenticatorData
    match BASE64_URL_SAFE_NO_PAD.decode(&response.authenticator_data) {
        Ok(_) => {},
        Err(_) => return Err(AppError::InvalidField("authenticatorData is not valid base64url".to_string())),
    }
    
    // Validate signature
    if response.signature.is_empty() {
        return Err(AppError::InvalidField("signature cannot be empty".to_string()));
    }
    
    // Validate base64url encoding of signature
    match BASE64_URL_SAFE_NO_PAD.decode(&response.signature) {
        Ok(_) => {},
        Err(_) => return Err(AppError::InvalidField("signature is not valid base64url".to_string())),
    }
    
    // Call service to finish authentication
    let response = service.finish_authentication(&credential).await?;
    Ok(HttpResponse::Ok().json(response))
}

pub async fn health_check() -> HttpResponse {
    HttpResponse::Ok().json(ServerResponse::success())
}

// Helper function to validate base64url encoding
fn is_valid_base64url(input: &str) -> bool {
    // Check for valid base64url characters
    if input.chars().any(|c| !matches!(c, 'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_')) {
        return false;
    }
    
    // Try to decode to verify it's valid base64url
    BASE64_URL_SAFE_NO_PAD.decode(input).is_ok()
}
