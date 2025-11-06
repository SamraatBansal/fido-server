use crate::api::*;
use crate::error::{AppError, Result};
use crate::service::WebAuthnService;
use actix_web::{web, HttpResponse};
use base64::prelude::*;

pub async fn start_registration(
    request: web::Json<ServerPublicKeyCredentialCreationOptionsRequest>,
    service: web::Data<WebAuthnService>,
) -> Result<HttpResponse> {
    let response = service.start_registration(&request).await?;
    Ok(HttpResponse::Ok().json(response))
}

pub async fn finish_registration(
    credential: web::Json<ServerPublicKeyCredential>,
    service: web::Data<WebAuthnService>,
) -> Result<HttpResponse> {
    // Additional validation for registration
    if let ServerAuthenticatorResponse::Attestation(ref response) = credential.response {
        // Validate that required fields are present and not empty
        if response.client_data_json.is_empty() {
            return Err(AppError::InvalidField("clientDataJSON cannot be empty".to_string()));
        }
        if response.attestation_object.is_empty() {
            return Err(AppError::InvalidField("attestationObject cannot be empty".to_string()));
        }

        // Validate base64url encoding
        use base64::prelude::*;
        if let Err(_) = BASE64_URL_SAFE_NO_PAD.decode(&response.client_data_json) {
            return Err(AppError::InvalidField("clientDataJSON is not valid base64url".to_string()));
        }
        if let Err(_) = BASE64_URL_SAFE_NO_PAD.decode(&response.attestation_object) {
            return Err(AppError::InvalidField("attestationObject is not valid base64url".to_string()));
        }

        // Parse and validate client data JSON
        let client_data_bytes = BASE64_URL_SAFE_NO_PAD.decode(&response.client_data_json)?;
        let client_data: serde_json::Value = serde_json::from_slice(&client_data_bytes)?;

        // Validate client data structure
        let type_ = client_data.get("type").and_then(|t| t.as_str());
        if type_ != Some("webauthn.create") {
            return Err(AppError::InvalidField("clientDataJSON.type must be 'webauthn.create'".to_string()));
        }

        let challenge = client_data.get("challenge").and_then(|c| c.as_str());
        if challenge.is_none() {
            return Err(AppError::MissingField("clientDataJSON.challenge".to_string()));
        }
        if challenge == Some("") {
            return Err(AppError::InvalidField("clientDataJSON.challenge cannot be empty".to_string()));
        }

        let origin = client_data.get("origin").and_then(|o| o.as_str());
        if origin.is_none() {
            return Err(AppError::MissingField("clientDataJSON.origin".to_string()));
        }
        if origin == Some("") {
            return Err(AppError::InvalidField("clientDataJSON.origin cannot be empty".to_string()));
        }

        // Validate token binding if present
        if let Some(token_binding) = client_data.get("tokenBinding") {
            if !token_binding.is_object() {
                return Err(AppError::InvalidField("clientDataJSON.tokenBinding must be an object".to_string()));
            }
            let tb_obj = token_binding.as_object().unwrap();
            if !tb_obj.contains_key("status") {
                return Err(AppError::MissingField("clientDataJSON.tokenBinding.status".to_string()));
            }
            let status = tb_obj.get("status").and_then(|s| s.as_str());
            if !matches!(status, Some("present") | Some("supported") | Some("not-supported")) {
                return Err(AppError::InvalidField("clientDataJSON.tokenBinding.status must be 'present', 'supported', or 'not-supported'".to_string()));
            }
        }
    } else {
        return Err(AppError::InvalidRequest("Expected attestation response".to_string()));
    }

    // Validate credential ID
    if credential.id.is_empty() {
        return Err(AppError::MissingField("id".to_string()));
    }
    if let Err(_) = BASE64_URL_SAFE_NO_PAD.decode(&credential.id) {
        return Err(AppError::InvalidField("id is not valid base64url".to_string()));
    }

    // Validate type
    if credential.type_ != "public-key" {
        return Err(AppError::InvalidField("type must be 'public-key'".to_string()));
    }

    let response = service.finish_registration(&credential).await?;
    Ok(HttpResponse::Ok().json(response))
}

pub async fn start_authentication(
    request: web::Json<ServerPublicKeyCredentialGetOptionsRequest>,
    service: web::Data<WebAuthnService>,
) -> Result<HttpResponse> {
    let response = service.start_authentication(&request).await?;
    Ok(HttpResponse::Ok().json(response))
}

pub async fn finish_authentication(
    credential: web::Json<ServerPublicKeyCredential>,
    service: web::Data<WebAuthnService>,
) -> Result<HttpResponse> {
    // Additional validation for authentication
    if let ServerAuthenticatorResponse::Assertion(ref response) = credential.response {
        // Validate that required fields are present and not empty
        if response.client_data_json.is_empty() {
            return Err(AppError::InvalidField("clientDataJSON cannot be empty".to_string()));
        }
        if response.authenticator_data.is_empty() {
            return Err(AppError::InvalidField("authenticatorData cannot be empty".to_string()));
        }
        if response.signature.is_empty() {
            return Err(AppError::InvalidField("signature cannot be empty".to_string()));
        }

        // Validate base64url encoding
        use base64::prelude::*;
        if let Err(_) = BASE64_URL_SAFE_NO_PAD.decode(&response.client_data_json) {
            return Err(AppError::InvalidField("clientDataJSON is not valid base64url".to_string()));
        }
        if let Err(_) = BASE64_URL_SAFE_NO_PAD.decode(&response.authenticator_data) {
            return Err(AppError::InvalidField("authenticatorData is not valid base64url".to_string()));
        }
        if let Err(_) = BASE64_URL_SAFE_NO_PAD.decode(&response.signature) {
            return Err(AppError::InvalidField("signature is not valid base64url".to_string()));
        }

        // Parse and validate client data JSON
        let client_data_bytes = BASE64_URL_SAFE_NO_PAD.decode(&response.client_data_json)?;
        let client_data: serde_json::Value = serde_json::from_slice(&client_data_bytes)?;

        // Validate client data structure
        let type_ = client_data.get("type").and_then(|t| t.as_str());
        if type_ != Some("webauthn.get") {
            return Err(AppError::InvalidField("clientDataJSON.type must be 'webauthn.get'".to_string()));
        }

        let challenge = client_data.get("challenge").and_then(|c| c.as_str());
        if challenge.is_none() {
            return Err(AppError::MissingField("clientDataJSON.challenge".to_string()));
        }
        if challenge == Some("") {
            return Err(AppError::InvalidField("clientDataJSON.challenge cannot be empty".to_string()));
        }

        let origin = client_data.get("origin").and_then(|o| o.as_str());
        if origin.is_none() {
            return Err(AppError::MissingField("clientDataJSON.origin".to_string()));
        }
        if origin == Some("") {
            return Err(AppError::InvalidField("clientDataJSON.origin cannot be empty".to_string()));
        }
    } else {
        return Err(AppError::InvalidRequest("Expected assertion response".to_string()));
    }

    // Validate credential ID
    if credential.id.is_empty() {
        return Err(AppError::MissingField("id".to_string()));
    }
    if let Err(_) = BASE64_URL_SAFE_NO_PAD.decode(&credential.id) {
        return Err(AppError::InvalidField("id is not valid base64url".to_string()));
    }

    // Validate type
    if credential.type_ != "public-key" {
        return Err(AppError::InvalidField("type must be 'public-key'".to_string()));
    }

    let response = service.finish_authentication(&credential).await?;
    Ok(HttpResponse::Ok().json(response))
}

pub async fn health_check() -> HttpResponse {
    HttpResponse::Ok().json(ServerResponse::success())
}