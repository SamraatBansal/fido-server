//! Registration controller for WebAuthn credential registration

use actix_web::{web, HttpRequest, HttpResponse, Result};
use serde_json::json;
use validator::Validate;
use webauthn_rs::prelude::*;

use crate::error::AppError;
use crate::schema::{
    RegistrationFinishRequest, RegistrationFinishResponseData, RegistrationStartRequest,
    RegistrationStartResponse,
};
use crate::services::fido::WebAuthnService;

/// Start WebAuthn registration
///
/// This endpoint initiates the WebAuthn registration flow by generating
/// a challenge and returning the necessary options for the client.
#[utoipa::path(
    post,
    path = "/api/v1/register/start",
    request_body = RegistrationStartRequest,
    responses(
        (status = 200, description = "Registration started successfully", body = RegistrationStartResponse),
        (status = 400, description = "Invalid request"),
        (status = 500, description = "Internal server error")
    ),
    tag = "registration"
)]
pub async fn start_registration(
    req: HttpRequest,
    web::Json(payload): web::Json<RegistrationStartRequest>,
    web::Data(webauthn_service): web::Data<WebAuthnService>,
) -> Result<HttpResponse> {
    // Validate request
    if let Err(validation_errors) = payload.validate() {
        return Ok(HttpResponse::BadRequest().json(json!({
            "error": "Validation failed",
            "details": validation_errors
        })));
    }

    // Extract origin from request
    let origin = req
        .headers()
        .get("Origin")
        .and_then(|h| h.to_str().ok())
        .unwrap_or_else(|| "http://localhost:8080");

    // Start registration
    match webauthn_service
        .start_registration(&payload.username, &payload.display_name)
        .await
    {
        Ok(options) => {
            let response = RegistrationStartResponse {
                challenge: options.challenge.clone(),
                user: options.user,
                pub_key_cred_params: options.pub_key_cred_params,
                rp: options.rp,
                authenticator_selection: options.authenticator_selection,
                attestation: options.attestation.to_string(),
                timeout: options.timeout,
            };

            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            log::error!("Failed to start registration: {}", e);
            Ok(HttpResponse::InternalServerError().json(json!({
                "error": "Failed to start registration",
                "message": "An error occurred while initiating registration"
            })))
        }
    }
}

/// Finish WebAuthn registration
///
/// This endpoint completes the WebAuthn registration flow by verifying
/// the attestation response and storing the credential.
#[utoipa::path(
    post,
    path = "/api/v1/register/finish",
    request_body = RegistrationFinishRequest,
    responses(
        (status = 200, description = "Registration completed successfully", body = RegistrationFinishResponseData),
        (status = 400, description = "Invalid request or attestation"),
        (status = 500, description = "Internal server error")
    ),
    tag = "registration"
)]
pub async fn finish_registration(
    req: HttpRequest,
    web::Json(payload): web::Json<RegistrationFinishRequest>,
    web::Data(webauthn_service): web::Data<WebAuthnService>,
) -> Result<HttpResponse> {
    // Validate request
    if let Err(validation_errors) = payload.validate() {
        return Ok(HttpResponse::BadRequest().json(json!({
            "error": "Validation failed",
            "details": validation_errors
        })));
    }

    // Convert request to WebAuthn format
    let attestation_response = match convert_to_attestation_response(&payload) {
        Ok(response) => response,
        Err(e) => {
            log::error!("Failed to convert attestation response: {}", e);
            return Ok(HttpResponse::BadRequest().json(json!({
                "error": "Invalid attestation format",
                "message": "The attestation response could not be processed"
            })));
        }
    };

    // Finish registration
    match webauthn_service
        .finish_registration(&attestation_response)
        .await
    {
        Ok(_) => {
            let response = RegistrationFinishResponseData {
                status: "success".to_string(),
                credential_id: payload.id.clone(),
                user_id: attestation_response.response.user.id.clone(),
                message: "Registration completed successfully".to_string(),
            };

            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            log::error!("Failed to finish registration: {}", e);
            let status_code = e.status_code();
            let error_response = match e {
                AppError::ChallengeNotFound => json!({
                    "error": "Challenge not found or expired",
                    "message": "The registration challenge is invalid or has expired"
                }),
                AppError::WebAuthn(_) => json!({
                    "error": "Attestation verification failed",
                    "message": "The attestation could not be verified"
                }),
                _ => json!({
                    "error": "Registration failed",
                    "message": "An error occurred during registration"
                }),
            };

            Ok(HttpResponse::build(status_code).json(error_response))
        }
    }
}

/// Convert registration request to WebAuthn attestation response
fn convert_to_attestation_response(
    request: &RegistrationFinishRequest,
) -> Result<PublicKeyCredential<AttestationResponse>, AppError> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

    let client_data_json = BASE64
        .decode(&request.response.client_data_json)
        .map_err(|e| AppError::BadRequest(format!("Invalid client data JSON encoding: {}", e)))?;

    let attestation_object = BASE64
        .decode(&request.response.attestation_object)
        .map_err(|e| AppError::BadRequest(format!("Invalid attestation object encoding: {}", e)))?;

    let raw_id = BASE64
        .decode(&request.raw_id)
        .map_err(|e| AppError::BadRequest(format!("Invalid credential ID encoding: {}", e)))?;

    let attestation_response = AttestationResponse {
        client_data_json: String::from_utf8(client_data_json)
            .map_err(|e| AppError::BadRequest(format!("Invalid client data JSON: {}", e)))?,
        attestation_object,
        transports: request.response.transports.clone(),
    };

    Ok(PublicKeyCredential {
        id: request.id.clone(),
        raw_id: BASE64.encode(raw_id),
        response: attestation_response,
        authenticator_attachment: request.authenticator_attachment.clone(),
        client_extension_results: request.client_extension_results.clone(),
        type_: "public-key".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web, App};
    use serde_json::json;

    #[actix_web::test]
    async fn test_start_registration_validation() {
        let app = test::init_service(
            App::new().route(
                "/api/v1/register/start",
                web::post().to(start_registration),
            ),
        )
        .await;

        // Test invalid request (short username)
        let req = test::TestRequest::post()
            .uri("/api/v1/register/start")
            .set_json(json!({
                "username": "ab",
                "display_name": "Test User"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_client_error());
    }

    #[actix_web::test]
    async fn test_finish_registration_validation() {
        let app = test::init_service(
            App::new().route(
                "/api/v1/register/finish",
                web::post().to(finish_registration),
            ),
        )
        .await;

        // Test invalid request (missing fields)
        let req = test::TestRequest::post()
            .uri("/api/v1/register/finish")
            .set_json(json!({
                "id": "test-id"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_client_error());
    }
}