//! Authentication controller for WebAuthn credential authentication

use actix_web::{web, HttpRequest, HttpResponse, Result};
use serde_json::json;
use validator::Validate;
use webauthn_rs::prelude::*;

use crate::db::{User, Credential};
use crate::error::AppError;
use crate::schema::{
    AuthenticationFinishRequest, AuthenticationFinishResponseData, AuthenticationStartRequest,
    AuthenticationStartResponse,
};
use crate::services::fido::WebAuthnService;

/// Start WebAuthn authentication
///
/// This endpoint initiates the WebAuthn authentication flow by generating
/// a challenge and returning the necessary options for the client.
#[utoipa::path(
    post,
    path = "/api/v1/authenticate/start",
    request_body = AuthenticationStartRequest,
    responses(
        (status = 200, description = "Authentication started successfully", body = AuthenticationStartResponse),
        (status = 400, description = "Invalid request"),
        (status = 404, description = "User not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "authentication"
)]
pub async fn start_authentication(
    req: HttpRequest,
    web::Json(payload): web::Json<AuthenticationStartRequest>,
    web::Data(webauthn_service): web::Data<WebAuthnService>,
) -> Result<HttpResponse> {
    // Validate request
    if let Err(validation_errors) = payload.validate() {
        return Ok(HttpResponse::BadRequest().json(json!({
            "error": "Validation failed",
            "details": validation_errors
        })));
    }

    // Start authentication
    match webauthn_service
        .start_authentication(&payload.username)
        .await
    {
        Ok(options) => {
            let response = AuthenticationStartResponse {
                challenge: options.challenge.clone(),
                allow_credentials: options.allow_credentials,
                user_verification: options.user_verification.to_string(),
                timeout: options.timeout,
                rp_id: options.rp_id,
            };

            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            log::error!("Failed to start authentication: {}", e);
            let status_code = e.status_code();
            let error_response = match e {
                AppError::UserNotFound => json!({
                    "error": "User not found",
                    "message": "No user exists with the provided username"
                }),
                AppError::InvalidCredential => json!({
                    "error": "No credentials found",
                    "message": "User has no registered credentials"
                }),
                _ => json!({
                    "error": "Failed to start authentication",
                    "message": "An error occurred while initiating authentication"
                }),
            };

            Ok(HttpResponse::build(status_code).json(error_response))
        }
    }
}

/// Finish WebAuthn authentication
///
/// This endpoint completes the WebAuthn authentication flow by verifying
/// the assertion response and authenticating the user.
#[utoipa::path(
    post,
    path = "/api/v1/authenticate/finish",
    request_body = AuthenticationFinishRequest,
    responses(
        (status = 200, description = "Authentication completed successfully", body = AuthenticationFinishResponseData),
        (status = 400, description = "Invalid request or assertion"),
        (status = 401, description = "Authentication failed"),
        (status = 500, description = "Internal server error")
    ),
    tag = "authentication"
)]
pub async fn finish_authentication(
    req: HttpRequest,
    web::Json(payload): web::Json<AuthenticationFinishRequest>,
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
    let assertion_response = match convert_to_assertion_response(&payload) {
        Ok(response) => response,
        Err(e) => {
            log::error!("Failed to convert assertion response: {}", e);
            return Ok(HttpResponse::BadRequest().json(json!({
                "error": "Invalid assertion format",
                "message": "The assertion response could not be processed"
            })));
        }
    };

    // Finish authentication
    match webauthn_service
        .finish_authentication(&assertion_response)
        .await
    {
        Ok(_) => {
            // Get user information for response
            let user_info = match get_user_by_credential_id(&assertion_response.raw_id, &webauthn_service) {
                Ok(info) => info,
                Err(e) => {
                    log::error!("Failed to get user info: {}", e);
                    return Ok(HttpResponse::InternalServerError().json(json!({
                        "error": "Authentication completed but failed to get user info",
                        "message": "Please try again"
                    })));
                }
            };

            let response = AuthenticationFinishResponseData {
                status: "success".to_string(),
                user_id: user_info.user.id.to_string(),
                username: user_info.user.username,
                display_name: user_info.user.display_name,
                message: "Authentication completed successfully".to_string(),
            };

            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            log::error!("Failed to finish authentication: {}", e);
            let status_code = e.status_code();
            let error_response = match e {
                AppError::ChallengeNotFound => json!({
                    "error": "Challenge not found or expired",
                    "message": "The authentication challenge is invalid or has expired"
                }),
                AppError::InvalidCredential => json!({
                    "error": "Invalid credential",
                    "message": "The provided credential is invalid or not found"
                }),
                AppError::WebAuthn(_) => json!({
                    "error": "Assertion verification failed",
                    "message": "The assertion could not be verified"
                }),
                _ => json!({
                    "error": "Authentication failed",
                    "message": "An error occurred during authentication"
                }),
            };

            Ok(HttpResponse::build(status_code).json(error_response))
        }
    }
}

/// Convert authentication request to WebAuthn assertion response
fn convert_to_assertion_response(
    request: &AuthenticationFinishRequest,
) -> Result<PublicKeyCredential<AssertionResponse>, AppError> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

    let client_data_json = BASE64
        .decode(&request.response.client_data_json)
        .map_err(|e| AppError::BadRequest(format!("Invalid client data JSON encoding: {}", e)))?;

    let authenticator_data = BASE64
        .decode(&request.response.authenticator_data)
        .map_err(|e| AppError::BadRequest(format!("Invalid authenticator data encoding: {}", e)))?;

    let signature = BASE64
        .decode(&request.response.signature)
        .map_err(|e| AppError::BadRequest(format!("Invalid signature encoding: {}", e)))?;

    let raw_id = BASE64
        .decode(&request.raw_id)
        .map_err(|e| AppError::BadRequest(format!("Invalid credential ID encoding: {}", e)))?;

    let assertion_response = AssertionResponse {
        client_data_json: String::from_utf8(client_data_json)
            .map_err(|e| AppError::BadRequest(format!("Invalid client data JSON: {}", e)))?,
        authenticator_data,
        signature,
        user_handle: request.response.user_handle.clone(),
    };

    Ok(PublicKeyCredential {
        id: request.id.clone(),
        raw_id: BASE64.encode(raw_id),
        response: assertion_response,
        authenticator_attachment: request.authenticator_attachment.clone(),
        client_extension_results: request.client_extension_results.clone(),
        type_: "public-key".to_string(),
    })
}

/// Get user information by credential ID
fn get_user_by_credential_id(
    raw_id: &str,
    webauthn_service: &WebAuthnService,
) -> Result<crate::db::UserWithCredentials> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use diesel::prelude::*;

    let credential_id = BASE64
        .decode(raw_id)
        .map_err(|e| AppError::BadRequest(format!("Invalid credential ID encoding: {}", e)))?;

    let mut conn = webauthn_service.pool.get()?;

    // Get credential
    let credential: Credential = crate::schema::credentials::table
        .filter(crate::schema::credentials::credential_id.eq(&credential_id))
        .first(&mut conn)
        .map_err(|e| AppError::Database(format!("Failed to fetch credential: {}", e)))?;

    // Get user
    let user: User = crate::schema::users::table
        .filter(crate::schema::users::id.eq(credential.user_id))
        .first(&mut conn)
        .map_err(|e| AppError::Database(format!("Failed to fetch user: {}", e)))?;

    // Get all user credentials
    let credentials: Vec<Credential> = crate::schema::credentials::table
        .filter(crate::schema::credentials::user_id.eq(user.id))
        .load(&mut conn)
        .map_err(|e| AppError::Database(format!("Failed to fetch user credentials: {}", e)))?;

    Ok(crate::db::UserWithCredentials { user, credentials })
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web, App};
    use serde_json::json;

    #[actix_web::test]
    async fn test_start_authentication_validation() {
        let app = test::init_service(
            App::new().route(
                "/api/v1/authenticate/start",
                web::post().to(start_authentication),
            ),
        )
        .await;

        // Test invalid request (empty username)
        let req = test::TestRequest::post()
            .uri("/api/v1/authenticate/start")
            .set_json(json!({
                "username": ""
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_client_error());
    }

    #[actix_web::test]
    async fn test_finish_authentication_validation() {
        let app = test::init_service(
            App::new().route(
                "/api/v1/authenticate/finish",
                web::post().to(finish_authentication),
            ),
        )
        .await;

        // Test invalid request (missing fields)
        let req = test::TestRequest::post()
            .uri("/api/v1/authenticate/finish")
            .set_json(json!({
                "id": "test-id"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_client_error());
    }
}