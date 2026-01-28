//! Registration controller

use actix_web::{web, HttpResponse, Result};
use validator::Validate;
use crate::schema::{
    RegistrationStartRequest, RegistrationFinishRequest, RegistrationStartResponse, 
    RegistrationFinishResponse, ApiResponse, ApiError
};
use crate::services::WebAuthnService;
use crate::db::DbManager;
use crate::error::{AppError, Result as AppResult};

/// Start registration endpoint
pub async fn start_registration(
    web::Json(request): web::Json<RegistrationStartRequest>,
    webauthn_service: web::Data<WebAuthnService>,
    db_manager: web::Data<DbManager>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse> {
    // Validate request
    if let Err(validation_errors) = request.validate() {
        let error_response = ApiResponse::<RegistrationStartResponse>::error(
            ApiError::with_details(
                "VALIDATION_ERROR",
                "Request validation failed",
                serde_json::to_value(validation_errors).unwrap_or_default(),
            )
        );
        return Ok(HttpResponse::BadRequest().json(error_response));
    }

    // Extract client information
    let ip_address = req.connection_info().realip_remote_addr();
    let user_agent = req.headers().get("user-agent")
        .and_then(|h| h.to_str().ok());

    // Get database connection
    let mut conn = db_manager.get_connection()
        .map_err(|e| AppError::DatabaseError(format!("Failed to get database connection: {}", e)))?;

    match webauthn_service.start_registration(&mut conn, request, ip_address, user_agent).await {
        Ok(response) => {
            let api_response = ApiResponse::success(response);
            Ok(HttpResponse::Ok().json(api_response))
        }
        Err(e) => {
            log::error!("Registration start failed: {:?}", e);
            let api_response = ApiResponse::<RegistrationStartResponse>::error(
                ApiError::new("REGISTRATION_FAILED", &e.to_string())
            );
            Ok(HttpResponse::BadRequest().json(api_response))
        }
    }
}

/// Finish registration endpoint
pub async fn finish_registration(
    web::Json(request): web::Json<RegistrationFinishRequest>,
    webauthn_service: web::Data<WebAuthnService>,
    db_manager: web::Data<DbManager>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse> {
    // Validate request
    if let Err(validation_errors) = request.validate() {
        let error_response = ApiResponse::<RegistrationFinishResponse>::error(
            ApiError::with_details(
                "VALIDATION_ERROR",
                "Request validation failed",
                serde_json::to_value(validation_errors).unwrap_or_default(),
            )
        );
        return Ok(HttpResponse::BadRequest().json(error_response));
    }

    // Extract client information
    let ip_address = req.connection_info().realip_remote_addr();
    let user_agent = req.headers().get("user-agent")
        .and_then(|h| h.to_str().ok());

    // Get database connection
    let mut conn = db_manager.get_connection()
        .map_err(|e| AppError::DatabaseError(format!("Failed to get database connection: {}", e)))?;

    match webauthn_service.finish_registration(&mut conn, request, ip_address, user_agent).await {
        Ok(response) => {
            let api_response = ApiResponse::success(response);
            Ok(HttpResponse::Created().json(api_response))
        }
        Err(e) => {
            log::error!("Registration finish failed: {:?}", e);
            let api_response = ApiResponse::<RegistrationFinishResponse>::error(
                ApiError::new("REGISTRATION_FAILED", &e.to_string())
            );
            Ok(HttpResponse::BadRequest().json(api_response))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web};
    use serde_json::json;

    #[actix_web::test]
    async fn test_start_registration_validation() {
        let app = test::init_service(
            actix_web::App::new()
                .route("/register/start", web::post().to(start_registration))
        ).await;

        // Test invalid request (empty username)
        let req = test::TestRequest::post()
            .uri("/register/start")
            .set_json(json!({
                "username": "",
                "display_name": "Test User"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);
    }

    #[actix_web::test]
    async fn test_finish_registration_validation() {
        let app = test::init_service(
            actix_web::App::new()
                .route("/register/finish", web::post().to(finish_registration))
        ).await;

        // Test invalid request (invalid UUID)
        let req = test::TestRequest::post()
            .uri("/register/finish")
            .set_json(json!({
                "challenge_id": "invalid-uuid",
                "credential": {}
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);
    }
}