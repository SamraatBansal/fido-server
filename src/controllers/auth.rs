//! Authentication controller

use actix_web::{web, HttpResponse, Result};
use validator::Validate;
use crate::schema::{
    AuthenticationStartRequest, AuthenticationFinishRequest, AuthenticationStartResponse, 
    AuthenticationFinishResponse, SessionValidationRequest, SessionValidationResponse,
    LogoutRequest, LogoutResponse, ApiResponse, ApiError
};
use crate::services::{WebAuthnService, SessionService};
use crate::db::DbManager;
use crate::error::{AppError, Result as AppResult};

/// Start authentication endpoint
pub async fn start_authentication(
    web::Json(request): web::Json<AuthenticationStartRequest>,
    web::Data(webauthn_service): web::Data<WebAuthnService>,
    web::Data(db_manager): web::Data<DbManager>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse> {
    // Validate request
    if let Err(validation_errors) = request.validate() {
        let error_response = ApiResponse::<AuthenticationStartResponse>::error(
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

    // Use a mutable reference to the service
    let mut service = webauthn_service.as_ref().clone();

    match service.start_authentication(&mut conn, request, ip_address, user_agent).await {
        Ok(response) => {
            let api_response = ApiResponse::success(response);
            Ok(HttpResponse::Ok().json(api_response))
        }
        Err(e) => {
            log::error!("Authentication start failed: {:?}", e);
            let api_response = ApiResponse::<AuthenticationStartResponse>::error(
                ApiError::new("AUTHENTICATION_FAILED", &e.to_string())
            );
            Ok(HttpResponse::BadRequest().json(api_response))
        }
    }
}

/// Finish authentication endpoint
pub async fn finish_authentication(
    web::Json(request): web::Json<AuthenticationFinishRequest>,
    web::Data(webauthn_service): web::Data<WebAuthnService>,
    web::Data(db_manager): web::Data<DbManager>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse> {
    // Validate request
    if let Err(validation_errors) = request.validate() {
        let error_response = ApiResponse::<AuthenticationFinishResponse>::error(
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

    // Use a mutable reference to the service
    let mut service = webauthn_service.as_ref().clone();

    match service.finish_authentication(&mut conn, request, ip_address, user_agent).await {
        Ok(response) => {
            let api_response = ApiResponse::success(response);
            Ok(HttpResponse::Ok().json(api_response))
        }
        Err(e) => {
            log::error!("Authentication finish failed: {:?}", e);
            let api_response = ApiResponse::<AuthenticationFinishResponse>::error(
                ApiError::new("AUTHENTICATION_FAILED", &e.to_string())
            );
            Ok(HttpResponse::Unauthorized().json(api_response))
        }
    }
}

/// Validate session endpoint
pub async fn validate_session(
    web::Json(request): web::Json<SessionValidationRequest>,
    web::Data(session_service): web::Data<SessionService>,
    web::Data(db_manager): web::Data<DbManager>,
) -> Result<HttpResponse> {
    // Validate request
    if let Err(validation_errors) = request.validate() {
        let error_response = ApiResponse::<SessionValidationResponse>::error(
            ApiError::with_details(
                "VALIDATION_ERROR",
                "Request validation failed",
                serde_json::to_value(validation_errors).unwrap_or_default(),
            )
        );
        return Ok(HttpResponse::BadRequest().json(error_response));
    }

    // Get database connection
    let mut conn = db_manager.get_connection()
        .map_err(|e| AppError::DatabaseError(format!("Failed to get database connection: {}", e)))?;

    match session_service.validate_session(&mut conn, &request.session_token).await {
        Some(session) => {
            let response = SessionValidationResponse {
                valid: true,
                user_id: Some(session.user_id),
                expires_at: Some(session.expires_at),
                last_accessed_at: Some(session.last_accessed_at),
            };
            let api_response = ApiResponse::success(response);
            Ok(HttpResponse::Ok().json(api_response))
        }
        None => {
            let response = SessionValidationResponse {
                valid: false,
                user_id: None,
                expires_at: None,
                last_accessed_at: None,
            };
            let api_response = ApiResponse::success(response);
            Ok(HttpResponse::Ok().json(api_response))
        }
    }
}

/// Logout endpoint
pub async fn logout(
    web::Json(request): web::Json<LogoutRequest>,
    web::Data(session_service): web::Data<SessionService>,
    web::Data(db_manager): web::Data<DbManager>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse> {
    // Validate request
    if let Err(validation_errors) = request.validate() {
        let error_response = ApiResponse::<LogoutResponse>::error(
            ApiError::with_details(
                "VALIDATION_ERROR",
                "Request validation failed",
                serde_json::to_value(validation_errors).unwrap_or_default(),
            )
        );
        return Ok(HttpResponse::BadRequest().json(error_response));
    }

    // Extract client information for audit logging
    let ip_address = req.connection_info().realip_remote_addr();
    let user_agent = req.headers().get("user-agent")
        .and_then(|h| h.to_str().ok());

    // Get database connection
    let mut conn = db_manager.get_connection()
        .map_err(|e| AppError::DatabaseError(format!("Failed to get database connection: {}", e)))?;

    match session_service.invalidate_session(&mut conn, &request.session_token).await {
        Ok(_) => {
            let response = LogoutResponse {
                success: true,
                message: "Successfully logged out".to_string(),
            };
            let api_response = ApiResponse::success(response);
            Ok(HttpResponse::Ok().json(api_response))
        }
        Err(e) => {
            log::error!("Logout failed: {:?}", e);
            let response = LogoutResponse {
                success: false,
                message: format!("Logout failed: {}", e),
            };
            let api_response = ApiResponse::success(response);
            Ok(HttpResponse::BadRequest().json(api_response))
        }
    }
}

/// Get current user info (protected endpoint)
pub async fn get_current_user(
    web::Data(session_service): web::Data<SessionService>,
    web::Data(db_manager): web::Data<DbManager>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse> {
    // Extract session token from Authorization header
    let session_token = extract_session_token(&req)?;
    
    // Get database connection
    let mut conn = db_manager.get_connection()
        .map_err(|e| AppError::DatabaseError(format!("Failed to get database connection: {}", e)))?;

    match session_service.validate_session(&mut conn, &session_token).await {
        Some(session) => {
            // Return user information
            let user_info = serde_json::json!({
                "user_id": session.user_id,
                "session_id": session.id,
                "expires_at": session.expires_at,
                "last_accessed_at": session.last_accessed_at
            });
            let api_response = ApiResponse::success(user_info);
            Ok(HttpResponse::Ok().json(api_response))
        }
        None => {
            let api_response = ApiResponse::<serde_json::Value>::error(
                ApiError::new("INVALID_SESSION", "Session is invalid or expired")
            );
            Ok(HttpResponse::Unauthorized().json(api_response))
        }
    }
}

/// Extract session token from Authorization header
fn extract_session_token(req: &actix_web::HttpRequest) -> AppResult<String> {
    let auth_header = req.headers().get("authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| AppError::BadRequest("Missing Authorization header".to_string()))?;

    if !auth_header.starts_with("Bearer ") {
        return Err(AppError::BadRequest("Invalid Authorization header format".to_string()));
    }

    Ok(auth_header[7..].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web};
    use serde_json::json;

    #[actix_web::test]
    async fn test_start_authentication_validation() {
        let app = test::init_service(
            actix_web::App::new()
                .route("/auth/start", web::post().to(start_authentication))
        ).await;

        // Test invalid request (invalid URL in origin)
        let req = test::TestRequest::post()
            .uri("/auth/start")
            .set_json(json!({
                "origin": "invalid-url"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);
    }

    #[actix_web::test]
    async fn test_validate_session_validation() {
        let app = test::init_service(
            actix_web::App::new()
                .route("/auth/validate", web::post().to(validate_session))
        ).await;

        // Test invalid request (empty session token)
        let req = test::TestRequest::post()
            .uri("/auth/validate")
            .set_json(json!({
                "session_token": ""
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), actix_web::http::StatusCode::BAD_REQUEST);
    }

    #[actix_web::test]
    async fn test_extract_session_token() {
        let req = test::TestRequest::default()
            .insert_header(("authorization", "Bearer test-token"))
            .to_http_request();

        let token = extract_session_token(&req).unwrap();
        assert_eq!(token, "test-token");
    }

    #[actix_web::test]
    async fn test_extract_session_token_missing() {
        let req = test::TestRequest::default().to_http_request();

        let result = extract_session_token(&req);
        assert!(result.is_err());
    }

    #[actix_web::test]
    async fn test_extract_session_token_invalid_format() {
        let req = test::TestRequest::default()
            .insert_header(("authorization", "InvalidFormat test-token"))
            .to_http_request();

        let result = extract_session_token(&req);
        assert!(result.is_err());
    }
}