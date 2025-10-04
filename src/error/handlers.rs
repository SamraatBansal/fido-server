//! Error handlers

use actix_web::{dev::ServiceResponse, error::Error, Result};
use actix_web_lab::middleware::CatchAllErrorHandler;

/// Global error handler for the application
pub async fn handle_error(
    err: Error,
    req: actix_web::HttpRequest,
) -> Result<actix_web::HttpResponse> {
    // Log the error
    log::error!("Error processing request {}: {:?}", req.path(), err);

    // Convert to our AppError if possible
    let app_error: crate::error::AppError = if let Some(app_err) = err.as_error::<crate::error::AppError>() {
        app_err.clone()
    } else {
        crate::error::AppError::Internal(err.to_string())
    };

    // Use the ResponseError implementation
    Ok(app_error.error_response())
}

/// 404 Not Found handler
pub async fn handle_404(
    req: actix_web::HttpRequest,
) -> Result<actix_web::HttpResponse> {
    let error_response = crate::schema::responses::ErrorResponse::new(
        "not_found",
        &format!("Resource '{}' not found", req.path()),
    );

    Ok(actix_web::HttpResponse::NotFound().json(error_response))
}