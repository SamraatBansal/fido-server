//! API routes configuration

use actix_web::{web, HttpResponse, Result};
use crate::schema::common::{ErrorResponse, HealthResponse};

/// Health check endpoint
async fn health() -> Result<HttpResponse> {
    let response = HealthResponse::new("0.1.0".to_string());
    Ok(HttpResponse::Ok().json(response))
}

/// Configure all API routes
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1")
            .route("/register/start", web::post().to(register_start))
            .route("/register/finish", web::post().to(register_finish))
            .route("/authenticate/start", web::post().to(authenticate_start))
            .route("/authenticate/finish", web::post().to(authenticate_finish))
    )
    .route("/health", web::get().to(health));
}

/// Registration start endpoint (placeholder)
async fn register_start(_req: web::Json<serde_json::Value>) -> Result<HttpResponse> {
    // Placeholder implementation
    Ok(HttpResponse::NotImplemented().json(ErrorResponse::new("Not implemented yet".to_string(), 501)))
}

/// Registration finish endpoint (placeholder)
async fn register_finish(_req: web::Json<serde_json::Value>) -> Result<HttpResponse> {
    // Placeholder implementation
    Ok(HttpResponse::NotImplemented().json(ErrorResponse::new("Not implemented yet".to_string(), 501)))
}

/// Authentication start endpoint (placeholder)
async fn authenticate_start(_req: web::Json<serde_json::Value>) -> Result<HttpResponse> {
    // Placeholder implementation
    Ok(HttpResponse::NotImplemented().json(ErrorResponse::new("Not implemented yet".to_string(), 501)))
}

/// Authentication finish endpoint (placeholder)
async fn authenticate_finish(_req: web::Json<serde_json::Value>) -> Result<HttpResponse> {
    // Placeholder implementation
    Ok(HttpResponse::NotImplemented().json(ErrorResponse::new("Not implemented yet".to_string(), 501)))
}