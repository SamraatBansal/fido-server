//! Health check controller

use crate::error::Result;
use crate::models::dto::ServerResponse;
use actix_web::HttpResponse;

/// Health check endpoint
pub async fn health_check() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(ServerResponse::success()))
}