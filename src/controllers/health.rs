//! Health check controller

use actix_web::{HttpResponse, Result};
use serde_json::json;

/// Health check endpoint
pub async fn health_check() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(json!({
        "status": "ok",
        "message": "FIDO2 WebAuthn RP Server is running"
    })))
}