//! Health check controller

use actix_web::{get, HttpResponse, Result};
use serde_json::json;

/// Health check controller
pub struct HealthController;

impl HealthController {
    /// Create new health controller
    pub fn new() -> Self {
        Self
    }
}

impl Default for HealthController {
    fn default() -> Self {
        Self::new()
    }
}

/// Health check endpoint
#[get("/health")]
pub async fn health_check() -> Result<HttpResponse> {
    let response = json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "service": "fido-server"
    });

    Ok(HttpResponse::Ok().json(response))
}