//! Health check controller

use actix_web::{HttpResponse, Result};
use crate::schema::common::HealthResponse;

/// Health check controller
pub struct HealthController;

impl HealthController {
    /// Create a new health controller
    pub fn new() -> Self {
        Self
    }

    /// Health check endpoint
    pub async fn health() -> Result<HttpResponse> {
        let response = HealthResponse::new("0.1.0".to_string());
        Ok(HttpResponse::Ok().json(response))
    }
}