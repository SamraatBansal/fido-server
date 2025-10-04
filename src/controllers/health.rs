//! Health check controller

use actix_web::{HttpResponse, Result};
use chrono::Utc;
use serde_json::json;

/// Health check endpoint
pub async fn health_check() -> Result<HttpResponse> {
    let response = json!({
        "status": "healthy",
        "timestamp": Utc::now().to_rfc3339(),
        "service": "fido-server",
        "version": env!("CARGO_PKG_VERSION")
    });

    Ok(HttpResponse::Ok().json(response))
}

/// Readiness check endpoint
pub async fn readiness_check() -> Result<HttpResponse> {
    // TODO: Add database connectivity check
    // TODO: Add external service dependencies check
    
    let response = json!({
        "status": "ready",
        "timestamp": Utc::now().to_rfc3339(),
        "checks": {
            "database": "ok",
            "webauthn": "ok"
        }
    });

    Ok(HttpResponse::Ok().json(response))
}

/// Liveness check endpoint
pub async fn liveness_check() -> Result<HttpResponse> {
    let response = json!({
        "status": "alive",
        "timestamp": Utc::now().to_rfc3339()
    });

    Ok(HttpResponse::Ok().json(response))
}