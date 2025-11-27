//! Health check controller

use actix_web::{web, HttpResponse, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;
use crate::{AppState, AppError};

/// Health check response structure
#[derive(Serialize)]
struct HealthResponse {
    status: String,
    timestamp: DateTime<Utc>,
    services: ServiceStatus,
    version: String,
}

/// Service status structure
#[derive(Serialize)]
struct ServiceStatus {
    database: String,
    redis: String,
}

/// Health check endpoint handler
///
/// # Arguments
///
/// * `app_state` - Application state containing connection pools
///
/// # Returns
///
/// Returns HTTP 200 with service status or HTTP 503 if any service is down
pub async fn health_check(app_state: web::Data<AppState>) -> Result<HttpResponse> {
    let mut database_status = "connected".to_string();
    let mut redis_status = "connected".to_string();
    let mut overall_healthy = true;
    
    // Test database connectivity
    if let Err(e) = crate::db::test_connection(&app_state.db_pool) {
        database_status = "disconnected".to_string();
        overall_healthy = false;
        log::error!("Database health check failed: {}", e);
    }
    
    // Test Redis connectivity
    if let Err(e) = crate::redis::test_connection(&app_state.redis_pool).await {
        redis_status = "disconnected".to_string();
        overall_healthy = false;
        log::error!("Redis health check failed: {}", e);
    }
    
    let response = HealthResponse {
        status: if overall_healthy { "ok".to_string() } else { "error".to_string() },
        timestamp: Utc::now(),
        services: ServiceStatus {
            database: database_status.clone(),
            redis: redis_status.clone(),
        },
        version: "1.0.0".to_string(),
    };
    
    if overall_healthy {
        Ok(HttpResponse::Ok().json(response))
    } else {
        // Determine which service failed for the error message
        let error_message = match (&database_status, &redis_status) {
            ("disconnected", "connected") => "Service unavailable - database connection failed",
            ("connected", "disconnected") => "Service unavailable - redis connection failed", 
            ("disconnected", "disconnected") => "Service unavailable - database and redis connections failed",
            _ => "Service unavailable",
        };
        
        Err(AppError::ServiceUnavailable(error_message.to_string()).into())
    }
}