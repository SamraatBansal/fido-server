//! Health check endpoint handler

use crate::state::AppState;
use actix_web::{web, HttpResponse, Result};
use serde_json::json;

/// Health check endpoint response
///
/// Returns service status information including database and Redis connectivity
///
/// # Request
///
/// GET /health
///
/// # Response
///
/// Success (200):
/// ```json
/// {
///   "status": "ok",
///   "timestamp": "2024-01-01T00:00:00Z",
///   "version": "1.0.0",
///   "database": "connected",
///   "redis": "connected"
/// }
/// ```
///
/// Error (503):
/// ```json
/// {
///   "status": "error",
///   "errorMessage": "Database connection failed"
/// }
/// ```
pub async fn health_check(app_state: web::Data<AppState>) -> Result<HttpResponse> {
    log::debug!("Health check endpoint requested");

    match app_state.health_check().await {
        Ok(health_status) => {
            log::debug!("Health check successful");
            
            Ok(HttpResponse::Ok()
                .content_type("application/json")
                .json(json!({
                    "status": "ok",
                    "timestamp": health_status.timestamp.to_rfc3339(),
                    "version": health_status.version,
                    "database": health_status.database.to_string(),
                    "redis": health_status.redis.to_string()
                })))
        }
        Err(err) => {
            log::warn!("Health check failed: {}", err);
            
            // Check individual service statuses for detailed error reporting
            let mut database_status = "unknown";
            let mut redis_status = "unknown";
            
            // Try to get more specific status information
            if let Ok(partial_status) = get_partial_health_status(&app_state).await {
                database_status = match partial_status.database {
                    crate::state::ServiceStatus::Connected => "connected",
                    crate::state::ServiceStatus::Error(_) => "error",
                    crate::state::ServiceStatus::Unknown => "unknown",
                };
                
                redis_status = match partial_status.redis {
                    crate::state::ServiceStatus::Connected => "connected",
                    crate::state::ServiceStatus::Error(_) => "error",
                    crate::state::ServiceStatus::Unknown => "unknown",
                };
            }

            // Return 503 Service Unavailable with error details in FIDO2 format
            Ok(HttpResponse::ServiceUnavailable()
                .content_type("application/json")
                .json(json!({
                    "status": "error",
                    "errorMessage": determine_primary_error(database_status, redis_status),
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "version": env!("CARGO_PKG_VERSION"),
                    "database": database_status,
                    "redis": redis_status
                })))
        }
    }
}

/// Get partial health status even when overall health check fails
///
/// This allows us to report which specific services are failing
async fn get_partial_health_status(app_state: &AppState) -> Result<crate::state::HealthStatus, ()> {
    let mut status = crate::state::HealthStatus::default();

    // Check database (don't fail on error)
    match crate::db::test_connection(&app_state.db_pool) {
        Ok(()) => status.database = crate::state::ServiceStatus::Connected,
        Err(e) => status.database = crate::state::ServiceStatus::Error(e.to_string()),
    }

    // Check Redis (don't fail on error)
    match crate::redis::test_redis_connection(&app_state.redis_pool).await {
        Ok(()) => status.redis = crate::state::ServiceStatus::Connected,
        Err(e) => status.redis = crate::state::ServiceStatus::Error(e.to_string()),
    }

    Ok(status)
}

/// Determine the primary error message based on service statuses
fn determine_primary_error(database_status: &str, redis_status: &str) -> String {
    match (database_status, redis_status) {
        ("error", "error") => "Database and Redis connections failed".to_string(),
        ("error", _) => "Database connection failed".to_string(),
        (_, "error") => "Redis connection failed".to_string(),
        _ => "Service unavailable".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_determine_primary_error() {
        assert_eq!(
            determine_primary_error("error", "error"),
            "Database and Redis connections failed"
        );
        assert_eq!(
            determine_primary_error("error", "connected"),
            "Database connection failed"
        );
        assert_eq!(
            determine_primary_error("connected", "error"),
            "Redis connection failed"
        );
        assert_eq!(
            determine_primary_error("connected", "connected"),
            "Service unavailable"
        );
    }
}